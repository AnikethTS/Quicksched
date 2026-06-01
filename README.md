# Quicksched

A latency-optimized Linux CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx). Keeps interactive tasks (UI, audio, input handling) feeling snappy by separating them from batch and background work, with memory/I/O pressure awareness, thermal throttling, and live TUI + GUI monitoring.

Developed by **Aniketh T S**

## How it works

Tasks are classified into three dispatch tiers:

| Tier | Slice | CPU freq | DSQ |
|------|-------|----------|-----|
| **rt-like** | 2 ms | 100% | Global, checked first |
| **interactive** | 5 ms (10 ms burst) | 100% | Per-CPU, vtime-ordered |
| **batch** | 20 ms | 50% (adaptive) | Global, vtime-ordered |

### Classification

A task is **interactive** if its nice value is ≤ 0 (configurable), or after a few wakeup cycles it spends more than 50% of wall time sleeping — the fingerprint of I/O-bound, latency-sensitive work. The ratio is tracked with an EWMA so it adapts as workloads change. Kernel threads always go to batch.

A task is **rt-like** (ultra-interactive) if its nice value is ≤ −10 (configurable via `--nice-rt-max`). These tasks get a dedicated global DSQ checked before all per-CPU queues, so any idle CPU picks them up immediately.

Low-weight cgroup tasks (weight < 50) are forced to batch regardless of sleep ratio, catching background services that happen to sleep often.

### Scheduling behaviour

- **Per-CPU interactive DSQs** — each CPU owns an interactive DSQ. Wakeup tasks kick their target CPU with `SCX_KICK_PREEMPT` and wake up to 4 nearby idle CPUs to steal the task immediately (push-based load balancing).
- **Vtime ordering** — both interactive and batch DSQs are vtime-ordered. Interactive: `vtime = now − (100−util) × 0.5 ms`; tasks that sleep more get priority within their CPU's queue. Batch: tasks accumulate vruntime as CPU time consumed; a 100 ms lag window prevents starvation.
- **Burst detection** — interactive tasks that consistently saturate their slice (util ≥ 90%) earn up to 3 burst credits; each credit grants a 10 ms slice instead of 5 ms, giving transient CPU-hungry phases (JIT compilation, video decode) extra headroom without misclassifying the task.
- **Wakeup boost** — any task waking from sleep > 50 ms gets a one-shot interactive dispatch. I/O-bound batch tasks (low utilisation) also get this boost after just 5 ms sleep.
- **Work stealing** — idle CPUs steal from busy CPUs in three passes: same LLC → same NUMA node / different LLC → cross-NUMA. Cache-topology maps (`cpu_llc`, `cpu_node`) are populated from sysfs at startup; transparent no-op on single-socket machines.

### CPU frequency scaling

- Interactive and rt-like tasks run at 100% CPU freq.
- Batch tasks run at a configurable base frequency (default 50%).
- The base scales up linearly as the batch queue depth grows (up to 100% at 16+ queued tasks).
- Hysteresis: `scx_bpf_cpuperf_set` is skipped unless the new value differs by > 5%, avoiding micro-adjustments on stable workloads.

### Memory & pressure awareness

- Tasks performing direct memory reclaim (`PF_MEMALLOC`) are immediately forced to the front of the batch vtime queue.
- A per-task slice-utilisation EWMA tracks actual CPU usage. Tasks with EWMA < 40% are memory-stall-bound and capped at batch CPU frequency.
- **PSI memory pressure** (`--mem-pressure-pct`): when system-wide memory stall exceeds the threshold, batch CPU freq is reduced proportionally — from 75% of base at the threshold down to 25% at 3× the threshold. A 3-sample hysteresis prevents oscillation.
- **PSI I/O pressure** (`--io-pressure-pct`): same graduated throttle applied to I/O stall. Both sources are combined; the most restrictive wins.
- **Thermal throttling** (`--thermal-limit`): reads CPU package temperature from sysfs; applies the same graduated throttle when temperature exceeds the configured limit.

### RT preemption tracking

Short runs (< 300 µs) while still runnable are counted as suspected RT preemptions (`nr_rt_preempt`), visible in the TUI and JSON output.

### Safety

The BPF struct_ops link is tied to the userspace process file descriptor. If `scx_quicksched` exits or crashes, the kernel automatically reverts all tasks to CFS. `timeout_ms = 30000` provides an additional safeguard.

## Kernel compatibility

| Kernel | Status |
|--------|--------|
| < 6.12 | Not supported (no sched_ext) |
| 6.12 – 6.16 | Fully supported |
| 6.17+ | Supported |

## Requirements

- Linux kernel ≥ 6.12 with `CONFIG_SCHED_CLASS_EXT=y`
- `clang`, `gcc`, `bpftool`, `libbpf`, `ncurses`

Install all dependencies automatically:

```sh
sudo scripts/install-deps.sh
```

Or manually:

| Distro | Command |
|--------|---------|
| **Ubuntu / Debian** | `sudo apt install clang gcc libbpf-dev libncurses-dev linux-tools-$(uname -r)` |
| **Fedora** | `sudo dnf install clang gcc libbpf-devel ncurses-devel bpftool` |
| **RHEL / AlmaLinux** | `sudo dnf install epel-release && sudo dnf install clang gcc libbpf-devel ncurses-devel bpftool` |
| **Arch Linux** | `sudo pacman -S clang gcc libbpf ncurses bpf` |
| **openSUSE** | `sudo zypper install clang gcc libbpf-devel ncurses-devel bpftool` |

## Build

```sh
make
```

```sh
make clean        # remove build artefacts, preserve vmlinux.h cache
make clean-full   # remove everything including the vmlinux.h cache
```

## Install

```sh
sudo make install                   # installs to /usr/local/bin
sudo make install PREFIX=/usr       # installs to /usr/bin
sudo make uninstall
```

Installs `scx_quicksched`, `qs`, `quicksched-gui`, the man page, and the systemd unit file.

## Running

### Interactive TUI

```sh
sudo ./scx_quicksched
```

Press **`q`** to quit, **`c`** to open the live settings panel.

### Background manager (`qs`)

```sh
qs                  # start in background (no TUI), logs to /var/log/scx_quicksched.log
qs --status         # show PID and uptime
qs stop             # stop the background instance
qs [flags...]       # pass flags through to interactive TUI mode
```

### GUI

```sh
python3 gui/quicksched-gui      # or: quicksched-gui  (after make install)
```

Requires `python3-gi gir1.2-gtk-4.0`:

```sh
sudo apt install python3-gi gir1.2-gtk-4.0
```

Shows live wakeup latency sparklines, PSI pressure, dispatch mix bar, and all tunable settings with Gaming / Desktop / Server / Battery presets.

### Run as a service

```sh
sudo systemctl enable --now scx_quicksched
sudo systemctl status scx_quicksched
```

The unit restarts automatically on failure. It will not start on kernels that do not expose `/sys/kernel/sched_ext`.

### JSON output (for scripting)

```sh
sudo ./scx_quicksched --json
```

Emits one JSON line per stats interval to stdout. Fields include `interactive`, `batch`, `rt_like`, `burst`, `rt_preempt`, `lat_p50_us`, `lat_p99_us`, `psi_mem_some`, `psi_io_some`, `cpu_temp_c`, and more.

### Dry-run

```sh
sudo ./scx_quicksched --dry-run
```

Loads and JIT-compiles the BPF object and exits without attaching — useful for CI and pre-flight checks.

## Options

```
-i  --interactive-slice-us N    interactive slice in µs            (default: 5000)
-b  --batch-slice-us N          batch slice in µs                  (default: 20000)
-n  --nice-interactive-max N    nice threshold for interactive      (default: 0)
    --nice-rt-max N             nice threshold for rt-like DSQ      (default: -10)
-p  --interactive-sleep-pct N   min sleep % for interactive class   (default: 50)
    --batch-cpuperf-pct N       batch CPU freq %                    (default: 50)
    --no-cpuperf                disable CPU freq scaling
    --mem-pressure-pct N        throttle batch when PSI mem > N%    (default: 0=off)
    --io-pressure-pct N         throttle batch when PSI io  > N%    (default: 0=off)
    --thermal-limit N           throttle batch when CPU temp > N°C  (default: 0=off)
    --no-tui                    plain text output
    --json                      machine-readable JSON output
    --dry-run                   load and verify BPF; exit without attaching
    --slo-us N                  alert when p99 latency exceeds N µs (default: 0=off)
    --pidfile PATH              write PID to file (used by qs)
-s  --stats-interval N          stats interval in seconds           (default: 1, 0=off)
-v  --verbose                   verbose libbpf output
-V  --version                   print version and exit
-h  --help
```

## TUI

Refreshes every stats interval. Press **`c`** to open the settings panel, **`q`** to quit.

### SCHEDULING

| Row | Description |
|-----|-------------|
| `rt-like` | Ultra-interactive dispatches (nice ≤ nice-rt-max) |
| `interactive` | Normal interactive dispatches |
| `batch` | Batch dispatches |
| `idle-fast` | Tasks dispatched directly to idle CPU in select_cpu |
| `stolen` | Work-stolen from another CPU's interactive DSQ |
| `woke-boost` | Batch tasks granted one-shot interactive dispatch on wake |
| `burst` | Interactive tasks dispatched with 2× burst slice |
| `rt-preempt` | Suspected RT preemptions (short run, still runnable) |

### MEMORY

| Row | Description |
|-----|-------------|
| `mem psi` | Memory stall some/full avg10 — `[throttled]` when active |
| `io psi` | I/O stall some/full avg10 |
| `CPU N°C` | CPU package temperature (header, colour-coded) |
| `memalloc` | PF_MEMALLOC tasks demoted to batch |
| `preempted` | Tasks stopped before exhausting their slice |
| `mem-stall` | Dispatches where slice_util_ewma < 40% (RAM-bound) |

### CPU LOAD

Per-CPU dispatch rate bars; idle CPUs labelled; header shows active/total.

### WAKEUP LATENCY

avg / p50 / p99 and a log-scale histogram (< 1 µs → ~256 ms).

### Live settings panel (`c`)

| Setting | Presets |
|---------|---------|
| mem-pressure-pct | Off / 5% / 10% / 20% / 30% |
| io-pressure-pct | Off / 5% / 10% / 20% / 30% |
| nice-rt-max | Default / −5 / −10 / −15 / Disabled |
| batch-cpuperf-pct | Default / 25% / 50% / 75% / 100% |

Navigate with `UP/DN`, adjust with `LT/RT`, close with `c`.

## Presets

| Preset | mem-pct | io-pct | nice-rt-max | batch-cpuperf |
|--------|---------|--------|-------------|---------------|
| Gaming | 10% | 5% | −5 | 25% |
| Desktop | Off | Off | −10 | 50% |
| Server | 20% | 15% | −15 | 75% |
| Battery | 5% | 5% | −15 | 25% |

## Project structure

```
src/
  scx_quicksched.c          userspace: TUI, settings panel, JSON output, BPF lifecycle
  bpf/
    scx_quicksched.bpf.c    BPF scheduler (classification, vtime dispatch, LLC steal)
    scx_quicksched.h        shared types, constants, and map definitions
gui/
  quicksched-gui            GTK4 Python GUI (sparklines, presets, start/stop)
scripts/
  install-deps.sh           auto-detects distro and installs build dependencies
man/
  scx_quicksched.1          man page
packaging/
  scx_quicksched.service    systemd unit file
  scx_quicksched.spec       RPM spec (Fedora / RHEL / openSUSE)
  PKGBUILD                  Arch Linux package build script
qs                          background manager (start / --status / stop)
.github/workflows/
  ci.yml                    CI: Ubuntu, Fedora, Arch, sanitizers, clang-format
Makefile
```
