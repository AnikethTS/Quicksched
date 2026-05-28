# scx_snap

A latency-optimized Linux CPU scheduler built on [sched_ext](https://github.com/sched-ext/scx). Keeps interactive tasks (UI, audio, input handling) feeling snappy by separating them from batch and background work, with memory-pressure awareness and live TUI monitoring.

## How it works

Tasks are classified into two tiers:

- **Interactive** — short 5 ms slices, dispatched first, preempts batch tasks on wakeup, runs at full CPU frequency
- **Batch** — standard 20 ms slices, runs when no interactive work is pending, CPU frequency throttled to 50% by default

A task is interactive if its nice value is ≤ 0 (configurable), or after a few wakeup cycles it is spending more than 50% of its wall time sleeping — the fingerprint of I/O-bound, latency-sensitive work. The ratio is tracked with an EWMA so it adapts as workloads change. Kernel threads always go to batch.

Each CPU has its own interactive DSQ. When an interactive task wakes from I/O, it kicks its target CPU immediately (`SCX_KICK_PREEMPT`) rather than waiting for the next scheduling tick.

### Memory-awareness

- Tasks performing direct memory reclaim (`PF_MEMALLOC`) are immediately forced to the batch queue regardless of their classification.
- A per-task slice-utilisation EWMA tracks how much of each time slice a task actually consumes. Tasks whose EWMA drops below 40% are classified as memory-stall-bound and capped at batch CPU frequency — higher clock speed does not help RAM-bound work.

### Safety

The BPF struct_ops link is tied to the userspace process file descriptor. If `scx_snap` exits or crashes, the kernel automatically reverts all tasks to CFS. `timeout_ms = 30000` is set in the ops struct as an additional safeguard: the kernel self-reverts if any task fails to make progress for 30 seconds.

## Kernel compatibility

| Kernel | Status |
|--------|--------|
| < 6.12 | Not supported (no sched_ext) |
| 6.12 – 6.16 | Fully supported |
| 6.17+ | Supported (BPF_PROG context wrapper applied) |

## Requirements

- Linux kernel ≥ 6.12 with `CONFIG_SCHED_CLASS_EXT=y`
- `clang`, `gcc`, `bpftool`, `libbpf-dev`, `libncurses-dev`

```sh
sudo apt install clang gcc libbpf-dev libncurses-dev linux-tools-$(uname -r)
```

## Build

```sh
make
```

The Makefile auto-detects the target architecture, checks for required tools, generates `vmlinux.h` from the running kernel's BTF (cached by kernel version — only regenerated after a kernel upgrade), compiles the BPF program, and links the binary.

```sh
make clean        # remove build artefacts, preserve vmlinux.h cache
make clean-full   # remove everything including the vmlinux.h cache
```

## Install

```sh
sudo make install                        # installs to /usr/local/bin
sudo make install PREFIX=/usr            # installs to /usr/bin
sudo make uninstall                      # removes installed files
```

`make install` also installs the man page (`man scx_snap`) and the systemd unit file.

## Run

```sh
sudo ./scx_snap           # interactive TUI
sudo ./scx_snap --no-tui  # plain text output
```

Press Ctrl-C to stop. The kernel reverts all tasks to CFS automatically on exit.

Tune slices, nice threshold, or CPU frequency behaviour:

```sh
sudo scx_snap -i 3000 -b 15000 -n -1 --batch-cpuperf-pct 30
```

## Run as a service

```sh
sudo systemctl enable --now scx_snap
sudo systemctl status scx_snap
```

The unit restarts automatically on failure (`Restart=on-failure`). It will not start on kernels that do not expose `/sys/kernel/sched_ext`.

## Options

```
-i  --interactive-slice-us N    interactive slice in µs       (default: 5000)
-b  --batch-slice-us N          batch slice in µs             (default: 20000)
-n  --nice-interactive-max N    nice threshold                 (default: 0)
-p  --interactive-sleep-pct N   min sleep % for interactive   (default: 50)
    --batch-cpuperf-pct N       batch CPU freq %              (default: 50)
    --no-cpuperf                disable CPU freq scaling
    --no-tui                    plain text output
-s  --stats-interval N          stats interval in seconds     (default: 1, 0=off)
-v  --verbose                   verbose libbpf output
-h  --help
```

## TUI

The ncurses TUI refreshes every stats interval and shows three sections:

- **SCHEDULING** — per-second dispatch counts for interactive, batch, and idle-fast (local) queues with bar charts
- **MEMORY** — per-second memalloc-demoted task count and early-stop (preempted/stalled) count
- **WAKEUP LATENCY** — avg/p50/p99 wakeup latency and a log-scale histogram (bucket resolution doubles each step, from <1 µs to ~128 ms)

## Project structure

```
src/
  scx_snap.c          userspace: TUI, stats, BPF skeleton lifecycle
  bpf/
    scx_snap.bpf.c    BPF scheduler implementation
    scx_snap.h        shared types and constants
man/
  scx_snap.1          man page
packaging/
  scx_snap.service    systemd unit file
.github/workflows/
  ci.yml              GitHub Actions CI
Makefile
```
