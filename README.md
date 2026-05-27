# scx_snap

A latency-optimized Linux scheduler built on [sched_ext](https://github.com/sched-ext/scx). Keeps interactive tasks (UI, audio, input handling) feeling snappy by separating them from batch/background work.

## How it works

Tasks are classified into two tiers:

- **Interactive** — short 5ms slices, dispatched first, preempts batch tasks on wakeup
- **Batch** — standard 20ms slices, runs when no interactive work is pending

A task is interactive if its nice value is ≤ 0 (configurable), or after a few wakeup cycles it's spending more than 50% of its wall time sleeping — the fingerprint of I/O-bound, latency-sensitive work. The ratio is tracked with an EWMA so it adapts as workloads change. Kernel threads always go to batch.

Each CPU has its own interactive DSQ. When an interactive task wakes from I/O, it kicks its target CPU immediately (`SCX_KICK_PREEMPT`) rather than waiting for the next scheduling tick. CPU frequency is also boosted to max for interactive tasks and throttled for batch work via `scx_bpf_cpuperf_set`.

## Requirements

- Linux 6.12+ with `CONFIG_SCHED_CLASS_EXT=y`
- `clang`, `gcc`, `bpftool`, `libbpf-dev`

```sh
sudo apt install clang gcc libbpf-dev libncurses-dev linux-tools-$(uname -r)
```

## Build

```sh
make
```

The Makefile generates `vmlinux.h` from the running kernel's BTF, compiles the BPF program, and produces the `scx_snap` binary.

## Run

```sh
sudo ./scx_snap
```

Press Ctrl-C to stop. The kernel reverts all tasks to CFS automatically on exit.

Tune slices, nice threshold, or CPU frequency behavior:

```sh
sudo ./scx_snap -i 3000 -b 15000 -n -1 --batch-cpuperf-pct 30
```

## Options

```
-i  interactive slice in us         (default: 5000)
-b  batch slice in us               (default: 20000)
-n  nice threshold                  (default: 0)
-p  min sleep % for interactive     (default: 50)
    --batch-cpuperf-pct N           batch task CPU freq % (default: 50)
    --no-cpuperf                    disable freq scaling
    --no-tui                        plain text output instead of TUI
-s  stats interval in seconds       (default: 1, 0 to disable)
-v  verbose libbpf output
```
