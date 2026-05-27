# scx_snap

A latency-optimized Linux scheduler built on [sched_ext](https://github.com/sched-ext/scx). It keeps interactive tasks (UI, audio, input handling) feeling snappy by separating them from batch/background work.

## How it works

Tasks are put into one of two dispatch queues — interactive or batch. The interactive queue is always drained first, and tasks in it get a shorter 5ms time slice. Batch tasks get 20ms.

A task is classified as interactive if:
- its nice value is ≤ 0 (or whatever threshold you set), or
- after a few wakeup cycles, it's spending more than 50% of its wall time sleeping — the classic fingerprint of I/O-bound, latency-sensitive work

The sleep ratio is tracked with an EWMA so it adapts as workloads change. Kernel threads always go to batch.

When an idle CPU is found during `select_cpu`, the task bypasses the enqueue path entirely and goes straight to that CPU's local DSQ — this shaves a bit of latency off the hot path.

## Requirements

- Linux 6.12+ with `CONFIG_SCHED_CLASS_EXT=y`
- Rust toolchain
- `clang`, `libbpf-dev`, `bpftool` (`linux-tools-$(uname -r)`)

## Build

```sh
cargo build --release
```

The build script generates `vmlinux.h` from the running kernel's BTF and compiles the BPF program automatically.

## Run

Needs root to load a BPF scheduler:

```sh
sudo ./target/release/scx_snap
```

Tune the slices or classification threshold:

```sh
sudo ./target/release/scx_snap -i 3000 -b 15000 -n -1
```

Press Ctrl-C to stop. The kernel reverts all tasks to CFS automatically on exit.

## Options

```
-i  interactive slice in µs     (default: 5000)
-b  batch slice in µs           (default: 20000)
-n  nice threshold               (default: 0, tasks with nice <= this are always interactive)
-p  minimum sleep % for interactive classification  (default: 50)
-s  stats interval in seconds   (default: 1, 0 to disable)
-v  verbose libbpf output
```
