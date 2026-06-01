// SPDX-License-Identifier: GPL-2.0
#ifndef __SCX_QUICKSCHED_H
#define __SCX_QUICKSCHED_H

#define QS_VERSION "0.2.0"

#define QS_DSQ_BATCH 0x10000ULL
#define QS_MAX_CPUS 512

#define QS_SLICE_INTERACTIVE_NS 5000000ULL
#define QS_SLICE_BATCH_NS 20000000ULL

#define PF_KTHREAD 0x00200000
#define PF_MEMALLOC 0x00000800
#define QS_MIN_WAKEUPS 4
#define QS_EWMA_WEIGHT 7

/* Sleep duration above which a batch task gets one interactive boost on wake. */
#define QS_WAKEUP_BOOST_SLEEP_NS 50000000ULL /* 50 ms */
/* I/O-bound tasks (low util) boosted after a shorter sleep. */
#define QS_IO_BOOST_SLEEP_NS 5000000ULL /* 5 ms */
/* Minimum cpuperf delta before we actually call scx_bpf_cpuperf_set (hysteresis). */
#define QS_CPUPERF_HYSTERESIS 52 /* ~5 % of 1024 */
/* Batch vruntime lag window: tasks can't be more than this far behind the present. */
#define QS_VTIME_LAG_NS 100000000ULL /* 100 ms */
/* Interactive vtime sleep-credit per util percentage point (max 50 ms total). */
#define QS_IVTIME_CREDIT_NS 500000ULL
/* Slice util% above which a classified-interactive task earns burst credit. */
#define QS_BURST_UTIL_THRESHOLD 90
/* Max burst-slice dispatches a task can accumulate. */
#define QS_BURST_CREDIT_MAX 3
/* Burst slice = 2× interactive slice (10 ms). */
#define QS_SLICE_BURST_NS (QS_SLICE_INTERACTIVE_NS * 2)
/* Run durations shorter than this while still runnable hint at RT preemption. */
#define QS_RT_PREEMPT_NS 300000ULL /* 300 µs */

#define QS_LAT_BUCKETS 20

/* Tasks whose scx.weight is below this threshold are classified as batch
 * regardless of sleep ratio (catches low-priority cgroup services). */
#define QS_BATCH_WEIGHT_MAX 50

/* Batch queue depth at which batch tasks ramp to full CPU frequency. */
#define QS_CPUPERF_LOAD_FULL 16

/* Max CPUs to work-steal from; stride-spaced to cover the whole machine. */
#define QS_MAX_STEAL_CPUS 16

/* Global high-priority DSQ for ultra-interactive tasks (nice <= nice_rt_max). */
#define QS_DSQ_RT_LIKE 0x20000ULL
#define QS_SLICE_RT_LIKE_NS 2000000ULL /* 2 ms */

struct qs_task_ctx
{
    __u64 sum_run_ns;
    __u64 sum_sleep_ns;
    __u64 run_at;
    __u64 sleep_at;
    __u64 enqueue_at;
    __u64 assigned_slice_ns;
    __u64 slice_util_ewma; /* EWMA of slice utilisation % (0-100); 100 = CPU-bound */
    __u64 vruntime;        /* accumulated CPU time; used for vtime-ordered batch DSQ */
    __u32 wakeups;
    __u8 wakeup_boost; /* 1 = grant one interactive dispatch after long sleep */
    __u8 burst_credit; /* remaining burst-slice dispatches (0–QS_BURST_CREDIT_MAX) */
    __u8 pad[2];
};

struct qs_stats
{
    __u64 nr_interactive;
    __u64 nr_batch;
    __u64 nr_local;
    __u64 nr_preempted;      /* tasks that stopped before exhausting their slice */
    __u64 nr_memalloc;       /* tasks demoted to batch due to PF_MEMALLOC */
    __u64 nr_stolen;         /* tasks work-stolen from another CPU's interactive DSQ */
    __u64 nr_mem_stall;      /* dispatches where slice_util_ewma < 40 (RAM-bound) */
    __u64 nr_rt_like;        /* dispatches for ultra-interactive (nice <= nice_rt_max) */
    __u64 nr_wakeup_boosted; /* batch tasks granted one interactive dispatch on wake */
    __u64 nr_burst;          /* interactive tasks dispatched with 2× burst slice */
    __u64 nr_rt_preempt;     /* suspected RT-preempted dispatches (short run, runnable) */
};

/* Written by userspace when PSI memory pressure exceeds a threshold.
 * BPF uses batch_cpuperf_abs_override instead of the rodata default
 * when the field is non-zero, allowing live pressure-based throttling. */
struct qs_dynamic_cfg
{
    __u32 batch_cpuperf_abs_override; /* PSI-driven throttle; 0 = off */
    __u32 batch_cpuperf_live;         /* TUI-set base freq; 0 = use rodata */
    __s32 nice_rt_max_live;           /* TUI-set threshold (when nice_rt_max_set=1) */
    __u32 nice_rt_max_set;            /* 1 = nice_rt_max_live is valid */
};

struct qs_latency
{
    __u64 buckets[QS_LAT_BUCKETS];
    __u64 total_ns;
    __u64 count;
};

/* Global batch queue depth — used for adaptive CPU frequency scaling. */
struct qs_batch_depth
{
    __s64 depth;
};

/* Per-CPU dispatch counter — PERCPU_ARRAY, one entry per CPU. */
struct qs_cpu_load
{
    __u64 nr_dispatch;
    __u64 nr_interactive;
    __u64 nr_batch;
};

/* Exit information written by the BPF exit callback. */
#define QS_EXIT_REASON_LEN 64
#define QS_EXIT_MSG_LEN 128

struct qs_exit_info
{
    __u32 kind; /* enum scx_exit_kind */
    __u32 pad;
    char reason[QS_EXIT_REASON_LEN];
    char msg[QS_EXIT_MSG_LEN];
};

#endif
