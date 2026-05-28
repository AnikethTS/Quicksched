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

#define QS_LAT_BUCKETS 20

/* Tasks whose scx.weight is below this threshold are classified as batch
 * regardless of sleep ratio (catches low-priority cgroup services). */
#define QS_BATCH_WEIGHT_MAX 50

/* Batch queue depth at which batch tasks ramp to full CPU frequency. */
#define QS_CPUPERF_LOAD_FULL 16

struct qs_task_ctx
{
    __u64 sum_run_ns;
    __u64 sum_sleep_ns;
    __u64 run_at;
    __u64 sleep_at;
    __u64 enqueue_at;
    __u64 assigned_slice_ns;
    __u64 slice_util_ewma; /* EWMA of slice utilisation % (0-100); 100 = CPU-bound */
    __u32 wakeups;
    __u8 pad[4];
};

struct qs_stats
{
    __u64 nr_interactive;
    __u64 nr_batch;
    __u64 nr_local;
    __u64 nr_preempted; /* tasks that stopped before exhausting their slice */
    __u64 nr_memalloc;  /* tasks demoted to batch due to PF_MEMALLOC */
    __u64 nr_stolen;    /* tasks work-stolen from another CPU's interactive DSQ */
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
};

#endif
