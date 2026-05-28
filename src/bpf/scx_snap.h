// SPDX-License-Identifier: GPL-2.0
#ifndef __SCX_SNAP_H
#define __SCX_SNAP_H

#define SNAP_DSQ_BATCH 0x10000ULL
#define SNAP_MAX_CPUS 512

#define SNAP_SLICE_INTERACTIVE_NS 5000000ULL
#define SNAP_SLICE_BATCH_NS 20000000ULL

#define PF_KTHREAD 0x00200000
#define PF_MEMALLOC 0x00000800
#define SNAP_MIN_WAKEUPS 4
#define SNAP_EWMA_WEIGHT 7

#define SNAP_LAT_BUCKETS 20

struct snap_task_ctx
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

struct snap_stats
{
	__u64 nr_interactive;
	__u64 nr_batch;
	__u64 nr_local;
	__u64 nr_preempted; /* tasks that stopped before exhausting their slice */
	__u64 nr_memalloc;	/* tasks demoted to batch due to PF_MEMALLOC */
};

struct snap_latency
{
	__u64 buckets[SNAP_LAT_BUCKETS];
	__u64 total_ns;
	__u64 count;
};

#endif
