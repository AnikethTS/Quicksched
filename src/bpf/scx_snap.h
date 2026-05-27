// SPDX-License-Identifier: GPL-2.0
#ifndef __SCX_SNAP_H
#define __SCX_SNAP_H

#define SNAP_DSQ_INTERACTIVE 0ULL
#define SNAP_DSQ_BATCH 1ULL

#define SNAP_SLICE_INTERACTIVE_NS 5000000ULL
#define SNAP_SLICE_BATCH_NS 20000000ULL

#define PF_KTHREAD 0x00200000
#define SNAP_MIN_WAKEUPS 4
#define SNAP_EWMA_WEIGHT 7

struct snap_task_ctx
{
	__u64 sum_run_ns;
	__u64 sum_sleep_ns;
	__u64 run_at;
	__u64 sleep_at;
	__u32 wakeups;
	__u8 pad[4];
};

struct snap_stats
{
	__u64 nr_interactive;
	__u64 nr_batch;
	__u64 nr_local;
};

#endif
