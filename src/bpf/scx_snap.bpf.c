// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_snap.h"

#define ENOMEM 12

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct snap_task_ctx);
} task_stor SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct snap_stats);
} stats SEC(".maps");

const volatile __u64 slice_interactive_ns = SNAP_SLICE_INTERACTIVE_NS;
const volatile __u64 slice_batch_ns = SNAP_SLICE_BATCH_NS;
const volatile __s32 nice_interactive_max = 0;
const volatile __u32 interactive_sleep_pct = 50;

extern int scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id,
                               u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu,
                                  u64 wake_flags, bool *is_idle) __ksym;
extern u64 scx_bpf_now(void) __ksym;

static __always_inline bool task_is_interactive(struct task_struct *p,
                                                struct snap_task_ctx *tctx)
{
    __u64 total;
    __s32 nice;

    if (p->flags & PF_KTHREAD)
        return false;

    /* static_prio = MAX_RT_PRIO(100) + 20 + nice */
    nice = (__s32)p->static_prio - 120;

    if (nice < 0)
        return true;

    if (nice <= nice_interactive_max)
        return true;

    if (tctx->wakeups < SNAP_MIN_WAKEUPS)
        return false;

    total = tctx->sum_run_ns + tctx->sum_sleep_ns;
    if (total == 0)
        return false;

    return (tctx->sum_sleep_ns * 100) / total >= interactive_sleep_pct;
}

SEC("struct_ops/scx_snap_runnable")
void scx_snap_runnable(struct task_struct *p, u64 enq_flags)
{
    struct snap_task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_stor, p, 0, 0);
    if (!tctx)
        return;

    if ((enq_flags & SCX_ENQ_WAKEUP) && tctx->sleep_at > 0)
    {
        __u64 sleep_dur = scx_bpf_now() - tctx->sleep_at;

        tctx->sum_sleep_ns = (tctx->sum_sleep_ns * SNAP_EWMA_WEIGHT + sleep_dur) / (SNAP_EWMA_WEIGHT + 1);
        tctx->wakeups++;
        tctx->sleep_at = 0;
    }
}

SEC("struct_ops/scx_snap_select_cpu")
s32 scx_snap_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    struct snap_task_ctx *tctx;
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle)
    {
        tctx = bpf_task_storage_get(&task_stor, p, 0, 0);
        if (tctx)
        {
            bool interactive = task_is_interactive(p, tctx);
            __u64 slice = interactive ? slice_interactive_ns : slice_batch_ns;
            __u32 zero = 0;
            struct snap_stats *st;

            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);

            st = bpf_map_lookup_elem(&stats, &zero);
            if (st)
                st->nr_local++;
        }
    }

    return cpu;
}

SEC("struct_ops/scx_snap_enqueue")
void scx_snap_enqueue(struct task_struct *p, u64 enq_flags)
{
    struct snap_task_ctx *tctx;
    struct snap_stats *st;
    bool interactive;
    __u64 slice, dsq_flags = 0;
    __u64 dsq_id;
    __u32 zero = 0;

    tctx = bpf_task_storage_get(&task_stor, p, 0, 0);
    if (!tctx)
    {
        scx_bpf_dsq_insert(p, SNAP_DSQ_BATCH, slice_batch_ns, enq_flags);
        return;
    }

    interactive = task_is_interactive(p, tctx);

    if (interactive)
    {
        slice = slice_interactive_ns;
        dsq_id = SNAP_DSQ_INTERACTIVE;
        if (enq_flags & SCX_ENQ_WAKEUP)
            dsq_flags = SCX_ENQ_HEAD;
    }
    else
    {
        slice = slice_batch_ns;
        dsq_id = SNAP_DSQ_BATCH;
    }

    scx_bpf_dsq_insert(p, dsq_id, slice, dsq_flags);

    st = bpf_map_lookup_elem(&stats, &zero);
    if (st)
    {
        if (interactive)
            st->nr_interactive++;
        else
            st->nr_batch++;
    }
}

SEC("struct_ops/scx_snap_dispatch")
void scx_snap_dispatch(s32 cpu, struct task_struct *prev)
{
    if (scx_bpf_dsq_move_to_local(SNAP_DSQ_INTERACTIVE))
        return;
    scx_bpf_dsq_move_to_local(SNAP_DSQ_BATCH);
}

SEC("struct_ops/scx_snap_running")
void scx_snap_running(struct task_struct *p)
{
    struct snap_task_ctx *tctx = bpf_task_storage_get(&task_stor, p, 0, 0);

    if (tctx)
        tctx->run_at = scx_bpf_now();
}

SEC("struct_ops/scx_snap_stopping")
void scx_snap_stopping(struct task_struct *p, bool runnable)
{
    struct snap_task_ctx *tctx = bpf_task_storage_get(&task_stor, p, 0, 0);

    if (!tctx)
        return;

    if (tctx->run_at > 0)
    {
        __u64 run_dur = scx_bpf_now() - tctx->run_at;

        tctx->sum_run_ns = (tctx->sum_run_ns * SNAP_EWMA_WEIGHT + run_dur) / (SNAP_EWMA_WEIGHT + 1);
        tctx->run_at = 0;
    }

    if (!runnable)
        tctx->sleep_at = scx_bpf_now();
}

SEC("struct_ops/scx_snap_init_task")
s32 scx_snap_init_task(struct task_struct *p, struct scx_init_task_args *args)
{
    struct snap_task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return -ENOMEM;

    tctx->sum_run_ns = 0;
    tctx->sum_sleep_ns = 0;
    tctx->run_at = 0;
    tctx->sleep_at = 0;
    tctx->wakeups = 0;

    return 0;
}

SEC("struct_ops/scx_snap_exit_task")
void scx_snap_exit_task(struct task_struct *p, struct scx_exit_task_args *args) {}

SEC("struct_ops.s/scx_snap_init")
s32 scx_snap_init(void)
{
    int ret;

    ret = scx_bpf_create_dsq(SNAP_DSQ_INTERACTIVE, -1);
    if (ret < 0)
        return ret;

    return scx_bpf_create_dsq(SNAP_DSQ_BATCH, -1);
}

SEC("struct_ops/scx_snap_exit")
void scx_snap_exit(struct scx_exit_info *ei) {}

SEC(".struct_ops.link")
struct sched_ext_ops scx_snap_ops = {
    .select_cpu = (void *)scx_snap_select_cpu,
    .enqueue = (void *)scx_snap_enqueue,
    .dispatch = (void *)scx_snap_dispatch,
    .runnable = (void *)scx_snap_runnable,
    .running = (void *)scx_snap_running,
    .stopping = (void *)scx_snap_stopping,
    .init_task = (void *)scx_snap_init_task,
    .exit_task = (void *)scx_snap_exit_task,
    .init = (void *)scx_snap_init,
    .exit = (void *)scx_snap_exit,
    .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
    .name = "scx_snap",
};
