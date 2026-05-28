// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "scx_quicksched.h"

#define ENOMEM 12

char _license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct qs_task_ctx);
} task_stor SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qs_stats);
} stats SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qs_latency);
} latency SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qs_batch_depth);
} batch_depth_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qs_cpu_load);
} cpu_load SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct qs_dynamic_cfg);
} dynamic_cfg SEC(".maps");

const volatile __u64 slice_interactive_ns = QS_SLICE_INTERACTIVE_NS;
const volatile __u64 slice_batch_ns = QS_SLICE_BATCH_NS;
const volatile __s32 nice_interactive_max = 0;
const volatile __u32 interactive_sleep_pct = 50;
const volatile bool enable_cpuperf = true;
const volatile __u32 batch_cpuperf_abs = 512; /* pre-scaled to 0-1024 by userspace */

extern int scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym;
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym;
extern void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
                                  bool *is_idle) __ksym;
extern u64 scx_bpf_now(void) __ksym;
extern u32 scx_bpf_nr_cpu_ids(void) __ksym;
extern void scx_bpf_cpuperf_set(s32 cpu, u32 perf) __ksym;

/* __builtin_clzll is not supported by clang 18's BPF backend */
static __always_inline u32 log2_u64(u64 v)
{
    u32 r = 0;

    if (v >= (1ULL << 32))
    {
        v >>= 32;
        r += 32;
    }
    if (v >= (1ULL << 16))
    {
        v >>= 16;
        r += 16;
    }
    if (v >= (1ULL << 8))
    {
        v >>= 8;
        r += 8;
    }
    if (v >= (1ULL << 4))
    {
        v >>= 4;
        r += 4;
    }
    if (v >= (1ULL << 2))
    {
        v >>= 2;
        r += 2;
    }
    if (v >= (1ULL << 1))
    {
        r += 1;
    }
    return r;
}

static __always_inline bool task_is_interactive(struct task_struct *p, struct qs_task_ctx *tctx)
{
    __u64 total;
    __s32 nice;

    if (p->flags & PF_KTHREAD)
        return false;

    /* Low cgroup CPU weight → background service → force batch */
    if (p->scx.weight > 0 && p->scx.weight < QS_BATCH_WEIGHT_MAX)
        return false;

    /* static_prio = MAX_RT_PRIO(100) + 20 + nice */
    nice = (__s32)p->static_prio - 120;

    if (nice < 0)
        return true;

    if (nice <= nice_interactive_max)
        return true;

    if (tctx->wakeups < QS_MIN_WAKEUPS)
        return false;

    total = tctx->sum_run_ns + tctx->sum_sleep_ns;
    if (total == 0)
        return false;

    return (tctx->sum_sleep_ns * 100) / total >= interactive_sleep_pct;
}

static __always_inline void record_latency(u64 enqueue_at)
{
    struct qs_latency *lat;
    u64 now, delta_ns, delta_us;
    u32 bucket, zero = 0;

    now = scx_bpf_now();
    if (now <= enqueue_at)
        return;

    delta_ns = now - enqueue_at;
    delta_us = delta_ns / 1000;

    bucket = delta_us == 0 ? 0 : log2_u64(delta_us) + 1;

    if (bucket >= QS_LAT_BUCKETS)
        bucket = QS_LAT_BUCKETS - 1;

    lat = bpf_map_lookup_elem(&latency, &zero);
    if (lat)
    {
        lat->buckets[bucket]++;
        lat->total_ns += delta_ns;
        lat->count++;
    }
}

/*
 * Kernel 6.12+ passes struct_ops callback arguments via a context array
 * (R1 = ctx[]) rather than individual registers. BPF_PROG rewrites each
 * function to load args from ctx[0], ctx[1], … fixing "R2 !read_ok".
 * We return int; the kernel ignores the value for void-typed slots.
 */

SEC("struct_ops/scx_quicksched_runnable")
int BPF_PROG(scx_quicksched_runnable, struct task_struct *p, u64 enq_flags)
{
    struct qs_task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_stor, p, 0, 0);
    if (!tctx)
        return 0;

    if ((enq_flags & SCX_ENQ_WAKEUP) && tctx->sleep_at > 0)
    {
        __u64 sleep_dur = scx_bpf_now() - tctx->sleep_at;

        tctx->sum_sleep_ns =
            (tctx->sum_sleep_ns * QS_EWMA_WEIGHT + sleep_dur) / (QS_EWMA_WEIGHT + 1);
        tctx->wakeups++;
        tctx->sleep_at = 0;
        tctx->enqueue_at = scx_bpf_now();
    }
    return 0;
}

SEC("struct_ops/scx_quicksched_select_cpu")
s32 BPF_PROG(scx_quicksched_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    struct qs_task_ctx *tctx;
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
            struct qs_stats *st;

            tctx->assigned_slice_ns = slice;
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);

            st = bpf_map_lookup_elem(&stats, &zero);
            if (st)
                st->nr_local++;
        }
    }

    return cpu;
}

SEC("struct_ops/scx_quicksched_enqueue")
int BPF_PROG(scx_quicksched_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct qs_task_ctx *tctx;
    struct qs_stats *st;
    bool interactive;
    __u64 slice, dsq_flags = 0;
    __u64 dsq_id;
    __u32 zero = 0;
    s32 sel_cpu;

    if (p->flags & PF_MEMALLOC)
    {
        scx_bpf_dsq_insert(p, QS_DSQ_BATCH, slice_batch_ns, enq_flags);
        st = bpf_map_lookup_elem(&stats, &zero);
        if (st)
            st->nr_memalloc++;
        struct qs_batch_depth *bd = bpf_map_lookup_elem(&batch_depth_map, &zero);
        if (bd)
            __sync_fetch_and_add(&bd->depth, 1LL);
        return 0;
    }

    tctx = bpf_task_storage_get(&task_stor, p, 0, 0);
    if (!tctx)
    {
        scx_bpf_dsq_insert(p, QS_DSQ_BATCH, slice_batch_ns, enq_flags);
        return 0;
    }

    interactive = task_is_interactive(p, tctx);
    sel_cpu = p->scx.selected_cpu;

    if (interactive)
    {
        slice = slice_interactive_ns;
        dsq_id = (sel_cpu >= 0 && sel_cpu < QS_MAX_CPUS) ? (u64)sel_cpu : 0;

        if (enq_flags & SCX_ENQ_WAKEUP)
        {
            dsq_flags = SCX_ENQ_HEAD;
            scx_bpf_kick_cpu(sel_cpu >= 0 ? sel_cpu : 0, SCX_KICK_PREEMPT);
        }
    }
    else
    {
        slice = slice_batch_ns;
        dsq_id = QS_DSQ_BATCH;
        struct qs_batch_depth *bd = bpf_map_lookup_elem(&batch_depth_map, &zero);
        if (bd)
            __sync_fetch_and_add(&bd->depth, 1LL);
    }

    tctx->assigned_slice_ns = slice;
    scx_bpf_dsq_insert(p, dsq_id, slice, dsq_flags);

    st = bpf_map_lookup_elem(&stats, &zero);
    if (st)
    {
        if (interactive)
            st->nr_interactive++;
        else
            st->nr_batch++;
    }
    return 0;
}

SEC("struct_ops/scx_quicksched_dispatch")
int BPF_PROG(scx_quicksched_dispatch, s32 cpu, struct task_struct *prev)
{
    u32 nr_cpus = scx_bpf_nr_cpu_ids();
    __u32 zero = 0;
    struct qs_cpu_load *cl;

    /* Own interactive DSQ */
    if (cpu >= 0 && (u32)cpu < nr_cpus && scx_bpf_dsq_move_to_local((u64)cpu))
        goto dispatched;

    /* Work-steal from up to 8 neighbouring CPUs' interactive DSQs.
     * This also drains interactive queues of CPUs going offline. */
    if (cpu >= 0)
    {
        for (u32 i = 1; i <= 8; i++)
        {
            u32 steal = ((u32)cpu + i) % nr_cpus;
            if (scx_bpf_dsq_move_to_local((u64)steal))
            {
                struct qs_stats *st = bpf_map_lookup_elem(&stats, &zero);
                if (st)
                    st->nr_stolen++;
                goto dispatched;
            }
        }
    }

    /* Global batch DSQ */
    if (scx_bpf_dsq_move_to_local(QS_DSQ_BATCH))
    {
        struct qs_batch_depth *bd = bpf_map_lookup_elem(&batch_depth_map, &zero);
        if (bd)
            __sync_fetch_and_add(&bd->depth, -1LL);
        goto dispatched;
    }

    return 0;

dispatched:
    cl = bpf_map_lookup_elem(&cpu_load, &zero);
    if (cl)
        cl->nr_dispatch++;
    return 0;
}

SEC("struct_ops/scx_quicksched_running")
int BPF_PROG(scx_quicksched_running, struct task_struct *p)
{
    struct qs_task_ctx *tctx;
    s32 cpu;

    tctx = bpf_task_storage_get(&task_stor, p, 0, 0);
    if (!tctx)
        return 0;

    tctx->run_at = scx_bpf_now();

    cpu = bpf_get_smp_processor_id();

    if (enable_cpuperf)
    {
        bool mem_stall = tctx->wakeups >= QS_MIN_WAKEUPS && tctx->slice_util_ewma < 40;
        __u32 zero = 0;
        u32 perf;

        if (mem_stall)
        {
            struct qs_stats *st = bpf_map_lookup_elem(&stats, &zero);
            if (st)
                st->nr_mem_stall++;
        }

        if (task_is_interactive(p, tctx) && !mem_stall)
        {
            perf = 1024;
        }
        else
        {
            /* Use PSI-driven override when userspace sets it, else rodata default. */
            struct qs_dynamic_cfg *dcfg = bpf_map_lookup_elem(&dynamic_cfg, &zero);
            __u32 base = (dcfg && dcfg->batch_cpuperf_abs_override)
                             ? dcfg->batch_cpuperf_abs_override
                             : batch_cpuperf_abs;

            /* Adaptive: scale batch CPU freq up as the batch queue grows. */
            struct qs_batch_depth *bd = bpf_map_lookup_elem(&batch_depth_map, &zero);
            __s64 depth = bd ? bd->depth : 0;

            if (depth <= 0)
            {
                perf = base;
            }
            else if (depth >= QS_CPUPERF_LOAD_FULL)
            {
                perf = 1024;
            }
            else
            {
                __u64 extra = (__u64)depth * (1024 - base) / QS_CPUPERF_LOAD_FULL;
                perf = base + (u32)extra;
            }
        }
        scx_bpf_cpuperf_set(cpu, perf);
    }

    if (tctx->enqueue_at > 0)
    {
        record_latency(tctx->enqueue_at);
        tctx->enqueue_at = 0;
    }
    return 0;
}

SEC("struct_ops/scx_quicksched_stopping")
int BPF_PROG(scx_quicksched_stopping, struct task_struct *p, bool runnable)
{
    struct qs_task_ctx *tctx = bpf_task_storage_get(&task_stor, p, 0, 0);

    if (!tctx)
        return 0;

    if (tctx->run_at > 0)
    {
        __u64 run_dur = scx_bpf_now() - tctx->run_at;

        tctx->sum_run_ns = (tctx->sum_run_ns * QS_EWMA_WEIGHT + run_dur) / (QS_EWMA_WEIGHT + 1);
        tctx->run_at = 0;

        if (tctx->assigned_slice_ns > 0)
        {
            __u64 util = run_dur * 100 / tctx->assigned_slice_ns;
            if (util > 100)
                util = 100;
            tctx->slice_util_ewma =
                (tctx->slice_util_ewma * QS_EWMA_WEIGHT + util) / (QS_EWMA_WEIGHT + 1);

            /* Stayed runnable but used <90% of slice → preempted or stalled. */
            if (runnable && util < 90)
            {
                __u32 zero = 0;
                struct qs_stats *st = bpf_map_lookup_elem(&stats, &zero);
                if (st)
                    st->nr_preempted++;
            }
        }
    }

    if (!runnable)
        tctx->sleep_at = scx_bpf_now();
    return 0;
}

SEC("struct_ops/scx_quicksched_init_task")
s32 BPF_PROG(scx_quicksched_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
    struct qs_task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return -ENOMEM;

    tctx->sum_run_ns = 0;
    tctx->sum_sleep_ns = 0;
    tctx->run_at = 0;
    tctx->sleep_at = 0;
    tctx->enqueue_at = 0;
    tctx->assigned_slice_ns = 0;
    tctx->wakeups = 0;
    /* Start optimistic so a new task isn't penalised before its first wakeup. */
    tctx->slice_util_ewma = 100;

    return 0;
}

SEC("struct_ops/scx_quicksched_exit_task")
int BPF_PROG(scx_quicksched_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
    return 0;
}

SEC("struct_ops.s/scx_quicksched_cpu_online")
int BPF_PROG(scx_quicksched_cpu_online, s32 cpu)
{
    /* A CPU came online (e.g. hotplug). Ensure its interactive DSQ exists.
     * If scx_quicksched_init already created it, scx_bpf_create_dsq returns
     * -EEXIST which is harmless. */
    if (cpu >= 0 && cpu < QS_MAX_CPUS)
        scx_bpf_create_dsq((u64)cpu, -1);
    return 0;
}

SEC("struct_ops/scx_quicksched_cpu_offline")
int BPF_PROG(scx_quicksched_cpu_offline, s32 cpu)
{
    /* Work-stealing in dispatch will drain this CPU's interactive DSQ
     * once it stops consuming tasks.  No explicit action required. */
    return 0;
}

SEC("struct_ops.s/scx_quicksched_init")
s32 scx_quicksched_init(void)
{
    u32 nr_cpus = scx_bpf_nr_cpu_ids();
    u32 cpu;
    int ret;

    for (cpu = 0; cpu < QS_MAX_CPUS; cpu++)
    {
        if (cpu >= nr_cpus)
            break;
        ret = scx_bpf_create_dsq((u64)cpu, -1);
        if (ret < 0)
            return ret;
    }

    return scx_bpf_create_dsq(QS_DSQ_BATCH, -1);
}

SEC("struct_ops/scx_quicksched_exit")
int BPF_PROG(scx_quicksched_exit, struct scx_exit_info *ei)
{
    return 0;
}

SEC(".struct_ops")
struct sched_ext_ops scx_quicksched_ops = {
    .select_cpu = (void *)scx_quicksched_select_cpu,
    .enqueue = (void *)scx_quicksched_enqueue,
    .dispatch = (void *)scx_quicksched_dispatch,
    .runnable = (void *)scx_quicksched_runnable,
    .running = (void *)scx_quicksched_running,
    .stopping = (void *)scx_quicksched_stopping,
    .init_task = (void *)scx_quicksched_init_task,
    .exit_task = (void *)scx_quicksched_exit_task,
    .cpu_online = (void *)scx_quicksched_cpu_online,
    .cpu_offline = (void *)scx_quicksched_cpu_offline,
    .init = (void *)scx_quicksched_init,
    .exit = (void *)scx_quicksched_exit,
    .timeout_ms = 30000,
    .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
    .name = "scx_quicksched",
};
