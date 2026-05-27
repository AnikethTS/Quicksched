#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "scx_snap.h"
#include "scx_snap.skel.h"

static volatile int stop;
static int verbose;

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void sig_handler(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog)
{
    printf(
        "Usage: %s [OPTIONS]\n\n"
        "Latency-optimized sched_ext scheduler. Requires root.\n\n"
        "Options:\n"
        "  -i, --interactive-slice-us N   interactive slice in us  (default: 5000)\n"
        "  -b, --batch-slice-us N         batch slice in us         (default: 20000)\n"
        "  -n, --nice-interactive-max N   nice threshold            (default: 0)\n"
        "  -p, --interactive-sleep-pct N  min sleep %% for interactive (default: 50)\n"
        "      --batch-cpuperf-pct N      batch CPU freq %%         (default: 50)\n"
        "      --no-cpuperf               disable CPU freq scaling\n"
        "  -s, --stats-interval N         stats interval in seconds (default: 1)\n"
        "  -v, --verbose                  verbose libbpf output\n"
        "  -h, --help\n",
        prog);
}

static void read_percpu(struct bpf_map *map, void *out, size_t elem_sz)
{
    int ncpus = libbpf_num_possible_cpus();
    size_t stride = (elem_sz + 7) & ~(size_t)7;
    uint8_t *buf = calloc(ncpus, stride);
    if (!buf)
        return;

    uint32_t key = 0;
    if (bpf_map__lookup_elem(map, &key, sizeof(key), buf, stride * ncpus, 0))
        goto out;

    memset(out, 0, elem_sz);

    size_t nwords = elem_sz / sizeof(uint64_t);
    for (int cpu = 0; cpu < ncpus; cpu++)
    {
        uint64_t *src = (uint64_t *)(buf + cpu * stride);
        uint64_t *dst = (uint64_t *)out;
        for (size_t w = 0; w < nwords; w++)
            dst[w] += src[w];
    }
out:
    free(buf);
}

static uint64_t lat_percentile(uint64_t *buckets, int pct)
{
    uint64_t total = 0;
    for (int i = 0; i < SNAP_LAT_BUCKETS; i++)
        total += buckets[i];
    if (!total)
        return 0;

    uint64_t target = ((uint64_t)pct * total + 99) / 100;
    uint64_t acc = 0;
    for (int i = 0; i < SNAP_LAT_BUCKETS; i++)
    {
        acc += buckets[i];
        if (acc >= target)
            return i == 0 ? 0 : 3 * (1ULL << (i - 1)) / 2;
    }
    return 1ULL << (SNAP_LAT_BUCKETS - 1);
}

int main(int argc, char **argv)
{
    uint64_t interactive_slice_us = 5000;
    uint64_t batch_slice_us = 20000;
    int32_t nice_interactive_max = 0;
    uint32_t interactive_sleep_pct = 50;
    uint32_t batch_cpuperf_pct = 50;
    int no_cpuperf = 0;
    uint32_t stats_interval = 1;

    static const struct option long_opts[] = {
        {"interactive-slice-us", required_argument, 0, 'i'},
        {"batch-slice-us", required_argument, 0, 'b'},
        {"nice-interactive-max", required_argument, 0, 'n'},
        {"interactive-sleep-pct", required_argument, 0, 'p'},
        {"batch-cpuperf-pct", required_argument, 0, 1},
        {"no-cpuperf", no_argument, 0, 2},
        {"stats-interval", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "i:b:n:p:s:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'i':
            interactive_slice_us = strtoull(optarg, NULL, 10);
            break;
        case 'b':
            batch_slice_us = strtoull(optarg, NULL, 10);
            break;
        case 'n':
            nice_interactive_max = (int32_t)strtol(optarg, NULL, 10);
            break;
        case 'p':
            interactive_sleep_pct = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 1:
            batch_cpuperf_pct = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 2:
            no_cpuperf = 1;
            break;
        case 's':
            stats_interval = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (interactive_sleep_pct > 100 || batch_cpuperf_pct > 100)
    {
        fprintf(stderr, "error: percentage values must be 0-100\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    struct scx_snap_bpf *skel = scx_snap_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    skel->rodata->slice_interactive_ns = interactive_slice_us * 1000;
    skel->rodata->slice_batch_ns = batch_slice_us * 1000;
    skel->rodata->nice_interactive_max = nice_interactive_max;
    skel->rodata->interactive_sleep_pct = interactive_sleep_pct;
    skel->rodata->enable_cpuperf = !no_cpuperf;
    skel->rodata->batch_cpuperf_abs = batch_cpuperf_pct * 1024 / 100;

    if (scx_snap_bpf__load(skel))
    {
        fprintf(stderr, "failed to load BPF object: %s\n", strerror(errno));
        scx_snap_bpf__destroy(skel);
        return 1;
    }

    skel->links.scx_snap_ops = bpf_map__attach_struct_ops(skel->maps.scx_snap_ops);
    if (!skel->links.scx_snap_ops)
    {
        fprintf(stderr, "failed to attach scheduler: %s\n", strerror(errno));
        scx_snap_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("scx_snap started\n");
    printf("  slices: interactive=%llus batch=%llus\n",
           (unsigned long long)interactive_slice_us,
           (unsigned long long)batch_slice_us);
    printf("  interactive: nice <= %d or sleep >= %u%%\n",
           nice_interactive_max, interactive_sleep_pct);
    if (!no_cpuperf)
        printf("  cpuperf: interactive=100%% batch=%u%%\n", batch_cpuperf_pct);

    struct snap_stats prev_stats = {};
    struct snap_latency prev_lat = {};

    while (!stop)
    {
        sleep(stats_interval ? stats_interval : 1);
        if (stop)
            break;

        if (!stats_interval)
            continue;

        struct snap_stats cur_stats = {};
        struct snap_latency cur_lat = {};

        read_percpu(skel->maps.stats, &cur_stats, sizeof(cur_stats));
        read_percpu(skel->maps.latency, &cur_lat, sizeof(cur_lat));

        uint64_t d_int = cur_stats.nr_interactive >= prev_stats.nr_interactive
                             ? cur_stats.nr_interactive - prev_stats.nr_interactive
                             : 0;
        uint64_t d_batch = cur_stats.nr_batch >= prev_stats.nr_batch
                               ? cur_stats.nr_batch - prev_stats.nr_batch
                               : 0;
        uint64_t d_local = cur_stats.nr_local >= prev_stats.nr_local
                               ? cur_stats.nr_local - prev_stats.nr_local
                               : 0;
        uint64_t total = d_int + d_batch + d_local;

        if (total > 0)
        {
            printf("interactive=%6llu  batch=%6llu  idle-fast=%6llu  (%llu%% interactive)\n",
                   (unsigned long long)d_int,
                   (unsigned long long)d_batch,
                   (unsigned long long)d_local,
                   (unsigned long long)(d_int * 100 / total));
        }

        uint64_t d_count = cur_lat.count >= prev_lat.count
                               ? cur_lat.count - prev_lat.count
                               : 0;
        uint64_t d_total_ns = cur_lat.total_ns >= prev_lat.total_ns
                                  ? cur_lat.total_ns - prev_lat.total_ns
                                  : 0;
        uint64_t d_buckets[SNAP_LAT_BUCKETS];
        for (int i = 0; i < SNAP_LAT_BUCKETS; i++)
            d_buckets[i] = cur_lat.buckets[i] >= prev_lat.buckets[i]
                               ? cur_lat.buckets[i] - prev_lat.buckets[i]
                               : 0;

        if (d_count > 0)
        {
            uint64_t avg_us = d_total_ns / d_count / 1000;
            uint64_t p50 = lat_percentile(d_buckets, 50);
            uint64_t p99 = lat_percentile(d_buckets, 99);
            printf("latency (wakeups):  avg=%lluus  p50=%lluus  p99=%lluus  n=%llu\n",
                   (unsigned long long)avg_us,
                   (unsigned long long)p50,
                   (unsigned long long)p99,
                   (unsigned long long)d_count);
        }

        prev_stats = cur_stats;
        prev_lat = cur_lat;
    }

    printf("scx_snap exiting\n");
    scx_snap_bpf__destroy(skel);
    return 0;
}
