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
#include <time.h>
#include <ncurses.h>
#include <bpf/libbpf.h>
#include "scx_quicksched.h"
#include "scx_quicksched.skel.h"

static volatile int stop;
static int verbose;
static int no_tui;
static uint64_t slo_us = 0;

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
        "Latency-optimized sched_ext scheduler. Requires root.\n"
        "Developed by Aniketh T S\n\n"
        "Options:\n"
        "  -i, --interactive-slice-us N   interactive slice in us  (default: 5000)\n"
        "  -b, --batch-slice-us N         batch slice in us         (default: 20000)\n"
        "  -n, --nice-interactive-max N   nice threshold            (default: 0)\n"
        "  -p, --interactive-sleep-pct N  min sleep %% for interactive (default: 50)\n"
        "      --batch-cpuperf-pct N      batch CPU freq %%         (default: 50)\n"
        "      --no-cpuperf               disable CPU freq scaling\n"
        "      --no-tui                   plain text output\n"
        "      --slo-us N                 alert when p99 latency exceeds N us (0=off)\n"
        "  -s, --stats-interval N         stats interval in seconds (default: 1)\n"
        "  -v, --verbose                  verbose libbpf output\n"
        "  -V, --version                  print version and exit\n"
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

static void read_percpu_array(struct bpf_map *map, void *out, size_t elem_sz, int ncpus)
{
    size_t stride = (elem_sz + 7) & ~(size_t)7;
    uint8_t *buf = calloc(ncpus, stride);
    if (!buf)
        return;

    uint32_t key = 0;
    if (bpf_map__lookup_elem(map, &key, sizeof(key), buf, stride * ncpus, 0))
        goto out;

    for (int i = 0; i < ncpus; i++)
        memcpy((uint8_t *)out + i * elem_sz, buf + i * stride, elem_sz);
out:
    free(buf);
}

static uint64_t lat_percentile(uint64_t *buckets, int pct)
{
    uint64_t total = 0;
    for (int i = 0; i < QS_LAT_BUCKETS; i++)
        total += buckets[i];
    if (!total)
        return 0;

    uint64_t target = ((uint64_t)pct * total + 99) / 100;
    uint64_t acc = 0;
    for (int i = 0; i < QS_LAT_BUCKETS; i++)
    {
        acc += buckets[i];
        if (acc >= target)
            return i == 0 ? 0 : 3 * (1ULL << (i - 1)) / 2;
    }
    return 1ULL << (QS_LAT_BUCKETS - 1);
}

#define CP_HEADER 1
#define CP_IACTIVE 2
#define CP_BATCH 3
#define CP_IDLE 4
#define CP_LAT 5
#define CP_DIM 6
#define CP_WARN 7

static void tui_init(void)
{
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    if (has_colors())
    {
        start_color();
        use_default_colors();
        init_pair(CP_HEADER, COLOR_CYAN, -1);
        init_pair(CP_IACTIVE, COLOR_GREEN, -1);
        init_pair(CP_BATCH, COLOR_YELLOW, -1);
        init_pair(CP_IDLE, COLOR_BLUE, -1);
        init_pair(CP_LAT, COLOR_MAGENTA, -1);
        init_pair(CP_DIM, COLOR_WHITE, -1);
        init_pair(CP_WARN, COLOR_RED, -1);
    }
}

static void draw_bar(int y, int x, int w, uint64_t val, uint64_t max, int cp)
{
    int filled = (max > 0 && w > 0) ? (int)(val * w / max) : 0;
    if (filled > w)
        filled = w;
    if (cp)
        attron(COLOR_PAIR(cp));
    for (int i = 0; i < filled; i++)
        mvaddch(y, x + i, ACS_BLOCK);
    if (cp)
        attroff(COLOR_PAIR(cp));
    for (int i = filled; i < w; i++)
        mvaddch(y, x + i, ' ');
}

static const char *lat_labels[QS_LAT_BUCKETS] = {
    "   <1us",
    "    1us",
    "    2us",
    "    4us",
    "    8us",
    "   16us",
    "   32us",
    "   64us",
    "  128us",
    "  256us",
    "  512us",
    "    1ms",
    "    2ms",
    "    4ms",
    "    8ms",
    "   16ms",
    "   32ms",
    "   64ms",
    "  128ms",
    "  256ms",
};

static void tui_draw(
    uint64_t interactive_slice_us, uint64_t batch_slice_us,
    int32_t nice_max, uint32_t sleep_pct,
    int cpuperf_off,
    uint64_t d_int, uint64_t d_batch, uint64_t d_local,
    uint64_t d_preempted, uint64_t d_memalloc,
    uint64_t d_count, uint64_t avg_us, uint64_t p50, uint64_t p99,
    uint64_t *d_buckets,
    uint64_t uptime_s,
    uint64_t slo_alert_us,
    uint64_t *d_cpu, int ncpus)
{
    int rows, cols;
    char uts[32];
    int row, bar_w, lat_w, avail, show, i;
    uint64_t tot, max_b;

    getmaxyx(stdscr, rows, cols);
    erase();

    if (rows < 12 || cols < 40)
    {
        mvprintw(0, 0, "terminal too small");
        refresh();
        return;
    }

    box(stdscr, 0, 0);

    attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvprintw(0, 2, " Quicksched ");
    attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

    attron(COLOR_PAIR(CP_DIM));
    mvprintw(0, 15, "by Aniketh T S");
    attroff(COLOR_PAIR(CP_DIM));

    snprintf(uts, sizeof(uts), " %02llu:%02llu:%02llu ",
             (unsigned long long)(uptime_s / 3600),
             (unsigned long long)((uptime_s % 3600) / 60),
             (unsigned long long)(uptime_s % 60));
    mvprintw(0, cols - (int)strlen(uts) - 1, "%s", uts);

    row = 1;

    if (slo_alert_us > 0 && p99 > slo_alert_us && row < rows - 1)
    {
        attron(COLOR_PAIR(CP_WARN) | A_BOLD);
        mvprintw(row++, 2, "  !! LATENCY SLO BREACH: p99=%lluus > %lluus !!  ",
                 (unsigned long long)p99, (unsigned long long)slo_alert_us);
        attroff(COLOR_PAIR(CP_WARN) | A_BOLD);
    }

    attron(COLOR_PAIR(CP_DIM));
    mvprintw(row++, 2,
             "slices: interactive=%lluus  batch=%lluus  nice<=%d  sleep>=%u%%  cpuperf: %s",
             (unsigned long long)interactive_slice_us,
             (unsigned long long)batch_slice_us,
             nice_max, sleep_pct,
             cpuperf_off ? "off" : "on");
    attroff(COLOR_PAIR(CP_DIM));

    row++;

    attron(A_BOLD);
    mvprintw(row++, 2, "SCHEDULING");
    attroff(A_BOLD);

    tot = d_int + d_batch + d_local;
    bar_w = cols - 34;
    if (bar_w < 8)
        bar_w = 8;

    struct
    {
        const char *label;
        uint64_t val;
        int cp;
    } srows[] = {
        {"  interactive", d_int, CP_IACTIVE},
        {"  batch      ", d_batch, CP_BATCH},
        {"  idle-fast  ", d_local, CP_IDLE},
    };
    for (i = 0; i < 3 && row < rows - 1; i++)
    {
        uint64_t pct = tot > 0 ? srows[i].val * 100 / tot : 0;
        attron(COLOR_PAIR(srows[i].cp));
        mvprintw(row, 2, "%s", srows[i].label);
        attroff(COLOR_PAIR(srows[i].cp));
        draw_bar(row, 16, bar_w, srows[i].val, tot > 0 ? tot : 1, srows[i].cp);
        mvprintw(row, 16 + bar_w + 1, "%7llu  %3llu%%",
                 (unsigned long long)srows[i].val, (unsigned long long)pct);
        row++;
    }

    row++;

    if (row >= rows - 1)
    {
        refresh();
        return;
    }

    attron(A_BOLD);
    mvprintw(row++, 2, "MEMORY");
    attroff(A_BOLD);

    {
        struct
        {
            const char *label;
            uint64_t val;
            int cp;
        } mrows[] = {
            {"  memalloc  ", d_memalloc, CP_BATCH},
            {"  preempted ", d_preempted, CP_LAT},
        };
        uint64_t mem_scale = tot > 0 ? tot : 1;
        for (i = 0; i < 2 && row < rows - 1; i++)
        {
            uint64_t pct = mrows[i].val * 100 / mem_scale;
            attron(COLOR_PAIR(mrows[i].cp));
            mvprintw(row, 2, "%s", mrows[i].label);
            attroff(COLOR_PAIR(mrows[i].cp));
            draw_bar(row, 16, bar_w, mrows[i].val, mem_scale, mrows[i].cp);
            mvprintw(row, 16 + bar_w + 1, "%7llu  %3llu%%",
                     (unsigned long long)mrows[i].val,
                     (unsigned long long)pct);
            row++;
        }
    }

    row++;

    if (row >= rows - 1)
    {
        refresh();
        return;
    }

    attron(A_BOLD);
    mvprintw(row++, 2, "CPU LOAD  (dispatch/s)");
    attroff(A_BOLD);

    if (ncpus > 0 && d_cpu != NULL)
    {
        /* Two CPU entries per row; each cell: "  CPUxxx [BBBBBBBB] nnnnn" */
        int cpu_bar_w = (cols - 8) / 2 - 18;
        if (cpu_bar_w < 4) cpu_bar_w = 4;

        uint64_t cpu_max = 1;
        for (int ci = 0; ci < ncpus; ci++)
            if (d_cpu[ci] > cpu_max)
                cpu_max = d_cpu[ci];

        int cell_w = (cols - 4) / 2;
        int col_idx = 0;
        for (int ci = 0; ci < ncpus && row < rows - 1; ci++)
        {
            int x = 2 + col_idx * cell_w;
            uint64_t pct = d_cpu[ci] * 100 / cpu_max;
            attron(COLOR_PAIR(CP_DIM));
            mvprintw(row, x, "CPU%3d", ci);
            attroff(COLOR_PAIR(CP_DIM));
            draw_bar(row, x + 6, cpu_bar_w, d_cpu[ci], cpu_max,
                     pct > 75 ? CP_IACTIVE : (pct > 30 ? CP_BATCH : CP_IDLE));
            mvprintw(row, x + 6 + cpu_bar_w + 1, "%5llu", (unsigned long long)d_cpu[ci]);
            col_idx++;
            if (col_idx >= 2)
            {
                col_idx = 0;
                row++;
            }
        }
        if (col_idx > 0)
            row++;
    }

    row++;

    if (row >= rows - 1)
    {
        refresh();
        return;
    }

    attron(A_BOLD);
    mvprintw(row++, 2, "WAKEUP LATENCY");
    attroff(A_BOLD);

    if (row < rows - 1)
    {
        if (d_count > 0)
        {
            attron(COLOR_PAIR(CP_DIM));
            mvprintw(row++, 4, "avg=%lluus  p50=%lluus  p99=%lluus  n=%llu",
                     (unsigned long long)avg_us,
                     (unsigned long long)p50,
                     (unsigned long long)p99,
                     (unsigned long long)d_count);
            attroff(COLOR_PAIR(CP_DIM));
        }
        else
        {
            mvprintw(row++, 4, "no data yet");
        }
    }

    max_b = 1;
    for (i = 0; i < QS_LAT_BUCKETS; i++)
        if (d_buckets[i] > max_b)
            max_b = d_buckets[i];

    lat_w = cols - 24;
    if (lat_w < 8)
        lat_w = 8;
    avail = rows - row - 1;
    show = QS_LAT_BUCKETS < avail ? QS_LAT_BUCKETS : avail;

    for (int i = 0; i < show && row < rows - 1; i++)
    {
        attron(COLOR_PAIR(CP_DIM));
        mvprintw(row, 4, "%s", lat_labels[i]);
        attroff(COLOR_PAIR(CP_DIM));
        draw_bar(row, 12, lat_w, d_buckets[i], max_b, CP_LAT);
        if (d_buckets[i] > 0)
            mvprintw(row, 12 + lat_w + 1, "%llu", (unsigned long long)d_buckets[i]);
        row++;
    }

    attron(COLOR_PAIR(CP_DIM));
    mvprintw(rows - 1, 2, " developed by Aniketh T S ");
    attroff(COLOR_PAIR(CP_DIM));

    refresh();
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
        {"no-tui", no_argument, 0, 3},
        {"slo-us", required_argument, 0, 4},
        {"stats-interval", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "i:b:n:p:s:vVh", long_opts, NULL)) != -1)
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
        case 3:
            no_tui = 1;
            break;
        case 4:
            slo_us = strtoull(optarg, NULL, 10);
            break;
        case 's':
            stats_interval = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'V':
            printf("scx_quicksched %s\n", QS_VERSION);
            return 0;
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

    struct scx_quicksched_bpf *skel = scx_quicksched_bpf__open();
    if (!skel)
    {
        char errbuf[256];
        libbpf_strerror(-errno, errbuf, sizeof(errbuf));
        fprintf(stderr, "failed to open BPF object: %s\n", errbuf);
        return 1;
    }

    skel->rodata->slice_interactive_ns = interactive_slice_us * 1000;
    skel->rodata->slice_batch_ns = batch_slice_us * 1000;
    skel->rodata->nice_interactive_max = nice_interactive_max;
    skel->rodata->interactive_sleep_pct = interactive_sleep_pct;
    skel->rodata->enable_cpuperf = !no_cpuperf;
    skel->rodata->batch_cpuperf_abs = batch_cpuperf_pct * 1024 / 100;

    int err = scx_quicksched_bpf__load(skel);
    if (err)
    {
        char errbuf[256];
        libbpf_strerror(err, errbuf, sizeof(errbuf));
        fprintf(stderr, "failed to load BPF object: %s\n", errbuf);
        scx_quicksched_bpf__destroy(skel);
        return 1;
    }

    skel->links.scx_quicksched_ops = bpf_map__attach_struct_ops(skel->maps.scx_quicksched_ops);
    if (!skel->links.scx_quicksched_ops)
    {
        char errbuf[256];
        libbpf_strerror(-errno, errbuf, sizeof(errbuf));
        fprintf(stderr, "failed to attach scheduler: %s\n", errbuf);
        scx_quicksched_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!no_tui)
    {
        tui_init();
    }
    else
    {
        printf("scx_quicksched (Quicksched) — developed by Aniketh T S\n");
        printf("  slices: interactive=%lluus batch=%lluus\n",
               (unsigned long long)interactive_slice_us,
               (unsigned long long)batch_slice_us);
        printf("  interactive: nice <= %d or sleep >= %u%%\n",
               nice_interactive_max, interactive_sleep_pct);
        if (!no_cpuperf)
            printf("  cpuperf: interactive=100%% batch=%u%%\n", batch_cpuperf_pct);
    }

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 1)
        ncpus = 1;

    struct qs_cpu_load *prev_cpu_loads = calloc(ncpus, sizeof(*prev_cpu_loads));
    struct qs_cpu_load *cur_cpu_loads  = calloc(ncpus, sizeof(*cur_cpu_loads));
    uint64_t *d_cpu = calloc(ncpus, sizeof(*d_cpu));
    if (!prev_cpu_loads || !cur_cpu_loads || !d_cpu)
    {
        fprintf(stderr, "error: out of memory\n");
        if (!no_tui)
            endwin();
        free(prev_cpu_loads);
        free(cur_cpu_loads);
        free(d_cpu);
        scx_quicksched_bpf__destroy(skel);
        return 1;
    }

    struct qs_stats prev_stats = {};
    struct qs_latency prev_lat = {};
    time_t start_time = time(NULL);

    if (!no_tui)
    {
        uint64_t zero[QS_LAT_BUCKETS] = {};
        tui_draw(interactive_slice_us, batch_slice_us,
                 nice_interactive_max, interactive_sleep_pct,
                 no_cpuperf,
                 0, 0, 0, 0, 0, 0, 0, 0, 0, zero, 0,
                 slo_us, NULL, 0);
    }

    while (!stop)
    {
        sleep(stats_interval ? stats_interval : 1);
        if (stop)
            break;

        if (!stats_interval)
            continue;

        struct qs_stats cur_stats = {};
        struct qs_latency cur_lat = {};

        read_percpu(skel->maps.stats, &cur_stats, sizeof(cur_stats));
        read_percpu(skel->maps.latency, &cur_lat, sizeof(cur_lat));
        read_percpu_array(skel->maps.cpu_load, cur_cpu_loads,
                          sizeof(*cur_cpu_loads), ncpus);
        for (int i = 0; i < ncpus; i++)
            d_cpu[i] = cur_cpu_loads[i].nr_dispatch >= prev_cpu_loads[i].nr_dispatch
                           ? cur_cpu_loads[i].nr_dispatch - prev_cpu_loads[i].nr_dispatch
                           : 0;

        uint64_t d_int = cur_stats.nr_interactive >= prev_stats.nr_interactive
                             ? cur_stats.nr_interactive - prev_stats.nr_interactive
                             : 0;
        uint64_t d_batch = cur_stats.nr_batch >= prev_stats.nr_batch
                               ? cur_stats.nr_batch - prev_stats.nr_batch
                               : 0;
        uint64_t d_local = cur_stats.nr_local >= prev_stats.nr_local
                               ? cur_stats.nr_local - prev_stats.nr_local
                               : 0;

        uint64_t d_preempted = cur_stats.nr_preempted >= prev_stats.nr_preempted
                                   ? cur_stats.nr_preempted - prev_stats.nr_preempted
                                   : 0;
        uint64_t d_memalloc = cur_stats.nr_memalloc >= prev_stats.nr_memalloc
                                  ? cur_stats.nr_memalloc - prev_stats.nr_memalloc
                                  : 0;

        uint64_t d_count = cur_lat.count >= prev_lat.count
                               ? cur_lat.count - prev_lat.count
                               : 0;
        uint64_t d_total_ns = cur_lat.total_ns >= prev_lat.total_ns
                                  ? cur_lat.total_ns - prev_lat.total_ns
                                  : 0;
        uint64_t d_buckets[QS_LAT_BUCKETS];
        for (int i = 0; i < QS_LAT_BUCKETS; i++)
            d_buckets[i] = cur_lat.buckets[i] >= prev_lat.buckets[i]
                               ? cur_lat.buckets[i] - prev_lat.buckets[i]
                               : 0;

        uint64_t avg_us = d_count > 0 ? d_total_ns / d_count / 1000 : 0;
        uint64_t p50 = lat_percentile(d_buckets, 50);
        uint64_t p99 = lat_percentile(d_buckets, 99);

        if (!no_tui)
        {
            uint64_t uptime_s = (uint64_t)(time(NULL) - start_time);
            tui_draw(interactive_slice_us, batch_slice_us,
                     nice_interactive_max, interactive_sleep_pct,
                     no_cpuperf,
                     d_int, d_batch, d_local,
                     d_preempted, d_memalloc,
                     d_count, avg_us, p50, p99, d_buckets,
                     uptime_s, slo_us, d_cpu, ncpus);
        }
        else
        {
            uint64_t total = d_int + d_batch + d_local;
            if (total > 0)
                printf("interactive=%6llu  batch=%6llu  idle-fast=%6llu  (%llu%% interactive)\n",
                       (unsigned long long)d_int,
                       (unsigned long long)d_batch,
                       (unsigned long long)d_local,
                       (unsigned long long)(d_int * 100 / total));
            if (d_preempted > 0 || d_memalloc > 0)
                printf("memory:  preempted=%llu  memalloc-demoted=%llu\n",
                       (unsigned long long)d_preempted,
                       (unsigned long long)d_memalloc);
            if (d_count > 0)
            {
                printf("latency (wakeups):  avg=%lluus  p50=%lluus  p99=%lluus  n=%llu\n",
                       (unsigned long long)avg_us,
                       (unsigned long long)p50,
                       (unsigned long long)p99,
                       (unsigned long long)d_count);
                if (slo_us > 0 && p99 > slo_us)
                    printf("!! LATENCY SLO BREACH: p99=%lluus > %lluus !!\n",
                           (unsigned long long)p99, (unsigned long long)slo_us);
            }
        }

        prev_stats = cur_stats;
        prev_lat = cur_lat;
        memcpy(prev_cpu_loads, cur_cpu_loads, ncpus * sizeof(*cur_cpu_loads));
    }

    if (!no_tui)
        endwin();

    free(prev_cpu_loads);
    free(cur_cpu_loads);
    free(d_cpu);

    printf("scx_quicksched exiting\n");
    scx_quicksched_bpf__destroy(skel);
    return 0;
}
