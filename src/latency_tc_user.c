/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <net/if.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "latency_tc.skel.h"

/* latency_event structure from BPF code */
struct latency_event {
    __u32 seq;
    __u32 ack;
    __u64 latency_ns;
    __u16 src_port;
    __u16 dst_port;
    __u8  direction;  /* 0 = data→, 1 = ack←, 2 = SYN, 3 = FIN, 4 = RST, 5 = SEARCH_MATCH */
    __u32 payload_len;
};

/* Per-port statistics */
struct port_stats {
    __u64 sum_latency;
    __u64 count;
    __u16 local_port;
    __u16 remote_port;
};

#define MAX_PORT_STATS 1024
static struct port_stats port_stats_array[MAX_PORT_STATS];
static int num_port_stats = 0;

static volatile bool exiting = false;
static FILE *logfile = NULL;

/* ANSI color codes */
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/* Helper to print to both stdout and log file */
static void dual_printf(const char *format, ...)
{
    va_list args1, args2;

    va_start(args1, format);
    va_copy(args2, args1);

    /* Print to stdout */
    vprintf(format, args1);
    fflush(stdout);

    /* Print to log file if open */
    if (logfile) {
        vfprintf(logfile, format, args2);
        fflush(logfile);
    }

    va_end(args1);
    va_end(args2);
}

/* Helper to print colored text to stdout, plain text to log file */
static void dual_printf_color(const char *color, const char *format, ...)
{
    va_list args1, args2;
    char buffer[512];

    va_start(args1, format);
    va_copy(args2, args1);

    /* Format the message */
    vsnprintf(buffer, sizeof(buffer), format, args1);

    /* Print to stdout with color */
    printf("%s%s%s", color, buffer, COLOR_RESET);
    fflush(stdout);

    /* Print to log file without color */
    if (logfile) {
        fprintf(logfile, "%s", buffer);
        fflush(logfile);
    }

    va_end(args1);
    va_end(args2);
}

/* Find or create port stats entry */
static struct port_stats* get_port_stats(__u16 local_port, __u16 remote_port)
{
    /* Search for existing entry */
    for (int i = 0; i < num_port_stats; i++) {
        if (port_stats_array[i].local_port == local_port &&
            port_stats_array[i].remote_port == remote_port) {
            return &port_stats_array[i];
        }
    }

    /* Create new entry if space available */
    if (num_port_stats < MAX_PORT_STATS) {
        struct port_stats *stats = &port_stats_array[num_port_stats++];
        stats->sum_latency = 0;
        stats->count = 0;
        stats->local_port = local_port;
        stats->remote_port = remote_port;
        return stats;
    }

    return NULL;  /* No space */
}

/* Reset all port stats */
static void reset_port_stats(void)
{
    for (int i = 0; i < num_port_stats; i++) {
        port_stats_array[i].sum_latency = 0;
        port_stats_array[i].count = 0;
    }
}

/* Format bytes to human readable */
static void format_bytes(double bytes, char *buf, size_t buf_size)
{
    const char *units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
    int unit_idx = 0;

    while (bytes >= 1024.0 && unit_idx < 3) {
        bytes /= 1024.0;
        unit_idx++;
    }

    snprintf(buf, buf_size, "%.2f %s", bytes, units[unit_idx]);
}

/* Hàm in báo cáo mỗi giây */
static void print_report(struct latency_tc_bpf *obj)
{
    __u32 sum_key = 0, cnt_key = 1, total_key = 2, tcp_key = 3, match_key = 4;
    __u32 data_key = 5, ack_key = 6, lookup_key = 7;
    __u32 bytes_sent_key = 8, bytes_recv_key = 9;
    __u64 sum = 0, cnt = 0, total = 0, tcp_cnt = 0, match_cnt = 0;
    __u64 data_sent = 0, ack_recv = 0, lookups = 0;
    __u64 bytes_sent = 0, bytes_recv = 0;
    int fd = bpf_map__fd(obj->maps.stats);
    int nr_cpus = libbpf_num_possible_cpus();
    __u64 *values;

    static __u64 prev_bytes_sent = 0, prev_bytes_recv = 0;
    static __u64 prev_data_sent = 0, prev_ack_recv = 0;
    static time_t prev_time = 0;
    time_t now = time(NULL);
    double tx_speed = 0, rx_speed = 0;
    char tx_speed_str[32], rx_speed_str[32];
    __u64 window_data_sent = 0, window_ack_recv = 0;

    if (nr_cpus <= 0) {
        fprintf(stderr, "Failed to get number of CPUs\n");
        return;
    }

    values = calloc(nr_cpus, sizeof(__u64));
    if (!values) {
        fprintf(stderr, "Failed to allocate memory for per-CPU values\n");
        return;
    }

    /* Read and sum per-CPU values */
    if (bpf_map_lookup_elem(fd, &sum_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            sum += values[i];
    }
    if (bpf_map_lookup_elem(fd, &cnt_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            cnt += values[i];
    }
    if (bpf_map_lookup_elem(fd, &total_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            total += values[i];
    }
    if (bpf_map_lookup_elem(fd, &tcp_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            tcp_cnt += values[i];
    }
    if (bpf_map_lookup_elem(fd, &match_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            match_cnt += values[i];
    }
    if (bpf_map_lookup_elem(fd, &data_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            data_sent += values[i];
    }
    if (bpf_map_lookup_elem(fd, &ack_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            ack_recv += values[i];
    }
    if (bpf_map_lookup_elem(fd, &lookup_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            lookups += values[i];
    }
    if (bpf_map_lookup_elem(fd, &bytes_sent_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            bytes_sent += values[i];
    }
    if (bpf_map_lookup_elem(fd, &bytes_recv_key, values) == 0) {
        for (int i = 0; i < nr_cpus; i++)
            bytes_recv += values[i];
    }

    free(values);

    /* Calculate window deltas for data/ack counts */
    if (prev_time > 0) {
        window_data_sent = data_sent - prev_data_sent;
        window_ack_recv = ack_recv - prev_ack_recv;
    } else {
        window_data_sent = data_sent;
        window_ack_recv = ack_recv;
    }
    prev_data_sent = data_sent;
    prev_ack_recv = ack_recv;

    /* Calculate speed */
    if (prev_time > 0) {
        time_t time_delta = now - prev_time;
        if (time_delta > 0) {
            tx_speed = (double)(bytes_sent - prev_bytes_sent) / time_delta;
            rx_speed = (double)(bytes_recv - prev_bytes_recv) / time_delta;
        }
    }
    prev_bytes_sent = bytes_sent;
    prev_bytes_recv = bytes_recv;
    prev_time = now;

    format_bytes(tx_speed, tx_speed_str, sizeof(tx_speed_str));
    format_bytes(rx_speed, rx_speed_str, sizeof(rx_speed_str));

    dual_printf("[%-9s] num_samples=%llu",
           "REPORT", (unsigned long long)cnt);

    if (cnt > 0) {
        double avg_us = (double)sum / cnt / 1000.0;   /* ns → µs */
        if (avg_us >= 10000.0) {
            dual_printf_color(COLOR_RED, "  avg=%.3f µs", avg_us);
        } else {
            dual_printf("  avg=%.3f µs", avg_us);
        }
    }

    dual_printf("  tx=%s rx=%s", tx_speed_str, rx_speed_str);
    dual_printf("  win_data=%llu win_ack=%llu",
           (unsigned long long)window_data_sent, (unsigned long long)window_ack_recv);
    dual_printf("\n");

    /* Print per-port latency statistics */
    if (num_port_stats > 0) {
        // dual_printf("Per-port latency (2s window):\n");
        for (int i = 0; i < num_port_stats; i++) {
            struct port_stats *ps = &port_stats_array[i];
            if (ps->count > 0) {
                double avg_us = (double)ps->sum_latency / ps->count / 1000.0;  /* ns → µs */
                if (avg_us >= 10000.0) {
                    dual_printf("  Port %u:%u -> samples=%llu ",
                           ps->local_port, ps->remote_port,
                           (unsigned long long)ps->count);
                    dual_printf_color(COLOR_RED, "avg=%.3f µs\n", avg_us);
                } else {
                    dual_printf("  Port %u:%u -> samples=%llu avg=%.3f µs\n",
                           ps->local_port, ps->remote_port,
                           (unsigned long long)ps->count, avg_us);
                }
            }
        }
    }

    /* Reset latency stats for next window (keep cumulative stats) */
    values = calloc(nr_cpus, sizeof(__u64));
    if (values) {
        /* Reset sum and cnt across all CPUs */
        for (int i = 0; i < nr_cpus; i++) {
            values[i] = 0;
        }
        bpf_map_update_elem(fd, &sum_key, values, BPF_ANY);
        bpf_map_update_elem(fd, &cnt_key, values, BPF_ANY);
        free(values);
    }

    /* Reset per-port stats for next window */
    reset_port_stats();
}

/* Ring‑buffer callback – show connection lifecycle events */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct latency_event *e = data;
    (void)ctx;
    (void)data_sz;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[32];

    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    switch (e->direction) {
        case 0:  /* DATA packet - skip */
            break;
        case 1:  /* ACK/latency measurement - track per-port stats */
            {
                struct port_stats *ps = get_port_stats(e->src_port, e->dst_port);
                if (ps) {
                    ps->sum_latency += e->latency_ns;
                    ps->count += 1;
                }
            }
            break;
        case 2:  /* SYN - new connection */
            dual_printf_color(COLOR_RED, "[%s] [SYN] New connection initiated - port %u:%u seq=%u\n",
                   time_str, e->src_port, e->dst_port, e->seq);
            break;
        case 3:  /* FIN - connection closing */
            dual_printf_color(COLOR_RED, "[%s] [FIN] Connection closing - port %u:%u seq=%u ack=%u\n",
                   time_str, e->src_port, e->dst_port, e->seq, e->ack);
            break;
        case 4:  /* RST - connection reset */
            dual_printf_color(COLOR_RED, "[%s] [RST] Connection reset - port %u:%u seq=%u ack=%u\n",
                   time_str, e->src_port, e->dst_port, e->seq, e->ack);
            break;
        case 5:  /* SEARCH_MATCH - pattern found in payload */
            {
                /* Print pattern match notification */
                dual_printf_color(COLOR_RED, "[%s] [PATTERN MATCH] port %u:%u payload_len=%u\n",
                       time_str, e->src_port, e->dst_port, e->payload_len);
            }
            break;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct latency_tc_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    const char *ifname = NULL;
    const char *target_ip_str = NULL;
    const char *log_filename = "log.txt";  /* Default log file */
    const char *search_pattern_str = NULL; /* Search pattern */
    __u32 ifindex = 0;
    __u32 target_ip_host = 0;
    struct in_addr addr;
    __u8 no_eth = 0;
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_ingress, .handle = 1, .priority = 1);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts_egress, .handle = 1, .priority = 1);
    bool hook_created = false;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <target_ip> [--no-eth] [--log <filename>] [--search <pattern>]\n", argv[0]);
        fprintf(stderr, "  --no-eth: Use for TUN interfaces (no Ethernet header)\n");
        fprintf(stderr, "  --log <filename>: Specify log file (default: log.txt)\n");
        fprintf(stderr, "  --search <pattern>: Search for pattern in outbound packet payloads\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s eth0 10.0.0.2\n", argv[0]);
        fprintf(stderr, "  %s tun0 112.11.0.100 --no-eth\n", argv[0]);
        fprintf(stderr, "  %s enp0s31f6 192.168.100.70 --log my_latency.log\n", argv[0]);
        fprintf(stderr, "  %s eth0 192.168.1.100 --search \"GET /api/\"\n", argv[0]);
        return 1;
    }
    ifname = argv[1];
    target_ip_str = argv[2];

    /* Parse optional arguments */
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--no-eth") == 0) {
            no_eth = 1;
        } else if (strcmp(argv[i], "--log") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --log requires a filename argument\n");
                return 1;
            }
            log_filename = argv[++i];
        } else if (strcmp(argv[i], "--search") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --search requires a pattern argument\n");
                return 1;
            }
            search_pattern_str = argv[++i];
            if (strlen(search_pattern_str) > 63) {
                fprintf(stderr, "Error: search pattern too long (max 63 bytes)\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    /* Parse interface name */
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        perror("if_nametoindex");
        return 1;
    }

    /* Parse target IP address */
    if (inet_pton(AF_INET, target_ip_str, &addr) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", target_ip_str);
        return 1;
    }
    target_ip_host = ntohl(addr.s_addr);  /* Convert to host byte order */

    /* Tăng rlimit cho BPF */
    struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rl);

    /* Set up libbpf debug output */
    libbpf_set_print(libbpf_print_fn);

    /* Load & verify BPF program */
    skel = latency_tc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set target IP address and no_eth flag before loading */
    skel->rodata->target_ip = target_ip_host;
    skel->rodata->no_eth = no_eth;

    /* Set search pattern if provided */
    if (search_pattern_str) {
        size_t pattern_len = strlen(search_pattern_str);
        memcpy((void*)skel->rodata->search_pattern, search_pattern_str, pattern_len);
        *(__u32*)&skel->rodata->search_pattern_len = pattern_len;
    }

    err = latency_tc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Setup TC hook */
    hook.ifindex = ifindex;

    /* Create clsact qdisc */
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err));
        goto cleanup;
    }
    hook_created = true;
    printf("✓ TC hook created/attached to %s\n", ifname);

    /* Attach egress program */
    opts_egress.prog_fd = bpf_program__fd(skel->progs.latency_tc_egress);
    if (opts_egress.prog_fd < 0) {
        fprintf(stderr, "Failed to get egress program FD: %d\n", opts_egress.prog_fd);
        goto cleanup;
    }
    printf("Egress program FD: %d\n", opts_egress.prog_fd);

    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &opts_egress);
    if (err) {
        fprintf(stderr, "Failed to attach TC egress program: %s (err=%d)\n", strerror(-err), err);
        goto cleanup;
    }
    printf("✓ TC egress program attached (captures outbound packets)\n");

    /* Attach ingress program */
    opts_ingress.prog_fd = bpf_program__fd(skel->progs.latency_tc_ingress);
    if (opts_ingress.prog_fd < 0) {
        fprintf(stderr, "Failed to get ingress program FD: %d\n", opts_ingress.prog_fd);
        goto cleanup_egress;
    }
    printf("Ingress program FD: %d\n", opts_ingress.prog_fd);

    hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_attach(&hook, &opts_ingress);
    if (err) {
        fprintf(stderr, "Failed to attach TC ingress program: %s (err=%d)\n", strerror(-err), err);
        goto cleanup_egress;
    }
    printf("✓ TC ingress program attached (captures inbound packets)\n");

    /* Ring‑buffer để nhận các sự kiện chi tiết */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup_ingress;
    }

    /* Đăng ký signal */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open log file */
    logfile = fopen(log_filename, "a");
    if (!logfile) {
        fprintf(stderr, "Warning: Failed to open %s for writing: %s\n", log_filename, strerror(errno));
        fprintf(stderr, "Continuing without file logging...\n");
    } else {
        printf("✓ Logging to %s\n", log_filename);
    }

    printf("\n=== eBPF TC latency monitor ===\n");
    printf("Interface: %s (ifindex=%u)\n", ifname, ifindex);
    printf("Target IP: %s\n", target_ip_str);
    printf("  - Host byte order: 0x%08X\n", target_ip_host);
    printf("  - Network byte order: 0x%08X\n", htonl(target_ip_host));
    printf("Mode: %s\n", no_eth ? "TUN/raw IP (no Ethernet header)" : "Ethernet");
    if (search_pattern_str) {
        printf("Search pattern: \"%s\" (%zu bytes)\n", search_pattern_str, strlen(search_pattern_str));
    }
    printf("Monitoring:\n");
    printf("  - Outbound (egress): TCP packets with dest IP = %s\n", target_ip_str);
    printf("  - Inbound (ingress): TCP packets with src IP = %s and ACK flag set\n", target_ip_str);
    if (search_pattern_str) {
        printf("  - Payload search: Will notify when pattern is found in outbound packets\n");
    }
    printf("\nPress Ctrl‑C to quit.\n\n");

    /* Main loop */
    while (!exiting) {
        /* Đọc sự kiện ring‑buffer (không chặn) */
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR)
            continue;   /* signal */
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }

        /* In báo cáo mỗi 2 giây */
        static time_t last = 0;
        time_t now = time(NULL);
        if (now - last >= 2) {
            print_report(skel);
            last = now;
        }
    }

    printf("\nDetaching TC programs and cleaning up …\n");

cleanup_ingress:
    hook.attach_point = BPF_TC_INGRESS;
    opts_ingress.flags = opts_ingress.prog_fd = opts_ingress.prog_id = 0;
    bpf_tc_detach(&hook, &opts_ingress);

cleanup_egress:
    hook.attach_point = BPF_TC_EGRESS;
    opts_egress.flags = opts_egress.prog_fd = opts_egress.prog_id = 0;
    bpf_tc_detach(&hook, &opts_egress);

cleanup:
    ring_buffer__free(rb);

    if (hook_created) {
        hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
        bpf_tc_hook_destroy(&hook);
    }

    latency_tc_bpf__destroy(skel);

    /* Close log file */
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }

    return err != 0;
}
