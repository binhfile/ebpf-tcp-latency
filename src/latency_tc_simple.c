/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Simpler TC latency monitor - assumes TC programs already attached via attach_tc.sh */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* latency_event structure from BPF code */
struct latency_event {
    __u32 seq;
    __u32 ack;
    __u64 latency_ns;
    __u8  direction;
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_report(int stats_fd)
{
    __u32 sum_key = 0, cnt_key = 1, total_key = 2, tcp_key = 3, match_key = 4;
    __u32 data_key = 5, ack_key = 6, lookup_key = 7;
    __u64 sum = 0, cnt = 0, total = 0, tcp_cnt = 0, match_cnt = 0;
    __u64 data_sent = 0, ack_recv = 0, lookups = 0;

    bpf_map_lookup_elem(stats_fd, &sum_key, &sum);
    bpf_map_lookup_elem(stats_fd, &cnt_key, &cnt);
    bpf_map_lookup_elem(stats_fd, &total_key, &total);
    bpf_map_lookup_elem(stats_fd, &tcp_key, &tcp_cnt);
    bpf_map_lookup_elem(stats_fd, &match_key, &match_cnt);
    bpf_map_lookup_elem(stats_fd, &data_key, &data_sent);
    bpf_map_lookup_elem(stats_fd, &ack_key, &ack_recv);
    bpf_map_lookup_elem(stats_fd, &lookup_key, &lookups);

    printf("[%-9s] total=%llu tcp=%llu matched=%llu data_sent=%llu ack_recv=%llu lookups=%llu latency=%llu",
           "REPORT", (unsigned long long)total, (unsigned long long)tcp_cnt,
           (unsigned long long)match_cnt, (unsigned long long)data_sent,
           (unsigned long long)ack_recv, (unsigned long long)lookups, (unsigned long long)cnt);

    if (cnt > 0) {
        double avg_us = (double)sum / cnt / 1000.0;   /* ns → µs */
        printf("  avg=%.3f µs", avg_us);
    }
    printf("\n");
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct latency_event *e = data;
    printf("[EVENT] seq=%u ack=%u latency=%.3f µs dir=%s\n",
           e->seq,
           e->ack,
           (double)e->latency_ns / 1000.0,
           e->direction ? "ACK←" : "DATA→");
    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_map *stats_map = NULL, *events_map = NULL;
    struct ring_buffer *rb = NULL;
    int stats_fd = -1, events_fd = -1;
    const char *target_ip_str = NULL;
    int err = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_ip>\n", argv[0]);
        fprintf(stderr, "  NOTE: TC BPF programs must be attached first using:\n");
        fprintf(stderr, "    sudo ./attach_tc.sh <interface>\n\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  sudo ./attach_tc.sh enp0s31f6\n");
        fprintf(stderr, "  sudo ./%s 192.168.100.70\n", argv[0]);
        return 1;
    }
    target_ip_str = argv[1];

    /* Find the BPF object by looking for our maps */
    printf("Looking for attached TC BPF programs...\n");

    /* Try to find the stats map */
    stats_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/stats");
    if (stats_fd < 0) {
        /* Try pinned location */
        stats_fd = bpf_obj_get("/sys/fs/bpf/stats");
    }

    if (stats_fd < 0) {
        fprintf(stderr, "Could not find 'stats' BPF map.\n");
        fprintf(stderr, "Make sure TC BPF programs are attached using:\n");
        fprintf(stderr, "  sudo ./attach_tc.sh <interface>\n");
        return 1;
    }
    printf("✓ Found stats map (FD: %d)\n", stats_fd);

    /* Try to find events map */
    events_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/events");
    if (events_fd < 0) {
        events_fd = bpf_obj_get("/sys/fs/bpf/events");
    }

    if (events_fd >= 0) {
        printf("✓ Found events map (FD: %d)\n", events_fd);

        /* Setup ring buffer */
        rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Warning: Failed to create ring buffer, events won't be shown\n");
        }
    } else {
        printf("Note: Events map not found, only stats will be shown\n");
    }

    /* Register signal handler */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n=== eBPF TC latency monitor ===\n");
    printf("Target IP: %s\n", target_ip_str);
    printf("Press Ctrl-C to quit.\n\n");

    /* Main loop */
    while (!exiting) {
        /* Poll ring buffer if available */
        if (rb) {
            err = ring_buffer__poll(rb, 100 /* ms */);
            if (err < 0 && err != -EINTR) {
                fprintf(stderr, "Error polling ring buffer: %d\n", err);
                break;
            }
        } else {
            usleep(100000); /* 100ms */
        }

        /* Print report every second */
        static time_t last = 0;
        time_t now = time(NULL);
        if (now != last) {
            print_report(stats_fd);
            last = now;
        }
    }

    printf("\nCleaning up...\n");
    ring_buffer__free(rb);
    if (stats_fd >= 0) close(stats_fd);
    if (events_fd >= 0) close(events_fd);

    printf("To detach TC programs, run: sudo ./detach_tc.sh <interface>\n");
    return 0;
}
