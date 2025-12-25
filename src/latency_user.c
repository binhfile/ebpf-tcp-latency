/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "latency.skel.h"

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

/* Hàm in báo cáo mỗi giây */
static void print_report(struct latency_bpf *obj)
{
    __u32 sum_key = 0, cnt_key = 1, total_key = 2, tcp_key = 3, match_key = 4;
    __u32 data_key = 5, ack_key = 6, lookup_key = 7;
    __u64 sum = 0, cnt = 0, total = 0, tcp_cnt = 0, match_cnt = 0;
    __u64 data_sent = 0, ack_recv = 0, lookups = 0;
    int fd = bpf_map__fd(obj->maps.stats);
    int nr_cpus = libbpf_num_possible_cpus();
    __u64 *values;

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

    free(values);

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

/* Ring‑buffer callback – chỉ để hiển thị chi tiết (tùy chọn) */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    /* Events disabled - only showing summary reports */
    (void)ctx;
    (void)data;
    (void)data_sz;
    return 0;
}

int main(int argc, char **argv)
{
    struct latency_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    const char *ifname = NULL;
    const char *target_ip_str = NULL;
    __u32 ifindex = 0;
    __u32 target_ip_host = 0;
    struct in_addr addr;
    __u8 no_eth = 0;

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <ifname> <target_ip> [--no-eth]\n", argv[0]);
        fprintf(stderr, "  --no-eth: Use for TUN interfaces (no Ethernet header)\n");
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s eth0 10.0.0.2\n", argv[0]);
        fprintf(stderr, "  %s tun0 112.11.0.100 --no-eth\n", argv[0]);
        return 1;
    }
    ifname = argv[1];
    target_ip_str = argv[2];

    /* Check for --no-eth flag */
    if (argc == 4) {
        if (strcmp(argv[3], "--no-eth") == 0) {
            no_eth = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[3]);
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

    /* Load & verify BPF program */
    skel = latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set target IP address and no_eth flag before loading */
    skel->rodata->target_ip = target_ip_host;
    skel->rodata->no_eth = no_eth;

    err = latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach XDP program to interface - try native first, then generic */
    int prog_fd = bpf_program__fd(skel->progs.latency_xdp_prog);

    /* Try native XDP first */
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "Native XDP attach failed (%s), trying generic XDP...\n", strerror(-err));
        /* Try generic XDP mode */
        err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
        if (err) {
            fprintf(stderr, "Failed to attach XDP program to %s: %s\n", ifname, strerror(-err));
            fprintf(stderr, "Note: XDP may not be supported on this interface or kernel.\n");
            goto cleanup;
        }
        printf("✓ XDP program attached in GENERIC/SKB mode to %s\n", ifname);
    } else {
        printf("✓ XDP program attached in NATIVE mode to %s\n", ifname);
    }

    printf("✓ BPF program FD: %d\n", prog_fd);

    /* Store the ifindex for cleanup */
    skel->links.latency_xdp_prog = (struct bpf_link *)1; /* Mark as attached */

    /* Ring‑buffer để nhận các sự kiện chi tiết */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    /* Đăng ký signal */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== eBPF latency monitor ===\n");
    printf("Interface: %s (ifindex=%u)\n", ifname, ifindex);
    printf("Target IP: %s\n", target_ip_str);
    printf("  - Host byte order: 0x%08X\n", target_ip_host);
    printf("  - Network byte order: 0x%08X\n", htonl(target_ip_host));
    printf("Mode: %s\n", no_eth ? "TUN/raw IP (no Ethernet header)" : "Ethernet");
    printf("Monitoring:\n");
    printf("  - Outbound: TCP packets with dest IP = %s\n", target_ip_str);
    printf("  - Inbound:  TCP packets with src IP = %s and ACK flag set\n", target_ip_str);
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

        /* In báo cáo mỗi giây */
        static time_t last = 0;
        time_t now = time(NULL);
        if (now != last) {
            print_report(skel);
            last = now;
        }
    }

    printf("\nDetaching XDP program and cleaning up …\n");

cleanup:
    ring_buffer__free(rb);

    /* Detach XDP program if attached */
    if (skel && skel->links.latency_xdp_prog && ifindex > 0) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
    }

    latency_bpf__destroy(skel);
    return err != 0;
}
