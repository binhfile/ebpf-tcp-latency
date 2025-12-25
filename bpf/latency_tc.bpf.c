/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

/* Define BPF_MAP_TYPE_RINGBUF if not available in headers */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF 27
#endif

/* -------------------- Định nghĩa cấu trúc -------------------- */
struct latency_event {
    __u32 seq;          /* TCP seq */
    __u32 ack;          /* TCP ack */
    __u64 latency_ns;  /* thời gian (ns) hoặc timestamp */
    __u8  direction;   /* 0 = data→, 1 = ack←, 2 = SYN, 3 = FIN, 4 = RST */
};

/* -------------------- BPF maps -------------------- */

/* 1. pending: lưu thời gian gửi DATA, key = seq (u32) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);      /* TCP seq */
    __type(value, __u64);    /* ktime_get_ns() */
    __uint(max_entries, 65536);
} pending SEC(".maps");

/* 2. per‑CPU histogram để tổng hợp nhanh (không bắt buộc) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);      /* 0 = sum latency, 1 = count, 2 = total pkts, 3 = tcp pkts, 4 = matched pkts
                                5 = data_sent, 6 = ack_recv, 7 = pending_lookups
                                8 = bytes_sent, 9 = bytes_recv */
    __type(value, __u64);
    __uint(max_entries, 16);
} stats SEC(".maps");

/* 3. ring‑buffer để gửi sự kiện lên userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);   /* 1 MiB */
} events SEC(".maps");

/* Target IP address - set from userspace via command line
 * Set to 0 to capture ALL TCP packets (filter in userspace) */
volatile const __u32 target_ip = 0;

/* Skip Ethernet header for TUN/raw IP interfaces - set from userspace */
volatile const __u8 no_eth = 0;

/* -------------------- Helper -------------------- */
static __always_inline int parse_tcp(void *data, void *data_end,
                     struct iphdr **iph, struct tcphdr **tcph)
{
    void *ip_start = data;

    /* Check if we need to parse Ethernet header */
    if (!no_eth) {
        /* Ethernet */
        struct ethhdr *eth = data;
        if ((void*)eth + sizeof(*eth) > data_end)
            return -1;
        if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
            return -1;
        ip_start = data + sizeof(*eth);
    }

    /* IP */
    *iph = ip_start;
    if ((void*)*iph + sizeof(**iph) > data_end)
        return -1;
    if ((*iph)->protocol != IPPROTO_TCP)
        return -1;

    /* TCP */
    *tcph = (void*)*iph + (*iph)->ihl * 4;
    if ((void*)*tcph + sizeof(**tcph) > data_end)
        return -1;
    return 0;
}

/* -------------------- TC egress (outbound DATA) -------------------- */
SEC("classifier/tc_egress")
int latency_tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    struct iphdr   *iph;
    struct tcphdr  *tcph;
    __u64 ts;
    __u32 key;
    struct latency_event *ev;

    /* Debug: count total packets */
    __u32 total_key = 2;
    __u64 *total = bpf_map_lookup_elem(&stats, &total_key);
    if (total)
        *total += 1;

    if (parse_tcp(data, data_end, &iph, &tcph) < 0)
        return TC_ACT_OK;   /* không phải TCP */

    /* Debug: count TCP packets */
    __u32 tcp_key = 3;
    __u64 *tcp_cnt = bpf_map_lookup_elem(&stats, &tcp_key);
    if (tcp_cnt)
        *tcp_cnt += 1;

    /* Convert target IP to network byte order */
    const __be32 target_ip_be = bpf_htonl(target_ip);

    /* Hướng DATA: máy → thiết bị (egress) */
    /* If target_ip is 0, capture ALL TCP packets */
    if (target_ip == 0 || iph->daddr == target_ip_be) {
        /* Debug: count matched packets */
        __u32 match_key = 4;
        __u64 *match_cnt = bpf_map_lookup_elem(&stats, &match_key);
        if (match_cnt)
            *match_cnt += 1;

        /* Report connection lifecycle events */
        if (tcph->syn || tcph->fin || tcph->rst) {
            ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
            if (ev) {
                ev->seq = bpf_ntohl(tcph->seq);
                ev->ack = bpf_ntohl(tcph->ack_seq);
                ev->latency_ns = bpf_ktime_get_ns();
                if (tcph->syn)
                    ev->direction = 2;  /* SYN */
                else if (tcph->fin)
                    ev->direction = 3;  /* FIN */
                else
                    ev->direction = 4;  /* RST */
                bpf_ringbuf_submit(ev, 0);
            }
            return TC_ACT_OK;
        }

        /* Debug: count data packets sent */
        __u32 data_key = 5;
        __u64 *data_cnt = bpf_map_lookup_elem(&stats, &data_key);
        if (data_cnt)
            *data_cnt += 1;

        /* Calculate payload length */
        __u32 tcp_hdr_len = tcph->doff * 4;
        __u32 ip_total_len = bpf_ntohs(iph->tot_len);
        __u32 ip_hdr_len = iph->ihl * 4;
        __u32 payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

        /* Only track packets with payload */
        if (payload_len == 0)
            return TC_ACT_OK;

        /* Track bytes sent */
        __u32 bytes_sent_key = 8;
        __u64 *bytes_sent = bpf_map_lookup_elem(&stats, &bytes_sent_key);
        if (bytes_sent)
            *bytes_sent += payload_len;

        /* Store timestamp at SEQ + payload_len (the expected ACK number) */
        key = bpf_ntohl(tcph->seq) + payload_len;
        ts  = bpf_ktime_get_ns();
        bpf_map_update_elem(&pending, &key, &ts, BPF_ANY);
    }

    return TC_ACT_OK;
}

/* -------------------- TC ingress (inbound ACK) -------------------- */
SEC("classifier/tc_ingress")
int latency_tc_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    struct iphdr   *iph;
    struct tcphdr  *tcph;
    __u64 ts;
    __u32 key;
    __u64 *pval;
    struct latency_event *ev;

    /* Don't count ingress in total (already counted in egress if bidirectional) */

    if (parse_tcp(data, data_end, &iph, &tcph) < 0)
        return TC_ACT_OK;   /* không phải TCP */

    /* Convert target IP to network byte order */
    const __be32 target_ip_be = bpf_htonl(target_ip);

    /* Hướng ACK: thiết bị → máy (ingress) */
    /* If target_ip is 0, capture ALL TCP packets */
    if (target_ip == 0 || iph->saddr == target_ip_be) {
        /* Debug: count matched packets */
        __u32 match_key = 4;
        __u64 *match_cnt = bpf_map_lookup_elem(&stats, &match_key);
        if (match_cnt)
            *match_cnt += 1;

        /* Report connection lifecycle events */
        if (tcph->syn || tcph->fin || tcph->rst) {
            ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
            if (ev) {
                ev->seq = bpf_ntohl(tcph->seq);
                ev->ack = bpf_ntohl(tcph->ack_seq);
                ev->latency_ns = bpf_ktime_get_ns();
                if (tcph->syn)
                    ev->direction = 2;  /* SYN */
                else if (tcph->fin)
                    ev->direction = 3;  /* FIN */
                else
                    ev->direction = 4;  /* RST */
                bpf_ringbuf_submit(ev, 0);
            }
            return TC_ACT_OK;
        }

        /* Track bytes received (payload in this direction) */
        __u32 tcp_hdr_len = tcph->doff * 4;
        __u32 ip_total_len = bpf_ntohs(iph->tot_len);
        __u32 ip_hdr_len = iph->ihl * 4;
        __u32 payload_len = ip_total_len - ip_hdr_len - tcp_hdr_len;

        __u32 bytes_recv_key = 9;
        __u64 *bytes_recv = bpf_map_lookup_elem(&stats, &bytes_recv_key);
        if (bytes_recv)
            *bytes_recv += payload_len;

        /* Kiểm tra là ACK (ACK flag set) */
        if (!(tcph->ack))
            return TC_ACT_OK;

        /* Debug: count ACK packets received */
        __u32 ack_key = 6;
        __u64 *ack_cnt = bpf_map_lookup_elem(&stats, &ack_key);
        if (ack_cnt)
            *ack_cnt += 1;

        /* ACK number is the next expected SEQ (SEQ + payload_len from DATA packet) */
        key = bpf_ntohl(tcph->ack_seq);
        ts  = bpf_ktime_get_ns();

        /* Debug: count pending lookups */
        __u32 lookup_key = 7;
        __u64 *lookup_cnt = bpf_map_lookup_elem(&stats, &lookup_key);
        if (lookup_cnt)
            *lookup_cnt += 1;

        /* Tìm timestamp đã lưu */
        pval = bpf_map_lookup_elem(&pending, &key);
        if (!pval)
            return TC_ACT_OK;   /* không có DATA tương ứng */

        /* Tính latency */
        __u64 latency = ts - *pval;

        /* Xóa entry */
        bpf_map_delete_elem(&pending, &key);

        /* Cập nhật stats (per‑CPU) */
        __u32 sum_key = 0, cnt_key = 1;
        __u64 *sum = bpf_map_lookup_elem(&stats, &sum_key);
        __u64 *cnt = bpf_map_lookup_elem(&stats, &cnt_key);
        if (sum && cnt) {
            *sum += latency;
            *cnt += 1;
        }

        /* Gửi sự kiện qua ring‑buffer (để user‑space có thể in chi tiết) */
        ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
        if (ev) {
            ev->seq      = key;  /* This is the ACK number that matched */
            ev->ack      = key;
            ev->latency_ns = latency;
            ev->direction = 1;   /* ACK */
            bpf_ringbuf_submit(ev, 0);
        }
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
