/* Quick test to check if BPF program loads */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpf/latency_tc.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(void)
{
    struct latency_tc_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);

    printf("Opening BPF object...\n");
    skel = latency_tc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    printf("✓ BPF object opened\n");

    /* Set some defaults */
    skel->rodata->target_ip = 0xC0A80101; /* 192.168.1.1 */
    skel->rodata->no_eth = 0;

    printf("Loading BPF object...\n");
    err = latency_tc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        latency_tc_bpf__destroy(skel);
        return 1;
    }
    printf("✓ BPF object loaded successfully\n");

    printf("Program FDs:\n");
    printf("  egress: %d\n", bpf_program__fd(skel->progs.latency_tc_egress));
    printf("  ingress: %d\n", bpf_program__fd(skel->progs.latency_tc_ingress));

    latency_tc_bpf__destroy(skel);
    printf("✓ All tests passed\n");
    return 0;
}
