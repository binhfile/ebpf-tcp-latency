# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# -------------------------------------------------
# Makefile cho dự án ebpf‑latency
# -------------------------------------------------
BPF_SRC   := bpf/latency.bpf.c
BPF_TC_SRC := bpf/latency_tc.bpf.c
USER_SRC  := src/latency_user.c
USER_TC_SRC := src/latency_tc_user.c
TARGET    := latency_monitor
TARGET_TC := latency_monitor_tc

# Các công cụ
CC        ?= gcc
CLANG     ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF    ?= $(shell pkg-config --libs libbpf) -lelf -lz

CFLAGS   := -O2 -Wall -g -I$(PWD)/bpf -I/usr/include/x86_64-linux-gnu
LDFLAGS  := $(LIBBPF) -lelf -lz

# -------------------------------------------------
all: $(TARGET) $(TARGET_TC)

# ----------- XDP BPF object (skeleton) -------------
bpf/latency.skel.h: $(BPF_SRC)
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $(BPF_SRC:.c=.o)
	bpftool gen skeleton $(BPF_SRC:.c=.o) > $@

# ----------- TC BPF object (skeleton) -------------
bpf/latency_tc.skel.h: $(BPF_TC_SRC)
	$(CLANG) $(CFLAGS) -target bpf -c $< -o $(BPF_TC_SRC:.c=.o)
	bpftool gen skeleton $(BPF_TC_SRC:.c=.o) > $@

# -------------- XDP User program --------------------
$(TARGET): bpf/latency.skel.h $(USER_SRC)
	$(CC) $(CFLAGS) $(USER_SRC) -o $@ $(LDFLAGS)

# -------------- TC User program --------------------
$(TARGET_TC): bpf/latency_tc.skel.h $(USER_TC_SRC)
	$(CC) $(CFLAGS) $(USER_TC_SRC) -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_TC) bpf/*.o* bpf/*.skel.h

.PHONY: all clean
