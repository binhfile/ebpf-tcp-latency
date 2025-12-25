# TC BPF Latency Monitor - Usage Guide

The TC BPF version can capture both outbound and inbound packets, solving the XDP limitation.

## Two Methods to Attach TC Programs

### Method 1: All-in-One (latency_monitor_tc)

This tries to attach TC programs using libbpf's TC API:

```bash
sudo ./latency_monitor_tc enp0s31f6 192.168.100.70
```

**Note**: If you get "Invalid argument" error, your libbpf version may not fully support the TC API. Use Method 2 instead.

### Method 2: Shell Script + Monitor (Recommended for compatibility)

This uses the standard `tc` command-line tool to attach programs:

```bash
# Step 1: Attach TC BPF programs to interface
sudo ./attach_tc.sh enp0s31f6

# Step 2: Set target IP in BPF program (before attaching, edit latency_tc.bpf.c line 48)
#         Or recompile with your target IP

# Step 3: Monitor (coming soon - simplified monitor program)
```

## Troubleshooting

### Error: "Invalid argument" when attaching

This means the `bpf_tc_attach()` libbpf function isn't working. Try:

1. **Check libbpf version**:
   ```bash
   pkg-config --modversion libbpf
   ```
   You need libbpf 0.6.0+ for full TC API support

2. **Use Method 2** (tc command) which works with older versions

3. **Run with debug output** to see the actual error:
   ```bash
   sudo ./latency_monitor_tc enp0s31f6 192.168.100.70 2>&1 | grep -A5 "libbpf:"
   ```

### Verify TC Programs Are Attached

```bash
# Check egress (outbound)
sudo tc filter show dev enp0s31f6 egress

# Check ingress (inbound)
sudo tc filter show dev enp0s31f6 ingress
```

You should see something like:
```
filter protocol all pref 49152 bpf chain 0
filter protocol all pref 49152 bpf chain 0 handle 0x1 latency_tc.bpf.o:[classifier/tc_egress] direct-action not_in_hw id 123
```

### Detach Programs

```bash
sudo ./detach_tc.sh enp0s31f6
```

## Why TC Instead of XDP?

Your tcpdump showed **outgoing** packets:
```
developer-pc.ssh > 192.168.100.70.54161
```

- **XDP**: Only captures INCOMING packets (RX path)
- **TC**: Captures BOTH incoming AND outgoing packets

For monitoring SSH from your machine to a remote server, you MUST use TC to see the outbound DATA packets.

## Expected Output

When working correctly:
```
[REPORT] total=150 tcp=150 matched=75 data_sent=40 ack_recv=35 lookups=35 latency=30 avg=1.234 µs
```

- **total > 0**: TC is capturing packets ✓
- **data_sent > 0**: Outbound packets to target IP ✓
- **ack_recv > 0**: Inbound ACKs from target IP ✓
- **latency > 0**: Successfully measuring RTT ✓
