# eBPF TCP Latency Monitor

This project provides two versions of TCP latency monitoring using eBPF:

## Programs

### 1. `latency_monitor` (XDP-based)
- **Uses**: XDP (eXpress Data Path)
- **Captures**: Only INCOMING (RX/ingress) packets
- **Limitation**: Cannot see outgoing packets
- **Best for**: Monitoring latency when you control both sides or when monitoring incoming connections

### 2. `latency_monitor_tc` (TC-based) ⭐ **RECOMMENDED**
- **Uses**: TC (Traffic Control) BPF
- **Captures**: BOTH incoming (ingress) AND outgoing (egress) packets
- **Works on**: All interface types (physical, virtual, TUN, etc.)
- **Best for**: Most use cases, especially when monitoring outbound connections

## The Problem with XDP

XDP only captures packets at **ingress** (when they arrive at the interface). For measuring latency of outbound TCP connections (like SSH from your machine to a remote server), XDP cannot see the outgoing DATA packets - it only sees incoming ACK packets.

**TC-BPF solves this** by attaching to both ingress and egress paths.

## Usage

### TC Version (Recommended)

```bash
# For normal Ethernet interfaces
sudo ./latency_monitor_tc enp0s31f6 192.168.100.70

# For TUN interfaces (no Ethernet header)
sudo ./latency_monitor_tc tun0 112.11.0.100 --no-eth
```

### XDP Version (Limited)

```bash
# Only works for incoming connections
sudo ./latency_monitor eth0 10.0.0.2
```

## How It Works

1. **Egress (TC only)**: Captures outbound TCP packets to target IP, stores timestamp with seq number
2. **Ingress**: Captures inbound TCP ACK packets from target IP
3. **Matching**: Matches ACK with previously sent DATA packet using sequence numbers
4. **Latency**: Calculates time difference between DATA sent and ACK received

## Output

```
[REPORT] total=100 tcp=100 matched=50 data_sent=25 ack_recv=25 lookups=25 latency=20 avg=1.234 µs
```

- **total**: Total packets captured
- **tcp**: Successfully parsed TCP packets
- **matched**: Packets to/from target IP
- **data_sent**: Outbound TCP DATA packets sent
- **ack_recv**: Inbound TCP ACK packets received
- **lookups**: Attempts to match ACK with DATA
- **latency**: Successful latency measurements
- **avg**: Average round-trip time in microseconds

## Building

```bash
make clean && make
```

## Requirements

- Linux kernel 5.4+ (5.9+ recommended for better virtual device support)
- libbpf
- clang/LLVM
- bpftool
- Root/sudo access

## Troubleshooting

If you get all zeros in the report:

1. **Use TC version**: `latency_monitor_tc` works in more cases
2. **Check for traffic**: Use tcpdump to verify packets are flowing
3. **Run diagnostic**: `sudo ./diagnose.sh <interface> <target_ip>`

## Why TC instead of XDP?

From your tcpdump output:
```
14:58:00.110246 IP developer-pc.ssh > 192.168.100.70.54161: Flags [.], seq ...
```

These are **outgoing** packets (developer-pc → 192.168.100.70). XDP cannot see outgoing packets, only incoming ones. TC-BPF can attach to both directions, making it the right choice for this use case.
