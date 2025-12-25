# Output Format Guide

## Running the Monitor

```bash
sudo ./latency_monitor_tc enp0s31f6 192.168.100.70
```

## Output Example

```
=== eBPF TC latency monitor ===
Interface: enp0s31f6 (ifindex=2)
Target IP: 192.168.100.70
  - Host byte order: 0xC0A86446
  - Network byte order: 0x4664A8C0
Mode: Ethernet
Monitoring:
  - Outbound (egress): TCP packets with dest IP = 192.168.100.70
  - Inbound (ingress): TCP packets with src IP = 192.168.100.70 and ACK flag set

Press Ctrl-C to quit.

[14:23:45] [SYN] New connection initiated - seq=3456789012
[14:23:45] [SYN] New connection initiated - seq=4123456789
[REPORT   ] total=512 tcp=512 matched=2048 data_sent=512 ack_recv=1536 lookups=1536 latency=480  avg=342.5 µs
[14:23:52] [FIN] Connection closing - seq=3456790000 ack=4123458000
[REPORT   ] total=1024 tcp=1024 matched=4096 data_sent=1024 ack_recv=3072 lookups=3072 latency=960  avg=345.2 µs
[14:23:58] [RST] Connection reset - seq=3456790500 ack=4123458500
[REPORT   ] total=1536 tcp=1536 matched=6144 data_sent=1536 ack_recv=4608 lookups=4608 latency=1440  avg=348.1 µs
```

## Event Types

### Connection Events (Real-time)
- **`[SYN]`**: New TCP connection being established
  - Shows when client initiates connection (3-way handshake start)
  - Format: `[HH:MM:SS] [SYN] New connection initiated - seq=<number>`

- **`[FIN]`**: TCP connection gracefully closing
  - Shows when either side initiates connection termination
  - Format: `[HH:MM:SS] [FIN] Connection closing - seq=<number> ack=<number>`

- **`[RST]`**: TCP connection forcefully reset
  - Shows when connection is abruptly terminated
  - Format: `[HH:MM:SS] [RST] Connection reset - seq=<number> ack=<number>`

### Summary Reports (Every Second)
- **`[REPORT]`**: Aggregated statistics updated every second
  - `total`: Total packets captured on egress
  - `tcp`: Successfully parsed TCP packets
  - `matched`: Packets matching target IP (or all if target=0)
  - `data_sent`: Outbound TCP DATA packets (with payload)
  - `ack_recv`: Inbound TCP ACK packets
  - `lookups`: ACK packets that tried to find matching DATA
  - `latency`: Successful DATA+ACK pairings (actual RTT measurements)
  - `avg`: Average round-trip time in microseconds

## Interpretation

### Good Connection Health
```
data_sent ≈ ack_recv ≈ lookups ≈ latency
```
This means most DATA packets are getting ACKed and matched successfully.

### Example: 90%+ Match Rate
```
[REPORT] total=500 tcp=500 matched=2000 data_sent=500 ack_recv=1500 lookups=1500 latency=450
```
- 500 DATA packets sent
- 1500 ACKs received (TCP can ACK multiple packets at once)
- 450 successful latency measurements (90% success rate)

### Connection Activity
- **New SSH session**: You'll see `[SYN]` events
- **Closing SSH**: You'll see `[FIN]` events (graceful)
- **Network issue/timeout**: You'll see `[RST]` events (forced reset)

## Use Cases

1. **Monitor SSH latency**: See RTT for every SSH session
2. **Detect connection issues**: `[RST]` events show problems
3. **Track connection lifecycle**: See when connections start/end
4. **Performance analysis**: Average latency shows network health
