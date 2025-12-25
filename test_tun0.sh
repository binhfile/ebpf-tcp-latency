#!/bin/bash
# Diagnostic script for tun0 XDP latency monitoring

echo "=== TUN0 Diagnostic Tool ==="
echo ""

echo "1. Checking tun0 interface:"
ip link show tun0
echo ""

echo "2. Checking IP addresses on tun0:"
ip addr show tun0
echo ""

echo "3. Checking for traffic on tun0 (5 seconds):"
echo "   Press Ctrl+C if you see packets..."
timeout 5 tcpdump -i tun0 -n -c 10 2>&1 || echo "No packets captured in 5 seconds"
echo ""

echo "4. Testing XDP attachment to tun0:"
echo "   Running latency_monitor for 3 seconds..."
timeout 3 ./latency_monitor tun0 112.11.0.100 --no-eth 2>&1 || true
echo ""

echo "=== Diagnostic complete ==="
echo ""
echo "What to look for:"
echo "- If 'total=' is 0, XDP is not seeing ANY packets (XDP may not work on tun0)"
echo "- If 'tcp=' is 0, XDP sees packets but they're not TCP"
echo "- If 'matched=' is 0, no packets match the target IP 112.11.0.100"
echo "- If 'latency_samples=' is 0, no successful DATA+ACK pairs captured"
echo ""
echo "If total=0, XDP likely doesn't work on this TUN interface."
echo "You may need to use TC (traffic control) BPF instead of XDP for TUN devices."
