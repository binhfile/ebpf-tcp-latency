#!/bin/bash
# Diagnostic tool for XDP latency monitoring

if [ $# -lt 2 ]; then
    echo "Usage: $0 <interface> <target_ip> [--no-eth]"
    echo "Example: $0 enp0s31f6 192.168.100.70"
    exit 1
fi

IFACE=$1
TARGET_IP=$2
NO_ETH=$3

echo "========================================="
echo "XDP Latency Monitor Diagnostics"
echo "========================================="
echo ""

echo "1. Checking interface: $IFACE"
if ! ip link show "$IFACE" &>/dev/null; then
    echo "   ✗ Interface $IFACE does not exist!"
    exit 1
fi
ip link show "$IFACE" | head -2
echo ""

echo "2. Checking IP addresses on $IFACE:"
ip addr show "$IFACE" | grep inet
echo ""

echo "3. Checking if XDP is already attached:"
ip link show "$IFACE" | grep -i xdp || echo "   No XDP program currently attached"
echo ""

echo "4. Checking for ANY traffic on $IFACE (5 seconds)..."
echo "   Looking for packets (press Ctrl+C if traffic appears)..."
PKTS=$(timeout 5 tcpdump -i "$IFACE" -c 10 -n 2>&1 | tee /dev/stderr | grep -c "IP ")
if [ "$PKTS" -eq 0 ]; then
    echo "   ✗ WARNING: No IP packets captured in 5 seconds!"
    echo "   Make sure there is actual traffic on this interface."
else
    echo "   ✓ Captured $PKTS IP packets"
fi
echo ""

echo "5. Checking for TCP traffic to/from $TARGET_IP (5 seconds)..."
timeout 5 tcpdump -i "$IFACE" -n "host $TARGET_IP and tcp" -c 5 2>&1 | tee /dev/stderr | grep -q "IP " && \
    echo "   ✓ TCP traffic detected to/from $TARGET_IP" || \
    echo "   ✗ No TCP traffic to/from $TARGET_IP in 5 seconds"
echo ""

echo "6. Running latency_monitor for 3 seconds..."
if [ "$NO_ETH" = "--no-eth" ]; then
    timeout 3 ./latency_monitor "$IFACE" "$TARGET_IP" --no-eth 2>&1 || true
else
    timeout 3 ./latency_monitor "$IFACE" "$TARGET_IP" 2>&1 || true
fi
echo ""

echo "========================================="
echo "Diagnostic Summary"
echo "========================================="
echo ""
echo "Expected behavior:"
echo "- total > 0: XDP is capturing packets"
echo "- tcp > 0: TCP packets are being parsed"
echo "- matched > 0: Packets to/from $TARGET_IP are found"
echo "- data_sent > 0: Outbound TCP packets to $TARGET_IP"
echo "- ack_recv > 0: Inbound TCP ACK packets from $TARGET_IP"
echo "- latency > 0: Successful DATA+ACK pairing"
echo ""
echo "If total=0:"
echo "- XDP might not be working on this interface"
echo "- No traffic is flowing on the interface"
echo "- Check if you need to run with 'sudo'"
echo ""
