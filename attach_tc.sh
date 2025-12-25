#!/bin/bash
# Helper script to attach TC BPF programs using tc command
# This is more compatible than the libbpf TC API

if [ $# -lt 1 ]; then
    echo "Usage: $0 <interface>"
    echo "Example: $0 enp0s31f6"
    exit 1
fi

IFACE=$1
EGRESS_OBJ="bpf/latency_tc.bpf.o"
INGRESS_OBJ="bpf/latency_tc.bpf.o"

# Check if interface exists
if ! ip link show "$IFACE" &>/dev/null; then
    echo "Error: Interface $IFACE does not exist"
    exit 1
fi

# Check if BPF object exists
if [ ! -f "$EGRESS_OBJ" ]; then
    echo "Error: BPF object $EGRESS_OBJ not found. Run 'make' first."
    exit 1
fi

echo "Attaching TC BPF programs to $IFACE..."

# Create clsact qdisc if it doesn't exist
echo "Creating clsact qdisc..."
tc qdisc add dev "$IFACE" clsact 2>/dev/null || echo "  (clsact already exists)"

# Attach egress program
echo "Attaching egress (outbound) program..."
tc filter add dev "$IFACE" egress bpf direct-action obj "$EGRESS_OBJ" sec classifier/tc_egress

if [ $? -eq 0 ]; then
    echo "✓ Egress program attached"
else
    echo "✗ Failed to attach egress program"
    exit 1
fi

# Attach ingress program
echo "Attaching ingress (inbound) program..."
tc filter add dev "$IFACE" ingress bpf direct-action obj "$INGRESS_OBJ" sec classifier/tc_ingress

if [ $? -eq 0 ]; then
    echo "✓ Ingress program attached"
else
    echo "✗ Failed to attach ingress program"
    # Clean up egress
    tc filter del dev "$IFACE" egress
    exit 1
fi

echo ""
echo "✓ TC BPF programs attached successfully to $IFACE"
echo ""
echo "To view attached programs:"
echo "  tc filter show dev $IFACE egress"
echo "  tc filter show dev $IFACE ingress"
echo ""
echo "To detach programs, run:"
echo "  sudo ./detach_tc.sh $IFACE"
