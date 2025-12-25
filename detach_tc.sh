#!/bin/bash
# Helper script to detach TC BPF programs

if [ $# -lt 1 ]; then
    echo "Usage: $0 <interface>"
    echo "Example: $0 enp0s31f6"
    exit 1
fi

IFACE=$1

echo "Detaching TC BPF programs from $IFACE..."

# Remove filters
tc filter del dev "$IFACE" egress 2>/dev/null && echo "✓ Egress program detached" || echo "  (no egress program)"
tc filter del dev "$IFACE" ingress 2>/dev/null && echo "✓ Ingress program detached" || echo "  (no ingress program)"

# Remove clsact qdisc
tc qdisc del dev "$IFACE" clsact 2>/dev/null && echo "✓ Clsact qdisc removed" || echo "  (no clsact qdisc)"

echo "Done."
