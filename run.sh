#!/bin/bash
# SDN Firewall – Setup & Run Script (POX edition)
# Ubuntu 24.04 | Mininet + POX + Open vSwitch

set -e
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERR] ${NC}  $1"; exit 1; }

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
POX_DIR="$PROJECT_DIR/pox"

install_deps() {
    info "Installing system dependencies..."
    sudo apt-get update -qq
    sudo apt-get install -y mininet openvswitch-switch python3 python3-pip git \
        iperf3 net-tools curl netcat-openbsd tshark wireshark-common
    info "Cloning POX..."
    [ ! -d "$POX_DIR" ] && git clone https://github.com/noxrepo/pox.git "$POX_DIR" || info "POX already cloned."
    cp "$PROJECT_DIR/firewall_controller_pox.py" "$POX_DIR/ext/firewall_controller.py"
    info "Done. Run: ./run.sh cleanup && ./run.sh controller"
}

check_ovs() {
    sudo systemctl start openvswitch-switch 2>/dev/null || true
    sudo ovs-vsctl show &>/dev/null || error "OVS not running."
}

cleanup() {
    info "Cleaning up..."; sudo mn --clean 2>/dev/null || true
    sudo pkill -f "pox.py" 2>/dev/null || true; sleep 1; info "Done."
}

start_controller() {
    check_ovs
    [ -d "$POX_DIR" ] || error "POX not found. Run: ./run.sh install"
    cp "$PROJECT_DIR/firewall_controller_pox.py" "$POX_DIR/ext/firewall_controller.py"
    info "Starting POX controller..."
    cd "$POX_DIR"
    nohup sudo python3 pox.py log.level --DEBUG firewall_controller \
        > "$PROJECT_DIR/pox.log" 2>&1 &
    echo $! > "$PROJECT_DIR/pox.pid"; sleep 3
    kill -0 $(cat "$PROJECT_DIR/pox.pid") 2>/dev/null \
        && info "POX started | pox.log | blocked_packets.log" \
        || error "POX failed. Check pox.log"
}

case "${1:-help}" in
    install)    install_deps ;;
    cleanup)    cleanup ;;
    controller) cleanup; start_controller ;;
    topology)   cd "$PROJECT_DIR"; sudo python3 topology.py ;;
    test)       cleanup; start_controller; sleep 2; cd "$PROJECT_DIR"; sudo python3 test_firewall.py ;;
    flows)      sudo ovs-ofctl dump-flows s1 2>/dev/null || warn "s1 not found" ;;
    log)        [ -f "$PROJECT_DIR/blocked_packets.log" ] && tail -30 "$PROJECT_DIR/blocked_packets.log" || warn "No log yet." ;;
    capture)    sudo tshark -i "${2:-s1-eth1}" -a duration:15 -w "$PROJECT_DIR/capture_$(date +%Y%m%d_%H%M%S).pcap" 2>/dev/null & ;;
    all)        cleanup; start_controller; cd "$PROJECT_DIR"; sudo python3 topology.py ;;
    *)          echo "Usage: $0 [install|cleanup|controller|topology|test|flows|log|capture|all]" ;;
esac
