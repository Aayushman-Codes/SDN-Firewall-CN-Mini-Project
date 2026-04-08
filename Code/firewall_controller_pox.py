"""
SDN-Based Firewall Controller — POX Edition
3-switch topology: s1 --- s2 --- s3

Place at: ~/sdn-firewall/pox/ext/firewall_controller.py

Launch with:
  cd ~/sdn-firewall
  sudo python3 pox/pox.py log.level --DEBUG firewall_controller
"""

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of

import logging
import os

log = core.getLogger()

# ── Log file ──────────────────────────────────────────────────────────────────
# Persist firewall events to a local file for auditing/debugging.
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "blocked_packets.log")
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(file_handler)

# ── Host identity reference (for logging only) ────────────────────────────────
# Friendly host labels used only in log output.
MAC_TO_HOST = {
    "00:00:00:00:00:01": "h1",
    "00:00:00:00:00:02": "h2",
    "00:00:00:00:00:03": "h3",
    "00:00:00:00:00:04": "h4",
    "00:00:00:00:00:05": "h5",
    "00:00:00:00:00:06": "h6",
}

# ── Firewall rules ────────────────────────────────────────────────────────────
# Rules are matched by highest priority first.
# Supported fields: src/dst MAC, src/dst IP, L4 proto, destination port.
FIREWALL_RULES = [
    # ── IP-based rules ────────────────────────────────────────────
    {
        "src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
        "src_mac": None, "dst_mac": None,
        "proto": None, "dst_port": None,
        "action": "block", "priority": 30,
        "description": "IP rule  | Block h3 (10.0.0.3) → h1 (all traffic)"
    },
    {
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "src_mac": None, "dst_mac": None,
        "proto": "tcp", "dst_port": 80,
        "action": "block", "priority": 25,
        "description": "IP rule  | Block h2 → h1 TCP:80 (HTTP)"
    },
    {
        "src_ip": "10.0.0.3", "dst_ip": "10.0.0.2",
        "src_mac": None, "dst_mac": None,
        "proto": "udp", "dst_port": 5001,
        "action": "block", "priority": 25,
        "description": "IP rule  | Block h3 → h2 UDP:5001 (iperf)"
    },
    {
        "src_ip": "10.0.0.6", "dst_ip": "10.0.0.3",
        "src_mac": None, "dst_mac": None,
        "proto": None, "dst_port": None,
        "action": "block", "priority": 28,
        "description": "IP rule  | Block h6 (10.0.0.6) → h3 (IP-based block)"
    },

    # ── MAC-based rules ───────────────────────────────────────────
    {
        "src_ip": None, "dst_ip": None,
        "src_mac": "00:00:00:00:00:05", "dst_mac": "00:00:00:00:00:02",
        "proto": None, "dst_port": None,
        "action": "block", "priority": 35,
        "description": "MAC rule | Block h5 (MAC 00:00:00:00:00:05) → h2 (MAC-based block)"
    },

    # ── Default allow ─────────────────────────────────────────────
    {
        "src_ip": None, "dst_ip": None,
        "src_mac": None, "dst_mac": None,
        "proto": None, "dst_port": None,
        "action": "allow", "priority": 1,
        "description": "Default allow all"
    },
]

# OpenFlow IP protocol numbers used for rule translation.
PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}

class FirewallSwitch(object):
    """Per-switch handler: learns MACs, evaluates policy, and programs flows."""

    def __init__(self, connection, is_firewall=False):
        # OpenFlow switch connection object.
        self.connection  = connection
        # L2 learning table: MAC -> ingress port.
        self.mac_to_port = {}
        # Runtime counters for basic observability.
        self.blocked_count = 0
        self.allowed_count = 0
        # If True, firewall logic is applied on this switch.
        self.is_firewall = is_firewall
        connection.addListeners(self)

        # Proactively install static drop rules once switch connects.
        if is_firewall:
            self._install_block_rules()

    # ── Proactive rule installation ───────────────────────────────────────────

    def _install_block_rules(self):
        """Push all BLOCK rules into the flow table immediately on connect."""
        for rule in FIREWALL_RULES:
            if rule["action"] != "block":
                continue

            match = of.ofp_match()

            src_mac  = rule.get("src_mac")
            dst_mac  = rule.get("dst_mac")
            src_ip   = rule.get("src_ip")
            dst_ip   = rule.get("dst_ip")
            proto    = rule.get("proto")
            dst_port = rule.get("dst_port")

            # MAC-based match fields (L2).
            if src_mac: match.dl_src = EthAddr(src_mac)
            if dst_mac: match.dl_dst = EthAddr(dst_mac)

            # IP-based match fields (L3/L4).
            if src_ip or dst_ip:
                match.dl_type = 0x0800   # Ethernet type IPv4 required for nw_* fields
                if src_ip: match.nw_src = IPAddr(src_ip)
                if dst_ip: match.nw_dst = IPAddr(dst_ip)
                if proto in PROTO_NUM:
                    match.nw_proto = PROTO_NUM[proto]
                    if dst_port and proto in ("tcp", "udp"):
                        match.tp_dst = dst_port

            msg = of.ofp_flow_mod()
            msg.match        = match
            # Keep firewall entries above reactive forwarding entries.
            msg.priority     = rule["priority"] + 100
            msg.idle_timeout = 0   # permanent
            msg.hard_timeout = 0   # permanent
            # No actions = DROP in OpenFlow 1.0
            self.connection.send(msg)

    # ── Packet-in handler ─────────────────────────────────────────────────────

    def _handle_PacketIn(self, event):
        """Main datapath handler for packets sent from switch to controller."""
        pkt = event.parsed
        if not pkt.parsed:
            return

        # Standard L2 MAC learning (learning-switch behavior).
        self.mac_to_port[pkt.src] = event.port
        out_port = self.mac_to_port.get(pkt.dst, of.OFPP_FLOOD)

        # Flood ARP to preserve host discovery/connectivity.
        if pkt.type == pkt.ARP_TYPE:
            self._send_packet(event, of.OFPP_FLOOD)
            return

        # Apply firewall checks only when this switch is in firewall mode.
        if self.is_firewall:
            ip_pkt   = pkt.find('ipv4')
            tcp_pkt  = pkt.find('tcp')
            udp_pkt  = pkt.find('udp')
            icmp_pkt = pkt.find('icmp')

            src_ip   = str(ip_pkt.srcip) if ip_pkt else None
            dst_ip   = str(ip_pkt.dstip) if ip_pkt else None
            src_mac  = str(pkt.src)
            dst_mac  = str(pkt.dst)
            proto    = None
            dst_port = None

            if tcp_pkt:
                proto    = "tcp"
                dst_port = tcp_pkt.dstport
            elif udp_pkt:
                proto    = "udp"
                dst_port = udp_pkt.dstport
            elif icmp_pkt:
                proto    = "icmp"

            # Highest-priority matching rule decides allow/block.
            rule = self._match_rule(src_ip, dst_ip, src_mac, dst_mac, proto, dst_port)

            if rule["action"] == "block":
                self.blocked_count += 1
                src_host = MAC_TO_HOST.get(src_mac, src_mac)
                dst_host = MAC_TO_HOST.get(dst_mac, dst_mac)
                log.warning(
                    "BLOCKED | rule='%s' | src=%s(%s) dst=%s(%s) proto=%s dport=%s",
                    rule["description"], src_host, src_ip or src_mac,
                    dst_host, dst_ip or dst_mac, proto, dst_port
                )
                # Explicit drop for the current buffered packet.
                drop = of.ofp_packet_out()
                drop.buffer_id = event.ofp.buffer_id
                drop.in_port   = event.port
                self.connection.send(drop)
                return

        # Allowed traffic path: reactively forward and (if possible) install flow.
        ip_pkt = pkt.find('ipv4')
        if not ip_pkt:
            self._send_packet(event, out_port)
            return

        self._allow(event, out_port)

    def _match_rule(self, src_ip, dst_ip, src_mac, dst_mac, proto, dst_port):
        """Return best matching rule by priority; fallback to implicit allow."""
        best     = None
        best_pri = -1
        for r in FIREWALL_RULES:
            if r["priority"] <= best_pri: continue
            if r["src_mac"]  and r["src_mac"]  != src_mac:  continue
            if r["dst_mac"]  and r["dst_mac"]  != dst_mac:  continue
            if r["src_ip"]   and r["src_ip"]   != src_ip:   continue
            if r["dst_ip"]   and r["dst_ip"]   != dst_ip:   continue
            if r["proto"]    and r["proto"]    != proto:    continue
            if r["dst_port"] and r["dst_port"] != dst_port: continue
            best     = r
            best_pri = r["priority"]
        return best if best else {"action": "allow", "description": "implicit allow"}

    def _allow(self, event, out_port):
        """Install short-lived forwarding flow and emit packet."""
        self.allowed_count += 1
        pkt = event.parsed
        if out_port != of.OFPP_FLOOD:
            msg = of.ofp_flow_mod()
            msg.match        = of.ofp_match.from_packet(pkt, event.port)
            msg.priority     = 10
            # Short timeouts keep forwarding rules adaptive.
            msg.idle_timeout = 30
            msg.hard_timeout = 60
            msg.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(msg)
        self._send_packet(event, out_port)

    def _send_packet(self, event, out_port):
        """Send a packet-out to forward current frame immediately."""
        msg = of.ofp_packet_out()
        msg.data    = event.ofp.data
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)


# ── POX App ───────────────────────────────────────────────────────────────────

class SDNFirewallApp(object):
    """POX app entrypoint: listens for new switches and attaches handlers."""

    def __init__(self):
        core.openflow.addListeners(self)
        log.info("=" * 60)
        log.info("SDN Firewall Controller (POX) — 3-switch topology")
        log.info("Firewall enforced on: ALL switches (Distributed Firewall Mode)")
        log.info("Loaded %d firewall rules.", len(FIREWALL_RULES))
        log.info("=" * 60)

    def _handle_ConnectionUp(self, event):
        """Instantiate per-switch controller object on each new connection."""
        dpid = event.dpid
        # Enforce firewall rules on all switches (s1, s2, s3),
        # including intra-switch traffic that may bypass a central choke point.
        is_fw = True
        label = "FIREWALL/EDGE"
        log.info("Switch connected: %s → %s", dpid_to_str(dpid), label)
        FirewallSwitch(event.connection, is_firewall=is_fw)

def launch():
    """POX-required launch hook."""
    core.registerNew(SDNFirewallApp)
