"""
SDN-Based Firewall Controller — POX Edition
Place at: ~/sdn-firewall/pox/ext/firewall_controller.py

Launch with:
  cd ~/sdn-firewall
  sudo python3 pox/pox.py log.level --DEBUG firewall_controller
"""

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of

import logging
import os

log = core.getLogger()

# ── Log file ──────────────────────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "blocked_packets.log")
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(file_handler)

# ── Firewall Rules ────────────────────────────────────────────────────────────
# proto: "tcp" | "udp" | "icmp" | None (None = all IP traffic)
FIREWALL_RULES = [
    {
        "src_ip": "10.0.0.3", "dst_ip": "10.0.0.1",
        "proto": None, "dst_port": None,
        "action": "block", "priority": 30,
        "description": "Block h3 → h1 (all traffic)"
    },
    {
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
        "proto": "tcp", "dst_port": 80,
        "action": "block", "priority": 25,
        "description": "Block HTTP TCP:80 from h2 → h1"
    },
    {
        "src_ip": "10.0.0.3", "dst_ip": "10.0.0.2",
        "proto": "udp", "dst_port": 5001,
        "action": "block", "priority": 25,
        "description": "Block iperf UDP:5001 from h3 → h2"
    },
    {
        "src_ip": None, "dst_ip": None,
        "proto": None, "dst_port": None,
        "action": "allow", "priority": 1,
        "description": "Default allow all"
    },
]

# Proto name → nw_proto number
PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}


class FirewallSwitch(object):

    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        self.blocked_count = 0
        self.allowed_count = 0
        connection.addListeners(self)
        log.info("FirewallSwitch connected to %s", dpid_to_str(connection.dpid))

    def _handle_PacketIn(self, event):
        pkt = event.parsed
        if not pkt.parsed:
            return

        # MAC learning
        self.mac_to_port[pkt.src] = event.port
        out_port = self.mac_to_port.get(pkt.dst, of.OFPP_FLOOD)

        # Always flood ARP so hosts can resolve each other
        if pkt.type == pkt.ARP_TYPE:
            self._send_packet(event, of.OFPP_FLOOD)
            return

        # Non-IP: just forward
        ip_pkt = pkt.find('ipv4')
        if not ip_pkt:
            self._send_packet(event, out_port)
            return

        src_ip = str(ip_pkt.srcip)
        dst_ip = str(ip_pkt.dstip)

        tcp_pkt  = pkt.find('tcp')
        udp_pkt  = pkt.find('udp')
        icmp_pkt = pkt.find('icmp')

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

        rule = self._match_rule(src_ip, dst_ip, proto, dst_port)

        if rule["action"] == "block":
            self._block(event, src_ip, dst_ip, proto, dst_port, rule)
        else:
            self._allow(event, out_port)

    def _match_rule(self, src_ip, dst_ip, proto, dst_port):
        best     = None
        best_pri = -1
        for r in FIREWALL_RULES:
            if r["priority"] <= best_pri:
                continue
            if r["src_ip"]   and r["src_ip"]   != src_ip:   continue
            if r["dst_ip"]   and r["dst_ip"]   != dst_ip:   continue
            if r["proto"]    and r["proto"]    != proto:    continue
            if r["dst_port"] and r["dst_port"] != dst_port: continue
            best     = r
            best_pri = r["priority"]
        return best if best else {"action": "allow", "description": "implicit allow"}

    def _block(self, event, src_ip, dst_ip, proto, dst_port, rule):
        packet = event.parsed
        ip_pkt = packet.find('ipv4')
        icmp_pkt = packet.find('icmp')

        # Allow ICMP replies only (type 0 = echo reply)
        if icmp_pkt and icmp_pkt.type == 0:
            self._send_packet(event, of.OFPP_FLOOD)
            return
        self.blocked_count += 1
        log.warning(
            "BLOCKED | rule='%s' src=%s dst=%s proto=%s dport=%s | total=%d",
            rule["description"], src_ip, dst_ip, proto, dst_port, self.blocked_count
        )

        # Build the most specific valid match for OVS/OpenFlow 1.0
        # Key: nw_proto MUST be set before tp_dst; never set tp_dst without nw_proto
        match = of.ofp_match()
        match.dl_type = 0x0800  # IPv4
        match.nw_src  = IPAddr(src_ip)
        match.nw_dst  = IPAddr(dst_ip)

        if proto in PROTO_NUM:
            match.nw_proto = PROTO_NUM[proto]
            if dst_port and proto in ("tcp", "udp"):
                match.tp_dst = dst_port
        # proto=None → match all IP protocols (no nw_proto field set)
        # This correctly matches ICMP, TCP, UDP from src→dst

        msg          = of.ofp_flow_mod()
        msg.match    = match
        msg.priority = rule["priority"] + 100   # higher than any allow rule
        msg.idle_timeout = 120
        msg.hard_timeout = 300
        # empty actions = DROP
        self.connection.send(msg)

        # Drop the current packet too
        drop = of.ofp_packet_out()
        drop.buffer_id = event.ofp.buffer_id
        drop.in_port   = event.port
        self.connection.send(drop)

    def _allow(self, event, out_port):
        self.allowed_count += 1
        pkt = event.parsed

        if out_port != of.OFPP_FLOOD:
            msg = of.ofp_flow_mod()
            msg.match    = of.ofp_match.from_packet(pkt, event.port)
            msg.priority = 10
            msg.idle_timeout = 30
            msg.hard_timeout = 60
            msg.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(msg)

        self._send_packet(event, out_port)

    def _send_packet(self, event, out_port):
        msg = of.ofp_packet_out()
        msg.data    = event.ofp.data
        msg.in_port = event.port
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)


class SDNFirewallApp(object):

    def __init__(self):
        core.openflow.addListeners(self)
        log.info("=" * 55)
        log.info("SDN Firewall Controller (POX) started")
        log.info("Loaded %d firewall rules", len(FIREWALL_RULES))
        for r in FIREWALL_RULES:
            log.info("  [%s pri=%d] %s", r["action"].upper(), r["priority"], r["description"])
        log.info("=" * 55)

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected", dpid_to_str(event.dpid))
        FirewallSwitch(event.connection)


def launch():
    core.registerNew(SDNFirewallApp)
