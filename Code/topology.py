#!/usr/bin/env python3
"""
Mininet Topology for SDN Firewall Project
Creates: 4 hosts + 1 switch + Ryu remote controller

Topology:
         h1 (10.0.0.1)
         |
h2 ── [ s1 ] ── h3
         |
         h4 (10.0.0.4)

Run with:
    sudo python3 topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def build_topology():
    setLogLevel("info")

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    info("*** Adding controller (Ryu running on localhost:6633)\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow10")

    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")

    info("*** Adding links (10 Mbps, 5 ms delay)\n")
    net.addLink(h1, s1, bw=10, delay="5ms")
    net.addLink(h2, s1, bw=10, delay="5ms")
    net.addLink(h3, s1, bw=10, delay="5ms")
    net.addLink(h4, s1, bw=10, delay="5ms")

    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])

    info("\n" + "=" * 60 + "\n")
    info("Network ready. Firewall rules active:\n")
    info("  BLOCKED: h3 (10.0.0.3) → h1 (10.0.0.1)  [all traffic]\n")
    info("  BLOCKED: h2 → h1, TCP port 80 (HTTP)\n")
    info("  BLOCKED: h3 → h2, UDP port 5001 (iperf)\n")
    info("  ALLOWED: everything else\n")
    info("=" * 60 + "\n")
    info("Run tests with: test_firewall.py OR manually via CLI\n")
    info("=" * 60 + "\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    build_topology()
