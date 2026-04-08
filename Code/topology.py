#!/usr/bin/env python3
"""
Mininet Topology for SDN Firewall Project

Topology:
  h1 (10.0.0.1) ─┐                          ┌─ h3 (10.0.0.3)
  h2 (10.0.0.2) ─┤─ [s1] ─── [s2/FW] ─── [s3] ─┤─ h4 (10.0.0.4)
  h5 (10.0.0.5) ─┘                          └─ h6 (10.0.0.6)

  s2 is the firewall switch (all rules enforced here).
  s1 and s3 are edge switches (plain forwarding).

Run with:
    sudo python3 topology.py
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def build_topology():
    """Create, start, and expose the 3-switch test topology in Mininet CLI."""
    # Show Mininet logs in terminal for easier debugging.
    setLogLevel("info")

    # Build Mininet with a remote controller and Open vSwitch kernel switches.
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False   # Keep deterministic MACs (set manually below).
    )

    # Controller is expected to be POX listening on localhost:6633.
    info("*** Adding controller (POX on localhost:6633)\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6633
    )

    info("*** Adding switches\n")
    # s2 is the middle firewall switch in this topology.
    s1 = net.addSwitch("s1", protocols="OpenFlow10")   # left edge
    s2 = net.addSwitch("s2", protocols="OpenFlow10")   # firewall (middle)
    s3 = net.addSwitch("s3", protocols="OpenFlow10")   # right edge

    info("*** Adding hosts\n")
    # Left side hosts (attached to s1).
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")

    # Right side hosts (attached to s3).
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")

    info("*** Adding links (10 Mbps, 5 ms delay)\n")
    # Access links: hosts -> edge switches.
    net.addLink(h1, s1, bw=10, delay="5ms")
    net.addLink(h2, s1, bw=10, delay="5ms")
    net.addLink(h5, s1, bw=10, delay="5ms")

    net.addLink(h3, s3, bw=10, delay="5ms")
    net.addLink(h4, s3, bw=10, delay="5ms")
    net.addLink(h6, s3, bw=10, delay="5ms")

    # Backbone links between switches.
    net.addLink(s1, s2, bw=10, delay="2ms")
    net.addLink(s2, s3, bw=10, delay="2ms")

    # Build topology objects and start controller/switches.
    info("*** Starting network\n")
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])

    # Print a quick runbook-style summary for users in CLI.
    info("\n" + "=" * 60 + "\n")
    info("Network ready.\n")
    info("Topology:  h1,h2,h5 --- [s1] --- [s2/FW] --- [s3] --- h3,h4,h6\n")
    info("\nFirewall rules active on s2:\n")
    info("  BLOCKED: h3  (10.0.0.3)          → h1  [all traffic]\n")
    info("  BLOCKED: h2  (10.0.0.2)          → h1  [TCP port 80]\n")
    info("  BLOCKED: h3  (10.0.0.3)          → h2  [UDP port 5001]\n")
    info("  BLOCKED: h5  (MAC 00:00:00:00:00:05) → h2 [MAC-based block]\n")
    info("  BLOCKED: h6  (IP  10.0.0.6)      → h3  [IP-based block]\n")
    info("  ALLOWED: everything else\n")
    info("=" * 60 + "\n")

    # Hand over control to interactive Mininet shell.
    CLI(net)

    # Cleanup when user exits CLI.
    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    # Script entrypoint for standalone execution.
    build_topology()