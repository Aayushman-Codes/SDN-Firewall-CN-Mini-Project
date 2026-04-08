#!/usr/bin/env python3
"""
Automated Test Suite for SDN Firewall — 3-switch topology
Demonstrates:
  Scenario A – Allowed vs Blocked (firewall rule enforcement)
  Scenario B – Normal vs Failure (direct command execution)

From Mininet CLI:
    mininet> py exec(open('/home/aayush/sdn-firewall/test_firewall2.py').read()); run_tests(net)

Standalone:
    sudo python3 test_firewall2.py
"""

import time

# ANSI color/style codes for readable terminal output.
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# Small output helpers used across test scenarios.
def passed(msg): print(f"  {GREEN}✔  PASS{RESET}  {msg}")
def failed(msg): print(f"  {RED}✗  FAIL{RESET}  {msg}")
def info(msg):   print(f"  {CYAN}ℹ{RESET}  {msg}")
def banner(msg): print(f"\n{BOLD}{YELLOW}{'─'*60}\n  {msg}\n{'─'*60}{RESET}")


def ping_test(src_host, dst_ip, expect_success=True, count=3):
    """Run ICMP ping and return (test_passed, raw_output)."""
    result  = src_host.cmd(f"ping -c {count} -W 2 {dst_ip}")
    success = " 0% packet loss" in result or f"{count} received" in result
    return success == expect_success, result


def iperf_tcp_test(server_host, client_host, port=5201, expect_success=True):
    """Run a short TCP iperf3 client/server check and validate expected result."""
    server_host.cmd(f"iperf3 -s -p {port} -D --one-off 2>/dev/null")
    time.sleep(0.5)
    output = client_host.cmd(f"iperf3 -c {server_host.IP()} -p {port} -t 3 2>&1")
    server_host.cmd("pkill iperf3 2>/dev/null; true")
    success = "receiver" in output and "error" not in output.lower()
    return success == expect_success, output


def http_test(server_host, client_host, port=80, expect_success=True):
    """Start a temporary netcat HTTP responder and test access via curl."""
    server_host.cmd(f"echo 'HTTP/1.0 200 OK\\n\\nHello' | nc -l -p {port} &")
    time.sleep(0.3)
    output = client_host.cmd(
        f"curl -s --max-time 3 http://{server_host.IP()}:{port}/ 2>&1 || echo CURL_FAILED")
    server_host.cmd("pkill nc 2>/dev/null; true")
    success = "CURL_FAILED" not in output and "timed out" not in output and "refused" not in output
    return success == expect_success, output


def udp_blocked_test(server_host, client_host, port=5001):
    """Send UDP payload and verify it was not received (True means blocked)."""
    server_host.cmd("rm -f /tmp/udp_recv.txt")
    server_host.cmd(f"nc -u -l -p {port} > /tmp/udp_recv.txt 2>&1 &")
    time.sleep(0.3)
    client_host.cmd(f"echo 'testpayload' | nc -u -w 2 {server_host.IP()} {port}")
    time.sleep(1)
    server_host.cmd("pkill nc 2>/dev/null; true")
    time.sleep(0.3)
    received = server_host.cmd("cat /tmp/udp_recv.txt 2>/dev/null").strip()
    return "testpayload" not in received   # True = blocked


def run_tests(net):
    """Execute all firewall validation checks and print a grouped summary."""
    # Resolve host handles once for cleaner test steps below.
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h4 = net.get("h4")
    h5 = net.get("h5")
    h6 = net.get("h6")

    # Each entry: (test_name, bool_passed)
    results = []

    # ══════════════════════════════════════════════════════════════
    # SCENARIO A – Allowed vs Blocked
    # ══════════════════════════════════════════════════════════════
    banner("SCENARIO A – Allowed vs Blocked (Firewall Rule Enforcement on s2)")

    print(f"\n  {BOLD}--- Allowed Traffic ---{RESET}\n")

    info("A1: h1 → h2 ping  (allowed — no rule blocks this)")
    ok, _ = ping_test(h1, h2.IP(), expect_success=True)
    (passed if ok else failed)("h1 → h2 reachable")
    results.append(("A1: h1→h2 ping allowed", ok))

    info("A2: h2 → h1 ping  (ICMP allowed — only TCP:80 from h2→h1 is blocked)")
    ok, _ = ping_test(h2, h1.IP(), expect_success=True)
    (passed if ok else failed)("h2 → h1 ICMP reachable")
    results.append(("A2: h2→h1 ICMP allowed", ok))

    info("A3: h4 → h1 ping  (fully allowed)")
    ok, _ = ping_test(h4, h1.IP(), expect_success=True)
    (passed if ok else failed)("h4 → h1 reachable")
    results.append(("A3: h4→h1 ping allowed", ok))

    info("A4: h1 → h4 iperf TCP  (allowed)")
    ok, _ = iperf_tcp_test(h4, h1, port=5201, expect_success=True)
    (passed if ok else failed)("h1 iperf TCP → h4")
    results.append(("A4: h1→h4 iperf TCP allowed", ok))

    info("A5: h3 → h2 ping  (ICMP allowed — only UDP:5001 from h3→h2 blocked)")
    ok, _ = ping_test(h3, h2.IP(), expect_success=True)
    (passed if ok else failed)("h3 → h2 ICMP reachable")
    results.append(("A5: h3→h2 ICMP allowed", ok))

    info("A6: h6 → h4 ping  (allowed — rule only blocks h6→h3)")
    ok, _ = ping_test(h6, h4.IP(), expect_success=True)
    (passed if ok else failed)("h6 → h4 reachable")
    results.append(("A6: h6→h4 ping allowed", ok))

    print(f"\n  {BOLD}--- Blocked Traffic ---{RESET}\n")

    info("A7: h3 → h1 ping  (BLOCKED — IP rule: all h3→h1 traffic dropped)")
    ok, _ = ping_test(h3, h1.IP(), expect_success=False)
    (passed if ok else failed)("h3 → h1 correctly blocked (IP rule)")
    results.append(("A7: h3→h1 blocked [IP rule]", ok))

    info("A8: h2 → h1 HTTP TCP:80  (BLOCKED — IP rule: TCP:80 from h2→h1 dropped)")
    ok, _ = http_test(h1, h2, port=80, expect_success=False)
    (passed if ok else failed)("h2 HTTP→h1:80 correctly blocked (IP rule)")
    results.append(("A8: h2→h1 HTTP:80 blocked [IP rule]", ok))

    info("A9: h3 → h2 UDP:5001  (BLOCKED — IP rule: UDP:5001 from h3→h2 dropped)")
    ok = udp_blocked_test(h2, h3, port=5001)
    (passed if ok else failed)("h3 UDP:5001→h2 correctly blocked (IP rule)")
    results.append(("A9: h3→h2 UDP:5001 blocked [IP rule]", ok))

    info("A10: h5 → h2 ping  (BLOCKED — MAC rule: src MAC 00:00:00:00:00:05 → h2 blocked)")
    ok, _ = ping_test(h5, h2.IP(), expect_success=False)
    (passed if ok else failed)("h5 → h2 correctly blocked (MAC rule)")
    results.append(("A10: h5→h2 blocked [MAC rule]", ok))

    info("A11: h6 → h3 ping  (BLOCKED — IP rule: src IP 10.0.0.6 → h3 blocked)")
    ok, _ = ping_test(h6, h3.IP(), expect_success=False)
    (passed if ok else failed)("h6 → h3 correctly blocked (IP rule)")
    results.append(("A11: h6→h3 blocked [IP rule]", ok))

    # ══════════════════════════════════════════════════════════════
    # SCENARIO B – Normal vs Failure (exact commands)
    # ══════════════════════════════════════════════════════════════
    banner("SCENARIO B – Normal vs Failure (Direct Command Execution)")

    print(f"\n  {BOLD}--- Normal Traffic (should reach destination) ---{RESET}\n")

    info("B1 [NORMAL]: h1 ping -c 3 h2")
    output = h1.cmd("ping -c 3 -W 2 " + h2.IP())
    ok = "0% packet loss" in output or "3 received" in output
    print(f"  Command: h1 ping -c 3 {h2.IP()}")
    print(f"  Result:  {'Reachable ✔' if ok else 'Unreachable ✗'}")
    (passed if ok else failed)("h1 → h2 reachable (normal)")
    results.append(("B1: h1 ping h2 [normal]", ok))

    print()
    info("B2 [NORMAL]: h3 ping -c 3 h2")
    output = h3.cmd("ping -c 3 -W 2 " + h2.IP())
    ok = "0% packet loss" in output or "3 received" in output
    print(f"  Command: h3 ping -c 3 {h2.IP()}")
    print(f"  Result:  {'Reachable ✔' if ok else 'Unreachable ✗'}")
    (passed if ok else failed)("h3 → h2 reachable (normal — ICMP allowed)")
    results.append(("B2: h3 ping h2 [normal]", ok))

    print(f"\n  {BOLD}--- Failure Traffic (should be blocked by firewall on s2) ---{RESET}\n")

    info("B3 [FAILURE]: h3 ping -c 3 h1")
    output = h3.cmd("ping -c 3 -W 2 " + h1.IP())
    blocked = "100% packet loss" in output or "0 received" in output
    ok = blocked
    print(f"  Command: h3 ping -c 3 {h1.IP()}")
    print(f"  Result:  {'Blocked ✔ (s2 IP drop rule: h3→h1)' if blocked else 'Reachable ✗ (should be blocked)'}")
    (passed if ok else failed)("h3 → h1 correctly blocked by s2")
    results.append(("B3: h3 ping h1 [failure/IP block]", ok))

    print()
    info("B4 [FAILURE]: h2 curl http://10.0.0.1")
    h1.cmd("echo 'HTTP/1.0 200 OK\n\nHello' | nc -l -p 80 &")
    time.sleep(0.3)
    output = h2.cmd("curl -s --max-time 3 http://10.0.0.1/ 2>&1 || echo CURL_FAILED")
    h1.cmd("pkill nc 2>/dev/null; true")
    blocked = "CURL_FAILED" in output or "timed out" in output or "refused" in output
    ok = blocked
    print(f"  Command: h2 curl http://10.0.0.1")
    print(f"  Result:  {'Blocked ✔ (s2 IP drop rule: TCP:80 h2→h1)' if blocked else 'Connected ✗ (should be blocked)'}")
    (passed if ok else failed)("h2 HTTP:80 → h1 correctly blocked by s2")
    results.append(("B4: h2 curl h1:80 [failure/IP block]", ok))

    print()
    info("B5 [FAILURE]: h3 iperf -u -c 10.0.0.2 -p 5001")
    h2.cmd("rm -f /tmp/udp_recv.txt")
    h2.cmd("nc -u -l -p 5001 > /tmp/udp_recv.txt 2>&1 &")
    time.sleep(0.3)
    h3.cmd("echo 'testpayload' | nc -u -w 2 10.0.0.2 5001")
    time.sleep(1)
    h2.cmd("pkill nc 2>/dev/null; true")
    time.sleep(0.3)
    received = h2.cmd("cat /tmp/udp_recv.txt 2>/dev/null").strip()
    blocked = "testpayload" not in received
    ok = blocked
    print(f"  Command: h3 iperf -u -c 10.0.0.2 -p 5001")
    print(f"  Result:  {'Blocked ✔ (s2 IP drop rule: UDP:5001 h3→h2)' if blocked else 'Delivered ✗ (should be blocked)'}")
    (passed if ok else failed)("h3 UDP:5001 → h2 correctly blocked by s2")
    results.append(("B5: h3 iperf UDP h2 [failure/IP block]", ok))

    print()
    info("B6 [FAILURE]: h5 ping -c 3 h2  (MAC-based block)")
    output = h5.cmd("ping -c 3 -W 2 " + h2.IP())
    blocked = "100% packet loss" in output or "0 received" in output
    ok = blocked
    print(f"  Command: h5 ping -c 3 {h2.IP()}")
    print(f"  Result:  {'Blocked ✔ (s2 MAC drop rule: 00:00:00:00:00:05→h2)' if blocked else 'Reachable ✗ (should be blocked)'}")
    (passed if ok else failed)("h5 → h2 correctly blocked by s2 (MAC rule)")
    results.append(("B6: h5 ping h2 [failure/MAC block]", ok))

    print()
    info("B7 [FAILURE]: h6 ping -c 3 h3  (IP-based block)")
    output = h6.cmd("ping -c 3 -W 2 " + h3.IP())
    blocked = "100% packet loss" in output or "0 received" in output
    ok = blocked
    print(f"  Command: h6 ping -c 3 {h3.IP()}")
    print(f"  Result:  {'Blocked ✔ (s2 IP drop rule: 10.0.0.6→h3)' if blocked else 'Reachable ✗ (should be blocked)'}")
    (passed if ok else failed)("h6 → h3 correctly blocked by s2 (IP rule)")
    results.append(("B7: h6 ping h3 [failure/IP block]", ok))

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("TEST SUMMARY")
    passed_count = sum(1 for _, ok in results if ok)
    total        = len(results)

    print(f"  {BOLD}Scenario A – Allowed vs Blocked:{RESET}")
    for name, ok in results[:11]:
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"    [{status}] {name}")

    print(f"\n  {BOLD}Scenario B – Normal vs Failure:{RESET}")
    for name, ok in results[11:]:
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"    [{status}] {name}")

    print(f"\n  Overall: {passed_count}/{total} tests passed")
    if passed_count == total:
        print(f"  {GREEN}{BOLD}All tests passed! Firewall working correctly.{RESET}")
    else:
        print(f"  {YELLOW}Some tests failed — check controller logs.{RESET}")

    return results


# ── Standalone mode ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Local imports keep standalone-only dependencies isolated from Mininet CLI mode.
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.log import setLogLevel
    from mininet.link import TCLink

    setLogLevel("warning")
    print(f"{BOLD}Starting Mininet for automated testing...{RESET}")
    print("Ensure POX is running:\n"
          "  sudo python3 pox/pox.py log.level --DEBUG firewall_controller\n")

    # Build topology programmatically to run tests without manual CLI setup.
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False
    )
    c0 = net.addController("c0", controller=RemoteController,
                            ip="127.0.0.1", port=6633)

    s1 = net.addSwitch("s1", protocols="OpenFlow10")
    s2 = net.addSwitch("s2", protocols="OpenFlow10")
    s3 = net.addSwitch("s3", protocols="OpenFlow10")

    # Hosts use fixed IP/MAC addresses to align with firewall rules.
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h5 = net.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    h6 = net.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")

    # Topology:
    #  h1,h2,h5 -- s1 -- s2 -- s3 -- h3,h4,h6
    net.addLink(h1, s1); net.addLink(h2, s1); net.addLink(h5, s1)
    net.addLink(h3, s3); net.addLink(h4, s3); net.addLink(h6, s3)
    net.addLink(s1, s2); net.addLink(s2, s3)

    # Start network and switches.
    net.build()
    c0.start()
    s1.start([c0]); s2.start([c0]); s3.start([c0])
    time.sleep(2)

    # Run test suite, then cleanly stop Mininet.
    run_tests(net)
    net.stop()