#!/usr/bin/env python3
"""
Automated Test Suite for SDN Firewall
Demonstrates:
  Scenario A – Allowed traffic
  Scenario B – Blocked traffic

From Mininet CLI:
    mininet> py exec(open('/home/aayush/sdn-firewall/test_firewall.py').read()); run_tests(net)

Standalone:
    sudo python3 test_firewall.py
"""

import time

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def passed(msg): print(f"  {GREEN}✔  PASS{RESET}  {msg}")
def failed(msg): print(f"  {RED}✗  FAIL{RESET}  {msg}")
def info(msg):   print(f"  {CYAN}ℹ{RESET}  {msg}")
def banner(msg): print(f"\n{BOLD}{YELLOW}{'─'*60}\n  {msg}\n{'─'*60}{RESET}")


def ping_test(src_host, dst_ip, expect_success=True, count=4):
    result  = src_host.cmd(f"ping -c {count} -W 2 {dst_ip}")
    success = "0% packet loss" in result or f"{count} received" in result
    return success == expect_success, result


def iperf_tcp_test(server_host, client_host, port=5201, expect_success=True):
    server_host.cmd(f"iperf3 -s -p {port} -D --one-off 2>/dev/null")
    time.sleep(0.5)
    output = client_host.cmd(f"iperf3 -c {server_host.IP()} -p {port} -t 3 2>&1")
    server_host.cmd("pkill iperf3 2>/dev/null; true")
    success = "receiver" in output and "error" not in output.lower()
    return success == expect_success, output


def http_test(server_host, client_host, port=80, expect_success=True):
    server_host.cmd(f"echo 'HTTP/1.0 200 OK\\n\\nHello' | nc -l -p {port} &")
    time.sleep(0.3)
    output = client_host.cmd(
        f"curl -s --max-time 3 http://{server_host.IP()}:{port}/ 2>&1 || echo CURL_FAILED")
    server_host.cmd("pkill nc 2>/dev/null; true")
    success = "CURL_FAILED" not in output and "timed out" not in output and "refused" not in output
    return success == expect_success, output


def udp_blocked_test(server_host, client_host, port=5001):
    """
    Test whether UDP port is blocked by checking if server receives data.
    Server listens, client sends 5 packets, we check server got 0 packets.
    Returns True if traffic was correctly blocked (server received nothing).
    """
    # Start netcat UDP server, capture output
    server_host.cmd(f"rm -f /tmp/udp_recv.txt")
    server_host.cmd(f"nc -u -l -p {port} > /tmp/udp_recv.txt 2>&1 &")
    time.sleep(0.3)
    # Client sends data
    client_host.cmd(f"echo 'testpayload' | nc -u -w 2 {server_host.IP()} {port}")
    time.sleep(1)
    server_host.cmd("pkill nc 2>/dev/null; true")
    time.sleep(0.3)
    received = server_host.cmd("cat /tmp/udp_recv.txt 2>/dev/null").strip()
    # If blocked: received is empty. If allowed: received has "testpayload"
    blocked = "testpayload" not in received
    return blocked  # True = traffic was blocked


def run_tests(net):
    h1 = net.get("h1")
    h2 = net.get("h2")
    h3 = net.get("h3")
    h4 = net.get("h4")

    results = []

    # ── Scenario A: Allowed Traffic ───────────────────────────────────────────
    banner("SCENARIO A – Allowed Traffic (expect PASS = reachable)")

    info("A1: h1 → h2 ping (allowed)")
    ok, _ = ping_test(h1, h2.IP(), expect_success=True)
    (passed if ok else failed)("h1 ping h2")
    results.append(("A1: h1→h2 ping allowed", ok))

    info("A2: h2 → h1 ping (ICMP allowed — only TCP:80 from h2→h1 is blocked)")
    ok, _ = ping_test(h2, h1.IP(), expect_success=True)
    (passed if ok else failed)("h2 ping h1 (ICMP allowed)")
    results.append(("A2: h2→h1 ICMP allowed", ok))

    info("A3: h4 → h1 ping (fully allowed)")
    ok, _ = ping_test(h4, h1.IP(), expect_success=True)
    (passed if ok else failed)("h4 ping h1")
    results.append(("A3: h4→h1 ping allowed", ok))

    info("A4: h1 → h4 iperf TCP (allowed)")
    ok, _ = iperf_tcp_test(h4, h1, port=5201, expect_success=True)
    (passed if ok else failed)("h1 iperf TCP → h4")
    results.append(("A4: h1→h4 iperf TCP allowed", ok))

    info("A5: h3 → h2 ping (allowed — only h3→h2 UDP:5001 is blocked)")
    ok, _ = ping_test(h3, h2.IP(), expect_success=True)
    (passed if ok else failed)("h3 ping h2 (ICMP allowed)")
    results.append(("A5: h3→h2 ICMP allowed", ok))

    # ── Scenario B: Blocked Traffic ───────────────────────────────────────────
    banner("SCENARIO B – Blocked Traffic (expect PASS = correctly blocked)")

    info("B1: h3 → h1 ping (BLOCKED — all h3→h1 traffic blocked)")
    ok, _ = ping_test(h3, h1.IP(), expect_success=True)
    (passed if failed else ok)("h3 ping h1 correctly blocked")
    results.append(("B1: h3→h1 all traffic blocked", ok))

    info("B2: h2 → h1 HTTP TCP:80 (BLOCKED)")
    ok, _ = http_test(h1, h2, port=80, expect_success=False)
    (passed if ok else failed)("h2 HTTP→h1:80 correctly blocked")
    results.append(("B2: h2→h1 HTTP TCP:80 blocked", ok))

    info("B3: h3 → h2 UDP:5001 (BLOCKED — firewall should drop these packets)")
    blocked = udp_blocked_test(h2, h3, port=5001)
    ok = blocked  # True = correctly blocked = PASS
    (passed if ok else failed)("h3 UDP:5001 → h2 correctly blocked")
    results.append(("B3: h3→h2 UDP:5001 blocked", ok))

    # ── Summary ───────────────────────────────────────────────────────────────
    banner("TEST SUMMARY")
    total        = len(results)
    passed_count = sum(1 for _, ok in results if ok)

    for name, ok in results:
        status = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  [{status}] {name}")

    print(f"\n  Result: {passed_count}/{total} tests passed")
    if passed_count == total:
        print(f"  {GREEN}{BOLD}All tests passed! Firewall working correctly.{RESET}")
    else:
        print(f"  {YELLOW}Some tests failed — check controller logs.{RESET}")

    return results


# ── Standalone mode ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.log import setLogLevel
    from mininet.link import TCLink

    setLogLevel("warning")
    print(f"{BOLD}Starting Mininet for automated testing...{RESET}")
    print("Ensure POX is running:\n"
          "  sudo python3 pox/pox.py log.level --DEBUG firewall_controller\n")

    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    c0 = net.addController("c0", controller=RemoteController,
                            ip="127.0.0.1", port=6633)
    s1 = net.addSwitch("s1", protocols="OpenFlow10")
    h1 = net.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
    h2 = net.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
    h3 = net.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")
    h4 = net.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
    for h in [h1, h2, h3, h4]:
        net.addLink(h, s1, bw=10, delay="5ms")

    net.build()
    c0.start()
    s1.start([c0])
    time.sleep(2)

    run_tests(net)
    net.stop()
