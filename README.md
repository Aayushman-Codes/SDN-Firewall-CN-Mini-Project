
# SDN-Based Firewall using POX Controller and Mininet

## Index
- [Problem Statement](#problem-statement)
- [Setup / Execution Steps](#setup--execution-steps)
- [Expected Output](#expected-output)
- [Network Topology](#network-topology)
- [Firewall Policy](#firewall-policy)
- [Experimental Validation](#experimental-validation)
- [RESULTS](#RESULTS)
- [Performance Analysis](#performance-analysis)
- [Flow Table Analysis](#flow-table-analysis)
- [Packet-Level Analysis](#packet-level-analysis-wireshark)
- [System Behavior](#system-behavior)
- [Conclusion](#conclusion)

---

## Problem Statement
Design and implement an SDN-based firewall using Mininet and a POX controller.  

---
This project implements a Software-Defined Networking (SDN) firewall using the POX controller and Mininet. The goal is to demonstrate firrwall-based flow rule installation, traffic filtering, and controller-switch interaction using OpenFlow.

---

## Setup / Execution Steps

### Setup & Execution

### Prerequisites

Ubuntu 24.04 VM with internet access.

### 1. Clone the repository

```bash
git clone https://github.com/Aayushman-Codes/sdn-firewall.git
cd sdn-firewall
chmod +x run.sh
```

### 1.1 Prepare a Virtual Environment

Inside your project folder, do this:

On windows:
```bash
sudo python3 -m venv venv
```
Move all the files inside the root directory of your project directory. The venv directory should also be present in the root directory itself.

Execute all the following code inside the Virtual Environment.
To activate the Virtual Environment:

If on powershell:
```bash
.\venv\Scripts\Activate.ps1
```

On Terminal"
```bash
.\venv\Scripts\Activate
```

### 2. Install dependencies

```bash
./run.sh install
```

This installs: `mininet`, `openvswitch-switch`, `ryu`, `iperf3`, `tshark`, `curl`, `netcat`.

### 3. Clean any previous Mininet state

```bash
./run.sh cleanup
```

### 4. Start the Ryu controller (Terminal 1)

```bash
./run.sh controller
```
Logs appear in ryu.log and blocked_packets.log


### 5. Start the Mininet topology (Terminal 2)

```bash
./run.sh topology
```
Opens the Mininet CLI (mininet>)



---

### 1. Start Controller
```bash
sudo python3 pox/pox.py log.level --DEBUG firewall_controller
```

### 2. Start Mininet
```bash
sudo python3 topology.py
```


### 3. Run Tests (Optional)

#### 3.1 Automatic Test


Run these inside the mininet> Command Line Interface:

```bash
pingall
```

This does an automatic test and shows which traffic is blocked by the switch and which is allowed.

#### 3.2 Manual Test

```bash
h1 ping -c 3 h2
h3 ping -c 3 h1
h2 curl http://10.0.0.1
h3 iperf -u -c 10.0.0.2 -p 5001
```

Run these with Wireshwark open in the background to test Results

---

## Expected Output

- Allowed traffic (e.g., h1 → h2) should succeed  
- Blocked traffic (e.g., h3 → h1) should fail  
- Flow table should contain `actions=drop` rules  
- Wireshark should show:
  - ICMP replies for allowed traffic  
  - TCP retransmissions for blocked connections  
  - UDP packets without response  

---

## Network Topology

```
          h1 (10.0.0.1)
           |
h2 ──── [s1/OVS] ──── h3
           |
          h4 (10.0.0.4)
```

---

## Firewall Policy

| Rule | Source | Destination | Protocol | Port | Action |
|------|--------|-------------|----------|------|--------|
| 1    | h3     | h1          | All      | -    | DROP   |
| 2    | h2     | h1          | TCP      | 80   | DROP   |
| 3    | h3     | h2          | UDP      | 5001 | DROP   |
| 4    | Any    | Any         | Any      | Any  | ALLOW  |

---

## Experimental Validation

### Allowed Traffic
- h1 → h2 ping ✔  
- h4 → h1 ping ✔  
- h1 → h4 TCP ✔  

### Blocked Traffic
- h3 → h1 ping ✘  
- h2 → h1 HTTP ✘  
- h3 → h2 UDP ✘  

---

# RESULTS:

## Performance Analysis

- Ping latency ≈ 29.7 ms  
- TCP throughput ≈ 7.81 Mbits/sec  
- UDP packets transmitted but not acknowledged  

---

## Flow Table Analysis

This flow table shows which traffic is blocked

```
priority=130, icmp, nw_src=10.0.0.3, nw_dst=10.0.0.1 actions=drop
priority=125, tcp, nw_src=10.0.0.2, nw_dst=10.0.0.1, tp_dst=80 actions=drop
priority=125, udp, nw_src=10.0.0.3, nw_dst=10.0.0.2, tp_dst=5001 actions=drop
```

---

## Packet-Level Analysis (Wireshark)

- ICMP allowed: request + reply  
- ICMP blocked: no reply  
- TCP blocked: SYN retransmissions  
- UDP blocked: no response  

---

## System Behavior

- First packet → controller (PacketIn)  
- Controller installs flow rules  
- Subsequent packets handled by switch  

---

## Conclusion

The SDN firewall successfully demonstrates:
- Dynamic rule installation  
- Selective traffic filtering  
- Efficient switch-level forwarding  

