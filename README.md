
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

## 1. Topology.py Output:

Here is the output for topology.py

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/topology_output.png)

This shows us how all connections except h3 -> h1 are working since the firewall blocks that connection:

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/Connection_Table.png)

As visible here, only h3 -> h1 has a "X" mark indicating connection failure and the rest are working.
This result is correct and shows that the firewall is working properly.


## Performance Analysis

Checking Ping Latency by creating a new h4 node in the network and checking its connection from h1:

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/latency.png)

Latency Check results:

- Ping latency ≈ 29.7 ms  
- TCP throughput ≈ 7.81 Mbits/sec  
- UDP packets transmitted but not acknowledged  

---

## Flow Table Analysis

For the set of commands on mininet CLI:

```bash
h1 ping -c 3 h2
h3 ping -c 3 h1
h2 curl http://10.0.0.1
h3 iperf -u -c 10.0.0.2 -p 5001
```

This flow table shows which traffic is blocked:

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/flowtable.png)

```
priority=130, icmp, nw_src=10.0.0.3, nw_dst=10.0.0.1 actions=drop 
----------> h3 can't ping h1
priority=125, tcp, nw_src=10.0.0.2, nw_dst=10.0.0.1, tp_dst=80 actions=drop  
-------> TCP from h2 is blocked -> firewall working correctly
priority=125, udp, nw_src=10.0.0.3, nw_dst=10.0.0.2, tp_dst=5001 actions=drop
-------> UDP from h3 is blocked -> firewall working correctly
```

---

## Packet-Level Analysis (Wireshark)

- ICMP allowed: request + reply  

**Command Ran:**

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/h1command.png)

**Wireshark Output:**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/h1wireshark.png)


- ICMP blocked: no reply (h3 -> h1 icmp blocked)


**Command Ran:**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/icmpblockcmd.png)

**Wireshark Output**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/icmpblockwireshark.png)

Source keeps sending ARP messages and gets wrong/garbled location of h1 as an ARP reply from h3.
This indicates firewall is blocking the connection properly.


- TCP blocked: SYN retransmissions 


**Command Ran:**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/tcpblockcmd.png)

Command request gets no reply and closes connection upon timeout.

**Wireshark Output**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/tcpblockwireshark.png)

Repeatedly Retransmitted SYN messages from the source but none of these packets reach the destination.
This indicates firewall is blocking the TCP connection properly.


- UDP blocked: no response  


**Command Ran:**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/udpblockcmd.png)


**Wireshark Output**
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/udpblockwireshark.png)

---

## Automated Testing:
### 1. Allowed vs blocked:

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/testa.png)



### 2. Normal vs failure:

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/testb.png)

#### Test Results:

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/testresults.png)

## System Behavior

- First packet → controller (PacketIn)  
- Controller installs flow rules  
- Subsequent packets handled by switch  

---

## Conclusion

The SDN firewall successfully demonstrates:
- Selective traffic filtering  
- Efficient switch-level forwarding  
- Effecting tracking of connection requests and replies through POX
- Both test scenarios tested and passed.

