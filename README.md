
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

##### Allowed traffic
```bash
h1 ping -c 3 h2
h4 ping -c 3 h1
h5 ping -c 3 h1
h6 ping -c 3 h4
```

##### Blocked traffic (IP rules)
```bash
h3 ping -c 3 h1
h6 ping -c 3 h3
```

##### Blocked traffic (TCP rule)
```bash
h2 curl http://10.0.0.1
```

##### Blocked traffic (UDP rule)
```bash
h3 iperf -u -c 10.0.0.2 -p 5001
```

##### Blocked traffic (MAC rule)
```bash
h5 ping -c 3 h2
```

### 4. Full Automated Test:

```bash
sudo python3 test_firewall.py
```

This test above runs all the above mentioned tests and much more to validate results. A screenshot of its output has been uploaded in the RESULTS section.

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
h1 (10.0.0.1) ─┐                              ┌─ h3 (10.0.0.3)
h2 (10.0.0.2) ─┤── [s1] ─── [s2/FW] ─── [s3] ─┤─ h4 (10.0.0.4)
h5 (10.0.0.5) ─┘                              └─ h6 (10.0.0.6)
```

s2 handles all the firewall blocking, while s1 and s3 are peripheral routers with all the ports
---

## Firewall Policy

| Rule | Type    | Source | Destination | Protocol | Port | Action |
|------|---------|--------|-------------|----------|------|--------|
| 1    | IP      | h3     | h1          | All      | -    | DROP   |
| 2    | IP      | h2     | h1          | TCP      | 80   | DROP   |
| 3    | IP      | h3     | h2          | UDP      | 5001 | DROP   |
| 4    | IP      | h6     | h3          | All      | -    | DROP   |
| 5    | MAC     | h5     | h2          | All      | -    | DROP   |
| 6    | Default | Any    | Any         | Any      | Any  | ALLOW  |

---

## Experimental Validation

### Blocked Traffic
- h3 → h1 ping ✘  
- h2 → h1 HTTP ✘  
- h3 → h2 UDP ✘  
- h6 → h3 IP ✘
- h5 → h2 MAC ✘

---

# RESULTS:

## 1. Topology.py Output:

Here is the output for topology.py

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/topology_output.png)

**Connection Table:**

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/Connection_Table.png)

Here, we can see that the blockage of pings sent is taking in a two way format instead of the one way format we expected from the Firewall Policy table above. This is infact a Feature and not a Bug with the code. This happens because a "Ping Illusion" is created due to one way blocking of returning response packages explained below:

Below is the reason why ping fails in both directions when we only block ```h3 -> h1```:

- **Test A (h3 ping h1):** Host 3 sends an ICMP Echo Request to Host 1. The firewall sees src=h3, dst=h1, matches your drop rule, and destroys the packet. **Result: Ping fails.**

- **Test B (h1 ping h3):** Host 1 sends an ICMP Echo Request to Host 3. The firewall sees src=h1, dst=h3. There is no rule blocking this, so the packet goes through. Host 3 receives it and generates an ICMP Echo Reply, sending it back to Host 1. However, this reply packet has src=h3, dst=h1. The firewall sees this, matches your drop rule, and destroys the reply packet. **Result: Ping fails.**

So essentially we can clearly see that in each of the cases, the Echo Reply Packets are getting destroyed by the middle s2 router and hence the connection is not going through even though the router blocks only one way traffic. If s1 and s3 were connected directly or through ghost routers, then we would see ```h1 -> h3``` packets being acknowledged in the Connection Table image above since there is no middle router blocking the packet as the very first router that receives the packet from s3 is the destination router s1 itself.

Similar logic applies to the other blocked traffic.


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
h4 ping -c 3 h1
h5 ping -c 3 h1
h6 ping -c 3 h4
```
The above commands should go through completely fine

The 5 commands below will be blocked:

```bash
h3 ping -c 3 h1
h6 ping -c 3 h3
```

```bash
h2 curl http://10.0.0.1

h3 iperf -u -c 10.0.0.2 -p 5001

h5 ping -c 3 h2
```

This flow table shows which traffic is blocked:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/flowtable.png)
This screenshot gives us the flow table dump for the project and proves that the project is completely working.

```
priority=130, icmp, nw_src=10.0.0.3, nw_dst=10.0.0.1 actions=drop 
----------> h3 can't ping h1
priority=128,ip,nw_src=10.0.0.6,nw_dst=10.0.0.3 actions=drop
priority=125, tcp, nw_src=10.0.0.2, nw_dst=10.0.0.1, tp_dst=80 actions=drop  
-------> TCP from h2 is blocked -> firewall working correctly
priority=125, udp, nw_src=10.0.0.3, nw_dst=10.0.0.2, tp_dst=5001 actions=drop
-------> UDP from h3 is blocked -> firewall working correctly
priority=135,dl_src=00:00:00:00:00:05,dl_dst=00:00:00:00:00:02 actions=drop
-------> MAC address correctly blocked
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
Sender s1:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/icmpblockwireshark.png)
Sender keeps sending ICMP messages but gets no responce
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/icmpblocks2.png)
S2 receives messages from s1 but never forwards it to s3
Receiver s3:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/icmpblocks3.png)
Receiver keeps sending ICMP Echo packets but gets no acknowledgement from s1

Source keeps sending ICMP messages and gets no response.
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

- MAC Addres Blocked: no response messages
**Command Run**
Router s1 sends Ping requests but gets no replies:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/macblocks1.png)

Router s2 doesnt even process the ICMP replies this time due to MAC address blocking:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/macblocks2.png)

Router s3 doesn't receive any Ping request package so no need for it to send Echo Package:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/macblocks3.png)


## Automated Testing:
### 1. Allowed vs blocked:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/testa.png)



### 2. Normal vs failure:
![Could not display image, please download/check Output_Images Directory properly](/Output_Images/testb_1.png)

![Could not display image, please download/check Output_Images Directory properly](/Output_Images/testb_2.png)



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

