# CLI-based Network Traffic Monitoring & Analysis Tool
Main Repository for 4th Semester, 2nd Mini Project on Computer Networks (UE23CS252B) for a CLI-based Network Traffic Analysis, Monitoring &amp; Security Tool

## Team Members
Class & Section: Semester 4th, 'A' Section, B.Tech. Computer Science Engineering
1. Aania George (SRN: PES1UG23CS007)
2. Akhilesh Anil (SRN: PES1UG23CS045)

## Summary of Project
A comprehensive CLI-based Network Analysis, Monitoring & Security Toolkit built using Python Raw Sockets to offer low-level access and deep inspection of network traffic. It includes packet sniffing, connection monitoring, performance measurement, threat detection, and geographical analysis — all without relying on external libraries like Scapy or Wireshark.

## Features 
### 1. Raw Packet Sniffing
Captures and parses live network traffic at the Ethernet and IP level using raw sockets in Python.
### 2. GeoIP Tracking
Maps the geographical location of IP addresses in real-time using packet metadata.
### 3. ICMP Ping
Sends Custom ICMP Echo Requests to check host reachability and measures round-trip time.
### 4. TCP Connection Monitor
Tracks active TCP connections and identifies open sessions across the network.
### 5. TCP Flow Analysis
Analyzes TCP stream behavior including packet count, session duration, and flow statistics.
### 6. Port Scanner
Identifies open ports on a target host by crafting and sending custom TCP/UDP packets.
### 7. TCP Network Performance Monitor
Monitors network throughput and latency using active TCP probes and metrics.
### 8. Simple DoS Attack Detection
Detects abnormal traffic bursts and high-frequency packet flows indicative of DoS attempts.
### 9. Exploratory Data Analysis on Captured Raw Packet Sniffing Data
Performs EDA on stored packet logs to uncover traffic patterns, protocols used, and anomalies.

## System Requirements
1. Linux System (due to use of ```AF_PACKET``` for Raw Sockets)
2. Root privileges to run ```sudo```

## Run Instructions 
<pre><code>
  ```bash 
  # Run this command in the same directory 
  sudo python3 Main.py ```
</code></pre>
