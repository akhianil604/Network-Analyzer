# Network-Analyzer
Main Repository for 4th Semester, 2nd Mini Project on Computer Networks (UE23CS252B) for a CLI-based Network Traffic Analysis, Monitoring &amp; Security Tool

## Team Members
Class & Section: Semester 4th, 'A' Section, B.Tech. Computer Science Engineering
1. Aania George (SRN: PES1UG23CS007)
2. Akhilesh Anil (SRN: PES1UG23CS045)

## Features 
#### 1. Raw Packet Sniffing
Captures and parses live network traffic at the Ethernet and IP level using raw sockets in Python.
2. GeoIP Tracking: Maps the geographical location of IP addresses in real-time using packet metadata.
3. ICMP Ping
4. TCP Connection Monitor
5. TCP Flow Analysis
6. Port Scanner
7. TCP Network Performance Monitor
8. Simple DoS Attack Detection
9. Exploratory Data Analysis on Captured Raw Packet Sniffing Data

## System Requirements
1. Linux System (due to use of ```AF_PACKET``` for Raw Sockets)
2. Root privileges to run ```sudo```

## Run Instructions 
<pre> ```bash # Run this command in the same directory sudo python3 Main.py ``` </pre>
