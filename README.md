
## Log Analysis Lab - README.md Output (Paste into GitHub)

This lab is basically just a long and (very) tedious process of weeding out the most suspicious things about the log entries. The lab required we look through the log to spot obvious issues, unusual patterns, and anomalies, and then provide a summary explaining what we identified, why it is an issue, and what problems it could or absolutely will cause.

I documented 10 issues (as per the rubric), and I also completed the Bonus content of documenting the rest of the 25 issues (Upon the *insistance* of my mother, with help from her and both of us spending longer than expected begging google to help us).  
**Some of the biggest issues I noticed** were legacy/risky protocols (FTP/SMTP), lateral-movement-friendly services (SMB/SQL), repeat denied attempts that look like beaconing, and weird broadcast/multicast behavior on UDP 443.
**If this were a real incident,** I’d treat the suspicious hosts as most important, identify the asset owners, pull endpoint logs, and confirm whether these services are a potential or actual threat/issue. Additional things I could do include: I would correlate the activity with DNS, authentication, and proxy logs to see if there’s a broader pattern. I would then check the external IPs against threat intelligence sources and compare the behavior to the system’s normal baseline to determine whether it’s truly abnormal. If the activity appeared malicious, I would isolate the affected host, block the destination IPs at the firewall, and preserve relevant logs for further forensic analysis.

**Log Format:**
Each entry includes a Timestamp, Source IP, Destination IP, Protocol, Port, Action (Allow/Deny), Bytes Transferred.

**Method (How I flagged issues)**
- Unusual or risky ports/protocols (FTP, SQL, SMB, etc. )
 - Repeated attempts to the same destination (possible beaconing)
 - Broadcast/multicast traffic in places it shouldn’t be
 - Large transfers that could be data leaving the network
 - Denied traffic that looks like scanning or blocked malware behavior
 
**Identified Issues:**
Each issue includes the exact fields required by the rubric: log snippet, description, reason for concern, potential impact, and technically possible explanations.

### Issue 1
**Log Entries:**
```plaintext
2023-02-17 09:34:09 127.0.0.1 127.0.0.1 TCP 3000 Allow 57289
```
**Description of log entries:** Localhost-to-localhost traffic on TCP port 3000 with a decent amount of data moved.
**Reason for concern:** Port 3000 is a super common dev/test web port (Node/React). In an enterprise-ish log, that can mean an unapproved local service. It’s not automatically evil, but it’s definitely “sus. ”  Port 3000 is commonly used for development web servers, so unexpected localhost traffic on this port in an enterprise environment could indicate an unapproved or rogue local service running.
**Potential impact:** If it’s a rogue process, it could be hosting a hidden service, staging data locally, or acting like a pivot point for other attacks. If malicious, this activity could represent a hidden service staging data, supporting lateral movement, or acting as a pivot point for further attacks.
**Possible explanations:** Legit dev server; legit local app; misconfiguration (service left running); malware pretending to be a local service. This may simply reflect legitimate development activity or a local application, but it could also indicate a misconfigured service left running or malware masquerading as a normal process.

### Issue 2
**Log Entries:**
```plaintext
2023-02-17 09:39:19 127.0.0.1 127.0.0.1 TCP 9200 Allow 38192
2023-02-17 09:39:22 127.0.0.1 127.0.0.1 TCP 9200 Allow 44735
2023-02-17 09:39:25 127.0.0.1 127.0.0.1 TCP 9200 Allow 61208
```
**Description of log entries:** Repeated localhost connections on TCP port 9200 with large byte counts.
**Reason for concern:** Port 9200 is commonly Elasticsearch. Elasticsearch is powerful, but if it’s misused/exposed it can leak a ton of data. Heavy local activity can also mean something is scraping/dumping data. Port 9200 is commonly associated with Elasticsearch, and heavy localhost activity on this port could indicate data indexing, scraping, or potential misuse of a local data store.
**Potential impact:** Sensitive data exposure, local staging before exfiltration, or an attacker using a local datastore to search for secrets. If abused, this behavior could expose sensitive data locally, allow staging before exfiltration, or enable an attacker to search and extract valuable information.
**Possible explanations:** Legit Elastic stack; dev/testing; misconfigured service; malware querying local data. This may represent legitimate Elasticsearch usage for logging or development, but it could also indicate a misconfigured service or malware querying local data repositories.

### Issue 3
**Log Entries:**
```plaintext
2023-02-17 09:36:07 192.168.1.61 217.23.2.15 TCP 21 Allow 3629
2023-02-17 09:36:15 192.168.1.61 141.98.10.195 TCP 21 Allow 2745
```
**Description of log entries:** Outbound FTP (TCP 21) from an internal host to external IPs.
**Reason for concern:** FTP is old-school and insecure (plaintext creds). If this is real, someone is moving files in a way that’s easy to intercept. FTP transmits credentials and data in plaintext, so outbound FTP traffic can expose sensitive information and is often considered insecure in modern environments.
**Potential impact:** Credential theft, data leakage, or unauthorized file transfers. If misused, this activity could lead to credential theft, unauthorized file transfers, or data exfiltration outside the network.
**Possible explanations:** Legacy file transfer; misconfigured app; user doing manual FTP; attacker exfiltrating data via FTP. This may reflect a legacy file transfer process or a misconfigured application, but it could also indicate a user manually transferring files or an attacker exfiltrating data via FTP.
### Issue 4
**Log Entries:**
```plaintext
2023-02-17 09:39:03 192.168.1.19 40.94.31.197 TCP 1433 Allow 37419
2023-02-17 09:39:08 192.168.1.19 40.94.25.38 TCP 1433 Allow 32780
2023-02-17 09:39:11 192.168.1.19 40.94.28.182 TCP 1433 Allow 41935
```
**Description of log entries:** Outbound SQL Server traffic (TCP 1433) from an internal host to external IPs.
**Reason for concern:** SQL (1433) is usually internal-only. External SQL connections can mean database exposure or risky configuration. SQL traffic on port 1433 is typically restricted to internal systems, so outbound connections to external IPs may indicate database exposure or a risky configuration.
**Potential impact:** Database exposure, credential compromise, data exfiltration, or an attacker tunneling database access. If malicious or misconfigured, this could lead to database compromise, credential theft, unauthorized data access, or data exfiltration.
**Possible explanations:** Legit cloud SQL; firewall misconfig; compromised host accessing external DB; admin/test activity. This activity may reflect legitimate access to a cloud-hosted database, a firewall configuration issue, authorized administrative testing, or a compromised host attempting external database communication.

### Issue 5
**Log Entries:**
```plaintext
2023-02-17 09:33:54 192.168.1.24 216.58.194.206 TCP 443 Allow 752489
```
**Description of log entries:** Very large outbound HTTPS transfer (752,489 bytes) to an external IP.
**Reason for concern:** Big outbound transfers aren’t always bad, but they’re a classic “check this” moment because exfil often rides over HTTPS. Although large outbound HTTPS transfers can be legitimate, attackers frequently use encrypted web traffic to disguise data exfiltration, making this activity worth closer review.
**Potential impact:** Sensitive data could be leaving the network (files, creds, exports). If malicious, this transfer could represent sensitive files, credentials, or internal data being exfiltrated outside the network.
**Possible explanations:** Legit upload (cloud/email); software update; user sync; malware exfil over HTTPS. This may reflect a legitimate cloud upload, software update, or file synchronization process, but it could also indicate malware using HTTPS to exfiltrate data.

### Issue 6
**Log Entries:**
```plaintext
2023-02-17 09:38:24 192.168.1.72 111.221.29.254 TCP 443 Deny 0
2023-02-17 09:38:31 192.168.1.72 111.221.29.254 TCP 443 Deny 0
2023-02-17 09:38:39 192.168.1.72 111.221.29.254 TCP 443 Deny 0
2023-02-17 09:38:46 192.168.1.72 111.221.29.254 TCP 443 Deny 0
2023-02-17 09:38:53 192.168.1.72 111.221.29.254 TCP 443 Deny 0
```
**Description of log entries:** Repeated denied HTTPS attempts from the same internal host to the same destination.
**Reason for concern:** Repeated denies in a short window can look like beaconing or an automated retry loop. Malware does this a lot when it’s trying to phone home. Repeated denied HTTPS attempts from the same host in a short time frame can resemble automated beaconing behavior, which is commonly seen when malware is trying to reach its command-and-control server.
**Potential impact:** Could indicate a compromised host attempting command-and-control (C2). Even blocked attempts still mean something is trying. Even though the connections were blocked, this pattern could indicate a compromised system attempting to establish outbound C2 communications.
**Possible explanations:** Blocked malicious IP; misconfigured app retrying; DNS issues; security control blocking C2. This activity may reflect a blocked malicious destination, a misconfigured application stuck in a retry loop, DNS resolution issues, or a security control successfully preventing outbound C2 traffic.

### Issue 7
**Log Entries:**
```plaintext
2023-02-17 09:37:04 192.168.1.229 239.255.255.250 UDP 443 Allow 6273
2023-02-17 09:37:07 192.168.1.229 239.255.255.250 UDP 443 Allow 6273
2023-02-17 09:37:09 192.168.1.229 255.255.255.255 UDP 443 Allow 6273
2023-02-17 09:37:14 192.168.1.229 192.168.1.255 UDP 443 Allow 6273
```
**Description of log entries:** UDP traffic on port 443 being sent to multicast and broadcast addresses.
**Reason for concern:** 443 is usually TCP (HTTPS). UDP 443 can be QUIC, but broadcast/multicast UDP 443 is weird and feels like scanning/discovery using a “safe-looking” port. Port 443 is typically associated with HTTPS over TCP, so seeing UDP 443 sent to multicast and broadcast addresses is unusual and could indicate scanning or discovery activity attempting to blend in with normal-looking traffic.
**Potential impact:** Internal recon/scanning, worm-like propagation, or stealth traffic trying to blend in. If malicious, this behavior could support internal reconnaissance, worm-like propagation, or stealth communications that attempt to avoid detection.
**Possible explanations:** Misconfigured service; custom app; malware scanning; broken discovery behavior. This may represent a misconfigured service or custom application using UDP incorrectly, but it could also indicate malware scanning or abnormal discovery behavior.

### Issue 8
**Log Entries:**
```plaintext
2023-02-17 09:35:56 172.17.99.132 205.185.216.10 UDP 443 Deny 6340
```
**Description of log entries:** Denied outbound UDP 443 from an internal 172.17.x address.
**Reason for concern:** Denied UDP 443 can be legit QUIC getting blocked, or it can be malware trying to use UDP 443 and getting shut down. While UDP 443 may represent legitimate QUIC traffic, it can also be used for covert encrypted communications, so a denied attempt from an internal host is worth further investigation.
**Potential impact:** Potential covert comms attempt, or app breakage due to blocked QUIC (still a security+ops issue). If malicious, this could indicate an attempted covert communication channel, or alternatively it could disrupt legitimate applications relying on QUIC, creating both security and operational concerns.
**Possible explanations:** Legit QUIC blocked by policy; misconfigured app; malware using UDP 443; firewall policy mismatch. This behavior may reflect legitimate QUIC traffic being blocked by policy, a misconfigured application, malware attempting encrypted communication, or a firewall configuration mismatch.

### Issue 9
**Log Entries:**
```plaintext
2023-02-17 09:36:59 172.17.98.202 172.22.243.84 TCP 445 Allow 3917
```
**Description of log entries:** SMB traffic (TCP 445) from a 172.17.x host to a 172.22.x destination.
**Reason for concern:** SMB is a classic lateral-movement path (ransomware loves it). Also, 172.17.x often shows up with Docker/NAT, so seeing SMB from that range is odd depending on the setup. SMB is commonly exploited for lateral movement, especially in ransomware attacks, and seeing it originate from a 172.17.x range (often associated with Docker or NAT environments) could indicate unexpected or misconfigured behavior.
**Potential impact:** Unauthorized share access, lateral movement, malware propagation, or credential harvesting. If abused, this traffic could allow unauthorized access to file shares, credential harvesting, or the spread of malware across internal systems.
**Possible explanations:** Legit file share; backup process; misconfigured container/network; compromised host moving laterally. This may represent legitimate file sharing or backup activity, but it could also indicate a misconfigured container/network setup or a compromised host attempting lateral movement.

### Issue 10
**Log Entries:**
```plaintext
2023-02-17 09:36:44 192.168.1.80 185.151.204.30 TCP 48127 Deny 48
```
**Description of log entries:** Denied outbound connection to a high, non-standard TCP port (48127).
**Reason for concern:** Random high ports are often used for backdoors/C2. The deny is good, but the attempt is still suspicious. High-numbered non-standard ports are frequently used for backdoor or command-and-control communications, so even a denied attempt suggests something may have been trying to establish unauthorized connectivity.
**Potential impact:** If this worked elsewhere, it could enable remote control or stealthy exfil over a weird port. If successful in another environment, this type of connection could allow remote control of the host or stealthy data exfiltration over an uncommon port.
**Possible explanations:** Blocked malicious destination; app using random port; scan attempt; malware attempting backdoor connection. This could represent a blocked malicious destination, a legitimate application using a random port, a routine scan, or malware attempting to open a backdoor connection.

<hr>

# Bonus Stuff

### Issue 11
**Log Entries:**
```plaintext
2023-02-17 09:34:14 192.168.1.49 216.109.119.63 TCP 25 Allow 7421
```
**Description of log entries:** Outbound SMTP (TCP 25) from an internal host.
**Reason for concern:** Most user machines shouldn’t send SMTP straight to the internet. This could be a misconfigured device or a compromised host spamming. Most endpoint systems should not initiate direct SMTP connections to the internet, so this behavior could indicate misconfiguration or a compromised host attempting to send unauthorized email traffic.
**Potential impact:** Spam/phishing from inside the network, blacklisting, data leakage via email. If malicious, this activity could result in spam or phishing being sent from within the network, reputational damage through blacklisting, or sensitive data being leaked via email.
**Possible explanations:** Legit mail server; workstation misconfig; malware spamming; legacy app sending email alerts. This could represent legitimate mail server activity or an alerting application, but it could also indicate a misconfigured workstation or malware attempting to send outbound email.

### Issue 12
**Log Entries:**
```plaintext
2023-02-17 09:36:23 192.168.1.229 239.255.255.250 UDP 1900 Allow 459
```
**Description of log entries:** SSDP traffic (UDP 1900) to multicast (device discovery).
**Reason for concern:** SSDP/UPnP is common in home networks, but in enterprise networks it can be unnecessary and helpful for recon (finding devices/services). Although SSDP/UPnP is common for device discovery in home environments, in enterprise networks it can unnecessarily expose information about internal systems that attackers could use for reconnaissance.
**Potential impact:** Network mapping/recon that helps attackers; potential exposure if UPnP is allowed broadly. If abused, this traffic could assist an attacker in mapping devices and services on the network, increasing the risk of targeted exploitation.
**Possible explanations:** Legit discovery (printers/IoT); misconfigured host; unnecessary service running; attacker recon. This may simply reflect legitimate device discovery such as printers or IoT systems, but it could also indicate a misconfigured host or reconnaissance activity.

### Issue 13
**Log Entries:**
```plaintext
2023-02-17 09:34:01 192.168.1.211 62.128.197.131 UDP 51820 Allow 1440
```
**Description of log entries:** Outbound UDP traffic on port 51820 to an external IP.
**Reason for concern:** Port 51820 is commonly used by WireGuard VPN. Unexpected encrypted tunnels can bypass monitoring. Port 51820 is commonly associated with WireGuard VPN, so unexpected outbound traffic on this port could indicate an encrypted tunnel that bypasses standard monitoring controls.
**Potential impact:** Covert data exfiltration channel or unauthorized encrypted remote access. If malicious, this connection could provide a covert channel for data exfiltration or unauthorized remote access into the network.
**Possible explanations:** Legit VPN; developer tunnel; misconfiguration; attacker establishing encrypted C2. This may represent legitimate VPN usage or a developer tunnel, but it could also indicate misconfiguration or an attacker establishing encrypted command-and-control communications.

### Issue 14
**Log Entries:**
```plaintext
2023-02-17 09:34:27 192.168.1.142 43.250.192.131 TCP 80 Allow 1203
2023-02-17 09:34:29 192.168.1.142 133.242.174.247 TCP 80 Allow 1149
```
**Description of log entries:** Outbound HTTP connections to external IPs.
**Reason for concern:** Unencrypted HTTP traffic can expose credentials and session data. Because HTTP traffic is unencrypted, it can expose credentials or session information in transit, making it easier for attackers to intercept or manipulate the data.
**Potential impact:** Credential leakage or malicious content injection. If this traffic were compromised, it could result in credential theft, session hijacking, or the injection of malicious content into the user’s browsing session.
**Possible explanations:** User browsing; legacy app; update server; malware beaconing. This may simply reflect normal user browsing or a legacy application using HTTP, but it could also indicate malware communicating over an unencrypted channel.

### Issue 15
**Log Entries:**
```plaintext
2023-02-17 09:34:35 192.168.1.31 8.8.8.8 TCP 53 Allow 435
```
**Description of log entries:** DNS traffic over TCP to public DNS server.
**Reason for concern:** DNS over TCP may indicate large queries or tunneling. While DNS over TCP can be legitimate, it is less common than UDP and may indicate unusually large queries or even DNS tunneling activity.
**Potential impact:** Potential DNS tunneling for data exfiltration. If abused, DNS tunneling could allow data to be exfiltrated covertly through seemingly normal DNS traffic.
**Possible explanations:** Legit DNS fallback; large response; DNS tunneling malware. This could represent normal DNS fallback behavior for large responses, but it could also indicate malware leveraging DNS tunneling techniques.

### Issue 16
**Log Entries:**
```plaintext
2023-02-17 09:34:16 192.168.1.37 19.89.143.11 UDP 67 Allow 256
```
**Description of log entries:** UDP port 67 traffic to external IP.
**Reason for concern:** DHCP traffic should remain internal. DHCP traffic on UDP port 67 is normally confined to the local network, so seeing it directed to an external IP suggests something is misconfigured or behaving unexpectedly.
**Potential impact:** Misconfiguration or unusual external DHCP attempt. If this behavior is malicious or incorrect, it could indicate network misconfiguration, spoofed traffic, or improper external communication that bypasses normal DHCP boundaries.
**Possible explanations:** Misconfigured device; spoofed traffic; abnormal service. This could be a misconfigured device sending DHCP traffic outside the local subnet, spoofed packets, or an abnormal service incorrectly using the DHCP port.

### Issue 17
**Log Entries:**
```plaintext
2023-02-17 09:35:04 192.168.1.161 204.141.42.39 UDP 5060 Allow 5720
```
**Description of log entries:** Outbound SIP (VoIP) traffic on port 5060.
**Reason for concern:** SIP can be abused for toll fraud or C2. SIP traffic on port 5060 is commonly used for VoIP, but it can also be abused for toll fraud or as a covert command-and-control channel if not properly monitored.
**Potential impact:** Voice fraud or covert communications channel. If malicious, this traffic could enable unauthorized voice charges or provide an attacker with a hidden communication path inside the network.
**Possible explanations:** Legit VoIP; softphone; misconfiguration; attacker using SIP. This may represent legitimate VoIP or softphone usage, a configuration issue, or potentially an attacker leveraging SIP for unauthorized communications.

### Issue 18
**Log Entries:**
```plaintext
2023-02-17 09:36:29 192.168.1.119 104.244.42.1 TCP 80 Allow 55713
```
**Description of log entries:** Large HTTP transfer to external IP.
**Reason for concern:** Large outbound transfers may indicate exfiltration. Large outbound HTTP transfers can be a red flag because attackers often use normal web traffic to quietly move stolen data out of a network.
**Potential impact:** Sensitive data leaving network. If this transfer was malicious, it could represent sensitive files, credentials, or internal data being exfiltrated to an external system.
**Possible explanations:** File upload; sync process; malicious exfiltration. This could simply be a legitimate file upload or synchronization process, but it could also indicate an active data exfiltration attempt.

### Issue 19
**Log Entries:**
```plaintext
2023-02-17 09:36:59 172.17.98.202 172.22.243.84 TCP 445 Allow 3917
```
**Description of log entries:** SMB traffic between private ranges.
**Reason for concern:** SMB used for lateral movement. SMB traffic is commonly used in legitimate file sharing, but it’s also a well-known vector for lateral movement, especially in ransomware attacks.
**Potential impact:** File share compromise or ransomware spread. If abused, this traffic could allow an attacker to access shared resources, steal data, or spread malware across internal systems.
**Possible explanations:** Legit file access; backup; compromised host. This may represent normal file sharing or backup operations, but it could also indicate a compromised host attempting lateral movement.

### Issue 20
**Log Entries:**
```plaintext
2023-02-17 09:35:12 192.168.1.172 224.0.0.251 UDP 5353 Allow 164
```
**Description of log entries:** mDNS multicast traffic.
**Reason for concern:** Multicast discovery can aid recon. mDNS multicast traffic can be leveraged by attackers for passive reconnaissance because it reveals information about devices and services on the local network.
**Potential impact:** Internal mapping and device enumeration. If abused, this traffic could help an attacker map internal systems and identify potential targets for lateral movement.
**Possible explanations:** Legit device discovery; unnecessary service. This may simply be legitimate device discovery traffic (like printers or other services), or it could represent unnecessary services that increase the network’s exposure.

### Issue 21
**Log Entries:**
```plaintext
2023-02-17 09:35:30 192.168.1.34 35.186.224.47 ICMP 0 Allow 98
```
**Description of log entries:** Outbound ICMP echo traffic.
**Reason for concern:** ICMP used for recon and C2 checks. ICMP echo traffic can be used for simple reconnaissance or periodic command-and-control check-ins, so even basic ping activity can sometimes be part of something bigger.
**Potential impact:** Network mapping or beacon check-ins. If this traffic were malicious, it could allow an attacker to map reachable systems or verify that a compromised host is still online.
**Possible explanations:** Normal ping; troubleshooting; recon attempt. This could just be normal troubleshooting or connectivity testing, but it could also represent reconnaissance behavior probing the network.

### Issue 22
**Log Entries:**
```plaintext
2023-02-17 09:35:44 172.17.96.63 172.17.96.255 UDP 137 Allow 234
```
**Description of log entries:** NetBIOS broadcast traffic.
**Reason for concern:** NetBIOS often exploited for enumeration. NetBIOS broadcasts can be abused by attackers to enumerate systems and shares on the network, so even though it’s common, it’s also something that gets exploited a lot.
**Potential impact:** Host discovery and lateral movement. If misused, this kind of traffic could help an attacker identify active hosts and move laterally across the network.
**Possible explanations:** Normal Windows broadcast; reconnaissance. This could simply be normal Windows network behavior, or it could represent reconnaissance activity trying to map out the environment.

### Issue 23
**Log Entries:**
```plaintext
2023-02-17 09:35:56 172.17.99.132 205.185.216.10 UDP 443 Deny 6340
```
**Description of log entries:** Denied UDP 443 traffic.
**Reason for concern:** UDP 443 may indicate QUIC or covert channel attempts. UDP 443 is often used for QUIC, but it can also be abused as a covert encrypted channel, so seeing it denied makes me wonder whether something was trying to communicate in a way that avoids normal inspection.
**Potential impact:** Blocked encrypted communications. If this traffic were malicious and not blocked, it could allow encrypted command-and-control or data exfiltration to slip past traditional monitoring.
**Possible explanations:** Legit QUIC; firewall block; malware attempt. This could just be legitimate QUIC traffic getting blocked by policy, a misconfigured application, or potentially malware attempting to establish encrypted communications.

### Issue 24
**Log Entries:**
```plaintext
2023-02-17 09:36:04 192.168.1.85 128.1.248.42 UDP 123 Allow 287
```
**Description of log entries:** Outbound NTP traffic.
**Reason for concern:** NTP manipulation can impact time-based logging. This matters because if someone messes with NTP, they can throw off system time, which can break log accuracy and make incident timelines look totally different from what actually happened.
**Potential impact:** Log tampering or time skew attack. If an attacker manipulates time, they could hide their tracks, mess up forensic investigations, or cause authentication and logging systems to behave unpredictably.
**Possible explanations:** Legit time sync; misconfig; malicious time control. It could just be a normal time synchronization process, a configuration mistake, or in a worst-case scenario, someone deliberately trying to control system time for malicious purposes.

### Issue 25
**Log Entries:**
```plaintext
2023-02-17 09:37:17 192.168.1.150 162.159.134.234 TCP 443 Allow 70136
```
**Description of log entries:** Large HTTPS transfer to Cloudflare IP range.
**Reason for concern:** High-volume encrypted transfer. A high-volume encrypted HTTPS transfer to a Cloudflare IP range could mask the true destination of the data, making it harder to determine whether the activity is legitimate or malicious.
**Potential impact:** Potential exfil disguised as normal HTTPS. If abused, this transfer could represent sensitive data being exfiltrated under the cover of normal encrypted web traffic.
**Possible explanations:** Legit web activity; cloud app; exfil attempt. This may reflect legitimate web activity or communication with a cloud-hosted application, but it could also indicate an exfiltration attempt leveraging a CDN-backed endpoint.