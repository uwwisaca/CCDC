# Network Security Monitoring Deployment Guide
# CCDC 2026 - IDS/IPS/HIDS Implementation
# Date: January 30, 2026

## Overview

This directory contains scripts to deploy comprehensive network security monitoring for your CCDC environment using free and open-source tools:

- **Suricata**: Network IDS/IPS for threat detection
- **Wazuh**: Host-based intrusion detection system (HIDS)
- **Splunk Integration**: Centralized log analysis

## Network Architecture

```
                        [VyOS Router]
                        172.16.101.1
                              |
                    +---------+---------+
                    |                   |
              172.20.240.x          172.20.242.x
                    |                   |
        +-----------+--------+    +-----+------------+
        |                    |    |                  |
   [Windows Hosts]      [Cisco FTD]  [Ubuntu Ecom]  [Splunk]
   - Win11 (.100)      (.200)        (.30)          (.20)
   - AD/DNS (.102)                   [Suricata]     [Suricata]
   - Web (.101)                      [Wazuh Agents] [Wazuh Server]
   - FTP (.104)                                     
   [Wazuh Agents]
```

## Security Monitoring Placement

### Suricata IDS/IPS Placement

**Primary:** Ubuntu Ecom Server (172.20.242.30)
- Monitors 172.20.242.x network segment
- Detects threats targeting web/mail/database services
- Fast deployment from same machine
- Script: `install-suricata-ids.sh`

**Secondary:** Splunk Oracle Linux Server (172.20.242.20)
- Monitors same network segment
- Forwards alerts directly to Splunk
- Provides redundancy and centralized analysis
- Script: `install-suricata-splunk.sh`

### Wazuh HIDS Placement

**Server:** Splunk Oracle Linux Server (172.20.242.20) OR Ubuntu Ecom (172.20.242.30)
- Centralized management of all agents
- Script: `install-wazuh-server.sh`

**Agents:** All CCDC hosts (Windows + Linux)
- Windows: `install-wazuh-agent-windows.ps1`
- Linux: Deployed via `deploy-wazuh-agents-linux.sh`

## Installation Order (CCDC Competition Day)

### Phase 1: Core Infrastructure (T+0 minutes)
```bash
# On Ubuntu Ecom Server (172.20.242.30)
sudo ./install-suricata-ids.sh

# On Splunk Server (172.20.242.20)
sudo ./install-suricata-splunk.sh
sudo ./install-wazuh-server.sh
```

### Phase 2: Agent Deployment (T+10 minutes)
```powershell
# From Windows AD/DNS Server (172.20.240.102)
.\Deploy-Wazuh-Agents-Windows.ps1 -WazuhManager "172.20.242.20"
```

```bash
# From Ubuntu Ecom Server (172.20.242.30)
./deploy-wazuh-agents-linux.sh -m 172.20.242.20
```

## Scripts Reference

### Suricata Scripts

#### install-suricata-ids.sh
**Location:** `Ecommerce ubuntu server 24.0.3/Security/`
**Target:** Ubuntu Ecom Server (172.20.242.30)
**Purpose:** Primary network IDS/IPS monitoring

**Features:**
- Auto-detects network interface
- Monitors HOME_NET: 172.20.242.0/24, 172.20.240.0/24
- Custom CCDC detection rules:
  - SSH brute force detection
  - LDAP password spray (AD attacks)
  - FTP anonymous login attempts
  - SQL injection attempts
  - Web shell uploads
  - Reverse shell detection
  - Nmap scan detection
  - Mimikatz activity
  - SMB EternalBlue exploitation
- EVE JSON logging for Splunk integration
- Automatic daily rule updates
- Performance optimized (AF_PACKET mode)

**Usage:**
```bash
sudo ./install-suricata-ids.sh
```

**Post-Install:**
```bash
# View real-time alerts
tail -f /var/log/suricata/fast.log

# View JSON logs (for Splunk)
tail -f /var/log/suricata/eve.json | jq

# Monitor status
/usr/local/bin/suricata-monitor.sh

# Update rules manually
suricata-update
suricatasc -c reload-rules
```

#### install-suricata-splunk.sh
**Location:** `Splunk Oracle Linux 9.2 Splunk 10.0.2/Security/`
**Target:** Splunk Server (172.20.242.20)
**Purpose:** Network monitoring with Splunk integration

**Features:**
- Monitors 172.20.242.x network segment
- Forwards alerts to Splunk via syslog (port 5514)
- EVE JSON logging to /var/log/suricata/eve.json
- Automatic Splunk input configuration
- Optimized for Oracle Linux 9

**Usage:**
```bash
sudo ./install-suricata-splunk.sh

# Restart Splunk to apply configuration
/opt/splunk/bin/splunk restart
```

**Splunk Searches:**
```
# View Suricata alerts
index=main sourcetype=suricata*

# View alerts by severity
index=main sourcetype=suricata:json | stats count by alert.severity

# Top attacked hosts
index=main sourcetype=suricata:json | stats count by dest_ip | sort -count
```

### Wazuh Scripts

#### install-wazuh-server.sh
**Location:** Root directory
**Target:** Splunk Server (172.20.242.20) or Ubuntu Ecom (172.20.242.30)
**Purpose:** Centralized HIDS management

**Features:**
- Host-based intrusion detection
- File integrity monitoring (FIM) on critical directories:
  - /etc, /usr/bin, /usr/sbin, /bin, /sbin
  - /boot, /var/www, /opt/splunk/etc
- Vulnerability detection (CVE scanning)
- Rootcheck (rootkit detection)
- Active response (auto-block attacks)
- Log analysis for auth.log, syslog
- System monitoring (disk usage, network ports)

**Usage:**
```bash
sudo ./install-wazuh-server.sh
```

**Post-Install:**
```bash
# List connected agents
/var/ossec/bin/agent_control -l

# View real-time alerts
tail -f /var/ossec/logs/alerts/alerts.log

# Agent statistics
/var/ossec/bin/agent_control -i <agent_id>
```

#### install-wazuh-agent-windows.ps1
**Location:** Root directory
**Target:** All Windows hosts
**Purpose:** Install Wazuh agent on Windows

**Features:**
- Auto-downloads Wazuh agent 4.7.2
- Configures manager connection
- Windows Event Log monitoring
- Creates firewall rules
- Auto-starts service

**Usage:**
```powershell
# Install on single host
.\install-wazuh-agent-windows.ps1 -WazuhManager "172.20.242.20" -AgentName "Server2019Web"

# View agent status
Get-Service WazuhSvc

# View agent logs
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
```

#### Deploy-Wazuh-Agents-Windows.ps1
**Location:** Root directory
**Target:** Run from Windows AD/DNS Server (172.20.240.102)
**Purpose:** Bulk deployment to all Windows hosts

**Deploys to:**
- Windows 11 Workstation (172.20.240.100)
- Server 2019 AD/DNS (172.20.240.102)
- Server 2019 Web (172.20.240.101)
- Server 2022 FTP (172.20.240.104)

**Usage:**
```powershell
# Dry run (test without installing)
.\Deploy-Wazuh-Agents-Windows.ps1 -WazuhManager "172.20.242.20" -DryRun

# Deploy to all hosts
.\Deploy-Wazuh-Agents-Windows.ps1 -WazuhManager "172.20.242.20"
```

#### deploy-wazuh-agents-linux.sh
**Location:** Root directory
**Target:** Run from Ubuntu Ecom Server (172.20.242.30)
**Purpose:** Bulk deployment to all Linux hosts

**Deploys to:**
- Ubuntu Ecom Server (172.20.242.30)
- Splunk Server (172.20.242.20)
- Mailserver Fedora (172.20.242.40)
- Ubuntu Desktop (172.20.242.50)

**Usage:**
```bash
# Dry run
./deploy-wazuh-agents-linux.sh -m 172.20.242.20 -d

# Deploy to all hosts
./deploy-wazuh-agents-linux.sh -m 172.20.242.20
```

## Network Segments and Monitoring

### 172.20.242.x Network (Ubuntu/Splunk Segment)
**Monitored by:** Suricata on Ubuntu Ecom (.30) + Splunk Server (.20)
**Hosts:**
- Ubuntu Ecom Server (172.20.242.30) - Web/Mail/DB
- Splunk Server (172.20.242.20) - Monitoring/Logging
- Mailserver Fedora (estimated 172.20.242.40)
- Ubuntu Desktop (estimated 172.20.242.50)
- **Palo Alto Management** (172.20.242.150)

**Key Services to Monitor:**
- HTTP/HTTPS (80/443) - Web services
- SMTP (25) - Mail server
- MySQL (3306) - Database
- SSH (22) - Remote management
- Splunk Web (8000), Splunk API (8089)

### 172.20.240.x Network (Windows Segment)
**Monitored by:** Suricata on 172.20.242.x (cross-segment)
**Protected by:** Wazuh agents on all Windows hosts
**Hosts:**
- Windows 11 Workstation (172.20.240.100)
- Server 2019 Web (172.20.240.101)
- Server 2019 AD/DNS (172.20.240.102)
- Server 2022 FTP (172.20.240.104)
- **Cisco FTD Management** (172.20.240.200)

**Key Services to Monitor:**
- AD/LDAP (389/636) - Active Directory
- DNS (53) - Name resolution
- SMB (445) - File sharing
- RDP (3389) - Remote desktop
- HTTP/HTTPS (80/443) - IIS Web
- FTP (21) - File transfer

### 172.16.101.x Network (VyOS Router)
**Router:** VyOS 1.4.3 (172.16.101.1)
**Monitoring:** Traffic flows visible to Suricata via routing

## Detection Coverage

### Network-Level (Suricata)

**Reconnaissance Detection:**
- Port scans (Nmap, Masscan)
- Service enumeration
- DNS zone transfers
- SNMP sweeps

**Exploitation Detection:**
- SQL injection attempts
- Web shell uploads
- Directory traversal
- Command injection
- Buffer overflows
- Known CVE exploits

**Lateral Movement:**
- SMB brute force
- RDP brute force
- Pass-the-hash detection
- Mimikatz usage
- PsExec usage

**Data Exfiltration:**
- Unusual outbound connections
- DNS tunneling
- Large file transfers
- Reverse shells

### Host-Level (Wazuh)

**File Integrity Monitoring:**
- Configuration file changes (/etc/*)
- Binary modifications (/usr/bin, /sbin)
- Web root changes (/var/www)
- Boot sector modifications
- Splunk configuration changes

**Rootkit Detection:**
- Hidden processes
- Hidden files
- Hidden network ports
- Suspicious kernel modules
- Modified system binaries

**Vulnerability Scanning:**
- Outdated packages
- Known CVE vulnerabilities
- Weak configurations
- Missing patches

**Log Analysis:**
- Failed login attempts
- Privilege escalation
- User account changes
- Service restarts
- Unusual commands

## Splunk Integration

### Configure Splunk to Receive Suricata Logs

1. **EVE JSON Monitoring** (Automatic if using install-suricata-splunk.sh):
```
[monitor:///var/log/suricata/eve.json]
disabled = false
sourcetype = suricata:json
index = main
```

2. **Syslog Input**:
```
[tcp://5514]
disabled = false
sourcetype = suricata:syslog
index = main
```

3. **Wazuh Logs**:
```
[monitor:///var/ossec/logs/alerts/alerts.log]
disabled = false
sourcetype = wazuh:alert
index = main
```

### Useful Splunk Searches

```spl
# Dashboard: Security Overview
index=main (sourcetype=suricata* OR sourcetype=wazuh*)
| stats count by sourcetype

# High-Severity Alerts
index=main sourcetype=suricata:json alert.severity<=2
| table _time src_ip dest_ip alert.signature alert.severity

# Wazuh File Integrity Alerts
index=main sourcetype=wazuh:alert rule.groups=*syscheck*
| table _time agent.name syscheck.path syscheck.event

# Top Attackers
index=main sourcetype=suricata:json
| stats count by src_ip | sort -count | head 20

# Blocked IPs (Active Response)
index=main sourcetype=wazuh:alert rule.id=651
| table _time agent.name full_log
```

## Performance Tuning

### Suricata Performance

**For High Traffic Environments:**
```yaml
# Edit /etc/suricata/suricata.yaml
threading:
  set-cpu-affinity: yes
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ 1, 2, 3 ]
```

**Reduce False Positives:**
```bash
# Disable noisy rules
echo "# Disable rule 2100498" >> /etc/suricata/disable.conf
echo "2100498" >> /etc/suricata/disable.conf

# Update rules with disable list
suricata-update --disable-file=/etc/suricata/disable.conf
```

### Wazuh Performance

**Reduce Alert Frequency:**
```xml
<!-- Edit /var/ossec/etc/ossec.conf -->
<syscheck>
  <frequency>86400</frequency>  <!-- Daily instead of 12 hours -->
  <scan_on_start>no</scan_on_start>  <!-- Skip scan on startup -->
</syscheck>
```

## Troubleshooting

### Suricata Issues

**Suricata not capturing traffic:**
```bash
# Check interface
ip link show

# Verify Suricata is listening
tcpdump -i eth0 -c 10

# Check Suricata stats
tail -f /var/log/suricata/stats.log | grep capture.kernel

# Test rule detection
curl -A "() { :; }; /bin/bash -c 'echo vulnerable'" http://localhost/
tail -f /var/log/suricata/fast.log
```

**High CPU usage:**
```bash
# Check worker threads
ps aux | grep Suricata

# Reduce detect threads in /etc/suricata/suricata.yaml
detect-thread-ratio: 0.5
```

### Wazuh Issues

**Agent not connecting:**
```bash
# On agent (Linux)
systemctl status wazuh-agent
cat /var/ossec/logs/ossec.log | grep -i error

# On agent (Windows)
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50

# On manager
/var/ossec/bin/agent_control -l
tail -f /var/ossec/logs/ossec.log
```

**Agent authentication issues:**
```bash
# On manager, remove and re-add agent
/var/ossec/bin/manage_agents -r <agent_id>
/var/ossec/bin/manage_agents -a

# Restart manager
systemctl restart wazuh-manager
```

## Security Best Practices

### During CCDC Competition

1. **Deploy Early** - Install IDS/HIDS in first 15 minutes
2. **Monitor Continuously** - Have dedicated person watching alerts
3. **Tune Rules** - Disable false positive alerts quickly
4. **Document Incidents** - Log all detected attacks
5. **Active Response** - Use Wazuh to auto-block attackers
6. **Backup Logs** - Copy logs off-server regularly
7. **Network Segmentation** - Ensure firewall rules between segments

### Rule Tuning

**Add Custom Suricata Rules:**
```bash
# Edit /etc/suricata/rules/ccdc-custom.rules
alert http any any -> $HTTP_SERVERS any (msg:"CCDC Specific Attack"; content:"custom_pattern"; http_uri; sid:9000100; rev:1;)

# Reload rules
suricatasc -c reload-rules
```

**Add Custom Wazuh Rules:**
```xml
<!-- Edit /var/ossec/etc/rules/local_rules.xml -->
<group name="local,">
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <match>ccdc_critical_file</match>
    <description>Critical CCDC file modified</description>
  </rule>
</group>
```

## Log Locations

### Suricata
- **Fast Log:** `/var/log/suricata/fast.log` (human-readable alerts)
- **EVE JSON:** `/var/log/suricata/eve.json` (structured logs for Splunk)
- **Stats:** `/var/log/suricata/stats.log` (performance metrics)
- **HTTP Log:** `/var/log/suricata/http.log`
- **TLS Log:** `/var/log/suricata/tls.log`
- **DNS Log:** `/var/log/suricata/dns.log`

### Wazuh
- **Server Alerts:** `/var/ossec/logs/alerts/alerts.log`
- **Server Log:** `/var/ossec/logs/ossec.log`
- **Agent Logs (Linux):** `/var/ossec/logs/ossec.log`
- **Agent Logs (Windows):** `C:\Program Files (x86)\ossec-agent\ossec.log`

## Additional Resources

- **Suricata Documentation:** https://suricata.readthedocs.io/
- **Suricata Rules:** https://rules.emergingthreats.net/
- **Wazuh Documentation:** https://documentation.wazuh.com/
- **CCDC Rule Repository:** https://github.com/wazuh/wazuh-ruleset
- **Splunk Add-ons:**
  - Suricata App: https://splunkbase.splunk.com/app/2760/
  - Wazuh App: https://splunkbase.splunk.com/app/3642/

## Post-Competition Analysis

After CCDC, analyze your security posture:

```bash
# Generate attack timeline
jq -r '[.timestamp, .src_ip, .dest_ip, .alert.signature] | @csv' /var/log/suricata/eve.json > attack_timeline.csv

# Wazuh agent statistics
/var/ossec/bin/agent_control -l -s

# Most triggered rules
grep "Rule:" /var/ossec/logs/alerts/alerts.log | sort | uniq -c | sort -rn | head -20
```

---

**CCDC 2026 - Defense in Depth**

Network Monitoring (Suricata) + Host Protection (Wazuh) + Centralized Analysis (Splunk) = Comprehensive Security!
