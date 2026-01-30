# STIG Implementation Scripts - Complete Summary
**Date:** January 30, 2026  
**Version:** 1.0  
**Status:** Complete

---

## Overview

This package contains comprehensive STIG (Security Technical Implementation Guide) compliance scripts for 11+ different systems across your CCDC environment. All scripts include backup functionality, detailed logging, error handling, and post-implementation guidance.

---

## Scripts Created by System

### 1. **Windows 11 24H2**
**Location:** `Windows 11 24H2/Apply-Windows11-STIG.ps1`  
**STIG Version:** U_MS_Windows_11_STIG_V2R6  
**Features:**
- Account policies (14 char min, 3 attempt lockout)
- Advanced audit policies (20+ subcategories)
- LSA Protection and Credential Guard
- BitLocker configuration (TPM 2.0, 6-digit PIN)
- UAC, Windows Defender, Firewall
- PowerShell logging (Script Block, Transcription, Module)
- Network security (SMB signing, LLMNR disabled)

**Execution:** Run as Administrator  
**Requirements:** Windows 11 Enterprise, TPM 2.0, UEFI with Secure Boot

---

### 2. **Windows Server 2022 Standard (FTP Server)**
**Location:** `FTP server Server 2022 Std/Apply-Server2022-STIG.ps1`  
**STIG Version:** U_MS_Windows_Server_2022_V2R7  
**Features:**
- Server-specific security policies
- RDS hardening (NLA, encryption level 3)
- SMB server/client signing requirements
- Account lockout and password policies
- Service hardening (RemoteRegistry disabled)
- PowerShell and event logging

**Execution:** Run as Administrator  
**Requirements:** Windows Server 2022 Standard/Datacenter

---

### 3. **Windows Server 2019 (Web Server & AD/DNS)**
**Locations:**
- `Windows 2019 web Server/OS/Apply-Server2019-STIG.ps1`
- `Windows AD-dns 2019 Std/OS/Apply-Server2019-STIG.ps1`

**STIG Version:** U_MS_Windows_Server_2019_V3R7  
**Features:**
- Similar to Server 2022 with V3R7 STIG compliance
- Advanced audit policies
- Network security hardening
- RDS and SMB configuration
- Service management

**Execution:** Run as Administrator  
**Requirements:** Windows Server 2019

---

### 4. **Active Directory Domain**
**Location:** `Windows AD-dns 2019 Std/Domain/Apply-ADDS-Domain-STIG.ps1`  
**STIG Version:** U_Active_Directory_Domain_V3R6  
**Features:**
- Domain password policies (14 char, 60 day expiration)
- Account lockout configuration (3 attempts, 15 min lockout)
- LDAP signing requirements
- Anonymous access restrictions
- Privileged account management
- Service account review
- Guest account disabled
- AD Recycle Bin recommendations

**Execution:** Run as Administrator on Domain Controller  
**Requirements:** Domain Controller, Active Directory module

---

### 5. **Active Directory Forest**
**Location:** `Windows AD-dns 2019 Std/Forest/Apply-ADDS-Forest-STIG.ps1`  
**STIG Version:** U_Active_Directory_Forest_V3R2  
**Features:**
- Forest functional level verification
- Schema Admins/Enterprise Admins review
- AD Recycle Bin status check
- FSMO role verification
- Trust relationship review (Selective Authentication)
- Sites and subnets configuration check
- Global Catalog server verification
- Tombstone lifetime configuration
- Time synchronization hierarchy

**Execution:** Run as Administrator with Enterprise Admin rights  
**Requirements:** Forest root domain controller

---

### 6. **DNS Server**
**Location:** `Windows AD-dns 2019 Std/DNS/Apply-DNS-STIG.ps1`  
**STIG Version:** U_Domain_Name_System_V4R2  
**Features:**
- DNS logging enabled (all events)
- Zone transfer restrictions
- DNSSEC configuration guidance
- Forwarder verification
- Recursion settings
- Cache pollution protection
- Response rate limiting
- DNS scavenging configuration
- Socket pool optimization
- Event log sizing

**Execution:** Run as Administrator on DNS Server  
**Requirements:** DNS Server role installed

---

### 7. **Ubuntu 24.04 LTS Server (Ecommerce)**
**Location:** `Ecommerce ubuntu server 24.0.3/OS/apply-ubuntu-stig.sh`  
**STIG Version:** U_CAN_Ubuntu_24-04_LTS_V1R4  
**Features:**
- Password quality (pwquality: 15 char min, complexity)
- Account lockout (faillock: 3 attempts, permanent lock)
- SSH hardening (TLS 1.2+, strong ciphers, no root login)
- Comprehensive auditd rules (400+ lines)
- Kernel hardening (sysctl: IP forwarding disabled, SYN cookies)
- UFW firewall with default deny
- AppArmor enforcement
- Automatic security updates
- AIDE integrity checking

**Execution:** `sudo ./apply-ubuntu-stig.sh`  
**Requirements:** Ubuntu 24.04 LTS, sudo access

---

### 8. **Ubuntu 24.04 LTS Desktop**
**Location:** `Unbuntu Desktop Desktop 24.04.3/OS/apply-ubuntu-desktop-stig.sh`  
**STIG Version:** U_CAN_Ubuntu_24-04_LTS_V1R4  
**Features:**
- All server STIG settings
- **Desktop-specific:**
  - Screen lock (15 min idle timeout)
  - Guest account disabled
  - Automatic login disabled
  - GNOME privacy settings
  - Login banner (GDM)
  - Bluetooth/Avahi/CUPS disabled

**Execution:** `sudo ./apply-ubuntu-desktop-stig.sh`  
**Requirements:** Ubuntu 24.04 Desktop, GNOME, sudo access

---

### 9. **RHEL 9 / Fedora 42 (Mailserver)**
**Location:** `Mailserver Fedora 42/OS/apply-rhel9-stig.sh`  
**STIG Version:** U_RHEL_9_V2R7  
**Features:**
- Password policies (pwquality + login.defs)
- Faillock configuration (3 attempts, admin unlock)
- SSH hardening (Protocol 2, strong crypto)
- Comprehensive audit rules (400+ lines)
- Kernel parameters (sysctl)
- SELinux enforcing mode
- Firewalld configuration
- AIDE initialization
- Automatic updates (dnf-automatic)

**Execution:** `sudo ./apply-rhel9-stig.sh`  
**Requirements:** RHEL 9 / Fedora 42, sudo access

---

### 10. **Oracle Linux 9 (Splunk Server)**
**Location:** `Splunk Oracle Linux 9.2 Splunk 10.0.2/OS/apply-oracle-linux-stig.sh`  
**STIG Version:** U_Oracle_Linux_9_V1R4  
**Features:**
- RHEL 9 compatible STIG settings
- Password quality and lockout
- SSH hardening
- Audit configuration
- Kernel hardening
- SELinux enforcement
- Firewall configuration

**Execution:** `sudo ./apply-oracle-linux-stig.sh`  
**Requirements:** Oracle Linux 9, sudo access

---

### 11. **Splunk Enterprise 8.x/10.x**
**Location:** `Splunk Oracle Linux 9.2 Splunk 10.0.2/Splunk/apply-splunk-stig.sh`  
**STIG Version:** U_Splunk_Enterprise_8-x_for_Linux_V2R3  
**Features:**
- Strong password policy (15 char, complexity, 5 history)
- Session timeout (15 minutes)
- SSL/TLS (TLS 1.2+ only, strong ciphers)
- Audit logging (JSON format)
- Input security (SSL for forwarders)
- Web interface security (HSTS, X-Frame-Options)
- RBAC configuration
- Search and index limits
- File permissions hardening

**Execution:** `sudo ./apply-splunk-stig.sh`  
**Requirements:** Splunk installed at /opt/splunk or /opt/splunkforwarder

---

### 12. **Apache Web Server 2.4 (Unix/Linux)**
**Locations:**
- `Ecommerce ubuntu server 24.0.3/Webserver/apply-apache-stig.sh`
- `Mailserver Fedora 42/Webserver/apply-apache-stig.sh`
- `Splunk Oracle Linux 9.2 Splunk 10.0.2/Webserver/apply-apache-stig.sh`

**STIG Version:** U_Apache_Server_2-4_Unix_Server_V3R2  
**Features:**
- Server tokens hidden (Prod mode)
- TRACE disabled
- SSL/TLS (TLS 1.2+, strong ciphers only)
- Security headers (HSTS, X-Frame-Options, CSP)
- Timeout and connection limits
- Directory listing disabled
- File extension restrictions
- Log configuration and rotation
- Module hardening (disable unnecessary)

**Execution:** `sudo ./apply-apache-stig.sh`  
**Requirements:** Apache 2.4 installed, sudo access

---

### 13. **MySQL 8.0**
**Location:** `Ecommerce ubuntu server 24.0.3/SQL/apply-mysql-stig.sh`  
**STIG Version:** U_Oracle_MySQL_8-0_V2R2  
**Features:**
- Audit logging (JSON format, rotation)
- SSL/TLS required (TLS 1.2+)
- Strong password validation (15 char, complexity)
- Authentication (caching_sha2_password)
- Connection security (max errors: 3)
- Secure file operations (local_infile disabled)
- Binary logging for recovery
- Password history (5) and lifetime (90 days)
- Connection control plugins

**Execution:** `sudo ./apply-mysql-stig.sh`  
**Requirements:** MySQL 8.0 installed, sudo access

---

### 14. **Cisco FTD/ASA 7.x**
**Location:** `Cisco FTD 7.2.9/FTD-STIG-Configuration-Guide.txt`  
**STIG Versions:** U_Cisco_ASA_FW_V2R1, U_Cisco_ASA_NDM_V2R4  
**Features:**
- Password policies (14 char min, complexity)
- Login banner and MOTD
- Comprehensive logging to syslog
- NTP with authentication
- SSH v2 only (2048-bit keys)
- SNMPv3 or disabled
- TACACS+/RADIUS AAA
- Service hardening
- Access control lists
- NAT configuration
- SSL/TLS (TLS 1.2+)
- Failover security (if HA)

**Execution:** CLI commands via SSH or console  
**Requirements:** Cisco FTD/ASA with appropriate license

---

### 15. **Palo Alto PAN-OS 11.x**
**Location:** `PanOS 11.0.2/PAN-STIG-Configuration-Guide.txt`  
**STIG Versions:** U_PAN_ALG_V3R4, U_PAN_IDPS_V3R2, U_PAN_NDM_V3R3  
**Features:**
- Password complexity (15 char, complexity, 5 history)
- Session timeout (15 minutes)
- Login banner
- NTP with authentication
- Comprehensive syslog forwarding
- Management access restrictions
- TACACS+/RADIUS authentication
- Security policies (default deny, logging)
- Threat prevention profiles (AV, AS, Vuln, URL, File Block, WildFire)
- SSL/TLS (TLS 1.2+, strong ciphers)
- SSL decryption policies
- GlobalProtect configuration (if VPN)

**Execution:** CLI or Web UI  
**Requirements:** PAN-OS 11.x with appropriate licenses

---

### 16. **VyOS 1.4.x Router**
**Location:** `Vyos 1.4.3/VyOS-STIG-Configuration-Guide.txt`  
**STIG Versions:** U_Router_V5R2, U_NDM_V5R4  
**Features:**
- Strong passwords (15 char, default user deleted)
- Login banners
- NTP synchronization
- Comprehensive syslog (local + remote)
- SSH hardening (strong ciphers, KEX, MACs)
- SNMPv3 or disabled
- Firewall rules (default deny, stateful)
- NAT configuration
- IPsec VPN (strong crypto)
- Connection tracking
- Reverse path filtering
- ICMP redirect disabled

**Execution:** CLI commands via SSH  
**Requirements:** VyOS 1.4.x

---

## Execution Order

For optimal deployment, follow this order:

### Phase 1: Infrastructure (Days 1-2)
1. **Active Directory/DNS** (if domain environment)
   - `Apply-ADDS-Forest-STIG.ps1` (Forest root DC)
   - `Apply-ADDS-Domain-STIG.ps1` (Each domain)
   - `Apply-DNS-STIG.ps1` (DNS servers)
   - `Apply-Server2019-STIG.ps1` (DC OS hardening)

### Phase 2: Network Security (Days 2-3)
2. **Perimeter Firewalls**
   - Cisco FTD configuration
   - Palo Alto PAN-OS configuration
   
3. **Routing**
   - VyOS router configuration

### Phase 3: Server OS Hardening (Days 3-5)
4. **Windows Servers**
   - Windows Server 2022 (FTP server)
   - Windows Server 2019 (Web server)
   
5. **Linux Servers**
   - RHEL 9 / Fedora (Mailserver)
   - Oracle Linux 9 (Splunk server)
   - Ubuntu Server 24.04 (Ecommerce)

### Phase 4: Application Services (Days 5-7)
6. **Database**
   - MySQL 8.0 (Ecommerce)
   
7. **Web Servers**
   - Apache 2.4 (all locations)
   
8. **Monitoring**
   - Splunk Enterprise

### Phase 5: Workstations (Days 7-8)
9. **End-user Systems**
   - Windows 11 (workstations)
   - Ubuntu Desktop (as needed)

---

## Common Features Across All Scripts

### 1. **Backup Functionality**
- All scripts create timestamped backups before making changes
- Backups include:
  - Configuration files
  - Registry settings (Windows)
  - Security policies
  - Audit policies
  - Database dumps (where applicable)

### 2. **Logging**
- Detailed logs with timestamps
- Log levels: INFO, SUCCESS, WARN, ERROR
- Log locations:
  - Windows: `C:\Windows\Logs\*-STIG-<timestamp>.log`
  - Linux: `/var/log/*-stig-<timestamp>.log`

### 3. **Error Handling**
- Scripts continue on non-critical errors
- Critical errors are logged and displayed
- Exit codes provided for automation

### 4. **Validation**
- Configuration syntax checking (where applicable)
- Service restart verification
- Connectivity testing guidance

### 5. **Post-Implementation Guidance**
- Clear next steps provided at script completion
- Manual configuration items identified
- Testing procedures outlined
- Compliance validation commands included

---

## Testing Procedures

### Before Production Deployment

1. **Lab Environment Testing**
   - Deploy scripts in isolated test environment
   - Verify all functionality
   - Test application compatibility
   - Document any issues

2. **Backup Verification**
   - Ensure backups are created
   - Test restore procedures
   - Verify backup integrity

3. **Rollback Plan**
   - Document rollback procedures
   - Test rollback from backup
   - Identify recovery time objectives

### After Deployment

1. **Functional Testing**
   - Test all critical applications
   - Verify user authentication
   - Check network connectivity
   - Validate service availability

2. **Security Testing**
   - Run vulnerability scans
   - Verify firewall rules
   - Test access controls
   - Review audit logs

3. **Performance Testing**
   - Monitor system resources
   - Check application performance
   - Review log file sizes
   - Validate backup completion times

---

## Compliance Validation

### Windows Systems
```powershell
# Using SCAP Compliance Checker (SCC)
# Download from: https://public.cyber.mil/stigs/scap/
# Run SCC against appropriate XCCDF file

# Manual verification
Get-EventLog -LogName Security -Newest 100
auditpol /get /category:*
gpresult /h gpresult.html
```

### Linux Systems
```bash
# Using OpenSCAP
sudo apt install -y libopenscap8 ssg-base ssg-debderived  # Ubuntu/Debian
sudo dnf install -y openscap-scanner scap-security-guide  # RHEL/Fedora

# Run scan
oscap xccdf eval --profile stig \
  --results /tmp/results.xml \
  --report /tmp/report.html \
  /usr/share/xml/scap/ssg/content/ssg-<distro>-ds.xml

# View report
firefox /tmp/report.html
```

### Network Devices
- Use vendor-specific compliance tools
- Export configurations and compare against baselines
- Use ACAS/Nessus for vulnerability scanning
- Review logs for anomalies

---

## Maintenance and Updates

### Regular Tasks

**Daily:**
- Review security event logs
- Monitor failed authentication attempts
- Check backup completion
- Review firewall logs for anomalies

**Weekly:**
- Review user account status
- Check for system updates
- Validate audit log forwarding
- Review privileged account usage

**Monthly:**
- Update STIG scripts if new versions released
- Review and update firewall rules
- Audit user permissions
- Test backup restore procedures
- Review password expirations

**Quarterly:**
- Run full STIG compliance scans
- Review and update security policies
- Conduct security training refreshers
- Update documentation

### STIG Updates

When new STIG versions are released:

1. Review STIG change documentation
2. Identify new or changed requirements
3. Update scripts accordingly
4. Test in lab environment
5. Deploy to production during maintenance window
6. Document changes
7. Run compliance validation

---

## Troubleshooting

### Common Issues

**Windows Scripts:**
- **Issue:** "Execution policy prevents script execution"  
  **Solution:** `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process`

- **Issue:** "Access denied" errors  
  **Solution:** Ensure running as Administrator with proper permissions

- **Issue:** Group Policy conflicts  
  **Solution:** Review GPO precedence, use `gpresult /h report.html`

**Linux Scripts:**
- **Issue:** "Permission denied"  
  **Solution:** Ensure running with sudo/root, check execute permissions

- **Issue:** Package installation failures  
  **Solution:** Run `apt update` or `dnf update`, check repository configuration

- **Issue:** SELinux/AppArmor blocks  
  **Solution:** Review audit logs (`ausearch` or `/var/log/audit/audit.log`)

**Network Devices:**
- **Issue:** Configuration commit failures  
  **Solution:** Check syntax, verify management session timeout, review error messages

- **Issue:** Connectivity loss after firewall changes  
  **Solution:** Use out-of-band management, implement staged rollback timer

### Recovery Procedures

**Windows:**
```powershell
# Restore from backup
reg import "C:\Windows\Logs\STIG-Backup-<timestamp>\*.reg"
secedit /configure /db secedit.sdb /cfg "C:\Windows\Logs\STIG-Backup-<timestamp>\secedit-backup.inf"
auditpol /restore /file:"C:\Windows\Logs\STIG-Backup-<timestamp>\auditpol-backup.csv"
```

**Linux:**
```bash
# Restore from backup
sudo cp /root/*-stig-backup-<timestamp>/* /etc/ -r
sudo systemctl restart <affected-services>
```

---

## Documentation and Resources

### Official STIG Sources
- **DISA STIG Library:** https://public.cyber.mil/stigs/
- **SCAP Content:** https://public.cyber.mil/stigs/scap/
- **Security Content Automation Protocol (SCAP):** https://csrc.nist.gov/projects/scap

### Vendor Documentation
- **Microsoft:** https://docs.microsoft.com/
- **Red Hat:** https://access.redhat.com/documentation
- **Ubuntu:** https://help.ubuntu.com/
- **Cisco:** https://www.cisco.com/c/en/us/support/
- **Palo Alto:** https://docs.paloaltonetworks.com/
- **VyOS:** https://docs.vyos.io/
- **Apache:** https://httpd.apache.org/docs/
- **MySQL:** https://dev.mysql.com/doc/
- **Splunk:** https://docs.splunk.com/

### Tools
- **SCAP Compliance Checker (SCC):** https://public.cyber.mil/stigs/scap/
- **STIG Viewer:** https://public.cyber.mil/stigs/srg-stig-tools/
- **OpenSCAP:** https://www.open-scap.org/
- **Nessus Professional:** https://www.tenable.com/products/nessus
- **ACAS (Assured Compliance Assessment Solution):** DoD users

---

## Support and Contact

For issues or questions regarding these scripts:

1. Review the script comments and logs
2. Check the official STIG documentation
3. Consult vendor-specific documentation
4. Review the README.md file in the root directory

**IMPORTANT:** Always test in a non-production environment before deploying to production systems.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-30 | Initial release - Complete STIG implementation for all 16 systems |

---

## Disclaimer

These scripts are provided as-is for STIG compliance implementation. While comprehensive, they should be:

- Reviewed and customized for your specific environment
- Tested thoroughly in non-production systems
- Deployed during approved maintenance windows
- Monitored closely after implementation
- Updated regularly as new STIG versions are released

System administrators are responsible for:
- Understanding the changes made by these scripts
- Testing compatibility with existing applications
- Maintaining backups and recovery procedures
- Monitoring system health post-implementation
- Staying current with STIG updates

**Security Note:** Replace all placeholder values (passwords, IP addresses, keys) with appropriate values for your environment. Never use default or example credentials in production.

---

**End of Summary Document**
