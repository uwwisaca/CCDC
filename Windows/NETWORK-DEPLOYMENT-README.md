# Network Device STIG Deployment Guide
# Automated SSH Configuration Scripts
# Version: 1.0
# Date: January 30, 2026

## Overview

This directory contains automated SSH deployment scripts to apply STIG configurations to network devices from both Windows and Linux management machines.

## Available Scripts

### Windows PowerShell Scripts (Run from Windows Server 2019)
- **Deploy-Cisco-FTD-STIG.ps1** - Deploys STIG to Cisco FTD/ASA via SSH
  - Use from Windows Server 2019 AD/DNS (172.20.240.102)
  - Target: Cisco FTD (172.20.240.200) - Same network segment

### Linux Bash Scripts (Run from Ubuntu Server)
- **deploy-paloalto-stig.sh** - ⭐ **PRIMARY** Deploys STIG to Palo Alto firewall
  - Use from Ubuntu Ecom Server (172.20.242.30)
  - Target: Palo Alto (172.20.242.150) - Same network segment
- **deploy-vyos-stig.sh** - Deploys STIG to VyOS router
  - Use from Ubuntu Ecom Server (172.20.242.30)
  - Target: VyOS Router (172.16.10.1)
- **deploy-cisco-ftd-stig.sh** - Alternate method for Cisco FTD from Linux

## Prerequisites

### Windows Requirements
```powershell
# Install Posh-SSH module (scripts will auto-install if needed)
Install-Module -Name Posh-SSH -Force -Scope CurrentUser
```

### Linux Requirements
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y sshpass expect

# RHEL/Fedora
sudo dnf install -y sshpass expect
```

## Usage Examples

### From Windows Server 2019 AD/DNS (172.20.240.102)

#### Deploy to Cisco FTD (172.20.240.200) ✅ SAME NETWORK SEGMENT
```powershell


# Interactive (will prompt for passwords)
.\Deploy-Cisco-FTD-STIG.ps1 -HostIP "172.20.240.200" -Username "admin"

# With passwords specified
.\Deploy-Cisco-FTD-STIG.ps1 -HostIP "172.20.240.200" -Username "admin" -Password "IChanged123" -EnablePassword "IChanged123"

# Dry run (test without applying)
.\Deploy-Cisco-FTD-STIG.ps1 -HostIP "172.20.240.200" -Username "admin" -DryRun
```

### From Ubuntu Server (172.20.242.30)

#### Deploy to Cisco FTD
```bash
cd /path/to/CCDC-Stigs
chmod +x deploy-cisco-ftd-stig.sh

# Interactive (will prompt for passwords)
./deploy-cisco-ftd-stig.sh -h 172.20.240.200 -u admin

# With passwords
./deploy-cisco-ftd-stig.sh -h 172.20.240.200 -u admin -p IChanged123 -e IChanged123
Ecom Server (172.20.242.30)

#### Deploy to Palo Alto (172.20.242.150) ⭐ SAME NETWORK SEGMENT - USE THIS!
```bash
cd /path/to/CCDC-Stigs
chmod +x deploy-paloalto-stig.sh

# Interactive (RECOMMENDED)
./deploy-paloalto-stig.sh -h 172.20.242.150 -u admin

# With password
./deploy-paloalto-stig.sh -h 172.20.242.150 -u admin -p Changeme123

# Dry run (test first)
./deploy-paloalto-stig.sh -h 172.20.242.150 -u admin -d
```

#### Deploy to VyOS Router (172.16.10.1)
```bash
chmod +x deploy-vyos-stig.sh

# Interactive
./deploy-vyos-stig.sh -h 172.16.10.1 -u vyos

# With password
./deploy-vyos-stig.sh -h 172.16.10.1 -u vyos -p vyoschangeme

# Dry run
./deploy-vyos-stig.sh -h 172.16.10.1 -u vyos -d
```

#### (Alternative) Deploy to Cisco FTD from Linux
```bash
chmod +x deploy-cisco-ftd-stig.sh

# Note: Cisco FTD is on 172.20.240.x network
# Better to deploy from Windows Server 2019 on same segment
./deploy-cisco-ftd-stig.sh -h 172.20.240.200 -u admin
Network Devices:
- Cisco FTD:                   Inside:  172.20.240.254/24
  └─> Manages: Cisco FTD (172.20.240.200) - SAME SEGMENT ✅

- Ubuntu Ecom Server:         172.20.242.30  (net1: 172.25.20+team#.11)
  └─> Manages: Palo Alto (172.20.242.150) - SAME SEGMENT ✅
  └─> Manages: VyOS Router (172.16.10.1)

- Ubuntu Wks:                 dhcp           (net1: dynamic)

Network Devices:
- Cisco FTD:                   Inside:  172.20.240.254/24 (172.20.240.200 mgmt)
                               Outside: 172.16.102.254/24
                               External: 172.31.21.2/29
                               ⚠️ Deploy from Windows Server 2019 (same 172.20.240.x)

- Palo Alto:                   Management: 172.20.242.150
                               Outside:    172.16.102.254/24
                               Inside:     172.20.242.254/24
                               ⭐ Deploy from Ubuntu Ecom (same 172.20.242.x)

- VyOS Router:                 net1: 172.16.101.1/24
                               net2: 172.25.20.1/24
                               Deploy from Ubuntu Ecom

If you have existing base configurations:

**Palo Alto XML (PanOS 11.0.2/22.xml)**
- Import via Web UI: Device > Setup > Operations > Import Named Configuration Snapshot
- Or use script with `-UseXML` flag (PowerShell only)

**Cisco FTD (.txt config)**
- The scripts read commands from: `Cisco FTD 7.2.9/FTD-STIG-Configuration-Guide.txt`
- To use custom config, modify the `-ConfigFile` parameter

## Logging

All scripts create detailed logs in the `./Logs` directory:
- `cisco-ftd-deploy-YYYYMMDD-HHMMSS.log`
- `paloalto-deploy-YYYYMMDD-HHMMSS.log`
- `vyos-deploy-YYYYMMDD-HHMMSS.log`

## Security Considerations

1. **Credential Management**
   - Never hardcode passwords in scripts
   - Use interactive prompts or secure credential storage
   - Clear credential variables after use

2. **SSH Key Management**
   - Scripts use `-o StrictHostKeyChecking=no` for initial setup
   - After deployment, enable strict host key checking
   - Use SSH keys instead of passwords when possible

3. **Network Isolation**
   - Run deployment from management network only
   - Ensure proper firewall rules allow SSH access
   - Use jump hosts if direct access not available

4. **Backup Before Deployment**
   - Always backup current configurations before running scripts
   - Test in lab environment first
   - Have rollback plan ready

## Troubleshooting

### Connection Timeout
```bash
# Test basic connectivity
ping -c 4 172.20.240.200

# Test SSH port
nc -zv 172.20.240.200 22

# Check firewall rules
# On Windows
Test-NetConnection -ComputerName 172.20.240.200 -Port 22
```

### Authentication Failed
- Verify credentials are correct
- Check account lockout status on device
- Ensure account has proper privileges (enable/config access)

### Commands Not Executing
- Use `-DryRun` / `-d` flag to verify commands
- Check device prompt expectations in expect scripts
- Review log files for specific error messages

### Module/Package Not Found
```powershell
# Windows - Posh-SSH
Get-Module -ListAvailable -Name Posh-SSH
Install-Module -Name Posh-SSH -Force -Scope CurrentUser
```

```bash
# Linux - sshpass/expect
which sshpass expect
sudo apt-get install -y sshpass expect  # Ubuntu
sudo dnf install -y sshpass expect      # RHEL/Fedora
```

## Post-Deployment Validation

### Cisco FTD
```
show running-config
show ntp status
show logging
show ssh sessions
write memory
```

### Palo Alto
```
show config running
show system info
show ntp
show logging-status
commit
```

### VyOS
```
show configuration
show ntp
show log
show firewall
save
```

## CCDC Competition Tips

1. **Pre-stage Scripts**
   - Have all scripts ready before competition starts
   - Test in lab environment beforehand
   - Know the exact IPs and credentials

2. **Quick Deployment Order**
   - Deploy to edge devices first (VyOS, Palo Alto, Cisco FTD)
   - Harden management machines (Windows AD/DNS, Ubuntu)
   - Apply application STIG (IIS, Apache, Splunk, MySQL)

3. **Parallel Execution**
   - Deploy to multiple devices simultaneously from different machines
   - Windows Admin can handle Cisco/Palo while Linux admin does VyOS

4. **Rollback Plan**
   - Keep original configs backed up
   - Know how to restore configurations quickly
   - Test rollback procedures before competition

## Additional Resources

- DISA STIG Library: https://public.cyber.mil/stigs/
- Palo Alto CLI Reference: https://docs.paloaltonetworks.com/
- Cisco ASA/FTD Configuration Guide: https://cisco.com/
- VyOS Documentation: https://docs.vyos.io/

## Support

For issues or questions:
1. Review log files in `./Logs` directory
2. Check device console for error messages
3. Verify network connectivity and credentials
4. Consult configuration guide .txt files for manual steps
