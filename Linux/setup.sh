#!/bin/bash
set -e

# Checks if script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Please run script as root."
    exit 1
fi

# Run Shared Scripts
echo "Starting SSHD Script"
sudo bash Shared/sshd/setupSSHD.sh
echo "SSHD Script Handed Control to Setup"

echo "Shared Scripts Done."
echo "Starting Machine-Specific Scripts."

# Determine Machine for machine-specific scripts
MACHINE_IP=$(ip route get 172.16.101.1 | awk '{print $7; exit}')

if [[ "$MACHINE_IP" == "172.20.242.20" ]]; then # Detect Splunk & Run Correct Scripts
    echo "Machine Detected: Oracle-Splunk"
    #Install some dependencies, whatever is needed add below here -Thomas
    dnf install -y tmux
    dnf install -y audit
    echo "Dependencies downloaded and installed. You can alert Firewall Master that connection can be cut!"
    sudo bash OracleSplunk/addindexes.sh
    sudo bash OracleSplunk/passwordRefresh.sh
    sudo bash OracleSplunk/fail2banSetup.sh
    sudo bash OracleSplunk/apply-oracle-linux-stig.sh
    sudo bash OracleSplunk/apply-splunk-stig.sh

elif [[ "$MACHINE_IP" == "172.20.242.30" ]]; then # Detect Ecom & Run Correct Scripts
    echo "Machine Detected: Ubuntu-Ecommerce"
    #Install some dependencies, whatever is needed add below here -Thomas
    apt install -y tmux
    apt install -y audit
    echo "Dependencies downloaded and installed. You can alert Firewall Master that connection can be cut!"
    sudo bash UbuntuEcom/initialEcomHardening.sh
    sudo bash UbuntuEcom/ubuntuForwarderInstall.sh
    sudo bash UbuntuEcom/apply-ubuntu-stig.sh
    sudo bash UbuntuEcom/apply-mysql-stig.sh
    sudo bash UbuntuEcom/apply-apache-stig.sh

elif [[ "$MACHINE_IP" == "172.20.242.40" ]]; then # Detect Webmail & Run Correct Scripts
    echo "Machine Detected: Fedora-WebMail"
    #Install some dependencies, whatever is needed add below here -Thomas
    dnf install -y tmux
    dnf install -y audit
    echo "Dependencies downloaded and installed. You can alert Firewall Master that connection can be cut!"
    sudo bash FedoraMail/harden_firewall.sh
    sudo nash FedoraMail/fedoraForwarderInstall.sh
    sudo bash FedoraMail/apply-rhel9-stig.sh
    sudo bash FedoraMail/apply-apache-stig.sh

elif [[ -r /etc/os-release ]]; then # If no IP match, fall back to OS detection (Ubuntu Workstation)
    . /etc/os-release

    if [[ "$ID" == "ubuntu" && "$VERSION_ID" == "24.04" ]]; then
        echo "Machine Detected: Ubuntu-Workstation"
        #Install some dependencies, whatever is needed add below here -Thomas
        apt install -y tmux
        apt install -y audit
        echo "Dependencies downloaded and installed. You can alert Firewall Master that connection can be cut!"
        sudo bash UbuntuWkst/initialUWkstHardening.sh
        sudo bash UbuntuWkst/ubuntuForwarderInstall.sh
        sudo bash UbuntuWkst/apply-ubuntu-desktop-stig.sh

    fi
else
    echo "ERROR: Machine not automatically identified." 
    echo "Please Manually Run Machine-Specific Scripts!"
fi

# Run Audit
echo "Starting Audit"
sudo bash Shared/audit.sh

echo "Main Script Exiting..."
exit 0
