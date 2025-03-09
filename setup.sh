#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

is_installed() {
    dpkg -l "$1" &> /dev/null
    return $?
}

install_dependencies() {
    echo -e "${YELLOW}[+] Updating system and installing required tools...${NC}"
    sudo apt update -y && sudo apt upgrade -y
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[!] Failed to update system!${NC}"
        exit 1
    fi

    for package in $(cat requirements.txt); do
        if ! is_installed "$package"; then
            echo -e "${YELLOW}[+] Installing $package...${NC}"
            sudo apt install -y "$package"
            if [[ $? -ne 0 ]]; then
                echo -e "${RED}[!] Failed to install $package! Trying alternative methods...${NC}"
                sudo apt-get install -y "$package" || {
                    echo -e "${RED}[!] Installation of $package failed. Please install it manually.${NC}"
                    exit 1
                }
            fi
        else
            echo -e "${GREEN}[✔] $package is already installed.${NC}"
        fi
    done

    echo -e "${GREEN}[✔] All dependencies installed successfully!${NC}"
}

enable_ip_forwarding() {
    echo -e "${YELLOW}[+] Enabling IP Forwarding...${NC}"
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
    sudo sysctl -w net.ipv4.ip_forward=1
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[!] Failed to enable IP forwarding!${NC}"
        echo -e "${YELLOW}[!] Trying alternative method...${NC}"
        sudo sysctl -p /etc/sysctl.conf
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}[!] IP forwarding could not be enabled. Please check your system configuration.${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}[✔] IP Forwarding enabled successfully!${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root!${NC}"
        exit 1
    fi
}

echo -e "${GREEN}[+] Starting setup for MITM DF...${NC}"
check_root
install_dependencies
enable_ip_forwarding
echo -e "${GREEN}[✔] Setup completed successfully!${NC}"
