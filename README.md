# MITM-DF 
#آلقيـــــــــــــــآدهہ‌‏ آلزعيـــم
```markdown
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

---

## Installation:

### Step 1: Clone the Repository
Clone the tool from the GitHub repository:
```


```bash
git clone https://github.com/MohamedAbuAl-Saud/MITM-DF
cd MITM DF
sudo apt update
     sudo apt install -y ettercap-text-only sslstrip iptables nmap dsniff driftnet bettercap python3
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

## Support:
For support or questions, contact the developer via [Telegram](https://t.me/A_Y_TR) or visit the [Telegram Channel](https://t.me/cybersecurityTemDF).
