# Vulnerability Scanning

## Vuln Scan with Nessus

Install Nessus

* Navigate `https://www.tenable.com/downloads/nessus`
* Select `Linux - Ubuntu - aarch64` (MacOS on Arm64)
* Verify sha256sum
* Install .deb
* Start nessusd.service
* Natvigate `https://kali:8834/` 
* Continue and Select `Register for Nessus-Essentials`
* Enter business E-Mail, cause gmail NOT allowed

Nessus License Information
Activation Code: FZNC-NAFC-BJQX-L4RD-N7WW

```bash
# Verify
echo "9840971532c747cc41407054cc39438cf037f9c46e1eea8fa4ae4da76bd2c43b Nessus-10.7.4-ubuntu1804_aarch64.deb" > nessus.sha256
sha256sum -c nessus.sha256
Nessus-10.7.4-ubuntu1804_aarch64.deb: OK
# Install
sudo apt install ./Nessus-10.7.4-ubuntu1804_aarch64.deb
sudo systemctl start nessusd.service
# Configure
firefox https://kali:8834/
```

Using Nessus

* `Host Discovery` creates list of hosts and open ports
* `Basic Network Scan`performs full vulnerability scan (start)
* `Credentialed Patch Audit` performs a local vulerability scan
* `Advanced Dynamic Scan`  searches for CVEs and more (plugins)

### Basic Vulnerability Scan

* Enter Name
* Enter Targets
* Click Discovery
* Select `Custom`
* Navigate to `Port Scanning` and enter ports e.g. 443,80
* Navigate to `Host Discovery` and disable host ping
* Click Save > Launch

Scan Web Applications (Sitemap):

* Click Assesment
* Select `Custom`
* Click Web Applications
* Activite `Scan Web Applications`
* Review `Web Application Sitemap`

### Vulnerability Scan Analysis

* Nessus SYN Scan open ports
* Port Scan 8080,443 -> HTTP Multiple Issue -> INFO -> HTTP Version and Type
* Sitemap 8080,443 -> Web Application Sitemap

### Authenticated Patch Audit

* Enter Name
* Enter Targets
* Click Credential
* Select `SSH`
* Enter user credentials
* Select `sudo` for privilege elevation
* Enter credentials
* Click Save > Launch

Credentials Types

* SSH on Linux and MacOS
* WMI or SMB on Windows
* More credentials types `https://docs.tenable.com/nessus/Content/Credentials.htm`

Host Configurations

* AntiVirus or Firewall may block the scan or terminate the connection
* Configure Windows Hosts for Nessus authenticated assesment `https://docs.tenable.com/nessus/Content/CredentialedChecksOnWindows.htm`

### Patch Audit Analysis

* SSH 22 -> OS Identification and Installed Software Enumeration over SSH
* Patch Report finding lists missing security patches
