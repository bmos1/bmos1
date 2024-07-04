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
* Click Credentials
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

### Working with Plugins in Nessus

* Use `Advanced Dynamic Scan`
* Click to `Dynamic Plugins`
* Search for specific plugin by CVE number etc.  

## Vuln Scan with NMAP scripts

* Performs a lightweight vuln scan if Nessus make too much noise
* Requires scripts to be effective
* Manual `https://nmap.org/book/man-nse.html`
* NSE script are categorized in vuln, exploit, brute forcing, and network discovery, ...
* Use **safe** scripts and avoid **intrusive** because it might crash a target service or system

```bash
cat /usr/share/nmap/scripts/script.db  | grep "\"vuln\""
Entry { filename = "afp-path-vuln.nse", categories = { "exploit", "intrusive", "vuln", } }
Entry { filename = "broadcast-avahi-dos.nse", categories = { "broadcast", "dos", "intrusive", "vuln", } }
...
```

Lookup CVEs using **Vulner** `https://nmap.org/nsedoc/scripts/vulners.html`

* -sV Service detection is required to show PoCs or Exploits
* shows CVEs and more

```bash
# User vulner to lookup newer CVEs
nmap -sV --script vulners [--script-args mincvss=<arg_val>] <target>
# Category vuln = vulnerabilities
sudo nmap -sV -p <ports> --script "safe and vuln" <targets>
# Output example 
CVE-2021-41773  7.5     https://vulners.com/cve/CVE-2021-41773
```

Search for specific CVEs using NSE

* Use google to find NSE scripts
* Search for `cve-2021-41773.nse`
* Download NSE to `/usr/share/nmap/scripts/`
* --script-updatedb required

```bash
# Install script CVE-2021-41773 and update DB
sudo cp ~/Downloads/http-vuln-cve-2021-41773.nse /usr/share/nmap/scripts/http-vuln-cve2021-41773.nse
sudo nmap --script-updatedb
# Run Script
sudo nmap -sV -p <ports> --script "http-vuln-cve2021-41773" <targets>
```
