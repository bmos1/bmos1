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

Search environment variable starting with the letter u.

`set u`

```
echo %USERNAME%
set Username
powershell Get-ChildItem env:
set temp="dummy"
setx permant "dummy"
setx /s remote /u user\domain /p password permant "dummy"
setx /s remote /u user\domain /p password permant "dummy" /m
setx TZONE /k HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\TimeZoneInformation\StandardName
```

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
* -u user
* -p password
* -s super user nt authority
* cmd /c <command>

https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

```
psexec -i \myComputer cmd /c "systeminfo"
psexec -i \myComputer -u username -p password cmd
psexec -i \myComputer -u username -p password cmd /c "systeminfo"
psexec.exe -i \\192.168.54.100 -u administrator -p remoteadmin cmd
psexec.exe -i \\192.168.54.100 -u admin -p password cmd /c "type c:\Users\admin\Desktop\psexec-flag1.txt"
psexec.exe -i -s \\192.168.54.100 -u admin -p password cmd /c "type c:\Users\admin\Desktop\file.txt"
```