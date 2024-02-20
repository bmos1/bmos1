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

```
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
# Administering Active Directory