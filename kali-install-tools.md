# Install tools on Kali (Arm64 M1)

## Install UTM Shared Folder

Install Spice Guest Tools `https://gist.github.com/lokka30/e2f04045c3b982690279d5ca8da3acb9#file-spice-guest-tools-debian-utm-md`

```bash
sudo apt install spice-vdagent spice-webdavd
# Run spice-vdagent
echo "# Install Spice Guest Tools"  >> .zshrc
echo "spice-vdagent" >> .zshrc
```

## Install Run x86 apps on Arm64

```bash
sudo apt update
sudo apt install -y qemu-user-static binfmt-support
sudo dpkg --add-architecture amd64
sudo apt update
sudo apt install libc6:amd64
```

## Install Docker 

```bash
kali@kali:~$ sudo apt update
kali@kali:~$ sudo apt install -y docker.io
kali@kali:~$ sudo systemctl enable docker --now
```

## Install Shellter x86 only

* **Limitation**: Require x86, 32bit windows only
* Install Shellter for AV Evasion `https://github.com/dekadentno/bootleg-shellter-docker`

```docker
# Dockerfile
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y wget nano && \
    dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y wine32 && \
    rm -rf /var/lib/apt/lists/*

RUN wget https://github.com/ParrotSec/shellter/blob/master/shellter.exe -O /usr/bin/shellter && \
    chmod 775 /usr/bin/shellter && \
    cp /usr/bin/shellter /usr/share/shellter.exe

ENTRYPOINT ["bash"]
```

```bash
sudo docker build --network host --platform linux/amd64 -t shellter:7.2 .
docker run -it --rm shellter:7.2
```

## Install Veil Framework x86 only

* **Limitation**: Require x86 
* Install Veil for AV Evasion `https://github.com/Veil-Framework/Veil`


```bash
sudo apt -y install veil
/usr/share/veil/config/setup.sh --force --silent
```

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
