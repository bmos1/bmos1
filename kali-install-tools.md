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