# Binary Encoding

```bash 
echo "ibase = 2 ; 111" | bc
echo "obase = 2 ; 7" | bc
```
# Hex Encoding
* hex string to ascii
* -r -p to read plain hexadecimal dumps

```bash
echo "2829" | xxd -r -p
```

# Base64 Encoding
* ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
* 3x8 bits into 4x6 bits letters
* = padding character (end)

```bash
# avoid encoding CRLF
echo -n "Example text" | base64
echo RXhhbXBsZSB0ZXh0Cg== | base64 -d
```

```powershell
echo "RXhhbXBsZSB0ZXh0Cg==" > Base64.txt
certutil -decode Base64.txt outb64.txt
```

GZIP Encoding
* application/gzip
* rename file *.gz
* -N original name
* --keep file

```bash
gzip file.txt
gunzip --keep -N compressed.gz
# gunzip -c
zcat compressed.gz
```

# File Encoding
* --mime -i encoding

```bash
file --mime CarDriver.java
```

# Char Encoding
* -l list all char sets
* -f from encoding 
* -t to encoding
  * //IGNORE ignore not encodable chars (result: ?)
  * //ASCII
  * //TRANSLIT use similar looking char
  * e.g UTF-8//TRANSLIT
* -o output file

```bash
iconv -l 
iconv -f ASCII -t UTF-8 input.txt -o output.txt
iconv -f ISO88592 -t ASCII//TRANSLIT < input.txt > output.txt
``````

