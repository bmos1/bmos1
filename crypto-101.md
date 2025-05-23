# ROT13 Substitution Cipher
* Special case of Cesar Chiffre
* Substitute A-Z by rotation of 13 starting with N
* Translate or delete chars https://linux.die.net/man/1/tr

```bash
echo text to encrypt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
echo grkg gb rapelcg | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

# Weak XOR Stream Cipher
* key len is not equal to message
* message is a string not a bytearray

```python
#!/usr/bin/python3
import base64
from itertools import cycle 

key = 'K'.encode()
message = 'text to encrypt ЖИЛ'.encode()

encrypted = bytearray()
for m,k in zip (message, cycle(key)):
    encrypted.append(m^k)
print(f'Encrypted: {base64.b64encode(encrypted).decode()}')

decrypted = bytearray()
for c,k in zip (encrypted, cycle(key)):
    decrypted.append(c^k)
print(f'Decrypted: {decrypted.decode()}')
```

# Symmetric Block Cipher
* http://irtfweb.ifa.hawaii.edu/~lockhart/gpg/
* Secure because requires 64 bits blocks
* Use gpg to encrypt data with secret key
* List --cipher-algo with gpg --version
* -c, --symmetric with passphrase
* -d, --decrypt
* --output file

```bash
echo "Symmetric encryption." > msg
gpg -c --cipher-algo aes256 msg
gpg -c --cipher-algo twofish msg
gpg -d msg.gpg
file msg.gpg
```
# Asymmetric Cipher
* Use gpg to encrypt data with public key
* --amor ascii output instead of binary

```bash
# import keys to keyring
gpg --import pub.asc
gpg --import private.asc
```

```bash
echo "Asymmetric encryption." > msg
gpg --gen-key
gpg --output pub.asc --amor --export user@email.com
gpg --recipient Offsec --encrypt msg
gpg -d msg.gpg
```

# RSA Number Factorization
* Online RSA Calculators
* https://www.alpertron.com.ar/ECM.htm
* https://www.cs.drexel.edu/~jpopyack/Courses/CSP/Fa17/notes/10.1_Cryptography/RSA_Express_EncryptDecrypt_v2.html
* https://www.cs.drexel.edu/~jpopyack/Courses/CSP/Fa17/notes/10.1_Cryptography/RSAWorksheetv4e.html

# SSH Key Generation and Distribution
* Distribute key to authorized_keys file

```bash
ssh-gen
ssh-copy-id -i /home/kali/.ssh/id_rsa.pub user@remote
ssh -i /home/kali/.ssh/id_rsa.pub user@remote
scp -i /home/kali/.ssh/id_rsa path-to-file user@remote:/tmp/
```

# OpenSSL Key Generation

* -newkey Generate new key instead algorithm
* -x509 Output an X.509 certificate structure instead of a cert request
* -nodes Deprecated to no encrypt private key
* -noenc No encrypt private key

```bash
openssl req -newkey rsa:2048 -noenc -keyout bind_shell.key -x509 -days 45 -out bind_shell.crt
```

# SOCAT OpenSSL encrypted Bind-Shell

* use x509 cert to encrypt connection to bindshell listener
* verify=0 tells socat to not to check the client's certificate.
* fork spawn a child process
* EXEC:/bin/bash 


```bash
cat bind_shell.key bind_shell.crt > bind_shell.pem
sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
# client without cert and verification
socat - OPENSSL:remote:443,verify=0
```