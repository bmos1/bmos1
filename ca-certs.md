# List certs and CAs in PEM format 
* Linux 
* MacOS

```bash
cat /opt/homebrew/etc/ca-certificates/cert.pem | awk -v decoder='openssl x509 -noout -subject 2>/dev/null' ' /BEGIN/{close(decoder)};{print | decoder }'
security find-certificate -a -p | awk -v decoder='openssl x509 -noout -subject 2>/dev/null' ' /BEGIN/{close(decoder)};{print | decoder }'
```

# Verify certs and CAs in PEM format
* Linux
* MacOS

```bash
openssl verify -show_chain server-chain.pem
security verify-cert -v -c server-chain.pem
```

# Add and remove trusted CAs 
Linux
```bash
sudo cp foo.crt /usr/local/share/ca-certificates/foo.crt
sudo update-ca-certificates --fresh
```

MacOS
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/new-root-certificate.crt
sudo security delete-certificate -c "<name of existing certificate>"
```

Windows
```powershell
certutil -addstore -f "ROOT" new-root-certificate.crt
certutil -delstore "ROOT" serial-number-hex
```


# Linux CA path

```bash
ll /etc/ssl
```

# MacOS CA path

```bash
sudo security list-keychains
ll /System/Library/Keychains/
ll /Library/Keychains/
ll ~/Library/Keychains/
ll /opt/homebrew/etc/ca-certificates/
ll /etc/ssl
```

# Ressources
* https://learnings.bolmaster2.com/posts/add-certificates-to-trust-stores.html
* https://manuals.gfi.com/en/kerio/connect/content/server-configuration/ssl-certificates/adding-trusted-root-certificates-to-the-server-1605.html

