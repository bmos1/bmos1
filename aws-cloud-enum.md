# AWS Cloud Environment Enumeration

* The Route53 as routing service in AWS.
* The EC2 instance is a virtual machine in the AWS!
* The S3 is a datastore in AWS. [Methods for accessing a S3 bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-bucket-intro.html).

## Labs exersises require

* Initial configuration on kali linux
* 10-15 min after the deployment
* Result from AWS deployment  
  * Public DNS IP Address
  * Domain name of the target
  * Credentials for the IAM user attacker
    ACCESS_KEY_ID
    SECRET_ACCESS_KEY

```shell
# custom DNS from AWS labs must be the FIRST in the list
sudo gedit /etc/resolv.conf
cat /etc/resolv.conf
nameserver 44.205.254.229
...
nameserver 1.1.1.1

# verify that DNS IP is responding as expected
host offseclab.io 44.205.254.229
# verify that DNS resolver is configured correclty
host offseclab.io
```

After finishing AWS labs restart network service to clean up revolv.conf

```shell
sudo systemctl restart networking
```

## AWS DNS Recon and Find Authoritive DNS

* host to lookup domain name
* -t ns to list name server entries

```shell
# Clear all or specific ARP entries
ip -s -s neigh flush all
arp -d 192.168.1.1

# Get all servers names of authoritative DNS
host -t ns offseclab.io
offseclab.io name server ns-30-c.gandi.net.
offseclab.io name server ns-202-b.gandi.net.
offseclab.io name server ns-196-a.gandi.net.

# Verify AWS
whois awsdns-00.com | grep "Registrant Organization"

# Get public host IP for the domain
host offseclab.io

offseclab.io has address 217.70.184.38
offseclab.io mail is handled by 10 spool.mail.gandi.net.
offseclab.io mail is handled by 50 fb.mail.gandi.net.

# Get public host IP for sub domain services
host www.offseclab.io

www.offseclab.io is an alias for webredir.vip.gandi.net.
webredir.vip.gandi.net has address 217.70.184.50

# Get reverse lookup information
host 217.70.184.38

50.184.70.217.in-addr.arpa domain name pointer webredir.vip.gandi.net.
```

## AWS DNS Automated Recon

```shell
# Find subdomain by brute forcing with dns.txt
dnsenum offseclab.io --threads 100

Brute forcing with /usr/share/dnsenum/dns.txt:                                                                                                                            
_______________________________________________                                                                                                                           
                                                                                                                                                                          
www.offseclab.io.                        3136     IN    CNAME    webredir.vip.gandi.net.                                                                                  
webredir.vip.gandi.net.                  3556     IN    A        217.70.184.50
webmail.offseclab.io.                    4502     IN    CNAME    webmail.gandi.net.
webmail.gandi.net.                       372      IN    A        217.70.178.6

```

```shell
# Find typical DNS verification information in TXT records
host -t txt offseclab.io target-dns-server-IP
```


## AWS DNS Recon Extension OSINT Framework

* Perform enumeration **recursively for each new domain, subdomain and public IP** to get full environment information
* Follow guideline and use tools from [OSINT-Framework](https://osintframework.com/) to gather further valuable information

## AWS Automate Enum

Cloud enumeration tools are avaialable for kali

* Use [cloud-enum](https://www.kali.org/tools/cloud-enum/)
* Use [cloudbrute](https://www.kali.org/tools/cloudbrute/)

CloudEnum

* --keyword KEYWORD
* --keyfile KEYFILE
* --mutations add mutation to provided names
* --quick-scan to disable mutations
* --disalbe-xxx other CSPs


```shell
sudo apt install cloud-enum
cloud_enum --help

# Prepare the brute force keyfile
for key in "public" "private" "dev" "prod" "development" "production"; do echo "offseclab-assets-$key-axevtewi"; done | tee /tmp/keyfile.txt

cloud_enum --keyword offseclab-assets-public-axevtewi --quickscan --disable-azure --disable-gcp
cloud_enum --keyfile /tmp/keyfile.txt--quickscan --disable-azure --disable-gcp
```

Public faced services do have names like

```plain
AWS
s3.amazonaws.com
awsapps.com

Azure
web.core.windows.net
file.core.windows.net
blob.core.windows.net
azurewebsites.net
cloudapp.net

GCP
appspot.com
storage.googleapis.com
```

