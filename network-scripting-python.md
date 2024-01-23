# Network Scripting

* Write a client program with Python
* Write a server program with Python
* Write a port scanner with Python
* Website interaction with Python
* Website parser with Pyhton
* Capture and send packets with Scapy

https://www.kali.org/docs/introduction/default-credentials/

# Write a ping

```python
#!/usr/bin/python3
# ping.py
# ping throws socket.gaierror
ping = socket.gethostbyname('www.google.com')
print(ping)
host = socket.gethostbyaddr('8.8.8.8')
print(host)
```

# Write Python client
* https://docs.python.org/3/library/socket.html
* https://www.geeksforgeeks.org/socket-programming-python/

```python
#!/usr/bin/python3
# client.py
import socket
# AF_INET = IPv4, AF_INET6, IPv6
# AF_UNIX = Unix Domain Sockets (interprocess)
# SOCK_DGRAM = UDP, SOCK_STREAM = TCP 
# client = socket.socket(family = socket.AF_INET, type = socket.SOCK_STREAM, proto = 0)
try:
    with socket.socket() as client: 
        client.connect((host,port)) # tuple host port
        data = client.recv(1024)
        print data.decode('utf-8')  # decode from bytes
except ConnectionRefuseError:
    pass
```

## Python client interactive TELNET
* https://docs.python.org/3/library/telnetlib.html

```python
#!/bin/usr/python3
# interactive-client.py
import socket
import telnetlib

def do_interact(socket):
    t = telnetlib.Telnet()
    t.sock = socket
    t.interact()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "10.0.0.1"
port = 1234

client.connect((host, port))
banner = client.recv(1024)
print (banner.decode('utf-8'))
do_interact(client)
client.close()
```

## Python client to download binary file with arbitrary length

```python
#!/usr/bin/python3
# download-file.py
import sys
import socket

def binary_download(filename: str, host: str, port: int) -> bool:
    written = 0
    try: 
        with open (filename, "wb") as file:
            with socket.socket() as client:
                client.connect((host,port))
                while True:
                    data = client.recv(1024)
                    if not data:
                        print (f"Download finished: {str(written)} bytes")
                        return True
                    written += file.write(data)
    except ConnectionError as err:
        print ("Connection error: ", err)
    except IOError as err:
        print ("IO error:", err)
    
    return False
```

```python
#!/usr/bin/python3
# download-file.py
    import requests
    url = "http://10.0.0.1:1234/download"
    get = requests.get(url)
    with open("downloaded", "wb") as f:
    f.write(get.content)

    # using urlretrieve
    from urllib.request import urlretrieve
    url = "http://10.0.0.1:1234/download"
    dst = 'downloaded'
    urlretrieve(url, dst)
```

## Python split binary file content 

```python
#!/usr/bin/python3
# split-binary.py
import os
import sys

def split_binary(filename: str) -> bool:
    separator=b'\r\n\r\n'
    try:
        with open(filename, "rb") as file:
            files = file.read().split(separator)
            for file in files:
                data = file.split(b'.jpg\r\n')
                # filename \r\n content
                if len(data) != 2:
                    break
                filename = data[0].decode() + ".jpg"
                fcontent = data[1]
                print(f"Filename: {filename}, {len(fcontent)} bytes")
                with open (filename, "wb") as jpeg:
                    jpeg.write(fcontent)
        return True

    except IOError as err:
        print ("IO error: ", err)
    except IndexError as err:
        print ("Index error: ", err)

    return False
```

# Write Python Server
```python
#!/bin/usr/python3
# simple-server.py
import socket

host = socket.gethostname()
port = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((host,port))
    server.listen(2)
    print(f"Server is listening for incoming connections on port {port}")
    while True:
        try:
            conn, addr = server.accept()
            print(f"Established connection from IP {addr}")
            msg = "Connection Established" + "\r\n"
            conn.send(msg.encode())
            conn.close()
        except ConnectionError as err:
            print("ConnectionError: ", err)
            pass
```

# Write Python Port Scanner
```python
#!/bin/usr/python3
# port-scanner.py        
import socket
import time

print("Python port scanner")        
target_ip = input("Enter target IP: " )
target_portrange = input("Enter target port range min-max: ")
target_ports = target_portrange.split("-")
if(len(target_ports) != 2):
    print("Invalid input port range")
    exit(1)

ports_start = int(target_ports[0])
ports_end = int(target_ports[1])

print(f"Initiating scan for target IP: {target_ip}, port range {ports_start}-{ports_end}")
open_ports = []
start = time.time()
for port in range(ports_start, ports_end):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
        conn = scanner.connect_ex((target_ip,port))
        if (conn == 0):
            open_ports.append(port)
            print(f"Port {port}: OPEN")

print("Summary...")
print(f"Open ports: {', '.join(str(port) for port in open_ports)}")
totaltime = start - time.time()
print("Total time: %s" %(totaltime) )
```

# Write Python Port Knocker
```python
#!/bin/usr/python3
# port-knocker.py
import argparse
import socket
import time

parser = argparse.ArgumentParser(prog='port-knocker', description='Python port knocker')
parser.add_argument('-s', '--sort', action='store_true', default=False, help='sort the ports')
parser.add_argument('ip', type=str, help='Target IP of the host')
parser.add_argument('ports', metavar='port', type=int, nargs='+', help='Target ports')
args = parser.parse_args()

target_ip = args.ip
target_ports = args.ports
if(args.sort):
    target_ports.sort()

print(f"Initiating knocker for target IP: {target_ip}, ports {target_ports}")
open_ports = []
start = time.time()
for port in target_ports:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scanner:
        conn = scanner.connect_ex((target_ip,port))
        if (conn == 0):
            open_ports.append(port)
            print(f"Port {port}: OPEN")
totaltime = time.time() - start

print("Summary...")
print(f"Open ports: {', '.join(str(port) for port in open_ports)}")
print(f"Total time: {totaltime}" )
```

# Write a HTTP web server scanner using sockets

```python
#!/usr/bin/python3
#http-sockets.py
import socket
import argparse

parser = argparse.ArgumentParser(
                    prog='http-sockets',
                    description='Python web server client based on raw sockets communication')
parser.add_argument('host', type=str, help='Target hostname of the host')
parser.add_argument('-p', '--port', type=int, default=80, help='Target ports to be scanned')
parser.add_argument('-f', '--filename', type=str, help='Output filename')
args = parser.parse_args()

remote_host = args.host
remote_port = args.port

print(f"Sent HTTP request to server {remote_host} on port {remote_port}")
request = "GET / HTTP/1.1\r\nHost: " + remote_host + "\r\n\r\n"
print(request)

try:
    response = bytearray()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((remote_host,remote_port))
        client.send(request.encode())
        while True:
            chunk = client.recv(1024)
            if not chunk:
                break
            else:
                response.extend(chunk) 
    print(f"HTTP response has {len(response)} bytes")

    if (args.filename) :
        with open(args.filename, "w") as output:
            output.write(response.decode())
    else: 
        print(response.decode())

except ConnectionError as err:
    print("ConnectionError: ", err)
    pass
```

# Write Python web client

```python
#!/usr/bin/python3
#web-client.py

import requests
import argparse

parser = argparse.ArgumentParser(prog='web-client', description='Python web-client')
parser.add_argument('url', type=str, help='Target URL')
parser.add_argument('-q', '--quiet', action="store_true", default=False, help='Quiet mode')
parser.add_argument('-r', '--headers', action="store_true", default=False, help='Output Response headers')
parser.add_argument('-c', '--content', action="store_true", default=False, help='Output response content')
parser.add_argument('-f', '--filename', type=str, help='Output filename')
args = parser.parse_args()

target_url = args.url
response = requests.get(target_url)

if not args.quiet:
    print(f"Sent HTTP GET request to URL {target_url} ")
    print(f"HTTP response has {len(response.content)} bytes")
    print(f"HTTP response status code {response.status_code}")

response_headers = response.headers if args.headers else ""
response_content = response.content.decode() if args.content else response.text

if (args.filename) :
    with open(args.filename, "w") as output:
        output.write(response_headers)
        output.write(response_content)
else:
    print(response_headers) 
    print(response_content)
```

# Write Python HTML parser using BS4
* https://www.crummy.com/software/BeautifulSoup/bs4/doc/

```python
#!/usr/bin/python3
# html-crawler.py 
# pip3 install beautifulsoup4
    
import urllib3
import argparse
from urllib.request import urlopen
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(prog='html.parser.py', description='Pyhton HTML parser using BS4')
parser.add_argument('url', type=str, help='Target URL')
parser.add_argument('-v', '--verbose', action="store_true", default=False, help='Verbose output')
parser.add_argument('-t', '--text', action="store_true", default=False, help='Output text')
parser.add_argument('-l', '--link', action="store_true", default=False, help='Output links')
parser.add_argument('-c', '--crawler', action="store_true", default=False, help='Output all text by follwing the links recursive')
args = parser.parse_args()

url = urlopen(args.url)   
page = url.read()
soup = BeautifulSoup(page, "html.parser")

if(args.verbose):
    print (soup.prettify())

if(args.text):
    print("HTML texts ouput")
    print(soup.get_text())

if(args.link):
    print("HTML links ouput")
    for link in soup.find_all("a"):
        print(link.get("href"))

def follow_all_links(soup, base_url):
    for link in soup.find_all("a"):
        target_url =  base_url + link.get("href")
        soup = BeautifulSoup(urlopen(target_url).read(), 'html.parser')
        print(target_url)
        print(soup.get_text())
    
        follow_all_links(soup, base_url)

if(args.crawler):
    # ['https:', '', 'docs.python.org:8080', '3.4', 'tutorial', 'interpreter.html']
    print("HTML crawler follow all links")
    base_url = args.url.split('/')[0] + "//" + args.url.split('/')[2]
    follow_all_links(soup, base_url)
```


```python
#!/usr/bin/python3
# html-table-parser.py 
# pip3 install beautifulsoup4
from urllib.request import urlopen
from bs4 import BeautifulSoup

def parse_table(srcURL : URL) -> list:
    with urlopen(srcURL) as src:

        page = src.read()
        soup = BeautifulSoup(page, "html.parser")
        table = soup.find('table', attrs={'class':'table'})
        table_body = table.find('tbody')

        dataset = []
        rows = table_body.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            entry = []
            for col in cols:
                entry.append(col.text)
            dataset.append(entry)
        return dataset
```

# Write Python HTTP post client
```python
#!/usr/bin/pyhton3
# web-form-post.py

import requests
url = 'http://www.offensive-security.com'
info = {'check-key': 'check-value'}
post = requests.post(url, data = info)
print(post.text)
```

```python
#!/usr/bin/pyhton3
# html-form.login.py
def login(targetURL : URL, user: str, password: str) -> bool:
    global total_logins
    total_logins += 1
    form = {}
    form["username"]=user
    form["password"]=password
    post = requests.post(targetURL, data=form)
    soup = BeautifulSoup(post.text, "html.parser")
    div = soup.find("div", attrs={'class':'container'})  
    return (div.get_text(), post.status_code)
```

# Scapy
* https://scapy.readthedocs.io/en/latest/usage.html#simple-one-liners

```python
pkt1 = IP(dst="10.0.0.1", ttl=100) / TCP(dport=9876)
pkt1.show()
sr1(pkt1)

pkt2 = IP (dst = "10.0.0.1") / ICMP() / "Hello!"
pkt2.show()
sr1(pkt2)

pkt3 = IP (dst = "10.0.0.1") / UDP(dport=9876)/ "Hello!"
pkt3.show()
sr1(pkt3)

# scapy-icmp-ping.py
ans, unans = sr(IP(dst="192.168.1.0/24")/ICMP(), timeout=3)
ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )

#scapy-ack-scan.py
ans, unans = sr(IP(dst="www.slashdot.org")/TCP(dport=[80,666],flags="A"))
for s,r in ans:
    if s[TCP].dport == r[TCP].sport:
       print("%d is unfiltered" % s[TCP].dport)
for s in unans:
    print("%d is filtered" % s[TCP].dport)
```

# Permutation in Pyhton

```python
#!/usr/bin/python3   
# A Python program to print all 
# permutations using library function 
from itertools import permutations 
 
# Get all permutations of [1, 2, 3] 
perm = permutations([1, 2, 3]) 
 
# Print the obtained permutations 
for p in list(perm): 
    print (",".join(p)) 
```    

# Remove duplicates in pyhton list

```python 
# remove duplicates
colors = {"red", "green", "blue", "green"}
colors = list(set(colors))
```