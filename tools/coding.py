#!/bin/usr/python3
# interactive-client.py

import socket
import telnetlib

def do_interact(socket):
    t = telnetlib.Telnet()
    t.sock = socket
    t.interact()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "192.168.188.68"
port = 2003

client.connect((host, port))
banner = client.recv(1024)
print (banner.decode('utf-8'))
do_interact(client)
client.close()

#!/bin/usr/python3
# server.py

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

totaltime = time.time() - start
print("Total time: %s" %(totaltime) )


#!/bin/usr/python3
# port-knocker.py

import argparse
import socket
import time

parser = argparse.ArgumentParser(
                    prog='port-knocker',
                    description='Python port knocker')
parser.add_argument('-s', '--sort', action='store_true', default=False, help='sort the ports ascending')
parser.add_argument('ip', type=str, help='Target IP of the host')
parser.add_argument('ports', metavar='port', type=int, nargs='+', help='Target ports to be knocked by the port knocker')

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

#!/usr/bin/python3
#web-client.py

import requests
import argparse
import json

parser = argparse.ArgumentParser(
                    prog='web-client',
                    description='Python web server client')
parser.add_argument('url', type=str, help='Target URL')
parser.add_argument('-d', '--data', type=str, help="HTTP POST request data as JSON object")
parser.add_argument('-q', '--quiet', action="store_true", default=False, help='Quiet mode return response only')
parser.add_argument('-r', '--headers', action="store_true", default=False, help='Output Response headers')
parser.add_argument('-c', '--content', action="store_true", default=False, help='Output response content')
parser.add_argument('-f', '--filename', type=str, help='Output filename')
args = parser.parse_args()

target_url = args.url
data = json.loads(args.data)

if (args.data):
    response = requests.post(target_url, data = data)
    if not args.quiet:
        print(f"Sent HTTP {response.request.method} request to URL {target_url} ")
        print(f"Sent data {args.data} ")
else:
    response = requests.get(target_url)
    if not args.quiet:
        print(f"Sent HTTP {response.request.method} request to URL {target_url} ")

if not args.quiet:
    print(f"HTTP response has {len(response.content)} bytes")
    print(f"HTTP response status code {response.status_code}")

request_headers = response.request.headers if args.headers else ""  
response_headers = response.headers if args.headers else ""
response_content = response.content.decode() if args.content else response.text

if (args.filename) :
    with open(args.filename, "w") as output:
        output.write(request_headers)
        output.write(response_headers)
        output.write(response_content)
else:
    print(request_headers) 
    print(response_headers) 
    print(response_content)

#!/usr/bin/python3
# html-parser.py 
# utilize beautifulsoup4 (bs4)
# pip install beautifulsoup4
    
import urllib3
import argparse

from urllib.request import urlopen
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(
                    prog='html.parser.py',
                    description='Pyhton HTML parser using BS4')
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
    print("HTML texts output")
    print(soup.get_text())

if(args.link):
    print("HTML links output")
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


#!/usr/bin/pyhton3
#web-post.py

import requests

url = 'http://www.offensive-security.com'

info = {'check-key': 'check-value'}
post = requests.post(url, data = info)
print(post.text)



#!/usr/bin/python3   
# A Python program to print all 
# permutations using library function 
from itertools import permutations 
 
# Get all permutations of [1, 2, 3] 
perm = permutations([1, 2, 3]) 
 
# Print the obtained permutations 
for p in list(perm): 
    print (",".join(p)) 
