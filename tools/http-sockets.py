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
