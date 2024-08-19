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
