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
