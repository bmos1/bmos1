#!/bin/usr/python3
# port-scanner.py
        
from typing import List
import socket
import time


print("Python port scanner")     

def expand_ips(ip_string: str) -> List[str]:
    """
    Expand IP ranges like '192.168.1.10-20' and single IPs like '192.16.2.15'.
    """
    ips = []
    for part in ip_string.split(','):
        part = part.strip()
        if '-' in part:
            base, rng = part.rsplit('.', 1)
            start, end = rng.split('-')
            for i in range(int(start), int(end) + 1):
                ips.append(f"{base}.{i}")
        else:
            ips.append(part)
    return ips

def expand_ports(port_string: str) -> List[int]:
    """
    Expand port ranges string like '80,443,5432,8080-8443' into a list of ports.
    """
    ports = []
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports

target_ips = expand_ips(input("Enter target IPs (CSV): " ))
target_ports = expand_ports(input("Enter target ports (CSV): "))

print(f"Initiating scan for target IPs: {target_ips}, target ports {target_ports}")
start = time.time()
for ip in target_ips:
    open_ports = []
    print(f"[*] Scan IP: {ip}")
    for port in target_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scan:
            scan.settimeout(.2)
            conn = scan.connect_ex((ip,port))
            if (conn == 0):
                open_ports.append(port)
                print(f"[+] Port {port}: OPEN")
    print(f"[!] Summary {ip}:{','.join(str(port) for port in open_ports)}")
    
totaltime = time.time() - start
print("Total time: %s" %(totaltime) )
