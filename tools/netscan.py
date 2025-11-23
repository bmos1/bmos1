#!/bin/usr/python3
# port-scanner.py
        
import socket
import time
import ipaddress

print("Python network scanner")        

target_ip = input("Enter target IP network range: " )
target_ports = input("Enter target ports (CSV): ")
ports = target_ports.split(",")
ip_range = ipaddress.IPv4Network(target_ip, strict=False)

print(f"Initiating scan for target IP: {ip_range}, port range {ports}")

start = time.time()
for ip in ip_range:
    print(f"Scanning {ip}")
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as scan:
            scan.settimeout(.2)
            conn = scan.connect_ex((str(ip),int(port)))
            if (conn == 0):	
                print(f"Port {port}: OPEN")

totaltime = time.time() - start
print("Total time: %s" %(totaltime) )
