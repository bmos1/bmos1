#!/bin/usr/python3

import socket
import telnetlib

def do_interact(socket):
    t = telnetlib.Telnet()
    t.sock = socket
    t.interact()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()#"192.168.188.68"
port = 8080

client.connect((host, port))
banner = client.recv(1024)
print (banner.decode('utf-8'))
do_interact(client)
client.close()
