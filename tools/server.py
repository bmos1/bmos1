
#!/bin/usr/python3

import socket

host = "192.168.45.239" #socket.gethostname()
port = 8080

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((host,port))
    server.listen(4)
    print(f"Server {host} is listening for incoming connections on port {port}")
    while True:
        try:
            conn, addr = server.accept()
            print(f"Established connection from IP {addr}")
            msg = "Connection Established" + "\r\n"
            conn.send(msg.encode())
            print("> " + msg)
            data = conn.recv(1024)
            print("< " + data.decode())
            conn.close()
        except ConnectionError as err:
            print("ConnectionError: ",err)
            pass
