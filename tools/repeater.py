#!/usr/bin/python3
# repeater.py

import socket
import os
import sys
import time

ip="192.168.188.68"
port=2002

from timeit import default_timer as timer
from datetime import timedelta

def repeat_recv(host : str, port : int) -> bool:
    try:
        with socket.socket() as client:
            client.connect((host,port))
            data = client.recv(256)
            client.send(data)
            print(data.decode())
            data = client.recv(256)
            print(data.decode())
    except ConnectionRefusedError:
        print("Connection refused")
        return False

    return True

def receive_flag(host : str, port : int) -> bool:
    try:
        with socket.socket() as client:
            client.connect((host,port))
            while True:
                try:
                    data = client.recv(1024)
                    if (len(data) == 0):
                        print ("No more data ...")
                        break
                    string = data.decode('utf-8', 'ignore')
                    if(string.find("OS{") != -1):
                        print (string)
                        return True
                
                except UnicodeError as error:
                    print ("Unicode error: ", error)
                    continue
    
    except ConnectionError as error:
        print ("Connnection error: ",  error)
    return False


def receive_jpeg(host: str, port : int) -> bool:
    tempfile="download.dat"
    written=0
    try:
        with open (tempfile, "wb") as file:
            with socket.socket() as client:
                client.connect((host,port))
                while True:
                    data = client.recv(1024)
                    if not data:
                        print (f"Download finished: {str(written)} bytes")
                        break
                    written += file.write(data)

        print ("Split files")
        with open (tempfile, "rb") as temp:
            data = temp.read() 
            files = data.split(b'\r\n\r\n')
            print (f"Number of files {len(files)}")
            for file in files:
                data = file.split(b'.jpg\r\n')
                if(len(data) != 2):
                    break
                filename = data[0].decode() + ".jpg"
                fcontent = data[1]
                print (f"Filename: {filename}" )
                with open (filename, "wb") as jpeg:
                    jpeg.write(fcontent)
        
        print(f"Remove tempfile.")
        os.remove(tempfile)
                
    except ConnectionError as error:
        print ("Connection error: ", error)
        return False
    except IndexError as error:
        print ("Index error: ", error)


    return True

def jpeg_download(host : str, port : int) -> bool:
    buffer = bytearray()
    try:
        with socket.socket() as client:
            client.connect((host,port))
            while True:
                data = client.recv(1024)
                if not data:
                    break
                else:
                    buffer.extend(data)
        print (f"Downloaded {len(buffer)} bytes")

    except ConnectionError as err:
        print ("Connection error: ", err )
        return False

    try:
        chunks = buffer.split(b'\r\n\r\n')
        print (f"Splitted into {len(chunks)} chunks")
        for chunk in chunks:
            data = chunk.split(b'.jpg\r\n')
            if len(data) != 2:
                break
            filename = data[0].decode()+".jpg" 
            fcontent = data[1]
            with open (filename, "wb") as jpeg:
                jpeg.write(fcontent)
            print (f"Write JPEG: {filename}")

    except IOError as err:
        print ("IO Error: ", err)
        return False
    
    return True


def download_file(filename: str, host: str, port: int) -> bool:
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

def binary_split(filename: str) -> bool:
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







print("connecting to ip = " + ip + ", port = " + str(port) + " from = " + socket.gethostname())

#print ("warm up ...")
#time.sleep(15)

start = timer()
tempfile="download.dat"
download_file(tempfile, ip,port)
binary_split(tempfile)
os.remove(tempfile)

#success = 0
#while success < 100:
#    if (repeat_recv(ip,port)):
#        success += 1
#        print("connections = " + str(success))

end = timer()
print(timedelta(seconds=end-start))

