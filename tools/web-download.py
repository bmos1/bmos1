#!/usr/bin/python3
#web-header.py

import requests

URL = "http://192.168.218.68:8080/object"
get = requests.get(URL)
binary = get.content

with open("downloaded", "wb") as f:
    f.write(binary)


from urllib.request import urlretrieve

url = 'http://192.168.218.68:8080/object'
dst = 'downloaded-urlretrieve'
urlretrieve(url, dst)
