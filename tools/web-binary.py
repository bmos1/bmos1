#!/usr/bin/python3
#web-header.py

import requests
URL = "http://192.168.218.68:8080/object"
get = requests.get(URL)
with open("downloaded-manual", "wb") as f:
    f.write(get.content)


from urllib.request import urlretrieve
url = 'http://192.168.218.68:8080/object'
dst = 'downloaded-urlretrieve'
urlretrieve(url, dst)