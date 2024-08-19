#!/usr/bin/python3
#web-client.py

import requests
import argparse

parser = argparse.ArgumentParser(
                    prog='http-sockets',
                    description='Python web server client based on raw sockets communication')
parser.add_argument('url', type=str, help='Target URL')
parser.add_argument('-q', '--quiet', action="store_true", default=False, help='Quiet mode return response only')
parser.add_argument('-r', '--headers', action="store_true", default=False, help='Output Response headers')
parser.add_argument('-c', '--content', action="store_true", default=False, help='Output response content')
parser.add_argument('-f', '--filename', type=str, help='Output filename')
args = parser.parse_args()

target_url = args.url
response = requests.get(target_url)

if not args.quiet:
    print(f"Sent HTTP GET request to URL {target_url} ")
    print(f"HTTP response has {len(response.content)} bytes")
    print(f"HTTP response status code {response.status_code}")

response_headers = response.headers if args.headers else ""
response_content = response.content.decode() if args.content else response.text

if (args.filename) :
    with open(args.filename, "w") as output:
        output.write(response_headers)
        output.write(response_content)
else:
    print(response_headers) 
    print(response_content)
