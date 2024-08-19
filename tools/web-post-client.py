#!/usr/bin/python3
#web-client.py

import requests
import argparse
import json

parser = argparse.ArgumentParser(
                    prog='web-client',
                    description='Python web server client')
parser.add_argument('url', type=str, help='Target URL')
parser.add_argument('-d', '--data', type=str, help="HTTP POST request data as JSON object")
parser.add_argument('-q', '--quiet', action="store_true", default=False, help='Quiet mode return response only')
parser.add_argument('-r', '--headers', action="store_true", default=False, help='Output Response headers')
parser.add_argument('-c', '--content', action="store_true", default=False, help='Output response content')
parser.add_argument('-f', '--filename', type=str, help='Output filename')
args = parser.parse_args()

target_url = args.url
data = json.loads(args.data)

if (args.data):
    response = requests.post(target_url, data = data)
    if not args.quiet:
        print(f"Sent HTTP {response.request.method} request to URL {target_url} ")
        print(f"Sent data {args.data} ")
else:
    response = requests.get(target_url)
    if not args.quiet:
        print(f"Sent HTTP {response.request.method} request to URL {target_url} ")

if not args.quiet:
    print(f"HTTP response has {len(response.content)} bytes")
    print(f"HTTP response status code {response.status_code}")

request_headers = response.request.headers if args.headers else ""  
response_headers = response.headers if args.headers else ""
response_content = response.content.decode() if args.content else response.text

if (args.filename) :
    with open(args.filename, "w") as output:
        output.write(request_headers)
        output.write(response_headers)
        output.write(response_content)
else:
    print(request_headers) 
    print(response_headers) 
    print(response_content)
