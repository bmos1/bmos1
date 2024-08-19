#!/usr/bin/python3
# html-parser.py 
# utilize beautifulsoup4 (bs4)
# pip install beautifulsoup4
    
import urllib3
import argparse

from urllib.request import urlopen
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(
                    prog='html.parser.py',
                    description='Pyhton HTML parser using BS4')
parser.add_argument('url', type=str, help='Target URL')
parser.add_argument('-v', '--verbose', action="store_true", default=False, help='Verbose output')
parser.add_argument('-t', '--text', action="store_true", default=False, help='Output text')
parser.add_argument('-l', '--link', action="store_true", default=False, help='Output links')
parser.add_argument('-c', '--crawler', action="store_true", default=False, help='Output all text by follwing the links recursive')
args = parser.parse_args()

url = urlopen(args.url)   
page = url.read()
soup = BeautifulSoup(page, "html.parser")

if(args.verbose):
    print (soup.prettify())

if(args.text):
    print("HTML texts ouput")
    print(soup.get_text())

if(args.link):
    print("HTML links ouput")
    for link in soup.find_all("a"):
        print(link.get("href"))

def follow_all_links(soup, base_url):
    for link in soup.find_all("a"):
        target_url =  base_url + link.get("href")
        soup = BeautifulSoup(urlopen(target_url).read(), 'html.parser')
        print(target_url)
        print(soup.get_text())
    
        follow_all_links(soup, base_url)

if(args.crawler):
    # ['https:', '', 'docs.python.org:8080', '3.4', 'tutorial', 'interpreter.html']
    print("HTML crawler follow all links")
    base_url = args.url.split('/')[0] + "//" + args.url.split('/')[2]
    follow_all_links(soup, base_url)
