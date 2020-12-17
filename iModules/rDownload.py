from html.parser import HTMLParser
from urllib.request import urlopen 
import os
import re
import requests

re_url = re.compile(r'^(([a-zA-Z_-]+)://([^/]+))(/.*)?$')

# Usage
#download_directory(url,target)
 
# Ansi colors for styling output
cRED  = "\033[38;5;197m"
cCYAN = "\033[1;36m"
cYEL  = "\033[1;33m"
cPNK  = "\033[38;5;219m"
e     = "\033[0m"
side  = cPNK+"│"+cCYAN
divline   = cPNK+"├"+"─"*79+e

### For recursive donwloads

def resolve_link(link, url):
    m = re_url.match(link)
    if m is not None:
        if not m.group(4):
            return link + '/'
        else:
            return link
    elif link[0] == '/':
        murl = re_url.match(url)
        return murl.group(1) + link
    else:
        if url[-1] == '/':
            return url + link
        else:
            return url + '/' + link

class ListingParser(HTMLParser):
    def __init__(self, url):
        HTMLParser.__init__(self)

        if url[-1] != '/':
            url += '/'
        self.__url = url
        self.links = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for key, value in attrs:
                if key == 'href':
                    if not value:
                        continue
                    value = resolve_link(value, self.__url)
                    self.links.add(value)
                    break

def download_directory(url, target):
    def mkdir():
        if not mkdir.done:
            try:
                os.mkdir(target)
            except OSError:
                pass
            mkdir.done = True
    mkdir.done = False
    try:
        print("{} +{} Downloading {}{}{}".format(side,e,cYEL,url,e))
        response = urlopen(url,timeout=5)
        if response.info().get_content_type() == 'text/html':
            contents = response.read()
            parser = ListingParser(url)
            parser.feed(str(contents))
            for link in parser.links:
                link = resolve_link(link, url)
                if link[-1] == '/':
                    link = link[:-1]
                if not link.startswith(url):
                    continue
                name = link.rsplit('/', 1)[1]
                if '?' in name:
                    continue
                mkdir()
                download_directory(link, os.path.join(target, name))
            if not mkdir.done:
                if url[-1] != '/':
                    end = target[-5:].lower()
                    if not (end.endswith('.htm') or end.endswith('.html')):
                        target = target + '.html'
                    with open(target, 'wb') as fp:
                        fp.write(contents)
        else:
            buffer_size = 4096
            with open(target, 'wb') as fp:
                chunk = response.read(buffer_size)
                while chunk:
                    fp.write(chunk)
                    chunk = response.read(buffer_size)
    except:
        print("{}{}   {}> FAILED!{}".format(side,e,cRED,e))
        pass

### File Scraping ##############################################################

# Grab a single file from a URL 
def getSingleFile(fUrl,fpath):
    fOutput = ""
    fOutput += divline + "\n"
    fOutput += "{}{} Grabbing file from {}...\n".format(side,e,fUrl)
    rfile = fUrl.split("/")[-1:]
    url = re.compile(r"https?://")
    urlDir = url.sub('',fUrl.strip().strip('/'))
    fpath = fpath + urlDir
    try:
        dlfile = requests.get(fUrl,timeout=5)
        if dlfile.status_code >= 400:
            fOutput += "{}{}   {}> FAILED! Server status code was: {} {}\n".format(side,e,cRED,dlfile.status_code,e)
            return 0, 0, fOutput
        dlheaders = dlfile.headers 
        os.makedirs(os.path.dirname(fpath),exist_ok=True)
        open(fpath, 'wb').write(dlfile.content)
        return fpath, dlheaders, fOutput
    except:
        fOutput += "{}{}   {}> FAILED!{}".format(side,e,cRED,e)
        return 0, 0, fOutput

# Parse a remote directory and give the path back to the main function
def parseDir(rDirectory,fpath):
    url = re.compile(r"https?://")
    urlDir = url.sub('',rDirectory.strip().strip('/'))
    fpath = fpath + urlDir
    print("{}{} Scraping files... saving to {}{}{}".format(side,e,cCYAN,fpath,e))
    os.makedirs(os.path.dirname(fpath),exist_ok=True)
    download_directory(rDirectory,fpath)
    return fpath
