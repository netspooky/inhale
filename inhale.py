import argparse
import binwalk
import fnmatch
import hashlib
import json
import magic
import os
import re
import requests
import sys
import time
import yara
from datetime import datetime
from elasticsearch import Elasticsearch
from yara import CALLBACK_MATCHES

import iModules
from iModules import *

### PARSER ARGUMENTS ###########################################################
parser = argparse.ArgumentParser(description='inhale')

parser.add_argument('-f', dest='infile', help='File to add')
parser.add_argument('-d', dest='directory', help='Directory to add')
parser.add_argument('-r', dest='rDirectory', help='Remote directory (URL)')
parser.add_argument('-u', dest='urlFile', help='File from a URL')

parser.add_argument('-t', dest='tags', help='Additional Tags')
parser.add_argument('-b', dest='binWalkSigs', help="Turn off binwalk signatures with this flag", action="store_true")
parser.add_argument('-y', dest='yaraRules', action='store', help="Custom Yara Rules")
parser.add_argument('-o', dest='outdir', action='store',
                    help="Store scraped files in specific output dir (default: ./files/<date>/)")
parser.add_argument('-i', dest='noAdd', help="Just print info, don't add files to database", action="store_true")

### Global Vars ################################################################

ts    = time.gmtime()
today = time.strftime("%Y-%m-%d", ts)

# ANSI Colors
cBLK  = "\033[1;30m"
cRED  = "\033[38;5;197m"
cGRN  = "\033[1;32m"
cYEL  = "\033[1;33m"
cBLUE = "\033[1;34m"
cMGNT = "\033[1;35m"
cCYAN = "\033[1;36m"
cWHT  = "\033[1;37m"
cPNK  = "\033[38;5;219m"
cPURP = "\033[38;5;141m"
e     = "\033[0m"

# Text decorations
startline = cPNK+"╭"+"─"*79+e
divline   = cPNK+"├"+"─"*79+e
endline   = cPNK+"╰"+"─"*79+e
side      = cPNK+"│"+cCYAN

banner = """░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          ░░    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    ▒▒████████  ▒▒██  ░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒████  ██  ████  ████  ░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒██████  ██  ██████▒▒██  ░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ████████  ██  ██████▒▒▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░  ██████▒▒▒▒██████▒▒▒▒████▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒██████████\033[5m██\033[0m\033[38;5;219m  \033[5m██\033[0m\033[38;5;219m██████████  ░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░  ████▒▒██████\033[5m██\033[0m\033[38;5;219m  \033[5m██\033[0m\033[38;5;219m████████▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░  ████▒▒████████████████████  ░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░      ██████████████████▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒▒▒▒▒  ████████████████▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒▒▒▒▒▒▒  ████████████▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒▒▒▒▒▒▒  ██████████▒▒    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒    ▒▒▒▒  ░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░  ▒▒▒▒          ▒▒▒▒▒▒▒▒▒▒ ░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      ░░░░░░             ░░░░░░░░░░░░░░░░░░░░░░░░░
\033[1;30;47m                          inhale.py - Malware Inhaler                           """

### Database Functions #########################################################

def elasticPost(fileinfo):
    es = Elasticsearch()
    es.indices.create(index='inhaled', ignore=400)
    try:
        es.index(index="inhaled", doc_type="file", body=fileinfo)
        print("{}{} [+] Added {}{}{}!".format(side,e,cCYAN,fileinfo["filename"],e))
    except:
        print("{}{} {}[!] Could not add {}{} - Try passing -b to disable binwalk signatures!".format(side,e,cRED,fileinfo["filename"],e))

### File Operations ############################################################

# Recursively reads directory and creates a file list
def rGlob(treeroot, pattern):
    results = []
    for base, dirs, files in os.walk(treeroot):
        goodfiles = fnmatch.filter(files, pattern)
        results.extend(os.path.join(base, f) for f in goodfiles)
    return results

### Analysis Functions #########################################################

def getHashes(afile):
    BUF_SIZE = 65536
    hashlist = {}
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(afile, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    hashlist["md5"] = md5.hexdigest()
    hashlist["sha1"] = sha1.hexdigest()
    hashlist["sha256"] = sha256.hexdigest()
    return hashlist

# basically runs file command
def getMagic(afile):
    with magic.Magic() as m:
        filetype = m.id_filename(afile)
    return filetype

def getSize(afile):
    statinfo = os.stat(afile)
    return statinfo.st_size

# Find all URLS in a given file
def urlFind(string):
    url = re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)
    return url

def yaraMatch(data):
  print ("{} - {}{} {}".format(side,cRED,data["rule"],e))
  return yara.CALLBACK_CONTINUE

def binWalkScan(filename):
    sigz = {}
    for module in binwalk.scan(filename, signature=True, quiet=True):
        sigz[module.name] = []
        for result in module.results:
            preppedResult = {"offset": "0x%.8X" %result.offset, "description": result.description}
            sigz[module.name].append(preppedResult)
            print ("{}{}  0x{:08X}{} {}".format(side,cPURP,result.offset,e,result.description))
    return sigz

### Parsing Logic ##############################################################

def parseFile(inputfile):
    finfo    = {}
    binInfo  = r2hook.getBinInfo(inputfile)
    filename = inputfile
    filetype = getMagic(filename)
    baseName = filename.split("/")[-1:][0]
    ext      = baseName.split(".")[-1:][0]
    if ext == baseName:
        ext == "NONE" 
    bf       = open(filename, "rb") 
    binFile  = bf.read()            
    urls     = set(urlFind(binFile))
    fsize    = getSize(filename)
    hashes   = getHashes(filename)
    ###- Building the data structure to post to the database. -###
    finfo["filename"] = filename
    finfo["file_ext"] = ext
    finfo["filesize"] = fsize
    finfo["filetype"] = filetype
    finfo["md5"]      = hashes["md5"]
    finfo["sha1"]     = hashes["sha1"]
    finfo["sha256"]   = hashes["sha256"]
    finfo["added"]    = datetime.now()
    finfo["tags"]     = tags
    if "bin" in binInfo:
        b_arch     = binInfo["bin"]["arch"]
        b_baddr    = binInfo["bin"]["baddr"]
        b_binsz    = binInfo["bin"]["binsz"]
        b_bits     = binInfo["bin"]["bits"]
        b_canary   = binInfo["bin"]["canary"]
        b_class    = binInfo["bin"]["class"]
        b_compile  = binInfo["bin"]["compiled"]
        b_dbgfile  = binInfo["bin"]["dbg_file"]
        b_intrp    = binInfo["bin"]["intrp"]
        b_lang     = binInfo["bin"]["lang"]
        b_lsyms    = binInfo["bin"]["lsyms"]
        b_machine  = binInfo["bin"]["machine"]
        b_os       = binInfo["bin"]["os"]
        b_pic      = binInfo["bin"]["pic"]
        b_relocs   = binInfo["bin"]["relocs"]
        b_rpath    = binInfo["bin"]["rpath"]
        b_stripped = binInfo["bin"]["stripped"]
        b_subsys   = binInfo["bin"]["subsys"]
        # Fill the file info struct
        finfo["r2_arch"]     = b_arch
        finfo["r2_baddr"]    = b_baddr
        finfo["r2_binsz"]    = b_binsz
        finfo["r2_bits"]     = b_bits
        finfo["r2_canary"]   = b_canary
        finfo["r2_class"]    = b_class
        finfo["r2_compiled"] = b_compile
        finfo["r2_dbg_file"] = b_dbgfile
        finfo["r2_intrp"]    = b_intrp
        finfo["r2_lang"]     = b_lang
        finfo["r2_lsyms"]    = b_lsyms
        finfo["r2_machine"]  = b_machine
        finfo["r2_os"]       = b_os
        finfo["r2_pic"]      = b_pic
        finfo["r2_relocs"]   = b_relocs
        finfo["r2_rpath"]    = b_rpath
        finfo["r2_stripped"] = b_stripped
        finfo["r2_subsys"]   = b_subsys
    if "core" in binInfo:
        b_format   = binInfo["core"]["format"]
        b_iorw     = binInfo["core"]["iorw"]
        b_type     = binInfo["core"]["type"]
        finfo["r2_format"]   = b_format
        finfo["r2_iorw"]     = b_iorw
        finfo["r2_type"]     = b_type
    ###- Printing the Output -###
    print(divline)
    print("{} Filename │ {}{}".format(side,e,filename))
    print("{}  FileExt │ {}{}".format(side,e,ext))
    print("{} Filesize │ {}{}".format(side,e,fsize))
    print("{} Filetype │ {}{}".format(side,e,filetype))
    print("{}      MD5 │ {}{}".format(side,e,hashes["md5"]))
    print("{}     SHA1 │ {}{}".format(side,e,hashes["sha1"]))
    print("{}   SHA256 │ {}{}".format(side,e,hashes["sha256"]))
    print("{}──────────┼{}{}".format(side,"─"*68,e))
    print("{}{} BIN INFO {}│{}".format(side,cYEL,cCYAN,e))
    if "bin" in binInfo:
        print("{}     Arch │ {}{}".format(side,e,b_arch))
        print("{} baseAddr │ {}0x{:x}".format(side,e,b_baddr))
        print("{}  binSize │ {}{}".format(side,e,b_binsz))
        print("{}     Bits │ {}{}".format(side,e,b_bits))
        print("{}   Canary │ {}{}".format(side,e,b_canary))
        print("{}    Class │ {}{}".format(side,e,b_class))
        print("{} Compiled │ {}{}".format(side,e,b_compile))
        print("{} dbg_file │ {}{}".format(side,e,b_dbgfile))
        print("{}  Interp. │ {}{}".format(side,e,b_intrp))
        print("{} Language │ {}{}".format(side,e,b_lang))
        print("{}    lSyms │ {}{}".format(side,e,b_lsyms))
        print("{}  Machine │ {}{}".format(side,e,b_machine))
        print("{}       OS │ {}{}".format(side,e,b_os))
        print("{}      PIC │ {}{}".format(side,e,b_pic))
        print("{}   Relocs │ {}{}".format(side,e,b_relocs))
        print("{}    rPath │ {}{}".format(side,e,b_rpath))
        print("{} Stripped │ {}{}".format(side,e,b_stripped))
        print("{}  Subsys. │ {}{}".format(side,e,b_subsys))
    if "core" in binInfo:
        print("{}   Format │ {}{}".format(side,e,b_format))
        print("{}     iorw │ {}{}".format(side,e,b_iorw))
        print("{}     Type │ {}{}".format(side,e,b_type))
        print("{}──────────╯ {}".format(side,e))
    ###- Other matches -###
    print("{}{} YARA {}".format(side,cYEL,e))
    matches = rules.match(data=binFile, callback=yaraMatch, which_callbacks=CALLBACK_MATCHES,timeout=10)
    yMatch = [] 
    if len(matches) == 0:
        print("{}  No Matches{}".format(side,e))
    else:
        for match in matches:
            yMatch.append(match.rule)
    finfo["yara"] = yMatch
    if bwSigz:
        print("{}{} BINWALK {}".format(side,cYEL,e))
        bwSigs = binWalkScan(inputfile)
        finfo["binwalk"] = bwSigs
    if urls:
        urlStr = []
        print("{}{} FOUND \033[31m{}{} URLS\033[0m".format(side,cYEL,len(urls),cYEL))
        for url in urls:
            print("{} - {}{}".format(side,e,url.decode("utf-8")))
            urlStr.append(url.decode("utf-8"))
        finfo["urls"] = urlStr
    bf.close()
    return finfo

### File Scraping ##############################################################

# Grab a single file from a URL 
def getSingleFile(fUrl,fpath):
    print("{}{} Grabbing file from {}...".format(side,e,fUrl))
    rfile = fUrl.split("/")[-1:]
    url = re.compile(r"https?://")
    urlDir = url.sub('',fUrl.strip().strip('/'))
    fpath = fpath + urlDir
    try:
        dlfile = requests.get(fUrl,timeout=5)
        os.makedirs(os.path.dirname(fpath),exist_ok=True)
        open(fpath, 'wb').write(dlfile.content)
        return fpath
    except:
        print("{}{}   {}> FAILED!{}".format(side,e,cRED,e))
        print(endline)
        exit()

# Parse a remote directory and give the path back to the main function
def parseDir(rDirectory,fpath):
    url = re.compile(r"https?://")
    urlDir = url.sub('',rDirectory.strip().strip('/'))
    fpath = fpath + urlDir
    print("{}{} Scraping files... saving to {}{}{}".format(side,e,cCYAN,fpath,e))
    os.makedirs(os.path.dirname(fpath),exist_ok=True)
    rDownload.download_directory(rDirectory,fpath)
    return fpath

### Main logic #################################################################
if __name__ == '__main__':

    args       = parser.parse_args()
    infile     = args.infile
    directory  = args.directory
    rDirectory = args.rDirectory
    urlFile    = args.urlFile
    tags       = args.tags
    bwSigz     = args.binWalkSigs

    ###- Switches -###
    if args.yaraRules:
        rules = yara.compile(args.yaraRules)
    else:
        rules = yara.compile('YaraRules/index.yar')
    if args.outdir:
        fpath = "./" + args.outdir + "/"
    else:
        fpath = "./files/" + today + "/"
    if args.noAdd:
        add2db = 0
    else:
        add2db = 1
    if args.binWalkSigs:
        bwSigz = 0
    else:
        bwSigz = 1
    if tags:
        tags = args.tags
    else:
        tags = ""
    ### End Switches
    print(cPNK + banner + e)
    print(startline)
    print("{} * T A S K S * {}".format(side,e))
    if infile:
        print("{}{} + Printing information for {}{}{}".format(side,e,cCYAN,infile,e))
        try:
            inn = parseFile(infile)
        except BrokenPipeError:
            print("{}{} {}[!] File not found!{}".format(side,e,cRED,e))
            print(endline)
            sys.exit(1)
        if add2db:
            elasticPost(inn)
        else:
            z = 0
    elif directory:
        dirlist = rGlob(directory,"*")
        if len(dirlist) > 0:
            print("{}{} + Printing information for all files in {}{}{}".format(side,e,cCYAN,directory,e))
            if add2db:
                print("{}{} + Adding Directory {}{}{} to database".format(side,e,cCYAN,directory,e))
            for ff in dirlist:
                inn = parseFile(ff)
                if add2db:
                    elasticPost(inn)
        else:
            print("{}{}{} [!] No files found!{}".format(side,e,cRED,e))
            print(endline)
            sys.exit(1)
    elif urlFile:
        singleFile = getSingleFile(urlFile,fpath)
        inn = parseFile(singleFile)
        if add2db:
            inn["url"] = urlFile
            elasticPost(inn)
    elif rDirectory:
        fpath = parseDir(rDirectory,fpath)
        dirlist = rGlob(fpath,"*")
        if len(dirlist) > 0:
            print("{}{} + Printing information for all files scraped from {}{}{}".format(side,e,cCYAN,rDirectory,e))
            for ff in dirlist:
                inn = parseFile(ff)
                if add2db:
                    inn["url"] = rDirectory
                    elasticPost(inn)
        else:
            print("{}{}{} [!] No files downloaded!{}".format(side,e,cRED,e))
            print(endline)
            sys.exit(1)
    print(endline)
