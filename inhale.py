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
import time

import iModules
from iModules import *

CONFIG = helper.CONFIG # This imports our config file for use

### PARSER ARGUMENTS ###########################################################
parser = argparse.ArgumentParser(description='inhale')

parser.add_argument('-f', dest='infile', help='Analyze a single file')
parser.add_argument('-d', dest='directory', help='Analyze a directory of files')
parser.add_argument('-u', dest='urlFile', help='Analyze a remote file (url)')
parser.add_argument('-r', dest='rDirectory', help='Analyze a remote directory (url)')
parser.add_argument('-l', dest='urlList', help='Analyze a list of URLs in a text file')
parser.add_argument('-t', dest='tags', help='Add additional tags to the output.')
parser.add_argument('-b', dest='binWalkSigs', help="Turn off binwalk signatures", action="store_true")
parser.add_argument('-y', dest='yaraRules', action='store', help="Specify custom Yara Rules")
parser.add_argument('-o', dest='outdir', action='store',
                    help="Store scraped files in specific output dir (default: ./files/<date>/)")
parser.add_argument('-i', dest='noAdd', help="Just print info, don't add files to database", action="store_true")
parser.add_argument('--html', dest='htmlout', help="Save output as html to the webdir.", action="store_true")

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
        es.index(index="inhaled", body=fileinfo)
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

def setMagicFlags(m):
    # 0 Regular File
    # 1 ELF
    # 2 PE
    # 3 PDF
    # 4 Archive
    if m[0:3] == "ELF":
      return 1
    elif m[0:2] == "PE":
      return 2
    elif m[0:3] == "PDF":
      return 3
    elif "archive" in m:
      return 4
    elif "bzip2" in m:
      return 4
    elif "gzip" in m:
      return 4
    else:
      return 0

def getSize(afile):
    statinfo = os.stat(afile)
    return statinfo.st_size

# Find all URLS in a given file
def urlFind(string):
    url = re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*(),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)
    return url

def binWalkScan(filename):
    sigz = {}
    for module in binwalk.scan(filename, signature=True, quiet=True):
        sigz[module.name] = {}
        for result in module.results:
            sigz[module.name]["0x%.8X" %result.offset] = result.description
    return sigz

def yaraMatch(data):
  return yara.CALLBACK_CONTINUE

### Parsing Logic ##############################################################

def parseFile(inputfile):
  try:
    finfo    = {} # This holds all of the scan data 
    binInfo  = r2hook.getBinInfo(inputfile) # The binary data from radare2
    filename = inputfile
    filetype = getMagic(filename) # Get filetype from magic value
    fileFlag = setMagicFlags(filetype) # Get magic code, if any
    baseName = filename.split("/")[-1:][0]
    ext      = baseName.split(".")[-1:][0]
    if ext == baseName:
        ext == "NONE" 
    bf       = open(filename, "rb") 
    binFile  = bf.read()             # A buffer of the binary file
    urls     = set(urlFind(binFile)) # Finding urls in the file
    fsize    = getSize(filename)     # Get file size
    hashes   = getHashes(filename)   # Get MD5, SHA1, and SHA256

    ###- Building the data structure to post to the database. -###
    finfo["filename"] = filename
    finfo["file_ext"] = ext
    finfo["filesize"] = fsize
    finfo["filetype"] = filetype
    finfo["md5"]      = hashes["md5"]
    finfo["sha1"]     = hashes["sha1"]
    finfo["sha256"]   = hashes["sha256"]
    finfo["added"]    = datetime.now()
    finfo["tags"]     = tags # Tags from command line

    if "bin" in binInfo:
        # Fill the file info struct if it's a binary
        finfo["r2_arch"]     = binInfo["bin"]["arch"]
        finfo["r2_baddr"]    = binInfo["bin"]["baddr"]
        finfo["r2_binsz"]    = binInfo["bin"]["binsz"]
        finfo["r2_bits"]     = binInfo["bin"]["bits"]
        finfo["r2_canary"]   = binInfo["bin"]["canary"]
        finfo["r2_class"]    = binInfo["bin"]["class"]
        finfo["r2_compiled"] = binInfo["bin"]["compiled"]
        finfo["r2_dbg_file"] = binInfo["bin"]["dbg_file"]
        finfo["r2_intrp"]    = binInfo["bin"]["intrp"]
        finfo["r2_lang"]     = binInfo["bin"]["lang"]
        finfo["r2_lsyms"]    = binInfo["bin"]["lsyms"]
        finfo["r2_machine"]  = binInfo["bin"]["machine"]
        finfo["r2_os"]       = binInfo["bin"]["os"]
        finfo["r2_pic"]      = binInfo["bin"]["pic"]
        finfo["r2_relocs"]   = binInfo["bin"]["relocs"]
        finfo["r2_rpath"]    = binInfo["bin"]["rpath"]
        finfo["r2_stripped"] = binInfo["bin"]["stripped"]
        finfo["r2_subsys"]   = binInfo["bin"]["subsys"]

    if "core" in binInfo:
        # These are extra sections that sometimes don't appear in r2 output
        finfo["r2_format"]   = binInfo["core"]["format"]
        finfo["r2_iorw"]     = binInfo["core"]["iorw"]
        finfo["r2_type"]     = binInfo["core"]["type"]

    ### Binwalk ###
    if bwSigz:
        bwSigs = binWalkScan(inputfile)
        finfo["binwalk"] = bwSigs

    ### Yara ###
    yaraTimeout = CONFIG["analyst_opts"]["yara_timeout"]
    matches = rules.match(data=binFile, callback=yaraMatch, which_callbacks=CALLBACK_MATCHES,timeout=yaraTimeout)
    yMatch  = []  # A list of yara rule matches
    if len(matches) > 0:
        for match in matches:
            yMatch.append(match.rule)
    finfo["yara"] = yMatch
    
    ### URL Finder ###
    if urls:
        urlStr = []
        for url in urls:
            urlStr.append(url.decode("utf-8"))
        finfo["urls"] = urlStr

    ### telfhash ###
    if fileFlag == 1:
        th = r2hook.telfhasher(filename)
        if len(th) > 1:
            finfo["telfhash"] = th

    bf.close()
    return finfo
  except Exception as e:
    print(e)
    print("Error processing file!")
    return

### Main logic #################################################################
if __name__ == '__main__':

    args       = parser.parse_args()
    infile     = args.infile
    directory  = args.directory
    rDirectory = args.rDirectory
    urlFile    = args.urlFile
    tags       = args.tags
    bwSigz     = args.binWalkSigs
    urlList    = args.urlList

    ###- Command Line Switches -###
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

    ###- Config File Switches -###
    if CONFIG["options"]["enable_database"]:
        add2db = 1
    else:
        add2db = 0

    ### End Switches
    ansiout = ""
    ansiout += cPNK + banner + e + "\n"
    ansiout += startline + "\n"
    ansiout += "{} * T A S K S * {}\n".format(side,e)

    ###-- Processing single local file -----------------------------------------
    if infile:
        ansiout += "{}{} + Analyzing {}{}{}\n".format(side,e,cCYAN,infile,e)
        try:
            inn = parseFile(infile)
            ansiout += outputs.printAnsi(inn) # Make an option 
            ansiout += endline
            print(ansiout)
            if args.htmlout:
                outpath = outputs.generateHTML(ansiout,CONFIG["web"]["in_path"],CONFIG["web"]["fqdn"])
                print("HTML output is here! {}".format(outpath))
        except BrokenPipeError:
            print("{}{} {}[!] File not found!{}".format(side,e,cRED,e))
            print(endline)
            sys.exit(1)
        if add2db:
            elasticPost(inn)
        else:
            z = 0

    ###-- Processing files from local directory --------------------------------
    elif directory:
        dirlist = rGlob(directory,"*")
        print(dirlist)
        if len(dirlist) > 0:
            ansiout += "{}{} + Analyzing all files in {}{}{}\n".format(side,e,cCYAN,directory,e)
            if add2db:
                ansiout += "{}{} + Adding Directory {}{}{} to database\n".format(side,e,cCYAN,directory,e)
            for ff in dirlist:
                try:
                    inn = parseFile(ff)
                    ansiout += outputs.printAnsi(inn) # Make an option 
                    if add2db:
                        elasticPost(inn)
                except:
                    ansiout += "Couldn't process {}...continuing!".format(ff)
                    continue
            ansiout += endline
            print(ansiout)
            if args.htmlout:
                outpath = outputs.generateHTML(ansiout,CONFIG["web"]["in_path"],CONFIG["web"]["fqdn"])
                print("HTML output is here! {}".format(outpath))
        else:
            print("{}{}{} [!] No files found!{}".format(side,e,cRED,e))
            sys.exit(1)

    ###-- Processing single file from url --------------------------------------
    elif urlFile:
        singleFile, fHeaders, fOutput = rDownload.getSingleFile(urlFile,fpath)
        if singleFile == 0:
            ansiout += fOutput
            print(ansiout)
            print(endline)
            exit()
        ansiout += fOutput
        headersList = []
        for key, value in fHeaders.items():
            headersList.append("{}: {}".format(key, value)) # Create a header list
        inn = parseFile(singleFile)
        inn["headers"] = headersList # Add the headers
        ansiout += outputs.printAnsi(inn) # Make an option 
        ansiout += endline
        print(ansiout)
        if args.htmlout:
            outpath = outputs.generateHTML(ansiout,CONFIG["web"]["in_path"],CONFIG["web"]["fqdn"])
            print("HTML output is here! {}".format(outpath))
        if add2db:
            inn["url"] = urlFile
            elasticPost(inn)

    ###-- Processing a list of urls with files ---------------------------------
    elif urlList:
        ansiout += "{}{} + Analyzing all files in {}{}{}".format(side,e,cCYAN,urlList,e)
        with open(urlList,"r") as f:
            lines = f.readlines()
            for l in lines:
                try:
                    l = l.split("\n")[0]
                    singleFile, fHeaders, fOutput = rDownload.getSingleFile(l,fpath)
                    ansiout += fOutput
                    headersList = []
                    for key, value in fHeaders.items(): # maybe abstract this to a utils.py
                        headersList.append("{}: {}".format(key, value)) # Create a header list
                    inn = parseFile(singleFile)
                    inn["headers"] = headersList # Add the headers 
                    ansiout += outputs.printAnsi(inn) # make an option
                    if add2db:
                        inn["url"] = l
                        elasticPost(inn)
                except:
                    #ansiout += "Error with {}\n".format(l)
                    continue
        ansiout += endline
        print(ansiout)
        if args.htmlout:
            outpath = outputs.generateHTML(ansiout,CONFIG["web"]["in_path"],CONFIG["web"]["fqdn"])
            print("HTML output is here! {}".format(outpath))

    ###-- Processing files from remote directory -------------------------------
    elif rDirectory:
        fpath = rDownload.parseDir(rDirectory,fpath)
        dirlist = rGlob(fpath,"*")
        if len(dirlist) > 0:
            ansiout += "{}{} + Analyzing all files scraped from {}{}{}\n".format(side,e,cCYAN,rDirectory,e)
            for ff in dirlist:
                try:
                  inn = parseFile(ff)
                  ansiout += outputs.printAnsi(inn)
                  if add2db:
                      inn["url"] = rDirectory
                      elasticPost(inn)
                except:
                    ansiout += "Couldn't process {}...continuing!\n".format(ff)
                    continue
            ansiout += endline
            print(ansiout)
            if args.htmlout:
                outpath = outputs.generateHTML(ansiout,CONFIG["web"]["in_path"],CONFIG["web"]["fqdn"])
                print("HTML output is here! {}".format(outpath))
        else:
            print("{}{}{} [!] No files downloaded!{}".format(side,e,cRED,e))
            sys.exit(1)
