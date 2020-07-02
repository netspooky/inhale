import argparse
from elasticsearch import Elasticsearch
import pefile


### PARSER ARGUMENTS ###########################################################
parser = argparse.ArgumentParser(description='Query Inhale DB')
parser.add_argument('-q', dest='query', help='Search Query')
parser.add_argument('-sf', dest='showFields', help='Show Fields. Must be comma seperated. Ex: SHA1,filename,filetype,filesize')
parser.add_argument('-imphash', dest='imphash', help="Calculate ImpHash. For Windows PE files", action="store_true")
parser.add_argument('-imports', dest='imports', help='Show Imported DLLs. For Windows PE files', action="store_true")

### Global Vars ################################################################

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

### Database Functions #########################################################
def elasticQuery(query):
    es = Elasticsearch()
    searchParams = {
        'query':{
                'query_string':{
                "query":"{}".format(query) # search param
            }
        }
    }
    res = es.search(index='inhaled',body=searchParams)
    return res

### ES Result Filtering Operations #############################################

# Extracts filenames (complete path to file) of Windows PE files
def getWinPEFiles(esRes):
    hits = []
    for hit in esRes['hits']['hits']:
        # Check if file is a Windows PE file
        if 'r2_os' in hit['_source']:
            if hit['_source']['r2_os'] == "windows":
                hits.append(hit)
    return hits

### Analysis Functions #########################################################
def getImpHash(esRes):
    pefiles = getWinPEFiles(esRes)
    print(divline)
    if not pefiles:
        print("{} +{} No windows PE files returned from Query{}".format(side,e,cYEL,hits,e))
    else:
        print("{}  #  │{:^34}|{:^34}{}".format(side,"MD5","ImpHash",e))
        print("{}─────┼{:^34}┼{}{}".format(side,"─"*34,"─"*34,e))
        for idx, entry in enumerate(pefiles):
            pe = pefile.PE(entry['_source']['filename'])
            # Calculate imphash
            imphash = pe.get_imphash()
            # For the sake of terminal space I decided to show MD5 instead of SHA256
            print("{}{:^5}│{:^34}| {}{}".format(
                side,idx+1,entry['_source']['md5'], e,imphash)
            )
    print(divline)

def showFields(esRes, showFields):
    print(divline)
    fields = showFields.lower().split(',')
    for hit in esRes['hits']['hits']:
        for f in fields:
            # if key exists
            if f in hit['_source']:
                print("{}{:^10}│ {}{}".format(side,f,e,hit['_source'][f]))
        print(divline)

def showImportedDLLs(esRes):
    pefiles = getWinPEFiles(esRes)
    print(divline)
    # fields to display when showing PE Info
    fields = ['filename','filesize','filetype','md5','sha1','sha256']
    for hit in pefiles:
        print("{}{} PE Info  {}│{}".format(side,cYEL,cCYAN,e))
        for f in fields:
            # if key exists
            if f in hit['_source']:
                print("{}{:^10}│ {}{}".format(side,f,e,hit['_source'][f]))
        print("{}{}{}".format(side,"─"*76,e))
        # Show the imported DLL and the number of imported functions from that DLL
        print("{}{} Imports  {}│{} DLL Import{}".format(side,cYEL,cCYAN,cYEL,e))
        print("{}──────────┼{}{}".format(side,"─"*65,e))
        pe = pefile.PE(hit['_source']['filename'])
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            nFunctions = len(entry.imports)+1
            dllName = entry.dll.decode('utf-8')
            print("{}{:^10}│ {}{}".format(side,nFunctions,e,dllName))
        print(divline)
 
### Main logic #################################################################
if __name__ == '__main__':
    args       = parser.parse_args()
    query      = args.query
    imphash    = args.imphash
    fields     = args.showFields
    imports    = args.imports

    if query:
        print(startline)
        print("{} * T A S K S * {}".format(side,e))
        res = elasticQuery(query)
        hits = len(res['hits']['hits'])
        print("{} +{} Query Successful! {} hits: {}{}".format(side,e,cYEL,hits,e))
        if imphash:
            getImpHash(res)
        if fields:
            showFields(res,fields)
        if imports:
            showImportedDLLs(res)
        print("{}{} Finished All Tasks. {}".format(side,cPURP,e))
        print(endline)
