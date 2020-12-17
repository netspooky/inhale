import r2pipe
import json
 
try:
    from iModules.helper import *
except ImportError:
    from helper import *

if CONFIG["analyst_opts"]["telf_hash"]:
    import telfhash

### Constants for Radare2 for future use
coreMeta = [ "block",
             "fd",
             "file",
             "format",
             "humansz",
             "iorw",
             "mode",
             "obsz",
             "size",
             "type",
           ]

binMeta = [ "arch",
            "baddr",
            "binsz",
            "bintype",
            "bits",
            "canary",
            "checksums",
            "class",
            "compiled",
            "compiler"
            "crypto",
            "dbg_file",
            "endian",
            "havecode",
            "guid",
            "intrp",
            "laddr",
            "lang",
            "linenum",
            "lsyms",
            "machine",
            "maxopsz",
            "minopsz",
            "nx",
            "os",
            "pcalign",
            "pic",
            "relocs",
            "rpath",
            "sanitiz"
            "static",
            "stripped",
            "subsys",
            "va"
         ]

# This uses the json output from the radare2 i command
def getBinInfo(inputfile):
    r = r2pipe.open(inputfile)
    r2out = r.cmd('ij')
    binInfo = json.loads(r2out)
    return binInfo

def getSymbols(inputfile):
    r = r2pipe.open(inputfile)
    r2out = r.cmd('is')
    symInfo = json.loads(r2out)
    return symInfo


def telfhasher(elffile):
    if CONFIG["analyst_opts"]["telf_hash"]:
        t = telfhash.telfhash(elffile)
        return t[0]['telfhash']
    else:
        return 0

