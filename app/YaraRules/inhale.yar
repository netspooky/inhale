rule phiSRC : QBOT { 
meta:
  Author = "@netspooky"
  Description = "Checks for PHI-based PRNG within a source file. QBOT + Some Mirai"
strings:
   $a = "0x9e3779b9"
condition:
   $a
}
rule phiLE : QBOT {
meta:
  Author = "@netspooky"
  Description = "Checks for PHI-based PRNG - Little Endian"
strings:
  $a = {b9 79 37 9e}
condition:
  $a
}
rule phiBE : QBOT {
meta:
  Author = "@netspooky"
  Description = "Checks for PHI-based PRNG - Big Endian"
strings:
  $a = {9e 37 79 b9}
condition:
  $a
}

rule upxURL : OBFUSCATE { 
meta:
  Author = "@netspooky"
  Description = "Checks for the UPX URL"
strings:
   $a = "http://upx.sf.net"
condition:
   $a
}

rule DLinkuPNP : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.DLink.uPNP"
strings:
   $a = "/soap.cgi?service=WANIPConn1"
condition:
   $a
}

rule miraidb : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks for Mirai Database dependency - Useful for looking for compiled c2 binaries"
strings:
   $a = "github.com/go-sql-driver/mysql"
condition:
   $a
}

rule RealtekSOAP : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.Realtek"
strings:
   $a = "/picsdesc.xml"
condition:
   $a
}

rule ZyXELD1000 : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.ZyXEL.D1000"
strings:
   $a = "/UD/act?1"
condition:
   $a
}

rule CouchDB : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.CouchDB"
strings:
   $a = "/_config/query_servers/cmd"
   $b = "/_users/org.couchdb.user"
condition:
   any of them
}

rule DasanH640X : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.Dasan.H640X"
strings:
   $a = "/cgi-bin/login_action.cgi"
   $b = "txtUserId=a"
condition:
   any of them
}

rule GoAheadWeb : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.GoAheadWeb"
strings:
   $a = "/ftptest.cgi"
   $b = "/system.ini?loginuse&loginpas"
condition:
   any of them
}

rule GPON : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks GPON/EXPLOIT.Huawei.HG532"
strings:
   $a = "/ctrlt/DeviceUpgrade_1"
   $b = "NewStatusURL"
condition:
   any of them
}

rule libupnpSSDP : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.libupnpSSDP"
strings:
   $a = "M-SEARCH"
   $b = "ssdp:discover"
condition:
   any of them
}

rule NetgearDGN1000 : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.Netgear.DGN1000"
strings:
   $a = "todo=syscmd"
   $b = "/setup.cgi"
condition:
   any of them
}

rule R4IX : EXPLOIT { 
meta:
  Author = "@netspooky"
  Description = "Checks EXPLOIT.R4IX"
strings:
   $a = "/login.cgi"
   $b = "/set_ftp.cgi"
condition:
   any of them
}
