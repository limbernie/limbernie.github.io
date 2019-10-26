---
layout: post
title: "SolidState: 1 Walkthrough"
subtitle: "Not Solid Enough!"
date: 2018-11-24 19:59:42 +0000
last_modified_at: 2018-12-09 08:19:51 +0000
category: Walkthrough
tags: [VulnHub, SolidState]
comments: true
image:
  feature: solidstate-1-walkthrough.jpg
  credit: mse55065 / Pixabay
  creditlink: https://pixabay.com/en/board-layout-electronics-chip-1166770/
---

This post documents the complete walkthrough of SolidState: 1, a boot2root [VM][1] created by [Ch33z_plz][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

It's originally created for HackTheBox.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.20.130
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey:
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    syn-ack ttl 64 JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (192.168.20.128 [192.168.20.128]), PIPELINING, ENHANCEDSTATUSCODES,
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3    syn-ack ttl 64 JAMES pop3d 2.3.2
119/tcp  open  nntp    syn-ack ttl 64 JAMES nntpd (posting ok)
4555/tcp open  rsip?   syn-ack ttl 64
| fingerprint-strings:
|   GenericLines:
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for
|_    Login id:
```

`nmap` finds a couple of open ports. JAMES 2.3.2 sure brings back memories. :wink:

## JAMES Remote Administration Tool 2.3.2

Heck. This is **screwed up**.

<a class="image-popup">
![629c36fb.png](/assets/images/posts/solidstate-1-walkthrough/629c36fb.png)
</a>

Let's list down the users with `listusers`.

<a class="image-popup">
![8cd5a986.png](/assets/images/posts/solidstate-1-walkthrough/8cd5a986.png)
</a>

I have an evil idea. Let's change all the users' password to their usernames.

<a class="image-popup">
![69947cb7.png](/assets/images/posts/solidstate-1-walkthrough/69947cb7.png)
</a>

## Reading Other's Emails

Now that I have changed all the passwords, I can log in to their POP3 account to read their emails.

<a class="image-popup">
![30b3d5bc.png](/assets/images/posts/solidstate-1-walkthrough/30b3d5bc.png)
</a>

You can see that James asked John to send Mindy a temporary password for SSH access.

<a class="image-popup">
![756a4ea3.png](/assets/images/posts/solidstate-1-walkthrough/756a4ea3.png)
</a>

Let's see if the password is valid.

## Low-Privilege Shell

<a class="image-popup">
![227b5cb6.png](/assets/images/posts/solidstate-1-walkthrough/227b5cb6.png)
</a>

The password works but we have a small problem.

<a class="image-popup">
![600ffd3d.png](/assets/images/posts/solidstate-1-walkthrough/600ffd3d.png)
</a>

## Bypass Restricted Shell

This is almost trivial to bypass. We know SSH allows us to execute commands upon login. With this in mind, we can do something like this.

<a class="image-popup">
![fdb63dcc.png](/assets/images/posts/solidstate-1-walkthrough/fdb63dcc.png)
</a>

## Privilege Escalation

During enumeration of `mindy`'s account, I found a world-writable file `/opt/tmp.py`. Here's how it looks like.

<a class="image-popup">
![b832b86f.png](/assets/images/posts/solidstate-1-walkthrough/b832b86f.png)
</a>

If I had to guess, I would say this is run by `crontab` under `root`'s account. Let's replace it with something special. :smiling_imp:

<a class="image-popup">
![cb88cc77.png](/assets/images/posts/solidstate-1-walkthrough/cb88cc77.png)
</a>

About three minutes later, a `root` shell appears.

<a class="image-popup">
![e2b80d6f.png](/assets/images/posts/solidstate-1-walkthrough/e2b80d6f.png)
</a>

## What's the Flag?

<a class="image-popup">
![1f886db9.png](/assets/images/posts/solidstate-1-walkthrough/1f886db9.png)
</a>

:dancer:

## Afterthought

Here's the user's flag for completeness sake.

<a class="image-popup">
![f55b594c.png](/assets/images/posts/solidstate-1-walkthrough/f55b594c.png)
</a>

[1]: https://www.vulnhub.com/entry/solidstate-1,261/
[2]: https://www.vulnhub.com/author/ch33z_plz,242/
[3]: https://www.vulnhub.com/
