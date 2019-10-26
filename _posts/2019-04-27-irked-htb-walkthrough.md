---
layout: post
title: "Irked: Hack The Box Walkthrough"
date: 2019-04-27 15:14:43 +0000
last_modified_at: 2019-04-27 15:25:53 +0000
category: Walkthrough
tags: ["Hack The Box", Irked, retired]
comments: true
image:
  feature: irked-htb-walkthrough.jpg
  credit: manfredrichter / Pixabay
  creditlink: https://pixabay.com/en/cat-grumpy-mood-bad-portrait-face-1950632/
---

This post documents the complete walkthrough of Irked, a retired vulnerable [VM][1] created by [MrAgent][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Irked is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.117 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-23 01:43:12 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.117                                    
Discovered open port 111/tcp on 10.10.10.117                                   
Discovered open port 65534/tcp on 10.10.10.117                                 
Discovered open port 48358/tcp on 10.10.10.117                                 
Discovered open port 22/tcp on 10.10.10.117
```

Interesting. `masscan` finds five open ports. Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p22,80,111,48358,65534 -A --reason 10.10.10.117 -oN nmap.txt
...
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey:
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
|_  256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.10 ((Debian))
| http-methods:
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2,3,4        111/tcp  rpcbind
|   100000  2,3,4        111/udp  rpcbind
|   100024  1          33661/udp  status
|_  100024  1          48358/tcp  status
48358/tcp open  status  syn-ack ttl 63 1 (RPC #100024)
65534/tcp open  irc     syn-ack ttl 63 UnrealIRCd
```

Hmm. IRC? Is this what it's about?

## Remote Command Execution - UnrealIRCd 3.2.8.1

So, the IRC daemon is UnrealIRCd 3.2.8.1.

<a class="image-popup">
![3d5cf3fb.png](/assets/images/posts/irked-htb-walkthrough/3d5cf3fb.png)
</a>

This particular version is susceptible to a remote code executation vulnerability as per EDB-ID [13853](https://www.exploit-db.com/exploits/13853) and it's extremely easy to exploit with `nc`.

<a class="image-popup">
![79ae3f2d.png](/assets/images/posts/irked-htb-walkthrough/79ae3f2d.png)
</a>

Meanwhile at my `nc` listener...

<a class="image-popup">
![350c9327.png](/assets/images/posts/irked-htb-walkthrough/350c9327.png)
</a>

Let's [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) the shell to a full TTY.

## Privilege Escalation

During enumeration of `ircd`'s account, I notice a `setuid` executable. Look at the timestamp on this guy.

<a class="image-popup">
![71fe007d.png](/assets/images/posts/irked-htb-walkthrough/71fe007d.png)
</a>

I ran the executable and spotted something very interesting. A `setuid` executable trying to run another executable that's missing? I smell privilege escalation.

<a class="image-popup">
![2a95e3aa.png](/assets/images/posts/irked-htb-walkthrough/2a95e3aa.png)
</a>

Simply `echo` the following Python code to `/tmp/listusers` and make it executable should do the trick.

<a class="image-popup">
![4b9f47d2.png](/assets/images/posts/irked-htb-walkthrough/4b9f47d2.png)
</a>

Getting `user.txt` and `root.txt` should be easy with a `root` shell.

:dancer:

## Afterthought

I thought it was interesting to share an additional observation during my enumeration of `ircd`'s account. I was looking for `user.txt` and found a text file `.backup` at `/home/djmardov/Documents`.

<a class="image-popup">
![ac818761.png](/assets/images/posts/irked-htb-walkthrough/ac818761.png)
</a>

The content of the file `.backup` is as follows.

<a class="image-popup">
![baf0c966.png](/assets/images/posts/irked-htb-walkthrough/baf0c966.png)
</a>

It appears that some kind of steganography is going on here. If I have to guess, I would say that something is hidden in this image and that the password is `UPupDOWNdownLRlrBAbaSSss`. Damn, that's the [Konami Code](https://en.wikipedia.org/wiki/Konami_Code)!

<a class="image-popup">
![92895787.png](/assets/images/posts/irked-htb-walkthrough/92895787.png)
</a>

Anyways, the box doesn't have any stego tools installed, so I enlisted the help of an online [tool](https://futureboy.us/stegano/decinput.html) to do the job of ***unhiding***, if you will.

<a class="image-popup">
![20c047a7.png](/assets/images/posts/irked-htb-walkthrough/20c047a7.png)
</a>

<a class="image-popup">
![a584a579.png](/assets/images/posts/irked-htb-walkthrough/a584a579.png)
</a>

There you have it. That must be `djmardov`'s password.

<a class="image-popup">
![95c5c2a0.png](/assets/images/posts/irked-htb-walkthrough/95c5c2a0.png)
</a>

[1]: https://www.hackthebox.eu/home/machines/profile/163
[2]: https://www.hackthebox.eu/home/users/profile/624
[3]: https://www.hackthebox.eu/
