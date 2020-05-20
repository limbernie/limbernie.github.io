---
layout: post
title: "Writeup: Hack The Box Walkthrough"
date: 2019-10-12 17:05:46 +0000
last_modified_at: 2019-10-12 17:05:46 +0000
category: Walkthrough
tags: ["Hack The Box", Writeup, retired]
comments: true
image:
  feature: writeup-htb-walkthrough.jpg
  credit: congerdesign / Pixabay
  creditlink: https://pixabay.com/photos/pencil-notes-chewed-paper-ball-1891732/
---

This post documents the complete walkthrough of Writeup, a retired vulnerable [VM][1] created by [jkr][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Writeup is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.138 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-06-11 06:06:24 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.138
Discovered open port 22/tcp on 10.10.10.138
```

Nothing unusual with the ports. Let's do one better with `nmap` scanning the discovered ports to establish the services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.138
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 dd:53:10:70:0b:d0:47:0a:e2:7e:4a:b6:42:98:23:c7 (RSA)
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
|_  256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 1 disallowed entry
|_/writeup/
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Nothing here yet.
```

Hmm. There's an entry in `robots.txt`, calling me to check it out. Here's how it looks like.


{% include image.html image_alt="1e44a210.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/1e44a210.png" %}



{% include image.html image_alt="f450fad8.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/f450fad8.png" %}


Pretty HTML :laughing:

### CMS Made Simple

If you check out the HTML source of `/writeup`, you'll see that CMS Made Simple was used.


{% include image.html image_alt="181486ab.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/181486ab.png" %}


And because this box is pretty new, you have to look for a relatively new exploit as well. For that, look no further than EDB-ID [46635](https://www.exploit-db.com/exploits/46635). Running the exploit is pretty self-explanatory.


{% include image.html image_alt="95f85e2b.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/95f85e2b.png" %}


Once that's done, we can go ahead and recover the password from the salted MD5 hash with John the Ripper.

```
# cat hash.txt
62def4866937f08cc13bab43bb14e6f7$5a599ef579066807
```

According to the exploit, the hash format is `md5($s.$p)`.

```
# john --list=subformats
...
UserFormat = dynamic_1017  type = dynamic_1017: md5($s.$p) (long salt)
...
```


{% include image.html image_alt="4b9f53a8.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/4b9f53a8.png" %}


It was super quick!

## Low-Privilege Shell

Perhaps the credential (`jkr:raykayjay9`) is meant for SSH? Well, there's only one way to find out.


{% include image.html image_alt="b3438b93.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/b3438b93.png" %}


Baam. Straight to `user.txt`.

## Privilege Escalation

During enumeration of `jkr`'s account, I noticed that it's in the `staff` group, which is pretty unusual. Check out what the `staff` group can do.


{% include image.html image_alt="44c65da7.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/44c65da7.png" %}


This means that `jkr` as a member of `staff`, can write stuff to `/usr/local/bin` and `/usr/local/sbin`! Now, I just need something to execute stuff from these two directories. Enter `pspy`.

See what happens when I log in.


{% include image.html image_alt="0a2b35b3.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/0a2b35b3.png" %}


Classic search path hijacking. Armed with this knowledge, we can create the following "fake" `run-parts`.


{% include image.html image_alt="26e46c2f.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/26e46c2f.png" %}


It creates a `.ssh` directory in `/root` if it doesn't exist and then `echo` a SSH public key I control to `authorized_keys`. Lastly, we simply pass all the original options and arguments to the real `run-parts`.

Let's test this concept.


{% include image.html image_alt="254e65e8.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/254e65e8.png" %}


Awesome. Getting `root.txt` is trivial.


{% include image.html image_alt="368f5c1f.png" image_src="/470670e2-503a-4307-bc82-bc0676affe05/368f5c1f.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/192
[2]: https://www.hackthebox.eu/home/users/profile/77141
[3]: https://www.hackthebox.eu/
