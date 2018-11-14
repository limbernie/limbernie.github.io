---
layout: post
title: "FourAndSix: 1 Walkthrough"
subtitle: "Elementary My Dear Watson"
date: 2018-09-05 08:09:19 +0000
last_modified_at: 2018-09-09 03:12:21 +0000
category: Walkthrough
tags: [VulnHub, FourAndSix]
comments: true
image:
  feature: fourandsix-1-walkthrough.jpg
  credit: shell_ghostcage / Pixabay
  creditlink: https://pixabay.com/en/western-style-antique-detective-2312246/
---

This post documents the complete walkthrough of FourAndSix: 1, a boot2root [VM][1] created by Fred, and hosted at [VulnHub][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Although there's no description for this VM, the name alone is interesting. FourAndSix is the homophone for forensic—expect fun challenges ahead.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 1c:8a:0e:a7:ae:6a:72:ab:c8:88:db:0b:fc:7d:53:c0 (RSA)
|   256 8a:9e:af:85:ef:41:51:54:ee:14:35:9d:78:46:cd:56 (ECDSA)
|_  256 0f:42:83:da:a5:7e:53:9c:a5:21:e4:3f:8a:d8:ad:28 (ED25519)
111/tcp  open  rpcbind syn-ack ttl 64 2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3         2049/tcp  nfs
|   100003  2,3         2049/udp  nfs
|   100005  1,3          844/udp  mountd
|_  100005  1,3         1008/tcp  mountd
1008/tcp open  mountd  syn-ack ttl 64 1-3 (RPC #100005)
2049/tcp open  nfs     syn-ack ttl 64 2-3 (RPC #100003)
```

There's nothing to explore except for NFS at `2049/tcp`. We'll start with that.

### Network File System

As usual, when it comes to NFS we'll use `showmount` to view the NFS exports from the VM.

```
# showmount -e 192.168.30.129
Export list for 192.168.30.129:
/shared (everyone)
```

Let's mount that.

![9dfdac56.png](/assets/images/posts/fourandsix-1-walkthrough/9dfdac56.png)

There's a file in `/shared` that appears to be a `dd` image of a USB stick.

![ef01a6f3.png](/assets/images/posts/fourandsix-1-walkthrough/ef01a6f3.png)

Indeed it is.

Let's mount that too.

![d4e2e4a4.png](/assets/images/posts/fourandsix-1-walkthrough/d4e2e4a4.png)

Now, what do we have here?

![1121935d.png](/assets/images/posts/fourandsix-1-walkthrough/1121935d.png)

Hello Kitties! :heart:

That's not the point, is it? Since the VM's theme is forensic, there must be something going on either with the graphical images or with the image of the USB stick.

Using `binwalk`, let's determine what are the files hidden inside `USB-stick.img`.

![23da2447.png](/assets/images/posts/fourandsix-1-walkthrough/23da2447.png)

Pulled a sneaky on ya!

What is the best tool to extract the two highlighted files? `dd` to the rescue.

![3fdf80b9.png](/assets/images/posts/fourandsix-1-walkthrough/3fdf80b9.png)

![c70964a0.png](/assets/images/posts/fourandsix-1-walkthrough/c70964a0.png)

Wait a minute. Something's not right.

![bebe934c.png](/assets/images/posts/fourandsix-1-walkthrough/bebe934c.png)

We have a corrupted RSA private key and a what seems like a complete RSA public key for SSH.

### RSA Private Key Recovery

For the curious and interested, there's an academic [paper](https://hovav.net/ucsd/papers/hs09.html) on this subject matter, "Reconstructing RSA Private Keys from Random Key Bits" by Nadia Heninger and Hovav Shacham.

I was thinking to myself, "It can't be this hard, right?".

### Network File System Redux

A feeling of defeat loomed upon me. I've no choice but to revisit the possibility of gaining access through NFS. As I was reading the OpenBSD [manpage](https://man.openbsd.org/exports.5) of `exports(5)`, a glimpse of hope starts to emerge.

![2fd7383f.png](/assets/images/posts/fourandsix-1-walkthrough/2fd7383f.png)

What if Fred left `-alldirs` in `/etc/exports`?

![6f0b6c9e.png](/assets/images/posts/fourandsix-1-walkthrough/6f0b6c9e.png)

OMFG. This can't be true??!!

### What's the Flag (WTF)

If the goal is to capture the flag, then I'm already there.

![5800e50d.png](/assets/images/posts/fourandsix-1-walkthrough/5800e50d.png)

:dancer:

If the goal is to get a `root` shell in OpenBSD, then you may want to consider the following strategies, in increasing effort and time:

1. Change the `root` pasword hash in `/etc/master.passwd` to something you know and control.
2. Inject your own SSH public key to `/root/.ssh/authorized_keys`. However, `root` is not permitted to log in and `PubKeyAuthentication` is also disabled. Nonetheless, we can edit the relevant options and manually reboot the VM.
3. Crack the `bcrypt` hashes in `/etc/master.passwd`. The default cost is ten rounds. Good luck with that!

### Afterthought

I almost fell for the corrupted key rabbit hole. :laughing:

[1]: https://www.vulnhub.com/entry/fourandsix-1,236/
[2]: https://www.vulnhub.com/
