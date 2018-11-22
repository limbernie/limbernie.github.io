---
layout: post
title: "FourAndSix: 2.01 Walkthrough"
subtitle: "You see, but you do not observe."
date: 2018-11-22 04:30:37 +0000
category: Walkthrough
tags: [VulnHub, FourAndSix]
comments: true
image:
  feature: fourandsix-2.01-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/police-crime-scene-murder-forensics-3284258/
---

This post documents the complete walkthrough of FourAndSix: 2.01, a boot2root [VM][1] created by Fred, and hosted at [VulnHub][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Although there’s no description for this VM, except for _"to become `root` and read `/root/flag.txt`"_, the name alone is interesting. FourAndSix is the homophone for forensic—expect fun challenges ahead.

### Introduction

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 ef:3b:2e:cf:40:19:9e:bb:23:1e:aa:24:a1:09:4e:d1 (RSA)
|   256 c8:5c:8b:0b:e1:64:0c:75:c3:63:d7:b3:80:c9:2f:d2 (ECDSA)
|_  256 61:bc:45:9a:ba:a5:47:20:60:13:25:19:b0:47:cb:ad (ED25519)
111/tcp  open  rpcbind syn-ack ttl 64 2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3         2049/tcp  nfs
|   100003  2,3         2049/udp  nfs
|   100005  1,3          809/tcp  mountd
|_  100005  1,3          997/udp  mountd
809/tcp  open  mountd  syn-ack ttl 64 1-3 (RPC #100005)
2049/tcp open  nfs     syn-ack ttl 64 2-3 (RPC #100003)
```

There’s nothing to explore except for NFS at `2049/tcp`. We’ll start with that.

### Network File System

As usual, when it comes to NFS we’ll use `showmount` to view the NFS exports from the VM.

<a class="image-popup">
![dc882f92.png](/assets/images/posts/fourandsix-2.01-walkthrough/dc882f92.png)
</a>

Let's mount that.

<a class="image-popup">
![6e211586.png](/assets/images/posts/fourandsix-2.01-walkthrough/6e211586.png)
</a>

It appears a 7z archive file is in the directory. Let's download the file and extract it.

<a class="image-popup">
![0c3a639f.png](/assets/images/posts/fourandsix-2.01-walkthrough/0c3a639f.png)
</a>

It's a 7z archive file alright, but it's password-protected.

<a class="image-popup">
![94470663.png](/assets/images/posts/fourandsix-2.01-walkthrough/94470663.png)
</a>

### John the Ripper

Let's see if **John the Ripper** can crack the password.

<a class="image-popup">
![ed399ce1.png](/assets/images/posts/fourandsix-2.01-walkthrough/ed399ce1.png)
</a>

Awesome. The password is `chocolate`.

<a class="image-popup">
![af920d01.png](/assets/images/posts/fourandsix-2.01-walkthrough/af920d01.png)
</a>

Now, what do we have here?

<a class="image-popup">
![7c027887.png](/assets/images/posts/fourandsix-2.01-walkthrough/7c027887.png)
</a>

A RSA key pair for SSH access.

If I've to guess, I'd say there's a `/home/user/.ssh/authorized_keys` and the content is as follows.

<a class="image-popup">
![492296c1.png](/assets/images/posts/fourandsix-2.01-walkthrough/492296c1.png)
</a>

### Low-privilege Shell

Let's see if we can log in to the host with the private key.

<a class="image-popup">
![ef1462cf.png](/assets/images/posts/fourandsix-2.01-walkthrough/ef1462cf.png)
</a>

Another password to crack?

Long story short, I've tried John the Ripper and it's no good. Let's write a simple password cracker in `bash`, with `ssh-keygen` as the main driver for password verification.

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

FILE=$1
PASSWORD=$2
COMMENT=user@fourandsix2

die() {
  for pid in $(ps aux \
               | grep -v grep \
               | grep 'parallel' \
               | awk '{ print $2 }'); do
    kill -9 $pid &>/dev/null
  done
}

if ssh-keygen -c -C "$COMMENT" -P "$PASSWORD" -f "$FILE" &>/dev/null; then
  echo "Password is '$PASSWORD'" | tee found.txt
  die
fi
```

Let's make use of `parallel` to split the job among my four vCPUs like so.

<a class="image-popup">
![ff18cb37.png](/assets/images/posts/fourandsix-2.01-walkthrough/ff18cb37.png)
</a>

Whoa. It's faster than I can blink my eye.

Time to log in.

<a class="image-popup">
![450f9a71.png](/assets/images/posts/fourandsix-2.01-walkthrough/450f9a71.png)
</a>

There you have it.

### Privilege Escalation

During enumeration of the `user` account, I notice the account is in the `wheel` group. Essentially, this is the superuser group; `root` is also in this group.

With that in mind, let's check out `/etc/doas.conf`, a `sudo` alternative.

<a class="image-popup">
![d700cafa.png](/assets/images/posts/fourandsix-2.01-walkthrough/d700cafa.png)
</a>

What do we have here? We can run `less` as `root`? I smell "escape to shell".

<a class="image-popup">
![0c9faa28.png](/assets/images/posts/fourandsix-2.01-walkthrough/0c9faa28.png)
</a>

Enter `v` to escape to `vi`, and then `!sh` to escape to shell. It's that simple.

### What's the Flag?

Getting the flag is trivial when you have a `root` shell.

<a class="image-popup">
![269ddcd1.png](/assets/images/posts/fourandsix-2.01-walkthrough/269ddcd1.png)
</a>

### Afterthought

It's nice to dabble in OpenBSD once in a while.

:dancer:

[1]: https://www.vulnhub.com/entry/fourandsix-201,266/
[2]: https://www.vulnhub.com/
