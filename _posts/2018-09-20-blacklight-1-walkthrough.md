---
layout: post
title: "Blacklight: 1 Walkthrough"
subtitle: "Invisible to the Eye"
date: 2018-09-20 18:36:46 +0000
last_modified_at: 2018-11-23 19:32:24 +0000
category: CTF
tags: [VulnHub, Blacklight]
comments: true
image:
  feature: blacklight-1-walkthrough.jpg
  credit: TheLight / Pixabay
  creditlink: https://pixabay.com/en/blacklight-light-bulb-blue-violet-915779/
---

This post documents the complete walkthrough of Blacklight: 1, a CTF-style [VM][1] created by [Carter][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

There's no description for this one. In a way, it's good because you don't know what to expect, and it kinda raises the fun factor.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: BLACKLIGHT
9072/tcp open  unknown syn-ack ttl 64
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, X11Probe:
|_    BLACKLIGHT console mk1. Type .help for instructions
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9072-TCP:V=7.70%I=7%D=9/19%Time=5BA1F04F%P=x86_64-pc-linux-gnu%r(NU
SF:LL,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20instr
SF:uctions\n")%r(GenericLines,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x
SF:20\.help\x20for\x20instructions\n")%r(GetRequest,34,"BLACKLIGHT\x20cons
SF:ole\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(HTTPOptions
SF:,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20instruc
SF:tions\n")%r(RTSPRequest,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\
SF:.help\x20for\x20instructions\n")%r(RPCCheck,34,"BLACKLIGHT\x20console\x
SF:20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(DNSVersionBindRe
SF:qTCP,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20ins
SF:tructions\n")%r(DNSStatusRequestTCP,34,"BLACKLIGHT\x20console\x20mk1\.\
SF:x20Type\x20\.help\x20for\x20instructions\n")%r(Help,34,"BLACKLIGHT\x20c
SF:onsole\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(SSLSessi
SF:onReq,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20in
SF:structions\n")%r(TLSSessionReq,34,"BLACKLIGHT\x20console\x20mk1\.\x20Ty
SF:pe\x20\.help\x20for\x20instructions\n")%r(Kerberos,34,"BLACKLIGHT\x20co
SF:nsole\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(SMBProgNe
SF:g,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20instru
SF:ctions\n")%r(X11Probe,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.h
SF:elp\x20for\x20instructions\n")%r(FourOhFourRequest,34,"BLACKLIGHT\x20co
SF:nsole\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(LPDString
SF:,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20instruc
SF:tions\n")%r(LDAPSearchReq,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x2
SF:0\.help\x20for\x20instructions\n")%r(LDAPBindReq,34,"BLACKLIGHT\x20cons
SF:ole\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(SIPOptions,
SF:34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20instruct
SF:ions\n")%r(LANDesk-RC,34,"BLACKLIGHT\x20console\x20mk1\.\x20Type\x20\.h
SF:elp\x20for\x20instructions\n")%r(TerminalServer,34,"BLACKLIGHT\x20conso
SF:le\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n")%r(NCP,34,"BLAC
SF:KLIGHT\x20console\x20mk1\.\x20Type\x20\.help\x20for\x20instructions\n");
```

`nmap` finds two open ports: `80/tcp` and `9072/tcp`. The second port is interesting. I used `nc` to connect to it. At first, I thought this is a remote shell. The port closed after two failed attempts to provide any meaningful instructions.

![73b19927.png](/assets/images/posts/blacklight-1-walkthrough/73b19927.png)

That leaves me with `80/tcp` to explore.

![745f1fcc.png](/assets/images/posts/blacklight-1-walkthrough/745f1fcc.png)

Thank you for the reassurance, Carter.

## Directory/File Enumeration

Time for some fuzzing. Let's use `gobuster` with `common.txt` from SecLists.

```
# gobuster -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -e -u http://192.168.30.129

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.30.129/
[+] Threads      : 20
[+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2018/09/20 13:22:19 Starting gobuster
=====================================================
http://192.168.30.129/.htaccess (Status: 403)
http://192.168.30.129/.htpasswd (Status: 403)
http://192.168.30.129/.hta (Status: 403)
http://192.168.30.129/css (Status: 301)
http://192.168.30.129/fonts (Status: 301)
http://192.168.30.129/footer (Status: 301)
http://192.168.30.129/img (Status: 301)
http://192.168.30.129/index.html (Status: 200)
http://192.168.30.129/javascript (Status: 301)
http://192.168.30.129/js (Status: 301)
http://192.168.30.129/robots.txt (Status: 200)
http://192.168.30.129/server-status (Status: 403)
=====================================================
2018/09/20 13:22:20 Finished
=====================================================
```

Hmm. `robots.txt` is available. Why didn't `nmap` pick this up?

![0e025469.png](/assets/images/posts/blacklight-1-walkthrough/0e025469.png)

Oh, the `robots.txt` is a non-conforming one. Also, the file `blacklight.dict` appears to be a wordlist.

## Flag: 1

The first flag is as follows.

![f3afd22b.png](/assets/images/posts/blacklight-1-walkthrough/f3afd22b.png)

9072 is the open port found by `nmap` earlier. What's the deal about "_the secret is at home_"?

## Reverse Shell

Although I've closed the port with my silly attempts, I always create a snapshot when the VM is first online. That way, even if I do anything stupid, I can always revert the snapshot.

Let's revert the snapshot and focus on `9072/tcp` this time, keeping in mind I have two attempts before the port closed on me for good.

![1efc7479.png](/assets/images/posts/blacklight-1-walkthrough/1efc7479.png)

To be honest, I've no idea what the hash is for. It's a SHA256 hash. I've also tried using the wordlist `blacklight.dict` to crack it, but to no avail. Nonetheless, all we have left is the `.exec` command. It better yield something! :angry:

***A couple of reverts later...***

I found the right command to run that'll give me a shell. A `root` shell no less!

_On the BLACKLIGHT console mk1_

![49688a51.png](/assets/images/posts/blacklight-1-walkthrough/49688a51.png)

_On my `nc` listener_

![8c849020.png](/assets/images/posts/blacklight-1-walkthrough/8c849020.png)

## Where's the Secret?

![fab23711.png](/assets/images/posts/blacklight-1-walkthrough/fab23711.png)

![6c64c46b.png](/assets/images/posts/blacklight-1-walkthrough/6c64c46b.png)

## Flag: 2

This is how `flag2-inside.jpg` looks like.

![4404fbdc.png](/assets/images/posts/blacklight-1-walkthrough/4404fbdc.png)

The hint is strong in this one.

> Outguess is a universal steganographic tool that allows the insertion of hidden information into the redundant bits of data sources.

Another hint is at `/root/.bash_history`.

![2a718b4c.png](/assets/images/posts/blacklight-1-walkthrough/2a718b4c.png)

To retrieve flag 2, use the following commond.

![8a5536b0.png](/assets/images/posts/blacklight-1-walkthrough/8a5536b0.png)

You thought this is the end, didn't you?

## Flag: 3

![ce99e2e6.png](/assets/images/posts/blacklight-1-walkthrough/ce99e2e6.png)

:dancer:

## Afterthought

This VM is a little different. The story doesn't end with a `root` shell. Rather, it's a CTF. As such, the story ends when you've captured all the flags.

![a93148a0.png](/assets/images/posts/blacklight-1-walkthrough/a93148a0.png)

Well-played, Carter, well-played&hellip;

[1]: https://www.vulnhub.com/entry/blacklight-1,242/
[2]: https://twitter.com/@cbrnrd
[3]: https://www.vulnhub.com/
