---
layout: post
title: "Querier: Hack The Box Walkthrough"
date: 2019-06-22 16:43:37 +0000
last_modified_at: 2019-06-22 16:50:34 +0000
category: Walkthrough
tags: ["Hack The Box", Querier, retired]
comments: true
image:
  feature: querier-htb-walkthrough.jpg
  credit: qimono / Pixabay
  creditlink: https://pixabay.com/illustrations/question-mark-important-sign-1872665/
---

This post documents the complete walkthrough of Querier, a retired vulnerable [VM][1] created by [egre55][2] and [mrh4sh][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Querier is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.125 --rate=1000                                                                                        

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-02-18 02:23:01 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 135/tcp on 10.10.10.125
Discovered open port 49667/tcp on 10.10.10.125
Discovered open port 49669/tcp on 10.10.10.125
Discovered open port 10000/tcp on 10.10.10.125
Discovered open port 10332/tcp on 10.10.10.125
Discovered open port 1433/tcp on 10.10.10.125
Discovered open port 445/tcp on 10.10.10.125
Discovered open port 49668/tcp on 10.10.10.125
Discovered open port 47001/tcp on 10.10.10.125
Discovered open port 49670/tcp on 10.10.10.125
Discovered open port 49665/tcp on 10.10.10.125
Discovered open port 139/tcp on 10.10.10.125
Discovered open port 49666/tcp on 10.10.10.125
Discovered open port 5985/tcp on 10.10.10.125
Discovered open port 49671/tcp on 10.10.10.125
```

Whoa. That's a lot of open ports! Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p445,49670,49668,49671,47001,139,49665,49667,49669,49664,49666,5985,1433,135 -A --reason -oN nmap.txt 10.10.10.125
...
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server  14.00.1000.00
| ms-sql-ntlm-info:
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-02-24T02:20:16
| Not valid after:  2049-02-24T02:20:16
| MD5:   0028 a071 4b76 91a3 939e 2212 8a7b 78b6
|_SHA-1: d4a5 c0ab 55a8 f1bd f6c9 5c21 73fb d0c9 d634 6c05
|_ssl-date: 2019-02-24T08:18:52+00:00; 0s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
...
Host script results:
| ms-sql-info:
|   10.10.10.125:1433:
|     Version:
|       name: Microsoft SQL Server
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server
|_    TCP port: 1433
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-02-24 08:18:51
|_  start_date: N/A
```

Interesting. I don't see the usual `http` service. However, we do have SMB. Let's see what can we find with `smbclient`.

### Server Message Block

Let's list the file shares, if any, using `smbclient`.


{% include image.html image_alt="e2d713e8.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/e2d713e8.png" %}


Sweet. Looks like there's one share, `Reports`.


{% include image.html image_alt="0e36f17d.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/0e36f17d.png" %}


And, there's a file in it. Let's grab that.

### Visual Basic for Applications

It turns out that the file is a macro-enabled spreadsheet. The best way to analyze macros spreadsheet is still, in my opinion, Microsoft Office, primarily because of the excellent Visual Basic Editor bundled with it. It doesn't take long to find what we are looking for.


{% include image.html image_alt="vba" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/vba.png" %}


Database credentials!

### Tabular Data Stream

Microsoft and Sybase uses Tabular Data Stream (TDS) as the underlying protocol for data transfer between a client and a database server. We can use `sqsh` in Kali Linux to remotely connect to Microsoft SQL Server.

First, we define a SQL server by creating `~/.freetds.conf` as follows.

```
# cat ~/.freetds.conf
[QUERIER]
  host = 10.10.10.125
  port = 1433
  tds version = 8.0
```

Once that's done, we can set the style to vertical.

```
# cat ~/.sqshrc
\set style=vert
```

Now, let's connect to the server using its name.

```
# sqsh -S QUERIER -U QUERIER\\reporting -P 'PcwTWTHRwryjc$c6'
```


{% include image.html image_alt="f85cb877.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/f85cb877.png" %}


Awesome.

### Undocumented Stored Procedure - `xp_dirtree`

Now that we have access to a MSSQL shell so to speak, we can execute `xp_dirtree` to exfiltrate NTLM hashes. But first, we need to set up a fake SMB server.

Impacket provides an excellent SMB server right off the box. Let's run that.

```
# impacket-smbserver deep /root/Downloads/querier -smb2support
```

You would want to enable SMB2 support. Remember your nmap scan?

```
ost script results:
| ms-sql-info:
|   10.10.10.125:1433:
|     Version:
|       name: Microsoft SQL Server
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server
|_    TCP port: 1433
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-02-24 08:18:51
|_  start_date: N/A
```

Execute `xp_dirtree`.


{% include image.html image_alt="499f86f6.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/499f86f6.png" %}


You should see the SMB requests in like this.


{% include image.html image_alt="44587811.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/44587811.png" %}


That's the NTLMv2 hash we've been waiting for! Copy the entire string in red and send it to John the Ripper for cracking.


{% include image.html image_alt="8eb08950.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/8eb08950.png" %}


Armed with the credential (`mssql-svc:corporate568`), let's see what if log in to the SQL server.


{% include image.html image_alt="83614c5c.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/83614c5c.png" %}


Sweet! But, do we have `sysadmin` privileges?


{% include image.html image_alt="bd054ba1.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/bd054ba1.png" %}


Now, we can enable the `xp_cmdshell` stored procedure since it's disabled by default.


{% include image.html image_alt="25d6b210.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/25d6b210.png" %}


## Low-Privilege Shell

We can make use of PowerShell's `Invoke-WebRequest` cmdlet to pull a copy of `nc.exe` to `C:\Reports` where `mssql-svc` has write permissions.


{% include image.html image_alt="4c241393.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/4c241393.png" %}


We'll then use `xp_cmdshell` to run a reverse shell back to us.


{% include image.html image_alt="322043e9.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/322043e9.png" %}


Voila! A low-privilege shell.


{% include image.html image_alt="b30ed4d7.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/b30ed4d7.png" %}


Let's get that `user.txt`. It's at `mssql-svc`'s desktop.


{% include image.html image_alt="6cd4ec26.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/6cd4ec26.png" %}


## Privilege Escalation

During enumeration of `mssql-svc`'s account, I notice that it's in the `NT AUTHORITY\SERVICE` group (SID 5-1-5-6). According to Microsoft documentation, it's

> A group that includes all security principals that have logged on as a service. Membership is controlled by the operating system.


{% include image.html image_alt="e2f6f709.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/e2f6f709.png" %}


In other words, the operating system enabled "Log on as a service" in the local security policy and `mssql-svc` is service account as the name suggests. Makes sense.

This gave me an idea to enumerate for weak services. Since I can use PowerShell, let's transfer [accesschk.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from SysInternals to the box. This nifty tool will aid us in the enumeration. I'll be looking for services where `NT AUTHORITY\SERVICE` group has write access.


{% include image.html image_alt="80463432.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/80463432.png" %}


What a pleasant surprise. `mssql-svc` has all access! Let's check out the service path with `sc`.


{% include image.html image_alt="497e1c83.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/497e1c83.png" %}


Notice that the service is executed with the `NT AUTHORITY\System` account? This is getting interesting. Suppose we change the service path to `nc.exe` previously uploaded and use it to run another reverse shell back to me. I get a `root` shell with privileges higher than that of `Administrator`. How cool is that?

Again, we'll use `sc` to modify the service path and to verify the result of our action.


{% include image.html image_alt="60577e6d.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/60577e6d.png" %}


Now, we restart the service with `net stop UsoSvc` and then `net start UsoSvc`.


{% include image.html image_alt="90e84691.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/90e84691.png" %}


Voila! Getting `root.txt` is easy when you have a `root` shell with `NT AUTHORITY\SYSTEM` privileges.


{% include image.html image_alt="b21d563c.png" image_src="/e1663bb9-4e33-4561-9d7a-b6e71d56f1c4/b21d563c.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/175
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/home/users/profile/2570
[4]: https://www.hackthebox.eu/
