---
layout: post
title: "Helpline: Hack The Box Walkthrough"
date: 2019-08-18 04:15:36 +0000
last_modified_at: 2019-08-18 04:19:37 +00000
category: Walkthrough
tags: ["Hack The Box", Helpline, retired]
comments: true
image:
  feature: helpline-htb-walkthrough.jpg
  credit: ElasticComputeFarm / Pixabay
  creditlink: https://pixabay.com/photos/telephone-technical-support-cisco-1223310/
---

This post documents the complete walkthrough of Helpline, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Helpline is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.132 --rate=1000                                                     

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-05-14 08:47:18 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 5985/tcp on 10.10.10.132
Discovered open port 49667/tcp on 10.10.10.132
Discovered open port 135/tcp on 10.10.10.132
Discovered open port 8080/tcp on 10.10.10.132
```

Quite the standard ports associated with a Windows machine. Now, let's do one better with `nmap` scanning the discovered ports to establish the services.

```
# nmap -n -v -Pn -p135,5985,8080,49667 -A --reason -oN nmap.txt 10.10.10.132
...
PORT      STATE SERVICE    REASON          VERSION
135/tcp   open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
5985/tcp  open  http       syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http-proxy syn-ack ttl 127 -
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=FBE4E36CF990855BB8E3C7B1E0B91B73; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Tue, 14 May 2019 07:52:40 GMT
|     Connection: close
|     Server: -
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <script language='JavaScript' type="text/javascript" src='/scripts/Login.js?9309'></script>
|     <script language='JavaScript' type="text/javascript" src='/scripts/jquery-1.8.3.min.js'></script>
|     <link href="/style/loginstyle.css?9309" type="text/css" rel="stylesheet"/>
|     <link href="/style/new-classes.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/new-classes-sdp.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/conflict-fix.css?9309" type="text/css" rel="stylesheet">
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Set-Cookie: JSESSIONID=2FE2FD50B0A690E025238B855358738F; Path=/; HttpOnly
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 01:00:00 GMT
|     Content-Type: text/html;charset=UTF-8
|     Vary: Accept-Encoding
|     Date: Tue, 14 May 2019 07:52:41 GMT
|     Connection: close
|     Server: -
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <script language='JavaScript' type="text/javascript" src='/scripts/Login.js?9309'></script>
|     <script language='JavaScript' type="text/javascript" src='/scripts/jquery-1.8.3.min.js'></script>
|     <link href="/style/loginstyle.css?9309" type="text/css" rel="stylesheet"/>
|     <link href="/style/new-classes.css?9309" type="text/css" rel="stylesheet">
|     <link href="/style/new-classes-sdp.css?9309" type="text/css" rel="stylesheet">
|_    <link href="/style/conflict-fix.css?9309" type="text/css" rel="stylesheet">
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: -
|_http-title: ManageEngine ServiceDesk Plus
49667/tcp open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
```

Interesting. Basically, we only have WinRM and `http` services to explore. Let's start with the `http` service. Here's how it looks like.


{% include image.html image_alt="3bf902a7.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/3bf902a7.png" %}


### ManageEngine ServiceDesk Plus 9.3

This version of ServiceDesk Plus is susceptible to [CVE-2019-10008](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10008), which allows session hijacking and privilege escalation from guest to administrator. And I have just the perfect exploit (EDB-ID [46659](https://www.exploit-db.com/exploits/46659)) for it.


{% include image.html image_alt="22b25875.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/22b25875.png" %}


Set the cookies in my browser (with the Cookie Manager Firefox add-on) as suggested and then navigate to the site.


{% include image.html image_alt="2013a328.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/2013a328.png" %}


Bam. I'm the `administrator` yo~

## Low-Privilege Shell

Now that I'm the `administrator`, it's best to create another account with the same privileges because setting cookies in the browser can be quite a pain in the ass.

To do that, go to the Admin->Users->Technicians page (strange that an Administrator is also considered a Technician `¯\_(ツ)_/¯`).

### ManageEngine ServiceDesk Plus Custom Triggers

Surprise, surprise. ServiceDesk Plus (or SDP) has super powers—the software is able to execute remote commands with custom triggers, i.e. Execute Script, upon meeting certain criteria in newly created requests or incidents. SDP is even so kind to give you an example.

_Go to Admin->Helpdesk Customizer->Custom Triggers_


{% include image.html image_alt="9be99be9.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/9be99be9.png" %}


_Execute Script_


{% include image.html image_alt="98b39381.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/98b39381.png" %}


The plan is to create a trigger to transfer a copy of `nc.exe` to the machine, and another to execute `nc.exe` as a reverse shell back to me.


{% include image.html image_alt="d8d1ada5.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/d8d1ada5.png" %}


You can see from above that I'm using the PowerShell `Invoke-WebRequest` cmdlet to download `nc.exe` from my attacking machine and saving it to `C:\Windows\tracing\nc.exe`. I have a SimpleHTTPServer set up on my attacking machine to host `nc.exe`. For the life of me, I have no clue why `C:\Windows\tracing` is world-writable but it works toward our advantage. The next trigger is to run the reverse shell. Both triggers will be activated when the subject of the new request starts with "avengers" "endgame" respectively.

Now, let's go to the Requests page to create our "Avengers: Endgame" requests.


{% include image.html image_alt="ad7c8dee.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/ad7c8dee.png" %}


_Creating the "avengers" request_


{% include image.html image_alt="aba8a740.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/aba8a740.png" %}


Nothing fancy. Create a new request with subject "avengers" and set the priority to High. Once created, the download will begin.


{% include image.html image_alt="ef69d463.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/ef69d463.png" %}


Similarly, create another new request with subject "endgame" and set the priority to High and wait for your reverse shell.


{% include image.html image_alt="5a48342f.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/5a48342f.png" %}


Boom. And this is not the only surprise.


{% include image.html image_alt="719aba65.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/719aba65.png" %}


Unbelievable.

### Getting `user.txt` and `root.txt`

It's pretty easy to find `user.txt`. `root.txt` should be at the usual location.


{% include image.html image_alt="20353e88.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/20353e88.png" %}


Time to claim it.


{% include image.html image_alt="83d3dcfd.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/83d3dcfd.png" %}


What the hell is going on? I'm `SYSTEM` yo??!! Turns out that both files are encrypted.


{% include image.html image_alt="1846c6e0.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/1846c6e0.png" %}



{% include image.html image_alt="34642297.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/34642297.png" %}


Only specific accounts are able to decrypt the files. I need credentials...

### Saving SAM, SECURITY and SYSTEM Hives

One way to retrieve credentials is to dump them out of the holy trinity of registry hives: SAM, SECURITY AND SYSTEM, with Impacket's `secretsdump.py`.

Saving them is not the issue. You can easily do that with `reg save hklm\sam` for example. The issue is where to save them so that I can download them to my attacking machine.

Our SDP is a web application and the web server serves static resources like images, right?


{% include image.html image_alt="e0d6dd51.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/e0d6dd51.png" %}


All we have to do is to find where the file is located and we can save our hives over there.

```
E:\>dir /s /b default-logo.png
dir /s /b default-logo.png
E:\ManageEngine\ServiceDesk\applications\extracted\AdventNetServiceDesk.eear\AdventNetServiceDeskWC.ear\AdventNetServiceDesk.war\images\default-logo.png
```

Bingo. And since I'm `SYSTEM`, saving the hives shouldn't be a problem.


{% include image.html image_alt="1e59a17f.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/1e59a17f.png" %}


Once that's done, we can download the files to my attacking machine.

```
# wget http://10.10.10.132:8080/images/sam
# wget http://10.10.10.132:8080/images/security
# wget http://10.10.10.132:8080/images/system
```

It's dumping time!


{% include image.html image_alt="62da879b.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/62da879b.png" %}


### Pass-the-Hash is <s>Dead</s>

What do we do with the hashes. Well, we can always crack them.


{% include image.html image_alt="83bae8f2.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/83bae8f2.png" %}


Hmm. Only `zachary`'s password is cracked. Perhaps a more efficient way is to pass-the-hash to a tool like FreeRDP. Before we do that, we need to disable Windows Defender and turn on Remote Desktop Services with PowerShell to give ourselves more options.

#### Disable Windows Defender Real-time Protection

```
PS> Set-MpPreference -DisableRealtimeMonitoring $true
```

#### Enable Remote Desktop Services

_Enable Remote Desktop_

```
PS> Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'-name "fDenyTSConnections" -Value 0
```

_Allow incoming RDP on firewall_

```
PS> Set-NetFirewallRule -Name RemoteDesktop-UserMode-In-TCP -Enabled true
```

_Enable secure RDP authentication_

```
PS> Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -name "UserAuthentication" -Value 1
```

### Hijacking Remote Desktop Services

During my enumeration, I noticed that `leo` is logged on to the physical console, probably through automatic logon.


{% include image.html image_alt="a17b2b83.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/a17b2b83.png" %}


And since I'm `SYSTEM`, I can make use of `tscon.exe` to hijack that session into my own. How do I do that? I can pass the `administrator`'s NTLM hash to FreeRDP instead of a password. That will create an RDP session and with `tscon.exe`, I can hand over `leo`'s session over to the newly created session.


{% include image.html image_alt="357adc29.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/357adc29.png" %}


A RDP session is created, albeit access is denied. Do not click "OK".


{% include image.html image_alt="00591a68.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/00591a68.png" %}


Turn over to the Windows shell.


{% include image.html image_alt="11fd2a0f.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/11fd2a0f.png" %}


You can see the newly created RDP session. Now issue the `tscon.exe` command like so:

```
C:\> tscon 1 /dest:rdp-tcp#2
```

The FreeRDP X window that's already open will switch to Leo's session and there's another encrypted file on Leo's desktop.


{% include image.html image_alt="43e432d0.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/43e432d0.png" %}


Damn. It's suppose to unlock! Anyways, we have `SYSTEM` privileges remember? One of the oldest tricks in the book is to replace `magnify.exe` with `cmd.exe`.


{% include image.html image_alt="865a4bd0.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/865a4bd0.png" %}


What's going on?


{% include image.html image_alt="9334e5ae.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/9334e5ae.png" %}


You can see that the creator has removed `SYSTEM`'s full control permissions. Here's an ugly hack. Take ownership of the file, grant `Everyone` full control to `magnify.exe` and then delete it.


{% include image.html image_alt="7a06ad69.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/7a06ad69.png" %}


Clicking the Magnifier pops up a beautiful `SYSTEM` shell in the RDP session.


{% include image.html image_alt="b8d0f2e9.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/b8d0f2e9.png" %}


What's so special with this shell? This shell opens Windows yo~


{% include image.html image_alt="a4af6a65.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/a4af6a65.png" %}


I know `leo` is able to login automatically without entering password. Here, I open up the Registry Editor and navigate to `HKLM\Software\Microsoft\Windows NT\CurrentVersion\WinLogon` to check out his password. With that, simply add `leo` to the **Remote Desktop Users** group and I can unlock the screen without changing anything.


{% include image.html image_alt="04f1e86f.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/04f1e86f.png" %}


Something's strange is going on. Even `leo` has limited permissions over `admin-pass.xml`.


{% include image.html image_alt="fe2433a4.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/fe2433a4.png" %}


That's why even `leo` can't decrypt `admin-pass.xml`.


{% include image.html image_alt="1de7b343.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/1de7b343.png" %}


Well, that's an easy fix. Although `leo` lacks the permission to decrypt the file, he's still the file owner after all. As such, we can still grant `leo` full control over the file.


{% include image.html image_alt="51b7a599.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/51b7a599.png" %}


Now, we should be able to decrypt `admin-pass.xml`.


{% include image.html image_alt="bea361b2.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/bea361b2.png" %}


Here's how it looks like.


{% include image.html image_alt="1f1aac16.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/1f1aac16.png" %}


#### Getting `root.txt`

Turns out that this is the Data Protection API blob (displayed as a hexstring) for the `administrator`'s password. We can decrypt the blob with the masterkey using `mimikatz dpapi` module. And to get to the masterkey, follow the `mimikatz` [howto](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files) on decrypting EFS files. Once it's decrypted, the `administrator`'s password is revealed.


{% include image.html image_alt="eff6d88f.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/eff6d88f.png" %}


Armed with this password, we can decrypt `root.txt`. Similar to `admin-pass.xml`, we have to give ourselves full control over the file to be able to decrypt.


{% include image.html image_alt="48fa9674.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/48fa9674.png" %}


#### Getting `user.txt`

For the first time, getting `user.txt` feels harder than `root.txt` due to the lack of hints. Well, there's a extremely subtle hint with the user `zachary`.


{% include image.html image_alt="9d9a3f2e.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/9d9a3f2e.png" %}


This sure is a strange group. I think the creator is telling us to look into Windows Events.


{% include image.html image_alt="87417078.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/87417078.png" %}


The only place I could think of where events contain password strings is the Security event, particularly the Process Creation tasks. Let's filter the events.


{% include image.html image_alt="d2a03c8d.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/d2a03c8d.png" %}


Then look for the string `tolu`.


{% include image.html image_alt="d07c6ad6.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/d07c6ad6.png" %}


There you go. Armed with `tolu`'s password, we can decrypt `user.txt`.


{% include image.html image_alt="3d0fd014.png" image_src="/f813f9bc-f48f-4bda-bc43-b7585e12dbfb/3d0fd014.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/180
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
