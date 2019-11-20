---
layout: post
title: "Pseudo: A Reversing Challenge"
date: 2019-11-19 02:11:27 +0000
last_modified_at: 2019-11-19 02:11:27 +0000
category: CTF
tags: ["Hack The Box", Pseudo, Reversing, retired]
comments: true
image:
  feature: pseudo-reversing-walkthrough.jpg
---

This post documents my attempt to complete Pseudo, a retired challenge created by [RoliSoft][1], and hosted at [Hack The Box][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Do you have enough permissions to get the flag?

## Introduction

The challenge is located at https://www.hackthebox.eu/home/challenges/download/18. It\'s a password-protected archive file.

## Analysis

There is one unknown file in the archive file.

<a class="image-popup">
![79a80293.png](/assets/images/challenges/pseudo-reversing-walkthrough/79a80293.png)
</a>

The file is an ELF for `aarch64` architecture. It probably won't run on my Kali Linux.

```
# file pseudo
pseudo: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked, no section header
```

In any case, I need to set up Linux in a fully emulated `aarch64` environment since my Kali Linux is a `x86_64` virtual machine.

### QEMU / AArch64 / Ubuntu Server 18.04

Enter QEMU. QEMU is a free and open-source emulator that performs hardware virtualization. I'm making use of Ubuntu's readily-built cloud image, which saves me from installing the operating system from scratch. I also need to bake in a pair of SSH key pair I control since that's the only way to access it.

<div class="filename"><span>cloud.txt</span></div>

```
#cloud-config
users:
  - name: bernie
    ssh-authorized-keys:
      - ssh-rsa AAAAB3Nza...
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    groups: sudo
    shell: /bin/bash
```

Use `cloud-localds` to build a cloud image with my SSH credentials baked in.

```
# cloud-localds --disk-format=qcow2 cloud.img cloud.txt
```

Running QEMU in a fully emulated environment is slightly complicated because of the various options. Here's my running configuration.

<div class="filename"><span>run.sh</span></div>

```
#!/bin/bash

qemu-system-aarch64 \
-smp 2 \
-m 1024 \
-M virt \
-cpu cortex-a57 \
-bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
-nographic \
-device virtio-blk-device,drive=image \
-drive if=none,id=image,file=ubuntu-16.04-server-cloudimg-arm64-uefi1.img,format=qcow2 \
-device virtio-blk-device,drive=cloud \
-drive if=none,id=cloud,file=cloud.img,format=qcow2 \
-device e1000,netdev=net0 \
-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22
```

I chose to run the configuration on `xterm` for aesthetic reason.

<a class="image-popup">
![09d6146e.png](/assets/images/challenges/pseudo-reversing-walkthrough/09d6146e.png)
</a>

Let's see if I can log in to it.

<a class="image-popup">
![1cac7182.png](/assets/images/challenges/pseudo-reversing-walkthrough/1cac7182.png)
</a>

Awesome. It\'s like having my own AWS EC2 instance!

### File Analysis

Because the file is stripped of all information (a.k.a "packed"), debugging it straight away won't do us any good. Let's check out the file headers.

<a class="image-popup">
![d635bf9c.png](/assets/images/challenges/pseudo-reversing-walkthrough/d635bf9c.png)
</a>

Here's our clue that it's packed. Notice that it has two ELF magic numbers? And, also "UPX"?

<a class="image-popup">
![35d50b29.png](/assets/images/challenges/pseudo-reversing-walkthrough/35d50b29.png)
</a>

Woohoo, we can unpack it.

### GDB + GEF

I read with interest that [GEF](https://github.com/hugsy/gef) supports ARM, so that's what I'm going to use.

<a class="image-popup">
![f1f1c8cb.png](/assets/images/challenges/pseudo-reversing-walkthrough/f1f1c8cb.png)
</a>

Awesome. Finally we have something! Let's place a breakpoint at the entry point and reverse it away.

<a class="image-popup">
![5c1c5cd4.png](/assets/images/challenges/pseudo-reversing-walkthrough/5c1c5cd4.png)
</a>

Damn, it's `aarch64` alright. I'm in unchartered territory man.

### Locating the `main` function

Because the executable is statically linked, it took a combination of radare2 (`aaaa`) and IDA Pro (call graphs) to locate the `main` function. This is how the `main` function looks like.

<a class="image-popup">
![b4f9742c.png](/assets/images/challenges/pseudo-reversing-walkthrough/b4f9742c.png)
</a>

At the beginning of the function, there's a check for the terminal size. If the column size is less than or equal to 158, an Internet Zoolander meme is printed out.

<a class="image-popup">
![ac09374d.png](/assets/images/challenges/pseudo-reversing-walkthrough/ac09374d.png)
</a>

Here's how the Assembly code for the terminal check looks like. It uses `ioctl`.

<a class="image-popup">
![432c19fc.png](/assets/images/challenges/pseudo-reversing-walkthrough/432c19fc.png)
</a>

Long story short, the instructions in the rounded reactangle are bytecode commands. I managed to decipher three of the commands.

1. 0xEF - Check User
2. 0x80 - Read Password
3. 0xD2 - Check Password

#### 0xEF - Check User

This command uses `malloc` to allocate five bytes of space for the string `USER` and then use `getenv` to get the username of the currently logged on user.

#### 0x80 - Read Password

This command reads the password from `stdin` and transforms each character by subtracting 94 (or `0x5e`) from the character's ordinal number.

<a class="image-popup">
![b83901ae.png](/assets/images/challenges/pseudo-reversing-walkthrough/b83901ae.png)
</a>

#### 0xD2 - Check Password

This command checks the transformed input password with the transformed actual password. The instruction that compares each character is shown below.

<a class="image-popup">
![17b70a33.png](/assets/images/challenges/pseudo-reversing-walkthrough/17b70a33.png)
</a>

The first five registers are shown below.

<a class="image-popup">
![46fbe81b.png](/assets/images/challenges/pseudo-reversing-walkthrough/46fbe81b.png)
</a>

The comparison goes on for sixteen characters. This is the transformed password.

<a class="image-popup">
![3f70b4ec.png](/assets/images/challenges/pseudo-reversing-walkthrough/3f70b4ec.png)
</a>

If the password is incorrect, the program goes into an infinite loop until you terminates it.

#### Decoding the Password

Since we knew how the password is transformed, I wrote a simple shell one-liner to decode it.

```
# for b in $(xxd -p password | sed -r 's/(..)/\1\n/g'); do printf \\$(printf "%o" $((0x$b + 0x5e))); done | rev && echo
~vms_all_the_way
```

Armed with the password, let's get that flag.

<a class="image-popup">
![ea63fa3a.png](/assets/images/challenges/pseudo-reversing-walkthrough/ea63fa3a.png)
</a>

The flags is `HTB{vms_4ll_th3_w4y}`.

:dancer:

[1]: https://www.hackthebox.eu/home/users/profile/1178
[2]: https://www.hackthebox.eu/
