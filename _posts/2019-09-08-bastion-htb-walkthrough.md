---
layout: post
title: "Bastion: Hack The Box Walkthrough"
date: 2019-09-08 07:52:30 +0000
last_modified_at: 2019-09-08 07:52:30 +0000
category: Walkthrough
tags: ["Hack The Box", Bastion, retired]
comments: true
image:
  feature: bastion-htb-walkthrough.jpg
  credit: Konevi / Pixabay
  creditlink: https://pixabay.com/photos/bastion-defense-building-3733262/
---

This post documents the complete walkthrough of Bastion, a retired vulnerable [VM][1] created by [L4mpje][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

Bastion is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.134 --rate=500

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-05-03 07:24:06 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49670/tcp on 10.10.10.134
Discovered open port 22/tcp on 10.10.10.134
Discovered open port 135/tcp on 10.10.10.134
Discovered open port 47001/tcp on 10.10.10.134
Discovered open port 445/tcp on 10.10.10.134
Discovered open port 49665/tcp on 10.10.10.134
Discovered open port 49667/tcp on 10.10.10.134
Discovered open port 49669/tcp on 10.10.10.134
Discovered open port 49666/tcp on 10.10.10.134
Discovered open port 49668/tcp on 10.10.10.134
Discovered open port 49664/tcp on 10.10.10.134
Discovered open port 139/tcp on 10.10.10.134
Discovered open port 5985/tcp on 10.10.10.134
```

`masscan` finds many open ports that appear to be associated with Windows. Let's do one better with `nmap`  scanning the discovered ports to establish the services.

```
# nmap -n -v -Pn -p22,135,139,445,5985 -A --reason -oN nmap.txt 10.10.10.134
...
PORT     STATE SERVICE      REASON          VERSION
22/tcp   open  ssh          syn-ack ttl 127 OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp  open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
...
Host script results:
|_clock-skew: mean: -39m59s, deviation: 1h09m15s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2019-05-03T09:32:33+02:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-05-03 07:32:32
|_  start_date: 2019-05-03 05:59:00
```

And since SMB is enabled, let's see if there are file shares.

<a class="image-popup">
![77dfaf57.png](/assets/images/posts/bastion-htb-walkthrough/77dfaf57.png)
</a>

`Backups` looks interesting, which I have read, write access by the way. Let's mount it.

```
# mkdir backups
# mount -t cifs -o 'rw,username=guest' //10.10.10.134/Backups backups
```

There's an interesting note at `note.txt`.

```
Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```

There are a couple of XML files. To that end, I wrote a simple script to prettify all of them.

<div class="filename"><span>prettify</span></div>

```bash
#!/bin/bash

for xml in *.xml; do
  iconv -f UNICODE -t ASCII < $xml \
  | xmllint -format - > ${xml%*.xml}.txt
done
```

Among the XML files, this one is interesting.

```xml
<?xml version="1.0"?>
<AsrSif>
  <Version AsrVersion="2.0"/>
  <System MachineName="L4MPJE-PC" Platform="x86" FirmwareType="1" OSVersion="6.1" BootWinDirectory="C:\Windows" BootSysDirectory="C:\Windows\system32" AutoExtend="1" SKU="0x10100"/>                  
  <DiskBuses NumBusType="1">
    <BusType Key="1" Type="11"/>
  </DiskBuses>
  <Disks NumMbrDisks="1" NumGptDisks="0">
    <MbrDisk NumPartitions="2" PartitionTableSize="4" BusKey="1" DeviceNumber="0" IsCritical="1" MbrSignature="0x8ae9dbe5" BytesPerSector="512" SectorsPerTrack="63" TracksPerCylinder="255" NumCylinders="1958" MediaType="12" DiskSize="16106127360" IsExcluded="0" IsShared="0">
      <MbrPartition PartitionIndex="0" PartitionFlag="6" BootFlag="1" PartitionType="0x7" FileSystemType="0x0" NumSymbolicNames="1" PartitionOffset="1048576" PartitionLength="104857600" IsCritical="1">
        <VolumeMountPoint SymbolicName="\??\Volume{9b9cfbc3-369e-11e9-a17c-806e6f6e6963}"/>
      </MbrPartition>
      <MbrPartition PartitionIndex="1" PartitionFlag="1" BootFlag="0" PartitionType="0x7" FileSystemType="0x0" NumSymbolicNames="2" PartitionOffset="105906176" PartitionLength="15999172608" IsCritical="1">
        <VolumeMountPoint SymbolicName="\DosDevices\C:"/>
        <VolumeMountPoint SymbolicName="\??\Volume{9b9cfbc4-369e-11e9-a17c-806e6f6e6963}"/>
      </MbrPartition>
    </MbrDisk>
  </Disks>
  <AsrVhd NumDisks="0"/>
  <FixedVolumes NumVolumeNames="2">
    <VolumeName VolumeGuid="\??\Volume{9b9cfbc4-369e-11e9-a17c-806e6f6e6963}" DosPath="\DosDevices\C:" FsName="NTFS" Label="" ClusterSize="0x1000"/>                                                   
    <VolumeName VolumeGuid="\??\Volume{9b9cfbc3-369e-11e9-a17c-806e6f6e6963}" DosPath="" FsName="NTFS" Label="System Reserved" ClusterSize="0x1000"/>                                                  
  </FixedVolumes>
  <RemovableMedia NumRemMedia="1">
    <Media DevicePath="\Device\CdRom0" VolumeGuid="\??\Volume{9b9cfbc7-369e-11e9-a17c-806e6f6e6963}" DosPath="\DosDevices\D:"/>                                                                        
  </RemovableMedia>
  <AsrLdm NumPacks="0"/>
</AsrSif>
```
It appears that we have two backup file systems in VHD, presumably one for the boot partition and the other for the C: volume.

<a class="image-popup">
![3b31ea9b.png](/assets/images/posts/bastion-htb-walkthrough/3b31ea9b.png)
</a>

Of course, we are interested in the C: volume.

## Mounting a guest filesystem with `guestmount`

We can simply mount the backup file system with [`guestmount`](http://libguestfs.org/guestmount.1.html), which is an awesome project by the way.

```
guestmount -a '/root/Downloads/bastion/backups/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd' -m /dev/sda1 --ro /root/Downloads/bastion/mount
```

|`-a`|—|add the image to mount|
|`-m`|—|the partition in the image to mount|
|`--ro`|—|read-only|

It'll take a while because we are mounting over SMB. Once it's done, it should look something like this.

<a class="image-popup">
![2b76aa92.png](/assets/images/posts/bastion-htb-walkthrough/2b76aa92.png)
</a>

## Credentials Recovery

Now that we have access to the backup file system, what files should we get? Credentials are stored in the SAM file as NTLM hashes, protected by the SYSKEY which in turn is stored in the SYSTEM registry hive. We can recover these credentials using Impacket's `secretsdump.py`. The required files SAM, SECURITY, and SYSTEM can all be found in `C:\Windows\System32\config`.

<a class="image-popup">
![e5a48961.png](/assets/images/posts/bastion-htb-walkthrough/e5a48961.png)
</a>

Once we have copied the three files, we can recover the credentials with `secretsdump.py` like so.

<a class="image-popup">
![44d6b33b.png](/assets/images/posts/bastion-htb-walkthrough/44d6b33b.png)
</a>

## Low-Privilege Shell

If I had to guess, I would say that's the password to `L4mpje`'s SSH account.

<a class="image-popup">
![51462ee4.png](/assets/images/posts/bastion-htb-walkthrough/51462ee4.png)
</a>

No surprise, the file `user.txt` is at the desktop.

<a class="image-popup">
![be653196.png](/assets/images/posts/bastion-htb-walkthrough/be653196.png)
</a>

## Privilege Escalation

During enumeration of `L4mpje`'s account, I noticed mRemoteNG installed. mRemoteNG is _the next generation of mRemote, open source, tabbed, multi-protocol, remote connections manager._ During my research into mRemoteNG, I also found out that mRemoteNG stores its connection details such as IP address, protocol, and more importantly to us, credentials (albeit encrypted) in a connections file named `confcons.xml`.

<a class="image-popup">
![edd5bd5e.png](/assets/images/posts/bastion-htb-walkthrough/edd5bd5e.png)
</a>

It's just a matter of copying the file with `scp` to my attacking machine for further analysis.

```
# scp L4mpje@10.10.10.134:/Users/L4mpje/AppData/Roaming/mRemoteNG/confCons.xml .
```

And this is how the file looks like.

```xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128" Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostname="192.168.1.75" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

Well, notice the encrypted credentials for `Administrator`?. I noted the credentials are encrypted with AES in the GCM mode with 1000 iterations. I'm not sure how strong is the encryption but it's best we don't try. A more efficient way is to load the connections file into a running mRemoteNG.

<a class="image-popup">
![5b20b834.png](/assets/images/posts/bastion-htb-walkthrough/5b20b834.png)
</a>

I believe we just have to change the hostname/IP to 10.10.10.134 and the protocol to SSH, and we should be able to get ourselves a `root` shell without having to decrypt the credentials.

<a class="image-popup">
![a5dfc8fe.png](/assets/images/posts/bastion-htb-walkthrough/a5dfc8fe.png)
</a>

Time to connect.

<a class="image-popup">
![730caeb8.png](/assets/images/posts/bastion-htb-walkthrough/730caeb8.png)
</a>

Awesome. The rest is trivial.

<a class="image-popup">
![bd40047e.png](/assets/images/posts/bastion-htb-walkthrough/bd40047e.png)
</a>

:dancer:


[1]: https://www.hackthebox.eu/home/machines/profile/186
[2]: https://www.hackthebox.eu/home/users/profile/29267
[3]: https://www.hackthebox.eu/
