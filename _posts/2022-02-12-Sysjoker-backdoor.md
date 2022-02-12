---
title: SysJoker backdoor - no OS is safe! 
author: Jack
date: 2022-02-12 10:28:00 +0000
categories: [KQL]
tags: [Blog, News, KQL, Backdoor, Malware, Linux, Windows, MacOS]
---

[*New SysJoker backdoor targets windows / MacOS and Linux...*](https://www.bleepingcomputer.com/news/security/new-sysjoker-backdoor-targets-windows-macos-and-linux/)

Recently researchers at Intezer discovered this new SysJoker backdoor malware after finding signs of it's activity on a Linux Server back in December 2021. Upon further analysis and investigation they found that this malware had been created to target the 3 major operating systems, while also being capable of being able remaining undetected . 

For a long time VirusTotal had minimal detections allowing it to go under the radar for a significant amount of time. The malware is wrriten in C++ and utilises github among a range of other technicues to remain undertected. 

Although Anti-virus providers should have updated detections for SysJoker by now, below i have included the Advanced hunting query written in KQL that i created using the IOCs published by Intezer. This query will alert you to any of the known SysJoker behvaiour / IOCs. 

{% include codeHeader.html %}
```
// Detect SysJoker Backdoor behvaiour and IOCs
// Additional details about threat: https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/
// Created by Jack Stubbs - 12.01.2022
let MaliciousSha256 = dynamic(["61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc", "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"]);
let MaliciousC2 = dynamic(["bookitlab.tech", "winaudio-tools.com", "graphic-updater.com", "github.url-mini.com", "office360-update.com", "drive.google.com/uc?export=download&id=1-NVty4YX0dPHdxkgMrbdCldQCpCaE-Hn", "drive.google.com/uc?export=download&id=1W64PQQxrwY3XjBnv_QAeBQu-ePr537eu"]);
union (
DeviceFileEvents
| where SHA256 in (MaliciousSha256)
),(
CommonSecurityLog
| where DestinationHostName in (MaliciousC2)
),(
DeviceNetworkEvents
| where RemoteUrl in (MaliciousC2)
),(
DeviceRegistryEvents
| where RegistryKey contains "HKEY_CURRENT_USERSoftwareMicrosoftWindowsCurrentVersionRun" and RegistryValueName contains "igfxCUIService" and RegistryValueData contains "igfxCUIService.exe"
)
| project DestinationHostName, SHA256, DeviceName, InitiatingProcessAccountUpn, RegistryKey, RegistryValueName, RegistryValueData
```