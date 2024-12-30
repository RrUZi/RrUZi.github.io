---
title: 'Floxif Family Infection Sample Analysis'
date: 2024-10-05
permalink: /Floxif Family Infection Sample Analysis/
tags:
  - malware
  - Floxif
--- 

## 1 Overview

The sample releases the symsrv.dll module in the directory C:\Program Files\Common Files\System, where symsrv.dll is the main infection module. The sample writes this module into memory and begins scanning files and directories on the victim's computer, infecting files outside of the %system%, %windows%, and %temp% folders to avoid infecting system files that could cause system instability. During the infection process, it downloads additional malicious module components from the attacker's C2 server, but due to the C2 being inactive, further analysis of other malicious modules is not possible.

## 2 Mitigation Recommendations

● Install an intelligent terminal defense system and perform a full system virus scan.

## 3 Detailed Analysis

### 3.1 setup.exe Analysis

After executing the sample (759FAE966FE22FB00B8331AF36556513), it first loads the symsrv.dll module and then releases it into the Program Files\Common Files\System directory.

| Time | Process ID | Operation | File |
| --- | --- | --- | --- |
| 11:19:13:871 | 0014284e3f2f0f18b4.. 3008:1052 | FILE touch | C:\Program Files\Common Files\System\symsrv.dll |
| 11:19:13:871 | 10014284e3f2f0f18b4... 3008:0 | FILE_open | C:\Program Files\Common Files\System\symsrv.dll |
| 11:19:13:871 | 0014284e3f2f0f18b4... 3008:1052 | FILE write | C:\Program Files\Common Files\System\symsrv.dll |
| 11:19:13:871 | 00014284e3f2f0f18b4... 3008:0 | FILE_modified | C:\Program Files\Common Files\System\symsrv.dll |
| 11:19:13:871 | 0014284e3f2f0f18b4... 3008:0 | FILE_open | C:\Program Files\Common Files\System\symsrv.dll |

The DLL path is written into the HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows registry key. Once a program loads, it will load the DLL specified in the AppInit_DLLs registry entry.

| Key | Type | Value |
| --- | --- | --- |
| AppInit_DLLs | REG_SZ | C:\PROGRA~1\COMMON~1\System\symsrv.dll |
| DdeSendTimeout | REG_DWORD | 0x00000000 (0) |
| DesktopHeapLogging | REG_DWORD | 0x00000001 (1) |
| abDeviceNotSelectedTimeout | REG_SZ | 15 |
| GDIProcessHandleQuota | REG_DWORD | 0x00002710 (10000) |
| ab]IconServiceLib | REG_SZ | IconCodecService.dll |
| LoadAppInit_DLLs | REG_DWORD | 0x00000001 (1) |
| RequireSignedAppInit_DLLs | REG_DWORD | 0x00000000 (0) |
| ShutdownWarningDialogTim... | REG_DWORD | 0xFFFFFFFF (4294967295) |
| ab Spooler | REG_SZ | yes |
| abTransmissionRetryTimeout | REG_SZ | 90 |
| USERNestedWindowLimit | REG_DWORD | 0x00000032 (50) |
| USERPostMessageLimit | REG_DWORD | 0x00002710 (10000) |
| USERProcessHandleQuota | REG_DWORD | 0x00002710 (10000) |

Once the DLL module is loaded, it begins to infect files.

3.2 symsrv.dll Analysis

The sample (98D56568C600383803D56B493B461BFA) is a DLL module. By examining the export table with PE tools, it is identified as an infectious virus of the F1oxif family.

After loading, the sample calls the GetSystemDirectoryA, GetWindowsDirectoryA, and GetTempPathA APIs to obtain the locations of the %system%, %windows%, and %temp% folders, thereby avoiding infection of files in these folders to prevent system shutdown issues.

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_1.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=6PSfs3BEJRVHB%2FFO5Ir%2BErhsTW4%3D)

It also initializes the C2 and some function addresses.

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_2.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=3uWbC6t3pmEZF3ZX6dQbMZoZxAA%3D)

![Image](http://darwin-controller-pro.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_3.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=6%2FZW52V4vHYjRb0Aa8DSMwcozY4%3D)

![Image](http://darwin-controller-pro.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_4.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=55%2FYj42c24pc%2FesmjU6hUaFcgEc%3D)

It then creates a mutex named "Global\SYS E0A9138".

Subsequently, it performs privilege escalation. After escalation, it hooks the KiUserExceptionDispatcher function for anti-debugging, and hooks RegOpenKeyExA, RegOpenKeyExW to protect its own registry entries. It also hooks CredReadW, CreateServiceA, CreateServiceW, OpenServiceA, OpenServiceW, WinVerifyTrust, CreateFileW, ExitProcess, CreateProcessInternalW, MessageBoxTimeoutW, and WahReferenceContextByHandle functions for self-preservation and file infection.


It checks whether common antivirus software exists on the computer.

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_8.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=zhycz7J9kT%2BbJ41TuFXtBM5AcII%3D)

Finally, it uses a combination of CreateToolhelp32Snapshot, Process32First, and Process32Next APIs to obtain the process list, and uses CreateToolhelp32Snapshot, Module32First, and Module32Next APIs to obtain the module list from each process.


The sample checks against the previously obtained three folders: %system%, %windows%, and %temp%.


If the traversed module path is not located in any of the three folders mentioned above, the sample reads the file into memory, performs the infection, renames the original file with a ".dat" extension, sets the file attributes to system file and hidden, then writes the infected file from memory back to disk with the original filename, and finally calls MoveFileExA to set the original file for deletion on the next startup.

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_11.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=A%2BMkLV7srM6g%2FbiYojU7crucck0%3D)

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_12.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=InonMGbtNVsDUWVge%2FOf2BdnFGY%3D)

During the infection process, the sample requests to download the following files from C2 (hxxp://5isohu.com/, hxxp://www.aieov.com/): logo.gif, setup.exe, so.gif.

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_13.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=YUD6dxGv17e5V%2F9kFhlRn1%2BuiJ8%3D)

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_14.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=CqSWg84RZ0uPrbRTcgzm579Somk%3D)

The following is the data traffic captured by wirsharp.

| Time | Source IP | Destination IP | Protocol | Request |
| --- | --- | --- | --- | --- |
| 40 5.257000 | 127.0.0.1 | 127.0.0.1 | HTTP | 133 HTTP/1.0 200 OK (text/html) |
| 231 11.185000 | 192.168.19.128 | 192.0.2.123 | HTTP | 98 GET /setup.exe HTTP/1.1 |
| 232 11.201000 | 192.168.19.128 | 192.168.19.128 | HTTP | 98 GET /setup.exe HTTP/1.1 |
| 363 12.340000 | 192.168.19.128 | 192.0.2.123 | HTTP | 101 GET/setup.exe HTTP/1.1 |
| 364 12.340000 | 192.168.19.128 | 192.168.19.128 | HTTP | 101 GET /setup.exeHTTP/1.1 |
| 423 12.464000 | 192.168.19.128 | 174.139.10.194 | HTTP | 98 GET /setup.exe HTTP/1.1 |
| 424 12.464000 | 192.168.19.128 | 192.168.19.128 | HTTP | 98 GET /setup.exe HTTP/1.1 |
| 494 12.886000 | 192.168.19.128 | 192.0.2.123 | HTTP | 97 GET /logo.gif HTTP/1.1 |
| 495 12.886000 | 192.168.19.128 | 192.168.19.128 | HTTP | 97 GET /logo.gif HTTP/1.1 |
| 502 12.886000 | 192.168.19.128 | 192.168.19.128 | HTTP | 133 HTTP/1.0 200 OK(image/gif) |
| 503 12.886000 | 192.0.2.123 | 192.168.19.128 | HTTP | 133 HTTP/1.0 200 OK(image/gif) |
| 1187 54.772000 | 192.168.19.128 | 192.0.2.123 | HTTP | 95 GET /so.gif HTTP/1.1 |
| 1188 54.772000 | 192.168.19.128 | 192.168.19.128 | HTTP | 95 GET /so.gif HTTP/1.1 |
| 1195 54.772000 | 192.168.19.128 | 192.168.19.128 | HTTP | 133 HTTP/1.0 200 OK(image/gif) |
| 1196 54.772000 | 192.0.2.123 | 192.168.19.128 | HTTP | 133 HTTP/1.0 200 OK(image/gif) |
| 1213 54.881000 | 192.168.19.128 | 192.0.2.123 | HTTP | 98 GET /so.gif HTTP/1.1 |
| 1214 54.881000 | 192.168.19.128 | 192.168.19.128 | HTTP | 98 GET /so.gif HTTP/1.1 |
| 1221 54.881000 | 192.168.19.128 | 192.168.19.128 | HTTP | 133 HTTP/1.0 200 OK(image/gif) |
| 1222 54.881000 | 192.0.2.123 | 192.168.19.128 | HTTP | 133 HTTP/1.0 200 OK(image/gif) |
| 1239 54.990000 | 192.168.19.128 | 174.139.10.194 | HTTP | 95 GET /so.gif HTTP/1.1 |
| 1240 54.990000 | 192.168.19.128 | 192.168.19.128 | HTTP | 95 GET /so.gif HTTP/1.1 |

1247 54.990000    192.168.19.128      192.168.19.128      HTTP     133 HTTP/1.0 200 OK(image/gif)

Among them, logo.gif is executed after download.

![Image](http://darwin-controller-pro-01.oss-cn-hangzhou.aliyuncs.com/docs/1323226763386974208/%E3%80%90%E5%8E%9F%E6%96%87%E3%80%91%E6%81%B6%E6%84%8F%E4%BB%A3%E7%A0%81%E9%80%86%E5%90%91%E5%88%86%E6%9E%90%E6%8A%A5%E5%91%8A_Floxif%E5%AE%B6%E6%97%8F%E6%84%9F%E6%9F%93%E5%BC%8F%E6%A0%B7%E6%9C%AC%E5%88%86%E6%9E%90_15.jpg?Expires=1735609923&OSSAccessKeyId=LTAI5tBVMtznbk7xyCa56gof&Signature=BUZ1AA6n6HjNquYmCYLv30Xy9Sw%3D)

Since both C2 servers are inactive and no related historical samples are associated, further analysis of subsequent payloads is not possible.
