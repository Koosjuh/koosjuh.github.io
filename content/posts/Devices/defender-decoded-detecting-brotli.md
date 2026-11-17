---
title: "Defender Decoded: Finding Brotli Across Your Environment"
date: 2026-11-16
lastmod: 2026-11-17
hero: "/images/posts/brotli.png"
description: "A quick-start guide to finding Brotli (CVE-2026-111497) in your environment with Microsoft Defender software inventory and KQL."
summary: "Start with the software inventory and Discovered vulnerabilities tab, then use KQL to investigate affected devices, Brotli DLLs, Node.js runtimes, and Python packages."
categories:
  - "Devices"
tags:
  - "Microsoft Defender"
  - "Defender Vulnerability Management"
  - "CVE-2026-111497"
  - "Advanced Hunting"
  - "KQL"
  - "Brotli"
  - ".NET"
  - "Node.js"
  - "Python"
  - "Defender Decoded"
draft: false
toc: true
menu:
  sidebar:
    name: "Finding Brotli"
    identifier: "defender-decoded-detecting-brotli"
    parent: "defender"
    weight: 20
---

Brotli is a lossless compression format, and Google's Brotli library is the implementation most software ships. **CVE-2026-111497** is an out-of-bounds write in that library's decoder, affecting versions 1.0.3 through 1.2.0. An application that decompresses attacker-supplied Brotli data can crash, leak process memory, or in some cases execute code. CISA added the CVE to its Known Exploited Vulnerabilities catalog on 27 October 2026.

The library is rarely installed on its own. It is compiled into runtimes such as Node.js and .NET and packaged for Python, so finding it means looking under several product names. This post does that with Defender's software inventory and Advanced Hunting.

The inventory query below is a broad name-based starting point: it searches registered software names for `brotli` across your devices, without filtering on a CVE. You may see Linux machines with Brotli packages, while copies bundled with applications can appear under a different product name. Check the software pages and the CVE findings as well.

## 1. Start with the software inventory

In the Microsoft Defender portal, open **Vulnerability management**, then **Inventories**, and select **Software**.

1. Search for **Brotli**, **Node.js**, **.NET**, and **Python**.
2. Open each relevant software page and check **Discovered vulnerabilities** for `CVE-2026-111497`. As of 17 November 2026, Defender lists CVE-2026-111497 on the **Discovered vulnerabilities** tab of these software pages. Coverage may change, so check your own tenant.
3. Open the CVE finding and review the affected devices. Use **Version distribution** to understand which software versions are present.

Node.js, .NET, and Python applications are three key places to check for affected Brotli components. For Python, check whether the `Brotli` or `brotlicffi` package is present. Also review other applications identified by the vendor advisory.

Please check the actual CVE finding. The general version distribution can also include installations that are not associated with it.

Run the following queries separately in **Microsoft Defender XDR Advanced Hunting**. Leave `TargetDevice` empty for all devices in your scope, or enter the exact `DeviceName`.

### Find directly registered Brotli software

```kql
let TargetDevice = "";
DeviceTvmSoftwareInventory
| where isempty(TargetDevice) or DeviceName =~ TargetDevice
| where SoftwareName contains "brotli"
| project DeviceName, OSPlatform, SoftwareVendor,
          SoftwareName, SoftwareVersion
| order by DeviceName asc
```

This is a name match, not a vulnerability check. Linux packages such as `libbrotli1` may appear here. For findings under .NET or another product name, use the software page and the next query.

## 2. Find the devices Defender associates with the CVE

Here we filter on the CVE across **all software names**. That also returns findings Defender registers against a parent product such as .NET.

```kql
let TargetCve = "CVE-2026-111497";
let TargetDevice = "";
DeviceTvmSoftwareVulnerabilities
| where CveId == TargetCve
| where isempty(TargetDevice) or DeviceName =~ TargetDevice
| project DeviceId, DeviceName, OSPlatform,
          SoftwareVendor, SoftwareName, SoftwareVersion,
          CveId, RecommendedSecurityUpdate
| order by SoftwareName asc, SoftwareVersion asc, DeviceName asc
```

To see which reported software versions account for the most devices:

```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-111497"
| summarize Devices = dcount(DeviceId)
    by SoftwareVendor, SoftwareName, SoftwareVersion
| order by Devices desc
```

One device can appear under several products or versions, so do not add these counts together as a unique device total.

## 3. Find Brotli DLLs and their locations

Search for Brotli-named DLLs, including `System.IO.Compression.Brotli.dll`, `brotlidec.dll`, `libbrotlidec.dll`, and MSYS variants. Encoder and common-library matches can help identify the application, but do not establish that its decoder is vulnerable.

`System.IO.Compression.Native.dll` helps locate .NET's native compression implementation. [Older .NET Core builds](https://github.com/dotnet/corefx/blob/v3.1.0/src/Common/src/Interop/Windows/Interop.Libraries.cs) can use `clrcompression.dll`. Both also handle other compression formats. Set `IncludeNativeContext` to `true` when following up on a .NET finding; the default excludes those generic helpers to reduce noise.

```kql
let TargetDevice = "";
let IncludeNativeContext = false;
union withsource=Source
    DeviceFileEvents,
    DeviceImageLoadEvents
| where Timestamp >= ago(30d)
| where isempty(TargetDevice) or DeviceName =~ TargetDevice
| extend IsBrotliDll = FileName contains "brotli"
                      and FileName endswith ".dll",
         IsNativeHelper = FileName in~ (
             "System.IO.Compression.Native.dll",
             "clrcompression.dll"
         )
| where IsBrotliDll or (IncludeNativeContext and IsNativeHelper)
| extend Evidence = iff(IsNativeHelper,
    "Native compression context", "Brotli-named DLL")
| summarize LastSeen = max(Timestamp)
    by DeviceName, Source, ActionType, Evidence, FileName, FolderPath,
       InitiatingProcessFileName, InitiatingProcessFolderPath
| order by DeviceName asc, LastSeen desc
```

Follow `FolderPath`. A shared .NET runtime, a DLL in an application folder, and a copy under `D:\Builds` can need different updates. Also check **Software Evidence** on the device's software inventory page.

`FileCreated`, `FileModified`, and `FileRenamed` show file activity. `ImageLoaded` shows a DLL load. Neither proves Brotli decompression was used, and a file event's initiating process might simply be an installer.

This is a Windows DLL search against recorded events. It cannot find every statically linked or renamed copy. No results do not establish absence. Microsoft's advisory also excludes classic **.NET Framework itself** from this CVE; a compression DLL filename alone is not a vulnerability verdict.

## 4. Check Node.js copies separately

Brotli can be built into the Node.js executable. Check where Node.js has actually run:

```kql
let TargetDevice = "";
DeviceProcessEvents
| where Timestamp >= ago(30d)
| where isempty(TargetDevice) or DeviceName =~ TargetDevice
| where FileName in~ ("node.exe", "node", "nodejs.exe", "nodejs")
| summarize LastSeen = max(Timestamp)
    by DeviceName, FileName, FolderPath,
       ProcessVersionInfoProductVersion,
       InitiatingProcessFileName
| order by DeviceName asc, LastSeen desc
```

Check the executable path and version against the Node.js or application vendor's advisory. This query misses inactive copies and runtimes embedded under another executable name.

## 5. Find Python's Brotli packages

For Python, look for the `Brotli` or `brotlicffi` package in the application's environment. Their native modules use names beginning with `_brotli` or `_brotlicffi`, with `.pyd` extensions on Windows and `.so` on Linux. A DLL-only filter misses those files.

```kql
let TargetDevice = "";
union withsource=Source
    DeviceFileEvents,
    DeviceImageLoadEvents
| where Timestamp >= ago(30d)
| where isempty(TargetDevice) or DeviceName =~ TargetDevice
| extend IsPythonPackagePath = FolderPath contains "site-packages"
                              or FolderPath contains "dist-packages"
| where (
    // This prefix covers both _brotli and _brotlicffi.
    FileName startswith "_brotli"
    and (FileName endswith ".pyd" or FileName endswith ".so")
)
or (
    IsPythonPackagePath
    and (
        FileName =~ "brotli.py"
        or FolderPath contains "brotlicffi"
        or FolderPath contains "brotli-"
    )
)
| summarize LastSeen = max(Timestamp)
    by DeviceName, Source, ActionType, FileName, FolderPath,
       InitiatingProcessFileName, InitiatingProcessFolderPath
| order by DeviceName asc, LastSeen desc
```

This finds recorded activity involving the native modules, wrappers, and package files. It gives you environment paths to inspect, rather than a list of every Python installation. A file event can also refer to an old or removed copy; library-load evidence depends on the available platform telemetry.

Use that environment's Python executable to confirm the package version and location:

```bash
python -m pip show Brotli brotlicffi
```

Run this inside the relevant virtual environment or use its full interpreter path. The Python version is not the Brotli package version. See the [package advisory](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) for affected and fixed releases.

## Validate the copy you found

Compare what you find against the fixed releases:

| Component | Fixed in |
| --- | --- |
| Google Brotli (upstream) | 1.0.10, 1.1.1, 1.2.1 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 |
| .NET | 8.0.33, 9.0.22, 10.0.14 (11.0.0-rc.3 for .NET 11) |
| Python `Brotli` | 1.2.1 |
| Python `brotlicffi` | 1.2.1.0 |

End-of-life Node.js lines such as 20.x are affected and will not receive a fix. Distribution packages do not follow these numbers: Debian's fixed bookworm package is still versioned 1.0.9-2+deb12u1, so use the distribution's advisory for those.

Run these checks against the installation or application environment identified above:

| Environment | Read-only starting check |
| --- | --- |
| Shared .NET runtime | `dotnet --list-runtimes` |
| Node.js | `node -p "JSON.stringify({path:process.execPath,node:process.versions.node})"` |
| Debian or Ubuntu | `dpkg -l '*brotli*'`, checking installed rows marked `ii` |
| RPM-based Linux | `rpm -qa '*brotli*'` |
| curl | `curl --version`, or `curl.exe --version` on Windows |

For official Node.js builds, judge by the Node.js release number, not by `process.versions.brotli`. Node.js 24.22.1 contains the fix but still reports Brotli 1.2.0, because the patch was applied to the bundled source without changing its version string.

Use the actual runtime path. The version on `PATH` does not account for every application copy. For .NET, check relevant architectures and custom installation paths too.

## Apply the update and verify

Update the identified runtime, package, or vendor application and restart the affected processes. **Applications with a bundled runtime need their own update.** Self-contained .NET and NativeAOT applications require rebuilding and redeployment where affected. Include deployed container images and build artifacts in that review.

Then rerun the CVE query after Defender processes the updated inventory. Check the remaining findings and confirm which copy the application now uses. The filenames usually stay the same, and old events remain in the query period, so continued filename matches do not mean the update failed.

These checks rely on the Defender portal and Advanced Hunting, and both have a 30 day horizon. Advanced Hunting covers at most the last 30 days of data, and Defender Vulnerability Management stops showing a device's vulnerabilities once it has not reported for 30 days. A device that has been offline longer than that disappears from the results, yet it can still be vulnerable when it comes back online. Repeat the checks every other day at first, then every other week. Recurring checks, or an update process that also reaches devices when they return, keep those devices from being missed.

## References

- [Brotli format specification](https://www.rfc-editor.org/rfc/rfc7932.html)
- [Microsoft Defender software inventory](https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-software-inventory)
- [Software inventory query schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwareinventory-table)
- [Software vulnerability query schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table)
- [File events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table), [DLL-load events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table), and [process events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [.NET advisory for CVE-2026-111497](https://github.com/dotnet/runtime/security/advisories/GHSA-p3jp-9v83-76w9)
- [Node.js security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [Ubuntu CVE tracker](https://ubuntu.com/security/CVE-2026-111497)
- [Red Hat CVE guidance for system and bundled libraries](https://access.redhat.com/security/cve/cve-2026-111497)
- [.NET runtime listing](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet) and [Node.js dependency versions](https://nodejs.org/api/process.html#processversions)
- [.NET native compression build](https://github.com/dotnet/runtime/blob/main/src/native/libs/System.IO.Compression.Native/CMakeLists.txt)
- [Brotli library build and component names](https://github.com/google/brotli/blob/master/CMakeLists.txt)
- [MinGW Brotli DLLs](https://packages.msys2.org/packages/mingw-w64-x86_64-brotli) and [MSYS Brotli DLLs](https://packages.msys2.org/packages/brotli)
- [Python Brotli module](https://github.com/google/brotli/blob/master/setup.py), [BrotliCFFI module](https://github.com/python-hyper/brotlicffi/blob/main/src/brotlicffi/_build.py), and [package advisory](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
