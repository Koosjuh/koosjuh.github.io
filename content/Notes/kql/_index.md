---
title: "Malware KQL"
date: 2026-03-13T15:00:00+01:00
draft: false
toc: false
---

```kql
DeviceFileEvents
| where FileName contains "FILE" and DeviceName == "HOST"

DeviceProcessEvents
| where FileName contains "FILE" and DeviceName == "HOST"

DeviceEvents
| where FileName contains "FILE" and DeviceName == "HOST"

DeviceFileEvents
| where SHA256 contains "SHA256" and DeviceName == "HOST"

DeviceProcessEvents
| where SHA256 contains "SHA256" and DeviceName == "HOST"

DeviceEvents
| where SHA256 contains "SHA256" and DeviceName == "HOST"
```
