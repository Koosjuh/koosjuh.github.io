---
title: "Session Validation"
description: "Template for validating user sessions across Entra ID and on-premises environments during security investigations."
---

## Session Validation

This template is used during investigations to validate whether a user session or authentication activity is legitimate across identity and endpoint telemetry sources.

---

## Entra ID

```text
**User**
#####
UPN:
- [AuditLogs]
- [InteractiveLogs]
- [Non interactive Logs]
- [Valid MFA]
- [Identity Info]
- [Office Activity]

Location
#####
**Location Details:**
- [IP interactive]
- [IP MFA]
- [IP Non interactive]
```
