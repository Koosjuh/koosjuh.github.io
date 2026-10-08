---
title: "Windows Hardening: Enable Local Security Authority (LSA) Protection"
date: 2026-10-08T11:00:00+02:00
description: "Understand Windows LSA Protection, its security benefits, potential compatibility risks, and how to assess your environment using Microsoft Defender Advanced Hunting and audit mode."
summary: "LSA Protection helps safeguard Windows authentication credentials, but enabling it on production servers requires careful planning. Learn how it works, what could break, and how to assess compatibility before deployment."
categories:
  - Cyber Security
  - Microsoft Defender
  - Windows Hardening
tags:
  - LSA Protection
  - LSASS
  - Credential Theft
  - Windows Server
  - Microsoft Defender XDR
  - Advanced Hunting
  - KQL
  - Windows Hardening
draft: true
toc: true
menu:
  sidebar:
    name: LSA Protection
    identifier: lsa-protection
    parent: Defender
    weight: 40
---

## Introduction

When reviewing security recommendations in Microsoft Defender, you may come across the recommendation to **Enable Local Security Authority (LSA) Protection**.

The Local Security Authority plays a critical role in Windows authentication, and protecting it reduces opportunities for attackers to steal credentials and compromise other systems.

However, enabling LSA Protection on production servers can introduce compatibility risks, particularly in environments using third-party authentication components or legacy software. **This function is turned on by default in Windows 11.**

So how do you determine whether enabling LSA Protection is safe?

In this article, we'll look at:

- What LSA and LSASS are.
- How LSA Protection works.
- The obvious security benefits of enabling it.
- The potential compatibility risks.
- How to use Microsoft Defender Advanced Hunting to investigate LSASS dependencies.
- How to enable Microsoft's LSA audit mode to identify potential incompatibilities before enforcement.

The goal is to better understand the security control and establish a practical starting point for assessing its impact before making changes to production systems.

---

## What is the Local Security Authority (LSA)?

The **Local Security Authority (LSA)** is a fundamental security component of the Windows operating system.

It is responsible for enforcing local security policies and supporting the authentication and authorization of users and services.

The LSA functionality is implemented primarily through the **Local Security Authority Subsystem Service (LSASS)**, which runs as `lsass.exe`.

Microsoft describes LSA as responsible for validating users during local and remote sign-ins and enforcing local security policies.

Reference: [Microsoft Learn: Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

### What does LSASS do?

LSASS handles several security-critical Windows functions.

**1. User Authentication**

When a user signs in to Windows, LSASS participates in validating the user's identity.

Depending on the environment, these can include:

- Local account authentication.
- Kerberos authentication.
- NTLM authentication.
- Authentication packages used by third-party software.

**2. Logon Sessions and Security Tokens**

After successful authentication, Windows establishes a logon session and creates an access token representing the user's identity, group memberships, and privileges.

Windows uses these access tokens when deciding whether a process or user is permitted to access a resource.

**3. Credential Handling**

LSASS handles sensitive authentication material needed to support Windows authentication and single sign-on functionality.
Depending on the operating system configuration and authentication methods, this can include credential-related secrets or reusable authentication material.

**4. Local Security Policy Enforcement**

LSA also supports the enforcement of security policies related to accounts, privileges, and authentication.

In short, LSASS is one of the most security-sensitive processes running on a Windows system. And that makes it an attractive target for attackers. Consider an attacker who has managed to compromise a Windows Server. Perhaps they exploited a vulnerable application or gained access through stolen credentials. Their initial access might be relatively limited, but one of their next objectives could be obtaining additional credentials.

Why?

Because credentials can allow an attacker to move from one system to another, impersonate users, or gain access to more privileged resources. This is where LSASS becomes interesting.

Since LSASS processes authentication information, attackers may attempt to access its memory to extract sensitive material.

### Credential Dumping

Credential dumping refers to techniques used to obtain authentication information from a compromised system. One common target is LSASS memory.

Depending on the configuration, attackers may attempt to recover:

- NTLM credential material.
- Kerberos tickets.
- Authentication secrets.
- Other sensitive information associated with active logon sessions.

Tools such as Mimikatz are well known for their ability to interact with Windows authentication mechanisms and extract certain types of credentials. If an attacker obtains credentials belonging to an administrator or another privileged identity, the consequences can extend well beyond the initially compromised server.

For example, a compromised application server could become a stepping stone toward more sensitive infrastructure. This is one of the reasons protecting LSASS is important. Before Protected Process Light was introducted attackers could easily dump all the credentials stored by LSASS. And enabling Protected Process Light is what the recommendation "Enable LSASS protection" is all about. 

**LSA Protection is a Windows security feature that allows LSASS to run as a Protected Process Light (PPL).**

Protected Process Light introduces additional restrictions on how other processes can interact with the protected process. Without this additional protection, an attacker who obtains sufficient privileges may have more opportunities to interact with LSASS memory. With LSA Protection enabled, Windows imposes stricter restrictions.

### What Changes When LSASS Runs as PPL?

The protection affects two important areas.

**1. Process Access Protection**

Windows restricts nonprotected processes from performing sensitive operations against protected LSASS. This includes operations that could otherwise allow unauthorized memory reading or code injection.

As a result, common user-mode techniques for extracting LSASS memory become more difficult.

**2. Protected Component Loading**

LSASS can load additional components to support authentication and security functions. However, when LSA Protection is enabled, these components must satisfy specific Microsoft signing and security requirements.

For example, Microsoft states that plug-ins loaded into protected LSA must have the required Microsoft signature. Some components must also meet additional security requirements established through Microsoft's Security Development Lifecycle guidance.

If a component does not meet these requirements, Windows may refuse to load it. This second part is important because it introduces potential compatibility risks.

Reference: [Microsoft Learn: Protected process requirements for plug-ins or drivers](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#protected-process-requirements-for-plug-ins-or-drivers)

Microsoft documents additional LSA protection specifically as a mechanism for helping prevent unauthorized memory access and code injection that could compromise credentials.

Reference: [Microsoft Learn: Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)

The next obvious step is tampering with the registry to disable this protection. When an attacker gets access they might want to disable this functionality or a malicious piece of software might have this hardcoded. A possible daily hunting query for this can be a detection that detects changes to the registry pertaining the RunAsPPL registry key.

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey endswith
    @"\SYSTEM\CurrentControlSet\Control\Lsa"
    or RegistryKey endswith
    @"\SYSTEM\ControlSet001\Control\Lsa"
    or RegistryKey endswith
    @"\SYSTEM\ControlSet002\Control\Lsa"
| where RegistryValueName has "RunAsPPL"
    or PreviousRegistryValueName has "RunAsPPL"
    | where RegistryValueName has "RunAsPPL"
    or PreviousRegistryValueName has "RunAsPPL"
| extend Assessment = case(
    ActionType contains "Deleted",
        "LSA Protection setting deleted",
    RegistryValueData in~ ("0", "0x00000000", "0x0"),
        "LSA Protection potentially disabled",
    RegistryValueData in~ ("1", "2", "0x00000001", "0x00000002"),
        "LSA Protection configuration modified",
    "Review registry modification"
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    PreviousRegistryValueData,
    RegistryValueData,
    Assessment,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName,
    DeviceId,
    ReportId
| order by Timestamp desc
```

This does require a reboot of the system and depending on the alerting this might also generate an alert for your SOC. 

---

### LSA Protection Versus Credential Guard

LSA Protection and Windows Credential Guard are related security technologies, but they serve different purposes.

| Feature | LSA Protection | Credential Guard |
|---|---|---|
| Primary purpose | Protect the LSASS process | Isolate supported credential secrets |
| Technology | Protected Process Light | Virtualization-based security |
| Restricts unauthorized LSASS memory access | Yes | Provides additional isolation for protected secrets |
| Restricts incompatible LSA plug-ins | Yes | Not its primary purpose |

Credential Guard isolates certain credentials using virtualization-based security, reducing their exposure even if the normal Windows operating system is compromised.

LSA Protection restricts access to the LSASS process and controls which components can load into it.

Both technologies contribute to protecting Windows authentication.

Reference: [Microsoft Learn: Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

---

# What Are the Risks of Enabling LSA Protection?

The primary concern when enabling LSA Protection is **application and authentication compatibility**.

LSASS does not operate entirely on its own. Windows supports additional authentication packages, security packages, password filters, smart card integrations, and other components. Some of these components are developed by third-party vendors.

When LSA Protection is enabled, LSASS runs as a Protected Process Light (PPL), turned on by default in Windows 11, turned off by default in Windows Server. This means that components attempting to load into LSASS must meet additional Microsoft signing and security requirements.

A component that previously loaded successfully may therefore be blocked when LSA Protection is enabled.

Depending on the component, this could affect authentication functionality, password synchronization, smart card authentication, or applications that depend on custom security packages.

Microsoft explicitly recommends identifying LSA plug-ins and drivers, validating their signing requirements, and testing compatibility before enabling protection across an environment.

**Microsoft documentation:** [Protected process requirements for plug-ins or drivers](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#protected-process-requirements-for-plug-ins-or-drivers)

## Starting an Assessment with Microsoft Defender Advanced Hunting

Before enabling LSA Protection, we can use Microsoft Defender XDR Advanced Hunting to identify components currently being loaded by LSASS.

This provides an initial understanding of possible third-party dependencies.

However, there is an important distinction:

**Advanced Hunting can help identify potential compatibility concerns, but it cannot guarantee that every component will function when LSA Protection is enabled.**

For that, Microsoft provides a dedicated LSA audit mode, which we will configure later.

### Query 1: Identify DLLs Loaded by LSASS

The `DeviceImageLoadEvents` table contains information about observed DLL loading activities.

Our first query identifies all DLLs that Microsoft Defender has observed being loaded by LSASS during the previous 30 days.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "lsass.exe"
| summarize
    Devices = dcount(DeviceId),
    DeviceNames = make_set(DeviceName, 20),
    LoadCount = count(),
    LastSeen = max(Timestamp)
    by FileName, FolderPath, SHA1
| order by Devices desc
```

**What does this query do?**

The query filters DLL loading events to those initiated by `lsass.exe`.

It then groups the results by DLL name, installation path, and SHA1 hash.

For each unique DLL, it displays:

- **Devices:** Number of distinct devices where the DLL was observed.
- **DeviceNames:** Up to 20 example devices where the DLL was loaded.
- **LoadCount:** Total number of observed loading events.
- **LastSeen:** The most recent loading event.
- **SHA1:** File hash used to identify and investigate the binary.

You will likely encounter standard Windows components such as `vaultcli.dll`, `WinSCard.dll`, and `samlib.dll`.

What we're particularly interested in are third-party DLLs, especially those belonging to authentication software, security applications, or older enterprise applications.

If LSASS loads a third-party DLL, that component may require additional validation before enabling LSA Protection.

**Important:** A DLL appearing in these results is not evidence that it is incompatible. It simply confirms that Defender observed LSASS loading the component. The reason we want to know this, is that we can see the protential impact.

Reference: [Microsoft Learn: DeviceImageLoadEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)

### Query 2: Check DLL Signing Information

Microsoft requires LSA plug-ins loaded into protected LSASS to meet specific signing requirements.

We can therefore take the previous query a step further by correlating the loaded DLLs with available certificate verification information.

The `DeviceFileCertificateInfo` table contains certificate-related information collected by Defender for Endpoint.

```kusto
let LSASSModules =
    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "lsass.exe"
    | where isnotempty(SHA1)
    | summarize
        Devices = dcount(DeviceId),
        DeviceNames = make_set(DeviceName, 20),
        LoadCount = count(),
        LastSeen = max(Timestamp)
        by SHA1, FileName, FolderPath;
let Certificates =
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | where isnotempty(SHA1)
    | summarize arg_max(Timestamp, *)
        by SHA1
    | project
        SHA1,
        IsSigned,
        IsTrusted,
        Signer,
        Issuer;
LSASSModules
| join kind=leftouter Certificates on SHA1
| extend Assessment = case(
    isnull(IsSigned), "Certificate data unavailable",
    tostring(IsSigned) == "0", "Unsigned",
    tostring(IsTrusted) == "0", "Untrusted signature",
    tostring(IsSigned) == "1"
        and tostring(IsTrusted) == "1", "Signed / trusted",
    "Unknown signature status"
)
| where Assessment != "Signed / trusted"
| project
    FileName,
    FolderPath,
    SHA1,
    Devices,
    DeviceNames,
    LoadCount,
    IsSigned,
    IsTrusted,
    Signer,
    Issuer,
    Assessment,
    LastSeen
| order by Devices desc
```

**What does this query do?**

First, it retrieves the DLLs observed being loaded by LSASS.

Next, it looks up available signing information for those DLLs using their SHA1 hashes.

Finally, it identifies components where:

- No certificate verification information is available.
- Defender reports that the file is unsigned.
- Defender reports that the file's signature is not trusted.

This can help narrow down which DLLs deserve further investigation.

**Understanding the limitations**

There are two important limitations to this query.

First, missing certificate information does not mean a DLL is unsigned. Defender might simply not have a corresponding certificate verification record.

Second, even a signed and trusted DLL is not necessarily compatible with protected LSASS.

Microsoft requires specific Microsoft signing conditions for protected LSA plug-ins. Standard certificate trust does not establish that these requirements are satisfied.

Therefore, this query should be used to identify investigation candidates, not to certify compatibility.

References:

- [Microsoft Learn: DeviceFileCertificateInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table)
- [Microsoft Learn: LSA plug-in signing requirements](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#signature-verification)

### Query 3: Investigate Code Integrity Events

Next, we can investigate whether Microsoft Defender has recorded Code Integrity-related activity.

Code Integrity is responsible for enforcing several Windows security requirements, including application control and code-signing policies.

The following query retrieves relevant App Control Code Integrity events.

```kusto
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in (
    "AppControlCodeIntegrityPolicyBlocked",
    "AppControlCodeIntegrityPolicyAudited",
    "AppControlCodeIntegrityOriginAudited"
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

**What does this query do?**

It searches for three types of App Control events:

| ActionType | Description |
|---|---|
| `AppControlCodeIntegrityPolicyBlocked` | A file was blocked by an enforced App Control policy |
| `AppControlCodeIntegrityPolicyAudited` | A file triggered an App Control policy audit event |
| `AppControlCodeIntegrityOriginAudited` | An audit event related to managed installer or reputation-based file origin |

The `AdditionalFields` column can provide further information about the relevant policy, signing level, and evaluated file.

For example, you may discover that a DLL was blocked because it did not satisfy the signing requirements of a Windows virtualization-based security policy.

However, this does not automatically mean that the event is related to LSA Protection.

**A Code Integrity block is not necessarily an LSASS block.**

Always examine the process responsible for the event and the policy involved.

If the event involves `svchost.exe`, for example, it should not automatically be classified as an LSASS compatibility issue.

Furthermore, these Advanced Hunting action types are not documented as complete substitutes for the specific Windows LSA audit events.

If you do not find any LSASS-related events, you still cannot conclude that all LSA components are compatible.

### Query 4: Investigate a Specific DLL and Its Process Relationships

Suppose our first query identifies an unfamiliar third-party DLL.

Before classifying it as a potential compatibility concern, we want to understand which processes are loading it.

Replace the server name with the relevant device in your environment.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where DeviceName =~ "SERVER_APP_01"
| where FileName =~ "Name_dll"
| summarize
    Loads = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by InitiatingProcessFileName,
       InitiatingProcessParentFileName
| order by Loads desc
```

**What does this query do?**

It identifies which processes have loaded the specified DLL on the selected server.

The results include:

- **InitiatingProcessFileName:** Process responsible for loading the DLL.
- **InitiatingProcessParentFileName:** Parent of that process.
- **Loads:** Number of observed loading events.
- **FirstSeen and LastSeen:** When the DLL loading activity was observed.

For example, the results might show:

```text
InitiatingProcessFileName: lsass.exe
InitiatingProcessParentFileName: wininit.exe
Loads: 16
```

This demonstrates that LSASS itself has been observed loading the third-party DLL. That makes it directly relevant to the compatibility assessment.

However, the DLL might also be loaded by other application processes. Identifying these relationships can help determine which applications or software components require further investigation. A DLL loaded by LSASS is not automatically incompatible with LSA Protection. Its role, signing requirements, and compatibility must still be validated.

---

# Enabling LSA Audit Mode

Advanced Hunting provides useful information, but it cannot answer the most important question definitively:

**Will an existing LSA plug-in fail to load when LSA Protection is enabled?**

Microsoft provides an audit mode specifically intended to help answer this question.

In audit mode, Windows evaluates LSA plug-ins and drivers against protected-process requirements without immediately blocking the components.

If a component fails the relevant checks, Windows records an event in the Code Integrity Operational log.

This allows administrators to identify potential compatibility problems before enabling enforcement. Please see the official documentation on how to enable this.

Reference: [Microsoft Learn: Audit for LSA plug-ins and drivers](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#audit-for-lsa-plug-ins-and-drivers-that-dont-load-as-a-protected-process)

---

# Validating LSA Protection After Enforcement

Once LSA Protection has been enabled, Windows can generate Code Integrity events when incompatible components fail to load.

These events are recorded in the same location:

```text
Applications and Services Logs
  Microsoft
    Windows
      CodeIntegrity
        Operational
```

| Event ID | Description |
|---|---|
| `3033` | A component fails Microsoft signing-level requirements |
| `3063` | A component fails shared-section requirements |

You can query these events using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id = 3033, 3063
} -ErrorAction SilentlyContinue |
Select-Object TimeCreated, Id, MachineName, Message
```

These event IDs are not exclusive to LSASS. Always verify which process and component the event references.

## Verify That LSASS Is Running as a Protected Process

Microsoft also documents how to verify that LSA Protection is actually active.

Open Event Viewer and navigate to:

```text
Event Viewer
  Windows Logs
    System
```

Look for **Event ID 12** from the `WinInit` provider.

The event should indicate that LSASS was started as a protected process at protection level 4.

You can retrieve it using PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Id = 12
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.ProviderName -match 'Wininit' -and
    $_.Message -match 'LSASS.exe'
} |
Select-Object TimeCreated, ProviderName, Id, Message
```

This is useful because the presence of a registry configuration does not always prove that LSASS is currently running in protected mode.

Reference: [Microsoft Learn: Verify LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#verify-lsa-protection)

---

# Final Considerations

The assessment process can be divided into two complementary methods.

**Microsoft Defender Advanced Hunting** helps identify observed LSASS DLL dependencies, investigate third-party components, and review available signing and Code Integrity telemetry.

**Microsoft's LSA audit mode** provides more targeted compatibility information by recording components that fail protected-process requirements without immediately blocking them.

Neither method can independently guarantee that enabling LSA Protection will not affect production applications.

**Microsoft documentation**

- [Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Protected-process requirements](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#protected-process-requirements-for-plug-ins-or-drivers)
- [LSA compatibility audit mode](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#audit-for-lsa-plug-ins-and-drivers-that-dont-load-as-a-protected-process)
- [DeviceImageLoadEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [DeviceFileCertificateInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table)
- [Verify LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#verify-lsa-protection)
