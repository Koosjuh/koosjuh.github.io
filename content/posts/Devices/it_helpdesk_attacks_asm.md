---
title: "Stopping Fake IT Support: RMM, Intune, Teams and User Awareness"
date: 2026-09-23
hero: "/images/posts/fake-it-helpdesk.png"
description: "Reducing the attack surface against fake IT helpdesk attacks by controlling remote access tooling, Microsoft Intune deployments, Teams external communication, and internal support processes."
summary: "A practical approach to reducing the opportunities attackers have to impersonate IT support and convince users to install or use unauthorized remote access tooling. Governing the entire process from beginning to end."
categories:
  - "Defender"
  - "Devices"
  - "Intune"
tags:
  - "Microsoft Defender for Endpoint"
  - "Microsoft Intune"
  - "Microsoft Teams"
  - "Advanced Hunting"
  - "KQL"
  - "RMM"
  - "Remote Access"
  - "Remote Support"
  - "Help Desk"
  - "Social Engineering"
  - "Attack Surface Management"
  - "Security Awareness"
  - "Endpoint Security"
  - "Fake Helpdesk"
draft: true
toc: true
menu:
  sidebar:
    name: Devices
    identifier: Configuration
    parent: "Devices"
    weight: 20
---

## Introduction

This blog is written from the perspective of an existing enterprise that wants to defend against Fake IT Helpdesk Attacks and/or standardize its remote support process.

Threat actors are increasingly impersonating IT and Helpdesk personnel to exploit the trust users place in legitimate support processes. Instead of relying on malware or software vulnerabilities for initial access, attackers may contact employees through phone calls, Microsoft Teams, or other communication channels and convince them to approve remote access, install Remote Management Tools, provide credentials, or accept elevation prompts. Microsoft has documented multiple recent campaigns where attackers impersonated IT personnel through Teams and then convinced users to provide remote access through legitimate support tooling such as Quick Assist.

Recent examples demonstrate that this is not a theoretical scenario:

Odido, February 2026: Odido confirmed that attackers associated with ShinyHunters impersonated members of its IT staff and contacted customer service employees through voice phishing. One of these attacks resulted in unauthorized access and the exfiltration of customer data.

**The less ambiguity there is around how IT support operates, the harder it becomes for an attacker to convincingly impersonate IT.**

The goal is to create one predictable and recognizable Helpdesk process. Employees should know which tool is used, how legitimate Helpdesk personnel contact them, what actions they may be asked to perform, and, equally important, what they should never be asked to do. On the technical side the software should be correctly configured and have the appropiate security controlls in place.

## Understanding the Attack

A typical Fake IT Helpdesk attack starts with an attacker contacting a user while impersonating IT support. The attacker creates urgency, convinces the user to start or install a Remote Management Tool, and then obtains interactive access to the device. The user on the other side generally does not have the technical know how and can fall for this sort of social engineering.

{{< mermaid >}}
flowchart LR
    A[Attacker impersonates IT / Helpdesk either via Phone or Teams] --> B[Creates urgency or claims a technical issue]
    B --> C[User is instructed to start or install an RMM tool]
    C --> D[Attacker obtains interactive access]
    D --> E[Credential or session theft]
    D --> F[Malware / Persistence]
    D --> G[Reconnaissance / Lateral Movement]
{{< /mermaid >}}

Legitimate RMM software is attractive to attackers because it already provides many capabilities required for hands-on-keyboard access, while its executables and network traffic may be considered legitimate within an enterprise environment.

Some remote-support tools can also run as portable or per-user applications without requiring administrative installation. Controls focused only on removing local administrator rights or preventing privileged software installation may therefore not be sufficient. The objective should be to clearly define which Remote Management Tools are authorized and how they may be used.

#### Portable RMM Software examples

| Product                     | Standard-user capability                                                                                                                                                                                                             | Vendor documentation                                                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| **TeamViewer QuickSupport** | Runs as a single executable without installation or Windows administrative rights. Administrative rights are only needed later if the technician needs to interact with UAC/elevated applications.                                   | TeamViewer explicitly states that QuickSupport “runs without installation or Windows or macOS administrative rights.” ([TeamViewer][1]) |
| **AnyDesk Portable**        | Can be downloaded and executed without installation and without administrator privileges. The session remains unelevated and cannot normally interact with UAC until elevated.                                                       | AnyDesk documents Portable Mode as not requiring administrator privileges. ([AnyDesk Help Center][2])                                   |
| **Splashtop SOS**           | The SOS executable can be downloaded and run directly by the user. Splashtop specifically documents it as running in Windows/macOS user space without installation. A standard-user session cannot interact with UAC until elevated. | Splashtop SOS documentation confirms both the no-install model and standard-user operation. ([Splashtop On-Prem Support][3])            |
| **Zoho Assist**             | Supports browser-based attended remote support without software installation or administrator privileges. It can initially operate at user level and has a separate elevation process for administrative operations.                 | Zoho explicitly states that its browser-based remote support requires neither installation nor elevated permissions. ([Zoho][4])        |

[1]: https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-classic/modules/quicksupport/?utm_source=chatgpt.com "QuickSupport"
[2]: https://support.anydesk.com/portable-vs-installed?utm_source=chatgpt.com "Installation"
[3]: https://support-splashtoponprem.splashtop.com/hc/en-us/articles/900000386743-Introduction-to-Splashtop-SOS?utm_source=chatgpt.com "Introduction to Splashtop SOS – Splashtop On-Prem - Support"
[4]: https://www.zoho.com/assist/remote-desktop/remote-desktop-software-without-download.html?utm_source=chatgpt.com "Remote Access Without Download or Installation - Zoho Assist"

**Disclaimer**

These type of applications (Zoho Assist not included) can be prevented with "WDAC" however many organisations do not choose to use this due to the administration overhead this brings.

## Discovering RMM Software with Microsoft Defender

### Why Inventory Matters

Before defining what should be allowed, determine what is already present in the environment.

### RMM Detection with KQL

Introduce the KQL detection used to identify known RMM products through processes, filenames, and other indicators.

**KQL Query**

```kql
// RMM discovery query
// To be added
```

### Reviewing the Results

Discuss:

* Expected RMM tooling
* Unexpected RMM tooling
* Legacy tools
* User-installed tools
* Tools that should no longer exist

## RMM Deployment Through Microsoft Intune

### Identify Centrally Deployed Remote Support Software

After discovering Remote Management Tools through Microsoft Defender, determine which remote support applications are intentionally deployed and managed by the organization.

Microsoft Intune and Microsoft Graph can be used to identify applications that are centrally deployed to managed devices.

```text
Microsoft Graph endpoints and examples to be added.
```

Compare the applications deployed through Intune with the RMM software identified through Microsoft Defender.

The objective is to answer a simple question:

**Is this Remote Management Tool present because IT deliberately deployed and manages it?**

Software detected on endpoints but not part of the approved deployment process should be investigated. This may include legacy support tools, user-installed applications, portable RMM software, or applications introduced outside the normal IT process.

---

## Standardizing Remote Support

Remote support should follow a single, documented, and recognizable process.

The exact technology used is less important than making sure the organization controls **how the software is deployed, who can use it, how authentication is performed, which devices can be accessed, and how users recognize legitimate support activity**.

### 1. Select the Approved Remote Support Platform

Organizations should define which Remote Management Tool or tools are officially approved for remote support.

When selecting a platform, consider at least:

* Integration with Microsoft Entra ID or another central identity provider
* Single Sign-On
* MFA and Conditional Access support
* Role-Based Access Control
* Device or endpoint access restrictions
* Support for allowlists and blocklists
* Session logging
* Session auditing or recording where required
* File-transfer controls
* Administrative elevation controls
* Centralized deployment
* API or reporting capabilities
* Integration with existing endpoint-management tooling

The objective is to prevent the Helpdesk environment from becoming a collection of different remote support applications with different authentication methods and security controls.

### 2. Centrally Deploy the Approved Client

Where a local client or agent is required, it should be deployed centrally through Microsoft Intune or another approved software-management platform.

Users should not normally be required to search for, download, or install remote support software themselves.

This provides an important security-awareness benefit:

> **The approved remote support application is already installed. IT will not ask you to download another remote access tool.**

If an attacker asks an employee to download AnyDesk, TeamViewer, ScreenConnect, Splashtop, or another Remote Management Tool outside the documented process, the request becomes easier for the employee to recognize as abnormal.

### 3. Centralize Helpdesk Authentication

Helpdesk personnel should authenticate through the organization's central identity platform whenever the selected RMM vendor supports it.

Prefer:

* Microsoft Entra ID Single Sign-On
* Phishing-resistant MFA
* Conditional Access
* Managed or compliant administrative devices
* Dedicated Helpdesk or administrative identities

Avoid creating separate unmanaged RMM accounts where possible.

Centralized authentication also allows access to be removed automatically when Helpdesk personnel leave the organization or change roles.

### 4. Apply Least-Privilege Access

Helpdesk personnel should receive only the permissions required to perform their support activities.

Remote support operators generally do not require highly privileged identities such as:

* Global Administrator
* Security Administrator
* Domain Administrator

Use the RMM platform's own RBAC capabilities together with Microsoft Intune RBAC and Microsoft Entra ID controls where applicable.

Where administrative elevation is required on an endpoint, prefer mechanisms that provide scoped or device-specific elevation rather than using highly privileged identities directly on user devices.

Examples include:

* Windows LAPS
* Microsoft Intune Endpoint Privilege Management
* Dedicated local administrative credentials
* Other controlled Just-In-Time elevation mechanisms

### 5. Restrict Which Devices Can Be Accessed

The approved remote support platform should not automatically provide unrestricted access to every corporate endpoint.

Where supported, configure policies defining:

* Which Helpdesk groups may initiate remote sessions
* Which endpoint groups they may access
* Which administrators may manage the RMM platform
* Whether external accounts may establish sessions
* Which session capabilities are allowed

A default-deny or explicit-allow model is preferable where the platform supports it.

For example, file transfer, clipboard access, unattended access, remote command execution, or switching control between users may not be required for every Helpdesk role.

### 6. Protect the Administrative Interface

Access to the RMM management portal should be treated as administrative access.

Where technically possible, require:

* Phishing-resistant MFA
* Microsoft Entra Conditional Access
* Managed or compliant administrative devices
* Access only from approved Helpdesk or administrative groups
* Restricted geographic or network access where appropriate

The objective is to protect both the identity used by the Helpdesk and the management interface capable of initiating remote connections.

### 7. Enable Logging and Session Auditing

Remote support activity should be logged centrally.

At minimum, organizations should be able to determine:

* Who initiated the session
* Which device was accessed
* When the session started
* When the session ended
* Which Helpdesk identity performed the session
* Whether administrative elevation occurred
* Whether file transfer or other sensitive functionality was used

Where supported and appropriate for the organization, session recording can provide additional auditing capabilities.

These logs should be retained according to the organization's security and compliance requirements and, where possible, integrated with the SIEM or monitoring platform.

### 8. Remove Unnecessary Remote Management Tools

Once the approved remote support process has been established, remove Remote Management Tools that are no longer required.

Multiple remote support products increase ambiguity.

If users regularly see several different remote-access applications, it becomes much harder to teach them which requests are legitimate.

The preferred situation is:

> **This is the tool IT uses. This is how IT contacts you. This is how a support session starts. Anything outside this process should be treated as suspicious.**

Defender inventory and Advanced Hunting can then be used periodically to identify RMM software that falls outside the approved list.

---

## Microsoft Teams External Communication

### External Communication as an Attack Surface

Remote support does not start with the RMM application itself.

Attackers first need a communication channel through which they can establish trust with the victim.

Microsoft Teams external communication can provide such a channel. An external user may contact an employee and impersonate Helpdesk personnel, another department, a supplier, or a Microsoft support representative.

Organizations should therefore review whether their current Teams external communication configuration matches their actual business requirements.

### Review Teams External Access

Review the tenant's Teams external communication settings and determine:

* Whether users need to communicate with arbitrary external Teams tenants
* Whether communication can be limited to approved domains
* Whether specific user populations require external communication
* Whether Helpdesk personnel ever legitimately initiate support through external Teams conversations
* Whether communication with unmanaged Teams accounts is required

```text
Teams configuration and Microsoft Graph endpoints to be added.
```

The objective is not necessarily to disable external Teams communication completely, but to reduce unnecessary communication paths where business requirements allow it.

### Define the Expected Support Communication Channel

Employees should know how legitimate IT personnel contact them.

For example, an organization may establish that:

* Helpdesk requests always originate from the internal ticketing system.
* Helpdesk personnel only contact users using internal Teams accounts.
* External Teams users never provide internal IT support.
* Remote sessions are only initiated after an existing support ticket has been created.

This makes the communication channel itself part of the security control.

---

## Establishing a Clear IT Support Process

The technical controls described above should support a documented internal process.

Organizations should clearly define:

* How employees request IT support
* How IT contacts employees
* Which remote support platform is used
* How a remote session is initiated
* Whether users are ever expected to install software
* How employees can verify the identity of the Helpdesk employee
* How administrative elevation is performed
* What actions Helpdesk personnel may request
* What Helpdesk personnel will never request

A possible process could look like this:

{{< mermaid >}}
flowchart LR
    A[User creates support request] --> B[Helpdesk ticket created]
    B --> C[Helpdesk contacts user through approved channel]
    C --> D[Existing approved RMM client is used]
    D --> E[User verifies support request]
    E --> F[Remote session established]
    F --> G[Session activity logged]
    G --> H[Session closed and ticket updated]
{{< /mermaid >}}

The objective is to remove ambiguity.

An attacker should not be able to introduce a completely different support process and still appear legitimate.

---

# Hands-On Example: TeamViewer with Microsoft Intune

The following section demonstrates how these principles can be implemented using TeamViewer and Microsoft Intune.

TeamViewer is used as an example because it integrates with Microsoft Intune and Microsoft Entra ID and provides several controls that demonstrate the concepts described above. Other Remote Management Tool vendors provide comparable capabilities.

## Enable the TeamViewer Integration

First, enable the TeamViewer integration within your Microsoft Intune environment.

Go to the [Microsoft Intune admin center](https://intune.microsoft.com).

Navigate to **Tenant administration** and select **Connectors and tokens**.

![Intune Tenant Administration](/static/images/posts/helpdesk/Intune_TenantAdministration_ConnectandTokens.png)

Select **TeamViewer connector**.

![TeamViewer Connector](/static/images/posts/helpdesk/Intune_ConnectandTokens_TeamViewerConnector.png)

Enable the **TeamViewer Connector** and complete the required authorization process to connect your TeamViewer environment with Microsoft Intune.

For the complete configuration and additional setup options, refer to the official TeamViewer documentation:

[TeamViewer Intune Integration Installation and User Guide](https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-tensor-classic/integrations/intune-integration-installation-and-user-guide/)

## Deploy the TeamViewer Client

Deploy the TeamViewer client as a mandatory application through Microsoft Intune.

This implements one of the primary controls described earlier: users should not normally need to download remote support software themselves.

Because the approved client is already installed, employees can be instructed that requests to download additional remote access software fall outside the normal Helpdesk process.

## Configure TeamViewer SSO

Configure Single Sign-On using Microsoft Entra ID for TeamViewer support accounts.

SSO centralizes authentication and allows Microsoft Entra security controls such as MFA and Conditional Access to protect TeamViewer access.

It also simplifies onboarding and offboarding because access can be controlled through Entra identities and groups.

For configuration guidance:

[Single Sign-On for Microsoft Entra ID](https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-tensor-classic/sso/single-sign-on-for-microsoft-entra-id/)

## Configure Helpdesk Permissions

Within Microsoft Intune, assign Helpdesk personnel only the permissions required to initiate remote assistance sessions.

The built-in **Help Desk Operator** role can be used as a starting point instead of assigning broad Microsoft Entra administrative roles.

For the TeamViewer integration specifically, Helpdesk personnel require permission to read the remote assistance connector and initiate remote assistance sessions.

![TeamViewer Integration Roles and Permissions](/static/images/posts/helpdesk/TeamViewerIntegration_Roles_Permissions.png)

This allows Helpdesk personnel to use the approved remote-support process without unnecessarily expanding their administrative privileges.

An example of connecting to a device through Microsoft Intune is shown below.

![Connection to Device](/static/images/posts/helpdesk/microsoft-intune-overview_connect_toDevice.avif)

> **Security Disclaimer:** When providing remote support, any credentials or authentication tokens entered or used on the remote endpoint may potentially be exposed if that endpoint is compromised. Highly privileged identities such as Global Administrator, Security Administrator, or Domain Administrator should therefore not normally be used directly on standard user endpoints. Where administrative elevation is required, prefer scoped or device-specific elevation mechanisms.

## Configure Conditional Access

Conditional Access can protect two different parts of the remote support process.

### Protect TeamViewer Authentication

When TeamViewer is integrated with Microsoft Entra ID using SSO, configure an Entra Conditional Access policy for the TeamViewer Enterprise Application.

For Helpdesk and TeamViewer administrators, consider requiring:

* Phishing-resistant MFA
* A compliant or otherwise trusted administrative device
* Membership of the required Helpdesk or administrative group

This protects access to the TeamViewer account and management environment.

### Protect Remote Connections

TeamViewer Tensor Conditional Access can provide an additional authorization layer controlling which support identities are allowed to connect to which managed endpoints.

For example:

{{< mermaid >}}
flowchart LR
    A[Helpdesk Engineer] --> B[Microsoft Entra ID]

    subgraph ENTRA[Microsoft Entra Conditional Access]
        B --> C[Phishing-resistant MFA]
        C --> D[Compliant or trusted device]
    end

    D --> E[TeamViewer SSO]

    subgraph TVCA[TeamViewer Conditional Access]
        E --> F[Approved Helpdesk Group]
        F --> G[Approved Device Groups]
        H[Other Users / External Accounts] --> I[Deny]
    end

    G --> J[Corporate Endpoints]
{{< /mermaid >}}

This creates two security boundaries:

**Microsoft Entra Conditional Access** determines who can authenticate to TeamViewer.

**TeamViewer Conditional Access** determines who can establish remote connections to corporate endpoints.

Where supported, additional session functionality such as file transfer or other remote-control capabilities can also be restricted according to Helpdesk requirements.

## Additional TeamViewer Security Controls

TeamViewer provides additional controls that can be evaluated depending on the organization's requirements, including:

* Block and Allow Lists
* Bring Your Own Certificate
* Device and user access restrictions
* Session policies
* Authentication and identity controls

The available security controls should be reviewed against the organization's standard remote-support requirements rather than enabled solely because they are available.

For additional information:

[TeamViewer Security Statement](https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/security/security-statement/)

### Disclaimer

I do not specifically recommend TeamViewer or this exact configuration.

TeamViewer is used here as a practical example of how the controls described in this article can be implemented. Other Remote Management Tool vendors provide similar capabilities such as SSO, MFA, RBAC, allowlists, access restrictions, session logging, and centralized deployment.

The important objective is not the specific vendor.

The objective is to establish **one controlled, predictable, and recognizable remote support process** that employees can distinguish from an attacker impersonating the Helpdesk.

## Turning Technical Controls into Security Awareness

This is where the technical controls and employee training come together.

Instead of training employees using vague statements such as:

> Be careful when someone claims to be IT.

The organization can provide much stronger rules:

> IT only uses our approved remote support platform.

> IT will never ask you to install another remote access tool.

> IT will only contact you through our documented support process.

> External Teams users are never authorized to perform IT support.

These statements become possible because the tenant and operational processes have been configured to make them true.

## Executive Summary

The objective is to remove as much uncertainty as possible.

Microsoft Defender provides visibility into remote access tooling already present on endpoints. And there should be an easy to use process and single application to enable remote support. All others should be investigated first, why were they there, and then subsequently removed.

Microsoft Intune provides visibility and control over what IT deliberately deploys.

Teams configuration reduces unnecessary communication paths.

Standardized IT processes define exactly what legitimate support looks like.

Security awareness can then be built around those technical and procedural absolutes.

## Conclusion

Fake IT helpdesk attacks exploit trust and ambiguity.

A well-configured environment cannot eliminate social engineering, but it can make the attacker's story much harder to believe.

The end goal is simple:

**Make legitimate IT support predictable, controlled, and verifiable.**
