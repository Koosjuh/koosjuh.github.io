---

title: "Reducing the Attack Surface Against Fake IT Helpdesk Attacks"
date: 2026-09-15
hero: "/images/posts/fake-it-helpdesk.png"
description: "Reducing the attack surface against fake IT helpdesk attacks by controlling remote access tooling, Microsoft Intune deployments, Teams external communication, and internal support processes."
summary: "A practical approach to reducing the opportunities attackers have to impersonate IT support and convince users to install or use unauthorized remote access tooling."
categories:
  - "Defender"
  - "Intune"
  - "Devices"
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
draft: true
toc: true
menu:
  sidebar:
    name: "Fake IT Helpdesk Attacks"
    identifier: "fake-it-helpdesk-attacks"
    parent: "defender"
    weight: 20
---

# Reducing the Attack Surface Against Fake IT Helpdesk Attacks

## Introduction

Briefly introduce the increase in attacks where threat actors impersonate IT or helpdesk personnel.

Main idea of the article:

**The less ambiguity there is around how IT support operates, the harder it becomes for an attacker to convincingly impersonate IT.**

This article will look at both the technical attack surface and the processes employees should expect when interacting with IT.

## Understanding the Attack

High-level overview of the attack pattern:

1. Attacker contacts the user pretending to be IT.
2. The attacker creates urgency or claims there is a technical problem.
3. The user is instructed to install or start remote access software.
4. The attacker obtains interactive access to the device.
5. The attacker attempts credential theft, session theft, lateral movement, or further persistence.

Discuss why legitimate RMM software is particularly useful to attackers.

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

### What Is Intune Deploying?

Use Microsoft Graph / Intune reporting to determine whether known RMM software is centrally deployed.

```text
Microsoft Graph endpoints and examples to be added.
```

Compare this with the Defender findings.

The goal is to answer:

**Is this remote access software present because IT deliberately deployed it?**

## Standardizing Remote Support

### Selecting the Approved RMM Platform

Discuss the process for selecting the organization's approved remote support solution.

Topics:

* Authentication
* MFA
* RBAC
* Logging
* Session auditing
* Device deployment
* Administrative access

### Deploying the Approved Platform

Discuss deploying the approved tooling centrally through Intune or another managed deployment mechanism.

### Removing Unnecessary RMM Tools

Reduce the number of remote support products that users could reasonably believe belong to IT.

## Microsoft Teams External Communication

### External Chat as an Attack Surface

Discuss how attackers can use Teams external communication to contact users while pretending to represent IT or another trusted organization.

### Reviewing Teams External Access

Review the relevant Teams external communication settings.

```text
Teams configuration and Graph endpoints to be added.
```

### Defining What Is Actually Required

Determine whether unrestricted external communication is required or whether the configuration can be reduced based on business requirements.

## Establishing a Clear IT Support Process

Technical controls should support a clearly defined internal process.

Document:

* How IT contacts employees
* Which remote support platform IT uses
* How a support session is initiated
* Whether users are ever expected to install software
* How an employee can verify that the person contacting them is actually IT
* What IT will never ask an employee to do

### Example: Team Viewer Native Integration

Enable Teamviewer in your Intune Environment.

Deploy Teamviewer Client
Configure the Teamviewer package, if it is nost installed on the host, the user will be prompted to download the version from the Microsoft Store however we the goal is to get a streamlined process therefore the client should already be on the device.

Configure SSO for Teamviewer

Configure Helpdesk Roles for Teamviewer

Configure Conditional Access for Teamviewer

Other Security Options

Please review https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/security/security-statement/ to see all the security options Team Viewer has to offer. 

Disclaimer

I do not specifically recommend TeamViewer; however, due to its native integrations, it provides a good example of how a Remote Management Tool can be selected, centrally configured, and streamlined into a single, understandable support process. This makes it easier to train employees to recognize and follow only the approved Helpdesk process, reducing the likelihood of successful social engineering and improving overall security awareness.

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

## Bringing It All Together

The objective is to remove as much uncertainty as possible.

Microsoft Defender provides visibility into remote access tooling already present on endpoints.

Microsoft Intune provides visibility and control over what IT deliberately deploys.

Teams configuration reduces unnecessary communication paths.

Standardized IT processes define exactly what legitimate support looks like.

Security awareness can then be built around those technical and procedural absolutes.

## Conclusion

Fake IT helpdesk attacks exploit trust and ambiguity.

A well-configured environment cannot eliminate social engineering, but it can make the attacker's story much harder to believe.

The end goal is simple:

**Make legitimate IT support predictable, controlled, and verifiable.**
