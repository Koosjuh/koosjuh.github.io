---
title: "tID Guard: Lightweight Tenant ID Guarding for Microsoft Entra Admins"
date: 2026-06-26
hero: "/images/posts/tid-guard.png"
description: "A lightweight Chrome extension that helps Microsoft Entra administrators identify the tenant they are working in."
summary: "tID Guard helps Microsoft Entra administrators verify the active tenant, convert supported links, and avoid working in the wrong environment."
categories:
  - "Tools"
  - "Microsoft Entra"
tags:
  - "Microsoft Entra"
  - "Chrome Extension"
  - "Tenant ID"
draft: false
toc: true
menu:
  sidebar:
    name: "tID Guard"
    identifier: "tools-tid-guard"
    parent: "tools"
    weight: 10
---

# tID Guard

The latest version of **tID Guard** can be downloaded from the TeamPurple repository on GitHub:

https://github.com/Koosjuh/TeamPurple/tree/main/Tools/tID%20Guard

You can either clone the repository or download it as a ZIP file using **Code → Download ZIP**.

## Lightweight Tenant ID Guarding for Microsoft Entra Administrators

If you work with Microsoft Entra every day, chances are you manage more than one tenant. Whether you're a consultant, MSP engineer, security analyst, or system administrator, switching between customer environments is simply part of the job.

The problem is that Microsoft documentation, support articles, GitHub repositories, and internal runbooks rarely include the Tenant ID in their links. After opening several browser tabs, it's surprisingly easy to lose track of which tenant you're currently administering.

Making a change in the wrong tenant can range from mildly frustrating to a very expensive mistake. Or exporting some information from the wrong tenant or analyzing the wrong data.

That's exactly why I built **tID Guard**.

---

## What is tID Guard?

tID Guard is a lightweight Google Chrome extension that provides an instant visual indication of the Microsoft Entra tenant you're currently working in.

Instead of creating dozens or even hundreds of browser profiles, you simply configure your "home" Tenant ID once. Every time you browse Microsoft Entra, tID Guard compares the active tenant with your configured Tenant ID and updates the toolbar icon accordingly.

The extension is intentionally simple and focuses on one thing:

**Helping you verify you're in the right tenant before you click.**

---

## Features

- Lightweight and fast
- One-time configuration
- Instant visual feedback
- Displays the current Tenant ID
- Optional friendly tenant name
- No cloud services
- No telemetry
- All data stored locally in your browser

---

## Status Indicators

tID Guard uses simple colour indicators that are always visible in your browser toolbar.

### Green

You're working in your configured Tenant ID.

### Red

You're currently signed in to a different tenant.

### Gray

You're not browsing a supported Microsoft page, or no Tenant ID could be determined.

Clicking the extension displays the full Tenant ID together with the optional tenant name you've configured.

---

## Why not just create browser profiles?

Browser profiles certainly work, and for many administrators they're a great solution. The challenge comes when you're responsible for dozens or even hundreds of Microsoft Entra tenants.

When you're writing documentation, investigating an incident, or performing administrative tasks for a specific customer, you often receive generic Microsoft links that don't contain a Tenant ID. Before you know it, you've clicked through several pages and it's easy to wonder:

*"Am I actually in the right tenant?"*

tID Guard was designed to solve exactly that problem.

Rather than maintaining a permanent database of customer Tenant IDs and names, you simply enter the Tenant ID you're working with for your current task. The extension can help convert supported Microsoft links to that tenant and continuously verifies whether you're actually working in the intended environment.

This information is intentionally temporary. It exists only for your current browser session and can be cleared at any time. After restarting the browser, the configured tenant is gone.

That design was intentional.

Keeping a permanent list of customer Tenant IDs and names inside the browser would effectively create a small directory of customer environments. While Tenant IDs are not secrets by themselves, pairing them with customer names creates information that could be useful during phishing or social engineering attacks.

By only remembering the tenant you're actively working on, tID Guard stays lightweight, reduces unnecessary stored information, and still provides the safety check that matters most: making sure you're in the correct tenant before you make changes.

---

## Privacy

Privacy was one of the primary design goals.

tID Guard:

- Does not send data anywhere
- Does not use external services
- Does not require an account
- Stores configuration locally using Chrome storage
- Allows you to remove your configured Tenant ID at any time

Everything happens locally inside your browser.

---

## Installation

1. Download or clone the TeamPurple repository. (https://github.com/Koosjuh/TeamPurple/tree/main/Tools/tID%20Guard)
2. Extract the project if you downloaded it as a ZIP file.
3. Open your Chromium-based browser and navigate to:

```text
chrome://extensions
```

or

```text
edge://extensions
```

or

```text
brave://extensions/
```

4. Enable **Developer mode**.
5. Select **Load unpacked**.
6. Browse to the extracted `Tools/tID Guard` folder.
7. Pin the extension to your browser toolbar.
8. Open the extension popup and configure your "home" Tenant ID.

Once configured, the extension immediately starts monitoring the active Microsoft Entra tenant and updates its icon as you browse.

---

## Source Code

tID Guard is part of my **TeamPurple** open-source repository.

Repository:
https://github.com/Koosjuh/TeamPurple/tree/main/Tools/tID%20Guard

Bug reports, feature requests and pull requests are always welcome.
