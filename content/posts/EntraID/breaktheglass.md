---
title: "Break-the-Glass Accounts: Ownership and design pitfalls in EntraID"
date: 2026-03-13
hero: "/images/posts/entra-break-glass.png"
description: "Common misconceptions and design pitfalls when implementing break-the-glass accounts in Entra ID."
summary: "A practical overview of common break-the-glass account implementation mistakes and recommendations for tenant recovery design."
categories:
  - "Entra ID"
tags:
  - "Break the Glass"
  - "Emergency Access"
  - "Identity Security"
draft: false
toc: true
menu:
  sidebar:
    name: "Break-the-Glass Accounts"
    identifier: "entra-break-glass"
    parent: "entraid"
    weight: 200
---

During my work I frequently encounter misconceptions about break-the-glass accounts and weaknesses in how they are implemented. Because these accounts are rarely used, their design is often treated as a simple checklist item rather than a security control that requires careful consideration. This short blog highlights some of the patterns I regularly see and the recommendations I typically provide when reviewing tenant configurations.

I will briefly cover the fundamentals and then move on to several implementation mistakes that appear surprisingly often in real environments.

---

## What are break the Glass Accounts and what are they used for?

Break the glass accounts are emergency accounts for first and foremost the owner of the Tenant. As a tenant owner, business owner you always need a way to get back into your tenant. Break-the-glass accounts exist to protect the tenant owner's ability to recover control, and their design should reflect that.

Having emergency access accounts is a good practice, but if they are implemented incorrectly they can become an obstacle rather than a safeguard. Emergency access accounts exist to recover from situations where normal administrative access fails. Therefore they should only be used in case of an emergency.

While the concept itself is simple, the way break-the-glass accounts are implemented often introduces avoidable risks. In the following sections I will walk through several common mistakes I encounter during tenant reviews.

---

## Who are they for?

The break the glass account is there namely for the Tenant Owner. The tenant owner is the first one that needs a Break the Glass account. You own the tenant, you own the business therefore you are the important factor in regaining control and deciding who gets access and who doesn't.

In the real world I often encounter business's that do have a Break the Glass account but don't have access to it, their MSP has access to it. The logic is, they do IT, they are the ones who must have emergency access. However the owner of the tenant and business should always have a Break the Glass account and after that it is up to the owner who they trust with other Break the Glass accounts.

It's simple, it's your business, it's your tenant, it's your responsibility. Doesn't mean you can't give your MSP or MSSP or both a break the glass account. When the trust is there, of course also don't have too many as well, however the tenant and business owner must have one. This is of course a governance stand point and to my knowledge is not officially recommended anywhere.

---

## Naming Convention

What I also sadly see a lot is that break the glass accounts are literally called Break the Glass account or Emergency Access account.

Examples:
- breakglass@contoso.onmicrosoft.com
- breakglass-admin@contoso.onmicrosoft.com
- emergencyaccess@contoso.onmicrosoft.com
- bga_{MSPNAME}@contoso.onmicrosoft.com

Or any other variation of this.

This of course weakens the posture. When a malicious actor gains access one of the first things that will happen is reconnaissance. I would suggest to make them at least work for it by implementing the naming convention you have for a regular user.

Example:

{first letter}.{lastname}@tenant.com


Doesn't mean they won't ever find it, but it won't be within 30 seconds. This brings me to the next point.

---

## Group or Direct assignment in Conditional Access Policy's?

Once they find your Break the Glass account what level of privilege would someone need to alter it?

I often see Break the Glass accounts in a Break the Glass account Group or a common Exclude group for Conditional access policies. I would suggest Directly assigning Break the Glass accounts to the conditional access policy.

When you want to remove a user from a group, this can be done with **User Administrator**. This is a common and low level privilege most admins and even some (not a good practice, but also common) "super users" have.

When the Break the glass account is removed from that Exclude you essentially just have a Global Admin. Depending on how it is designed, even more might break, such as monitoring and alerting.

When directly assigning a Break the Glass account to a conditional access policy, the level of privilege rises. You would need **Security Administrator** for instance and this already is less common.

Also directly assigning a Break the Glass account wouldn't give much administration trouble as there shouldn't be many to begin with. Microsoft recommends at least **2**. I would say *(my personal recommendation)* max **4** if you want to give your MSP/MSSP emergency access as well.

---

### Role Assignable Groups

There is of course also **Role Assignable Groups**, which can be configured as well. These can be used for governance and lifecycle management and there is an argument to be made for this.

However in essence **KISS — Keep It Simple**. I would begin with direct assignment.

Please see documentation below to read further on Role Assignable Groups. Group-based exclusions create an additional control surface. The environment matters.

---

## Monitoring and usage

When a Break the Glass account is used there should be an alert triggered.

This is common practice. A break the glass account login is an emergency. Emergencies have reasons and this reason should be checked and verified.

To set monitoring see documentation below from Microsoft and a blog post from Jeffrey Appel.

Also after a successful login the credentials should be renewed.

---

## Game Analogy

I collect video games and some people drink coffee for their personal touch, others have movie references. I have about 1500 games too choose from so, as someone who collects video games, I sometimes think about break-the-glass accounts in the context of Resident Evil.

One of the things that makes Resident Evil memorable is the way access is deliberately restricted. You find keys, solve puzzles, and slowly unlock parts of the environment. That design forces exploration and creates tension.

Imagine if the game simply gave you a master key from the start. You could unlock every door immediately. The game would be much faster, but it would also remove much of the experience and many of the moments that make the game interesting. I hold Resident Evil in high regard and played the original in September 1997. And I still play it every other year all the way through. 

![Resident Evil](/images/posts/games/residentevil.png)

---

## Documentation

Some interesting reads:

Microsoft Best Practices  
https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

NIST Zero Trust (Break the Glass section refers to Microsoft)  
https://pages.nist.gov/zero-trust-architecture/index.html

Role Assignable Groups  
https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept

Monitoring Break-Glass Accounts  
https://jeffreyappel.nl/monitor-azure-ad-break-glass-accounts-with-azure-sentinel/

The views expressed in this article are my own

