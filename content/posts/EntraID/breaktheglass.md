---
title: "Break-the-glass accounts: Ownership and common mistakes that weaken posture in EntraID"
date: 2026-03-13
hero: "/images/posts/entra-break-glass.png"
description: "Common misconceptions and design pitfalls when implementing break-the-glass accounts in Entra ID."
summary: "A practical overview of common break-the-glass account implementation mistakes and recommendations for tenant recovery design."
categories:
  - "Entra ID"
tags:
  - "Break the Glass"
  - "BG"
  - "Governance"
  - "Identity Security"
draft: false
toc: true
menu:
  sidebar:
    name: "break-the-glass Accounts"
    identifier: "break-the-glass"
    parent: "entraid"
    weight: 200
---

During my work I frequently encounter misconceptions about break-the-glass accounts and weaknesses in how they are implemented. Because these accounts are rarely used, their design is often treated as a simple checklist item rather than a security control that requires careful consideration. This short blog highlights some of the patterns I regularly see and the recommendations I typically provide when reviewing tenant configurations.

I will briefly cover the fundamentals and then move on to several implementation mistakes that appear surprisingly often in real environments. Disclaimer: This is not a best practice guide and also does not cover all aspects of a break-the-glass implementation. I only highlight some common flaws I see often which should require more thought. It's not about how an attacker gains access to your break-the-glass account as well, more so, an attacker locks you out of signing in to your emergency access.

---

## What are break-the-glass Accounts and what are they used for?

The first misconcenteption I see often is the debate who the break-the-glass accounts are emergency accounts for? Well they are for, first and foremost, the owner of the Tenant. As a tenant owner, business owner, you always need a way to get back into your tenant. Break-the-glass accounts exist to protect the tenant owner's ability to recover control, and their design should reflect that.

In the real world I often encounter businesses that do have a break-the-glass account however don't have access to it, their MSP has access to it. The logic is, they do IT, they are the ones who must have emergency access. However the owner of the tenant and business should always have a break-the-glass account and after that it is up to the owner who they trust with other break-the-glass accounts.

It's simple, it's your business, it's your tenant, it's your responsibility. When the trust is there, give emergency access to your MSP or MSSP as well, while at the same time keeping the number in check, however the tenant/business owner must always have the ability to regain control. 
This is of course a governance standpoint and to my knowledge is not officially recommended anywhere.

**The takeaway** 

Break-the-glass accounts are your way of gaining total control back over your tenant. That total control should always be in the tenant owners hands.

While the concept itself is simple, the way break-the-glass accounts are implemented often introduces avoidable risks. In the following sections I will walk through several common mistakes I encounter during tenant reviews.

---

## Naming Convention

What I also sadly see a lot is that break-the-glass accounts are literally called break-the-glass account or Emergency Access account.

Examples:
- breakglass@contoso.onmicrosoft.com
- breakglass-admin@contoso.onmicrosoft.com
- emergencyaccess@contoso.onmicrosoft.com
- bga_{MSPNAME}@contoso.onmicrosoft.com

Or any other variation of this.

This of course weakens the posture. When a malicious actor gains access one of the first things that will happen is reconnaissance. I would suggest to make them at least work for it by implementing the naming convention you have for a regular user. However there is an argument to be made that for visibility you would need this, which depending on how your tenant is run, it can be. However most of the time, it doesn't have to be. Naming convention applies to all accounts, also this one.

Example:

{firstletter}.{lastname}@tenant.com

Doesn't mean they won't ever find it, or that there are not other ways of finding out however the name doesn't have to give it away. And it's one less signal. What is the benefit for your organisation to have this in the name?

**The takeaway** 

Naming does not have to disclose function or privilege level. It can at least require some thought.

This brings me to the next point.

---

## Group or Direct assignment in Conditional Access?

Once they find your break-the-glass account what level of privilege would someone need to alter it?

I often see break-the-glasss accounts in a break-the-glass account group or a common Exclude group for Conditional Access policies. I would suggest directly assigning break-the-glass accounts to the Conditional Access policy.

When you want to remove a user from a group, this can be done with **User Administrator**. This is a common and low-level privilege most admins and even some (not a good practice, but also common) "super users" have.

When the break-the-glass account is removed from a conditional access policy, you essentially just have a Global Admin. Depending on how it is designed, even more might break, such as monitoring and alerting.

When directly assigning a break-the-glass account to a Conditional Access policy, the level of privilege rises. You would need **Security Administrator** for instance and this already is a less common priveledge.

Also directly assigning a break-the-glass account wouldn't give much administration trouble as there shouldn't be many to begin with. Microsoft recommends at least **2**. I would say *(my personal recommendation)* max **4** if you want to give your MSP/MSSP emergency access as well.

There is of course also **Role Assignable Groups**, which can be configured as well. These can be used for governance and lifecycle management and there is an argument to be made for this.

However in essence **keep it simple**. Avoid overengineering, I would just do direct assignment. These BG accounts shouldn't create that much overhead, and everyone in the IT organisation should know them. 

**The takeaway** 

Group-based exclusions introduce an additional control surface that can be modified with lower privileges. Direct assignment enforces a stricter privilege boundary, which aligns better with least privilege thinking.

Please see documentation below to read further on Role Assignable Groups. Group-based exclusions create an additional control surface. The environment matters.

---

## Monitoring and usage

When a break-the-glass account is used there should be an alert triggered. If any changes are made to the attack path, for instance, if a break-the-glass account is in a group, that group should be monitored for changes as well.

This is common practice. A break-the-glass account login is an emergency. Emergencies have reasons and this reason should be checked and verified, by the SOC or MSP.

To set monitoring see documentation below from Microsoft and a blog post from Jeffrey Appel.

However another common mistake I see is that credentials are not renewed after an emergency sign in. This is more of a process issue.

---

## The takeaway

For further best practices I would suggest reading the Microsoft and NIST documentation below. This post isn't about best practices or a guide on how to set it up. The key takeaway is that you need emergency access and that ability shouldn't be easily taken away. By setting a proper naming convention, you would add valuable time before a malicious actor finds out which break-the-glass accounts exist in the environment. So even an additional 5 minutes of reconnaissance can make a difference for a SOC. After finding out the break-the-glass accounts, the actor would need to escalate their privileges to Security Administrator before removing your ability to get back into the tenant.

For example, let’s say the session cookies of a super user with User Administrator privileges are stolen. An attacker would still need to perform reconnaissance to identify which accounts are used for emergency access. A proper naming convention may slow this down slightly, but it should not be relied upon as a security control.

With only User Administrator privileges, the attacker cannot directly remove high-privileged emergency accounts. They would need to escalate privileges or introduce a new identity to interfere with tenant recovery. This increases the number of required actions and therefore the likelihood of detection.

However, this assumes that role assignments, PIM, and monitoring are properly configured. In many environments, this is not the case, and escalation or persistence may be easier than expected.

---

## Documentation

Some interesting reads:

Microsoft Best Practices  
https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access

NIST Zero Trust (break-the-glass section refers to Microsoft)  
https://pages.nist.gov/zero-trust-architecture/index.html

Role Assignable Groups  
https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept

Monitoring break-the-glass 
https://jeffreyappel.nl/monitor-azure-ad-break-glass-accounts-with-azure-sentinel/

The views expressed in this article are my own.

