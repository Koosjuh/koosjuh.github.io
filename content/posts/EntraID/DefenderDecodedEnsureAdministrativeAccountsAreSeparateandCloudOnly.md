---
title: "Defender Decoded: Ensure Administrative Accounts Are Separate and Cloud-Only"
date: 2026-11-04
hero: "/images/posts/seperateadmin.png"
draft: true
description: "A practical look at administrative account separation, cloud-only identities, licensing, and leftover on-premises attributes."
categories:
  - "Entra ID"
tags:
  - "Microsoft Defender"
  - "Microsoft Entra ID"
  - "Secure Score"
  - "Identity Security"
  - "Defender Decoded"
---

## Description

Administrative accounts are special privileged accounts that can have varying levels of access to data, users, and settings. Regular user accounts should never be used for administrative tasks. In a hybrid environment, care should be taken to keep cloud administrative accounts separate from on-premises accounts.

Administrative accounts should not have unnecessary applications or productivity services assigned, such as email, Teams, or SharePoint. They should only have the access needed to perform administrative tasks.

## What does this recommendation check?

Microsoft does not publicly disclose the exact evaluation logic for this recommendation. However, these are two key checks when reviewing your administrative accounts:

- The account is cloud-only and is not synchronized from on-premises Active Directory.
- The account has the required security licensing without unnecessary productivity applications or services. Standalone Microsoft Entra ID P1 or P2 licenses are examples, depending on the features required.

These are checks against the recommendation’s requirements, not confirmed automated triggers.

If both checks pass and the recommendation is still not marked as **Completed**, an underlying issue might be at hand. However, the assessment’s scope, update timing, or manual verification requirements may also need to be checked. Please read further for the checks that can help investigate this.

## User impact

Administrative users will have to switch accounts when performing administrative tasks. Depending on the setup, this can involve separate browser profiles, separate sessions, or signing in and out instead of using their regular account’s SSO session. This is standard practice.

## Conclusion

You want this recommendation to be marked as completed, with the underlying controls in place.

Assume breach. The blast radius of a compromised admin account is already bad enough. You want to reduce the risk that compromising one account gives an attacker privileged access to both your on-premises and cloud environments.

Furthermore, you want separate admin accounts without a mailbox or unnecessary access to potential vulnerable productivity services. Giving an admin account these services increases its exposure and the likelihood of compromise.

So, how do we break this down for a CISO or administrator who wants to comply?

## What are “administrative accounts”?

First, we have to create an inventory of all our privileged accounts.

In the cloud, these are more than just `adm_` accounts. They can also be developer accounts or regular user accounts that hold a privileged role! That is a big no-no as well, but it does happen, more often than I care to admit.

For Entra ID, look for accounts that hold a privileged role, including accounts eligible to activate one through PIM.

For on-premises Active Directory, you can start with accounts in the admin OU and the built-in privileged groups. However, account names and OU locations will not tell you everything about their privileges.

There are several related recommendations and assessments in Defender that can help. Look for findings covering:

- Accounts in built-in operator groups.
- External and guest accounts with privileged roles. A guest account still has an object in your Entra tenant!
- Service accounts with Domain Admin or Global Administrator roles.
- Service accounts in privileged groups.
- GPOs assigning unprivileged identities to local groups with elevated privileges.
- Privileged accounts that allow delegation.

Please check the exposed entities in each relevant recommendation. All these findings can help uncover additional accounts that conventional methods might miss.

For on-premises identities, there are two scenarios.

## Scenario 1: You have an active hybrid environment

You have a hybrid environment with synchronized administrator accounts, or accounts that hold privileges in both environments.

There is also a Defender for Identity assessment: **Identify Entra ID privileged accounts that are also privileged in Active Directory**. Here, you can check the exposed entities for dual-privileged accounts.

An empty list does not mean that all your cloud administrators are cloud-only. Also check synchronized accounts that hold cloud privileges but have no privileged AD group memberships.

Administrative access needs to be separated between the two environments:

- Use separate administrative accounts for Entra ID and Active Directory.
- Stop synchronizing on-premises administrative accounts.
- Remove unnecessary privileges from either Entra ID or Active Directory.

For existing synchronized accounts with cloud privileges, a practical approach is to create a dedicated cloud-only admin account, assign the required roles, verify access, and then remove the cloud privileges from the synchronized account.

**Be careful when changing synchronization scope.** Excluding an existing synchronized account can trigger its deletion in Entra ID. Plan the migration before making that change.

You do not need to disable directory synchronization for the entire tenant just to create separate cloud-only admin accounts.

If you convert existing accounts to cloud-managed accounts, there could still be leftover attributes on the user objects. We will handle those in Scenario 2.

## Scenario 2: You no longer have an on-premises environment

You no longer have an on-premises environment, but this recommendation is still marked as incomplete.

There could be leftover attributes on accounts that were previously synchronized. When disabling directory synchronization, we need to be aware that stopping the service is different from disabling synchronization at tenant level.

Please see Microsoft’s documentation on [turning off directory synchronization](https://learn.microsoft.com/en-us/microsoft-365/enterprise/turn-off-directory-synchronization?view=o365-worldwide).

Microsoft documents a 72-hour waiting period before directory synchronization can be re-enabled. The conversion process can sometimes take longer, so this is not a guaranteed completion time.

Microsoft’s disable-sync guide states that the following properties are cleared:

- `DnsDomainName`
- `NetBiosName`
- `OnPremisesDistinguishedName`
- `OnPremisesSamAccountName`
- `OnPremisesUserPrincipalName`

However, Microsoft’s separate cleanup guide also explains that legacy on-premises attributes can remain after synchronization is disabled. Some of the same properties appear in both guides.

So, please check your administrator accounts after the conversion completes. Microsoft’s cleanup guide covers the following user attributes:

- `onPremisesDistinguishedName`
- `onPremisesDomainName`
- `onPremisesImmutableId`
- `onPremisesObjectIdentifier`
- `onPremisesSamAccountName`
- `onPremisesSecurityIdentifier`
- `onPremisesUserPrincipalName`

If these values remain and are no longer needed, follow Microsoft’s documented cleanup procedure. Back up the values before clearing them.

See [Clear on-premises attributes from migrated Microsoft Entra ID users](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-clear-on-premises-attributes).

A leftover attribute does not, by itself, mean the account is still synchronized. Clearing these attributes is also not a confirmed way to complete this recommendation. However we did see it on more than one occasion that this helped.

## Entra ID administrative accounts

In Entra ID, you can perform a first check by selecting **Roles and administrators**.

Use the **Privileged** filter to find roles Microsoft classifies as privileged. You can also sort the **Assignments** column in descending order to see which roles have assignments.

Then open each relevant role to see who is assigned. If you use PIM (You definitely should!), check both **Active assignments** and **Eligible assignments**. Active assignments can be permanent or time-bound.

Also check assignments through groups, as one group assignment can represent several users.

For ease of use, we can also do an initial inventory with KQL in Defender Advanced Hunting.

### KQL to see assigned roles

```kql
IdentityInfo
| where Timestamp > ago(30d)
| where isnotempty(AccountObjectId)
| summarize arg_max(Timestamp, *) by AccountObjectId
| where array_length(AssignedRoles) > 0
| project
    LastUpdated = Timestamp,
    AccountDisplayName,
    AccountUpn,
    AccountObjectId,
    AssignedRoles
| order by AccountUpn asc
```

This returns accounts with populated role assignments in their latest available record. It includes all reported roles, so you still need to determine which ones are privileged.

### KQL to check PIM assignments and eligibility

```kql
IdentityInfo
| where Timestamp > ago(30d)
| where isnotempty(AccountObjectId)
| summarize arg_max(Timestamp, *) by AccountObjectId
| extend PimRoles = column_ifexists(
    "PrivilegedEntraPimRoles", dynamic(null))
| where array_length(AssignedRoles) > 0
    or coalesce(array_length(bag_keys(PimRoles)), 0) > 0
| project
    LastUpdated = Timestamp,
    AccountDisplayName,
    AccountUpn,
    AccountObjectId,
    AssignedRoles,
    PimRoles
| order by AccountUpn asc
```

The `PrivilegedEntraPimRoles` field contains PIM assignment and eligibility schedules, excluding activated assignments.

An eligible role does not mean that the role is currently active. If this field is unavailable in your environment, the query cannot provide that PIM information.

Use these queries as a starting point and validate the results against Entra ID and PIM. They query the available hunting data, not the live directory.

See Microsoft’s [IdentityInfo documentation](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table).

## What about licenses?

Now that we have an inventory of our Entra ID administrative accounts, we can check which licenses and services are assigned.

Administrators should not have unnecessary productivity services enabled on their dedicated admin accounts.

Check for unnecessary services such as a mailbox, Teams, or SharePoint. Look at the enabled service plans as well as the license name, as a product license alone does not tell you which services are enabled.

Removing a mailbox license also does not remove the account’s administrative permissions to manage Exchange.

See [Microsoft Entra ID Governance licensing fundamentals](https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals).

## Handy tip!

Please go to **Entra ID > Users > All users**.

There, you can open **Manage view > Edit columns**.

Add the following columns where available:

- Assigned licenses.
- On-premises SAM account name.
- On-premises security identifier.
- On-premises immutable ID.
- On-premises user principal name.
- On-premises domain name.
- On-premises last sync date and time.
- On-premises distinguished name.

You can also inspect extension attributes and on-premises provisioning errors where available and relevant.

The columns available in the browser and the export may differ. Use **Download users** and select the properties you need.

Here, you can view the information in your browser or export it to Excel. Compare it with your role-assignment inventory, preferably using the user object ID.

The user export alone does not replace the PIM inventory. Combine them to find out which administrative accounts have licenses, which still have on-premises attributes, and where access needs to be separated.

## Verify the result

After making your changes, check that:

- Cloud administrative accounts are cloud-managed and are not synchronized from on-premises AD.
- Regular user accounts no longer hold unnecessary administrative roles.
- Active, eligible, and group-based assignments have been reviewed.
- Dedicated administrative accounts have only the required services enabled.
- The new administrative accounts can perform their intended tasks.

Then check the recommendation again. If it remains incomplete, review its assessment details before assuming there is still an account issue.

You can use everything we covered in this post to find out how your administrators are separated and what needs to be done to limit the blast radius of a compromised administrative account.
