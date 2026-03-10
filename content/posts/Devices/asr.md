---
title: "ASR Validation via TVM, Registry, and PowerShell"
date: 2026-03-10T06:00:23+06:00
hero: "/images/posts/asr.png"
description: "A practical deep dive into how Microsoft Defender for Endpoint validates ASR state through TVM, registry policy evidence, and local PowerShell effective state."
summary: "Learn how to validate ASR posture using Defender TVM, registry-based policy evidence, and local PowerShell checks, and understand why these sources do not always match the Defender portal UI."
categories:
  - "Microsoft Defender"
  - "Security"
  - "Endpoint"
tags:
  - "ASR"
  - "Microsoft Defender for Endpoint"
  - "TVM"
  - "Advanced Hunting"
  - "PowerShell"
  - "Registry"
draft: false
toc: true
menu:
  sidebar:
    name: "ASR Validation"
    identifier: "asr-validation"
    parent: "mde"
    weight: 300
---

# ASR Validation via Advanced Hunting, Registry Policy Evidence, and Local Effective State

When validating Attack Surface Reduction (ASR) posture in Microsoft Defender, different interfaces can appear to contradict each other.

A device may show as **Compliant** in Threat & Vulnerability Management (TVM), the registry may show a rule configured as **Block**, PowerShell may confirm the same effective state, and the portal UI may still mark that rule as **Not applicable**. This article explains why that happens and how to validate ASR correctly.

## Overview

ASR validation usually answers one of three different questions:

1. What is the effective ASR state on the device?
2. What ASR settings were deployed through policy?
3. What does Microsoft Defender report as posture in the portal?

These are related, but they are not identical. Each source represents a different layer of the platform and should be interpreted accordingly.

This article covers three validation methods:

- **TVM secure configuration assessment** for cloud-assessed posture
- **Registry policy evidence** for deployment proof
- **PowerShell effective state** for local Defender engine resolution

## Validation Method 1: TVM ASR Posture

### Purpose

This method uses `DeviceTvmSecureConfigurationAssessment`, optionally joined with `DeviceTvmSecureConfigurationAssessmentKB`, to report ASR-related posture per device.

### What it answers

- Whether the control is applicable to the device
- Whether the device is compliant
- What assessment context is reported, such as Block, Audit, or Off

### Why it matters

This reflects the posture that Defender Vulnerability Management reports through Advanced Hunting. It is a strong cloud-side indicator when you see values such as:

- `IsApplicable = true`
- `IsCompliant = true`
- `Context` indicating Block, Audit, or Off

### Important notes

- This is a **secure configuration assessment** view, not a raw policy view
- It shows what Defender reports as assessed posture
- It reflects the **last completed assessment**, not guaranteed real-time enforcement

## Validation Method 2: Registry Policy Evidence

### Purpose

This method uses registry telemetry in Advanced Hunting to identify policy writes that configure ASR rules. In many environments, this appears under:

`HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager`

Example value name:

`ASRRules`

The value data may contain pipe-separated entries such as:

`<GUID>=1|<GUID>=2|<GUID>=0`

### What it answers

- Whether ASR rules were written to the device by policy
- Which ASR rule GUIDs were configured
- Which state each rule was assigned
- Which process performed the write

For example, `omadmclient.exe` often indicates MDM or Intune policy delivery.

### State mapping

- `0` = Disabled
- `1` = Block
- `2` = Audit
- `6` = Warn

### Why it matters

Registry evidence is strong proof that configuration was deployed to the endpoint. If a GUID is present in the policy-backed value, that setting was explicitly written by a management channel.

This is especially useful when the portal presents inconsistent results.

### Important notes

- Policy presence does not always equal effective enforcement
- A configured rule may still be overridden, merged, or interpreted differently by the local engine

## Validation Method 3: PowerShell Effective State

### Purpose

This method reads the Defender engine's resolved ASR configuration from `Get-MpPreference` and maps:

- Rule GUID to friendly rule name
- Action code to effective mode such as Block, Audit, Disabled, or Warn

### What it answers

- What the Defender engine currently believes is configured for each ASR rule
- Which rules are known and mapped locally
- Which rules exist but are not yet included in the local mapping

### Why it matters

This is the closest local view of effective ASR state without requiring a block event to occur. It reflects the Defender engine after policy merge, conflict handling, and final resolution.

### Important notes

- It does not explain why a rule ended up in that state
- It does not account for runtime exclusions such as path, certificate, or hash-based exclusions

## When to Trust Which Signal

Because ASR state is represented across multiple planes, no single source should be treated as universal truth. The correct source depends on the question you are trying to answer.

### If you want to know what Defender is actually enforcing

**Trust:** PowerShell via `Get-MpPreference`

**Why:** This reflects the Defender engine's resolved configuration after merges, conflicts, and defaults are applied. It is the closest practical view of actual enforcement state.

**Caveats:**

- Does not explain policy source
- Does not include runtime exclusion logic

### If you want to know whether ASR was deployed through policy

**Trust:** Registry policy evidence

**Why:** ASR GUIDs in policy-backed registry locations provide strong evidence that a management plane explicitly wrote the setting to the device.

**Caveats:**

- Deployment intent does not guarantee local enforcement
- Engine resolution may differ from raw policy input

### If you want to know what Defender reports as security posture

**Trust:** TVM secure configuration assessment

**Why:** TVM reflects Defender's cloud-assessed posture, including applicability and compliance, independent of how the setting was deployed.

**Caveats:**

- Assessment latency applies
- Represents posture reporting, not direct engine state

## Rule of Thumb

- **Enforcement truth:** PowerShell
- **Deployment proof:** Registry policy evidence
- **Posture and reporting:** TVM secure configuration assessment

When results differ, use all three together to determine whether you are looking at deployment, effective enforcement, or cloud-reported posture.

## Why the Portal Can Appear Inconsistent

The Microsoft Defender portal does not always expose every ASR rule consistently across all views. In some cases, a rule may be:

- configured and enforced locally
- visible in registry policy evidence
- detected in block events
- but still shown as **Not applicable** in the ASR configuration UI

A common reason is that some ASR rules are not fully represented in TVM-backed secure configuration reporting. In those cases, the portal may not surface them consistently even though the rule is active and generating telemetry.

## Recommended Validation Approach

For reliable ASR troubleshooting, validate in this order:

1. **PowerShell** to confirm effective local enforcement
2. **Registry telemetry** to confirm policy deployment
3. **TVM assessment** to confirm cloud-reported posture

This sequence helps separate configuration intent from actual device state and portal interpretation.

## References

### Attack Surface Reduction

- [Attack surface reduction rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [Enable attack surface reduction rules](https://learn.microsoft.com/defender-endpoint/enable-attack-surface-reduction)

### Defender Vulnerability Management and TVM

- [DeviceTvmSecureConfigurationAssessment table](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicetvmsecureconfigurationassessment-table)
- [DeviceTvmSecureConfigurationAssessment Azure Monitor reference](https://learn.microsoft.com/azure/azure-monitor/reference/tables/devicetvmsecureconfigurationassessment)

### Local Defender Engine

- [Get-MpPreference cmdlet reference](https://learn.microsoft.com/powershell/module/defender/get-mppreference)

### Advanced Hunting Schema

- [Advanced hunting schema reference](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables)
