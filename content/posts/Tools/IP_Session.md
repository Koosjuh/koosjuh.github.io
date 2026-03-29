---
title: "IP Validation Tool"
date: 2026-03-28
hero: "/images/posts/ip-session-triage.png"
description: "Tool I created to retreive some basic information about IP's to help with investigating Cyber Security Incidents. Whilest simultaniously learning Powershell Secret Management."
summary: "This tool generates structured SOC ready IP triage output including location, ISP, VPN detection, and risk scoring using Scamalytics and ProxyCheck APIs with secure secret handling via Powershell Secret Management."
categories:
  - "Security"
  - "Tools"
tags:
  - "PowerShell"
  - "SOC"
  - "Triage"
  - "VPN"
  - "Investigation"
  - "Create your own tools"
draft: false
toc: true
menu:
  sidebar:
    name: "IP Validation Tool"
    identifier: "ip-validation-tool"
    parent: "tools"
    weight: 10
---

# IP validation tool

## Session validation

---

During my investigations when I have duty one of the most frequent things I do is validating sessions. Most of the time I investigate 2 types of entities: The user activity and the location it's from. The location investigation can become tedious as in the past I used Scamalytics and spur.us. Spur.us however changed their GUI and adjusted their limit rates, thus when I am on my corporate VPN I can never use spur.us because the night shift probably already used up all the API calls. One thing that verifies behaviour though is the VPN operator. Seeing "Nord VPN" for instance on sign in sessions 10x in the past and now for the 10th time this user generates an "Anonymous sign in", it helps to see that this is anonymous IP belongs to "Nord VPN".

So not being able to do this, or it takes 5 minutes longer per investigation is tedious to say the least. Something simple, should be simple and fast. To streamline this workflow, I created a PowerShell based IP session tool that generates a triage based on the properties of the IP address through scamalytics and proxycheck (my new spur). The function queries Scamalytics for infrastructure properties and location, and ProxyCheck for VPN attribution. The results are merged into a structured format that can be pasted directly into investigation notes or incident timelines.

The tool also integrates with Microsoft PowerShell SecretManagement and SecretStore to securely store API keys. Secrets remain locked by default, are unlocked only during analyst usage, and automatically lock again after the configured timeout. This is why I like blogging because this also forces me to think about handling secrets correctly. I am in no way shape or form a developer so if there is feedback if this can be better or safer or other ways please do comment and let me know!

The sections below describes the setup, secretvault configuration, script, and usage examples. 

**Disclaimer:** All api keys can (for the time being) be atained for `free`. The limits are of course low but in my case and I hope for your work/life balance as well, enough for 1 SOC analyst. 

## Get-ScamSpurTriage (Powershell Function)

**Note**

This is a legacy name. Spur does not support this, I now use Proxycheck.io. I like the name, for now it stays. :) Feel free to change the name and/or adjust the triage output to fit your style.

**Requirements:** You need API keys for

- **Scamalytics API v3** for location, ISP, risk score, and datacenter/TOR context
   - [Scamalytics](https://scamalytics.com/ip/api/enquiry?monthly_api_calls=5000 "Scamalytics IP Location & Infrastructure API")
   - Here you will receive an `API User` and `API Key`.
- **ProxyCheck v3** for VPN provider attribution, VPN/proxy confirmation, and first-seen timestamp
   - [ProxyCheck](https://proxycheck.io "Proxy/VPN detection API")
   - Here you will receive an `API Key`
- **Microsoft PowerShell SecretManagement / SecretStore** for secure local secret retrieval

Free tier is sufficient for 1 soc analyst. Do not use per department or team. This is for a single user. If you want this for a whole SOC the free tier will not suffice.

### Prerequisites

Install the required modules:

```powershell
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser
```
### Current vault model

This setup assumes:

- Vault name is **`SecretVault`** 
- The vault uses **Password** authentication
- The vault needs to be unlocked by the SecretVault password once every `4 hours`
- Timeout is **4 hours**
- First time running this script will ask for password for SecretVault to unlock it. Then it will either timeout after 4 hours or if you stop the terminal session you will need to unlock it again.

#### Required secret names

Store these secrets in `SecretVault`:

- `ScamalyticsUser`
- `ScamalyticsKey`
- `ProxyCheckKey`

You will end up with:

- a Vault that is locked by default
- Can only be unlocked by password in current user session
- Unlock required once per session (session assumes a SOC shift of 4 hours, please do adjust to your needs)
- Auto-lock after 4 hours or if the session is terminated
- Store the secretvault password in your password manager of choice.

#### Vault registration

If not already done:

```powershell
Register-SecretVault -Name SecretVault -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
```

#### SecretStore configuration

```powershell
Set-SecretStoreConfiguration `
    -Authentication Password `
    -PasswordTimeout 14400 `
    -Interaction Prompt
```

#### Store the API secrets in the vault

```powershell
Set-Secret -Vault SecretVault -Name ScamalyticsUser -Secret "YOUR_SCAMALYTICS_USER"
```

```powershell
Set-Secret -Vault SecretVault -Name ScamalyticsKey -Secret "YOUR_SCAMALYTICS_KEY"
```

```powershell
Set-Secret -Vault SecretVault -Name ProxyCheckKey -Secret "YOUR_PROXYCHECK_KEY"
```

### Script

```powershell
function Get-ScamSpurTriage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$IPs,

        [Parameter(Mandatory = $false)]
        [string]$BaseUrl = "https://api12.scamalytics.com/v3",

        [Parameter(Mandatory = $false)]
        [string]$VaultName = "SecretVault",

        [Parameter(Mandatory = $false)]
        [string]$ScamalyticsUserSecretName = "ScamalyticsUser",

        [Parameter(Mandatory = $false)]
        [string]$ScamalyticsKeySecretName = "ScamalyticsKey",

        [Parameter(Mandatory = $false)]
        [string]$ProxyCheckKeySecretName = "ProxyCheckKey",

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [int]$InitialRetryDelaySeconds = 2
    )

    function Invoke-WithRetry {
        param(
            [Parameter(Mandatory = $true)]
            [scriptblock]$ScriptBlock,

            [Parameter(Mandatory = $true)]
            [string]$OperationName,

            [Parameter(Mandatory = $false)]
            [int]$Retries = 3,

            [Parameter(Mandatory = $false)]
            [int]$InitialDelaySeconds = 2
        )

        $attempt = 0
        $delay = $InitialDelaySeconds

        while ($attempt -lt $Retries) {
            try {
                return & $ScriptBlock
            }
            catch {
                $attempt++

                if ($attempt -ge $Retries) {
                    throw
                }

                Write-Verbose "$OperationName failed on attempt $attempt. Retrying in $delay second(s)."
                Start-Sleep -Seconds $delay
                $delay = [Math]::Min($delay * 2, 30)
            }
        }
    }

    function Test-ValidIpAddress {
        param(
            [Parameter(Mandatory = $true)]
            [string]$InputIp
        )

        $nullIp = $null
        return [System.Net.IPAddress]::TryParse($InputIp, [ref]$nullIp)
    }

    try {
        $null = Get-SecretVault -Name $VaultName -ErrorAction Stop

        $storeStatus = Get-SecretStoreConfiguration -ErrorAction Stop
        if ($storeStatus.Authentication -eq 'Password') {
            Write-Verbose "SecretStore uses password authentication. Unlock it first with Unlock-SecretStore."
        }

        $ApiUser = Get-Secret -Vault $VaultName -Name $ScamalyticsUserSecretName -AsPlainText -ErrorAction Stop
        $ApiKey = Get-Secret -Vault $VaultName -Name $ScamalyticsKeySecretName -AsPlainText -ErrorAction Stop
        $ProxyCheckApiKey = Get-Secret -Vault $VaultName -Name $ProxyCheckKeySecretName -AsPlainText -ErrorAction Stop
    }
    catch {
        throw "Failed to retrieve secrets from vault '$VaultName'. If the vault is password protected, run Unlock-SecretStore first. $($_.Exception.Message)"
    }

    if (-not $IPs -or $IPs.Count -eq 0) {
        $inputIPs = Read-Host "Enter IP(s) (comma separated)"
        $IPs = $inputIPs -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    foreach ($rawIp in $IPs) {
        $ip = $rawIp.Trim()

        if (-not (Test-ValidIpAddress -InputIp $ip)) {
            Write-Warning "Skipping invalid IP: $ip"
            continue
        }

        $location = $null
        $isp = $null
        $score = $null
        $risk = $null
        $proxyTorDc = $null
        $provider = $null
        $proxyCheckVpnProxy = $null
        $firstSeen = $null

        $isVpn = $false
        $isTor = $false
        $isDatacenter = $false
        $isProxy = $false
        $label = $null

        try {
            $scamUrl = "${BaseUrl}/${ApiUser}/?key=${ApiKey}&ip=${ip}"
            Write-Verbose "Requesting Scamalytics for $ip"

            $resp = Invoke-WithRetry -OperationName "Scamalytics request for $ip" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-RestMethod -Uri $scamUrl -Method Get -ErrorAction Stop
            }

            $scam = $resp.scamalytics
            $ext  = $resp.external_datasources

            if ($scam.status -eq "ok") {
                if ($null -ne $scam.scamalytics_score) {
                    $score = $scam.scamalytics_score
                }

                if (-not [string]::IsNullOrWhiteSpace($scam.scamalytics_risk)) {
                    $risk = $scam.scamalytics_risk
                }

                if ($null -ne $scam.scamalytics_proxy.is_vpn) {
                    $isVpn = [bool]$scam.scamalytics_proxy.is_vpn
                }

                if ($null -ne $scam.scamalytics_proxy.is_datacenter) {
                    $isDatacenter = [bool]$scam.scamalytics_proxy.is_datacenter
                }

                if ($null -ne $ext.x4bnet.is_tor) {
                    $isTor = [bool]$ext.x4bnet.is_tor
                }

                if ($null -ne $ext.firehol.is_proxy) {
                    $isProxy = [bool]$ext.firehol.is_proxy
                }

                $proxyTorDc = "$isVpn / $isTor / $isDatacenter"

                if ($isVpn -or $isTor -or $isDatacenter -or $isProxy) {
                    $label = "VPN"
                }

                $mm   = $ext.maxmind_geolite2
                $dbip = $ext.dbip

                $city = $null
                $country = $null

                if ($mm) {
                    if (-not [string]::IsNullOrWhiteSpace($mm.ip_city)) {
                        $city = $mm.ip_city
                    }
                    if (-not [string]::IsNullOrWhiteSpace($mm.ip_country_name)) {
                        $country = $mm.ip_country_name
                    }
                }

                if ([string]::IsNullOrWhiteSpace($city) -and $dbip -and -not [string]::IsNullOrWhiteSpace($dbip.ip_city)) {
                    $city = $dbip.ip_city
                }

                if ([string]::IsNullOrWhiteSpace($country) -and $dbip -and -not [string]::IsNullOrWhiteSpace($dbip.ip_country_name)) {
                    $country = $dbip.ip_country_name
                }

                if (-not [string]::IsNullOrWhiteSpace($city) -and -not [string]::IsNullOrWhiteSpace($country)) {
                    $location = "$city, $country"
                }
                elseif (-not [string]::IsNullOrWhiteSpace($country)) {
                    $location = $country
                }

                if ($dbip -and -not [string]::IsNullOrWhiteSpace($dbip.isp_name)) {
                    $isp = $dbip.isp_name
                }
                elseif (-not [string]::IsNullOrWhiteSpace($scam.scamalytics_isp)) {
                    $isp = $scam.scamalytics_isp
                }
                elseif ($mm -and -not [string]::IsNullOrWhiteSpace($mm.as_name)) {
                    $isp = $mm.as_name
                }
            }
            else {
                $risk = "API status: $($scam.status)"
            }
        }
        catch {
            Write-Verbose "Scamalytics failed for $ip. $($_.Exception.Message)"
        }

        try {
            $pcUrl = "https://proxycheck.io/v3/${ip}?key=${ProxyCheckApiKey}&vpn=1&asn=1"
            Write-Verbose "Requesting ProxyCheck for $ip"

            $pcRaw = Invoke-WithRetry -OperationName "ProxyCheck request for $ip" -Retries $MaxRetries -InitialDelaySeconds $InitialRetryDelaySeconds -ScriptBlock {
                Invoke-WebRequest -Uri $pcUrl -UseBasicParsing -ErrorAction Stop
            }

            $pcResp = $pcRaw.Content | ConvertFrom-Json

            if ($pcResp.status -in @("ok", "warning")) {
                $pcProperty = $pcResp.PSObject.Properties | Where-Object { $_.Name -eq $ip }

                if ($null -ne $pcProperty) {
                    $pcData = $pcProperty.Value

                    if ($null -ne $pcData.detections) {
                        $pcVpn   = if ($null -ne $pcData.detections.vpn) { $pcData.detections.vpn } else { $null }
                        $pcProxy = if ($null -ne $pcData.detections.proxy) { $pcData.detections.proxy } else { $null }

                        if ($null -ne $pcVpn -or $null -ne $pcProxy) {
                            $proxyCheckVpnProxy = "$pcVpn / $pcProxy"
                        }

                        if (-not [string]::IsNullOrWhiteSpace([string]$pcData.detections.first_seen)) {
                            $firstSeen = [string]$pcData.detections.first_seen
                        }
                    }

                    $mainOperator = $null
                    $additionalOperators = @()

                    if ($null -ne $pcData.operator) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$pcData.operator.name)) {
                            $mainOperator = [string]$pcData.operator.name
                        }

                        if ($null -ne $pcData.operator.additional_operators) {
                            if ($pcData.operator.additional_operators -is [System.Array]) {
                                $additionalOperators = $pcData.operator.additional_operators | Where-Object {
                                    -not [string]::IsNullOrWhiteSpace([string]$_)
                                }
                            }
                            elseif (-not [string]::IsNullOrWhiteSpace([string]$pcData.operator.additional_operators)) {
                                $additionalOperators = @([string]$pcData.operator.additional_operators)
                            }
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($mainOperator) -and $additionalOperators.Count -gt 0) {
                        $provider = "$mainOperator, with additional overlap noted for $($additionalOperators -join ', ')"
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($mainOperator)) {
                        $provider = $mainOperator
                    }
                }
                else {
                    Write-Verbose "ProxyCheck returned status ok, but no IP result block was found for $ip"
                }
            }
            else {
                Write-Verbose "ProxyCheck status was $($pcResp.status)"
            }
        }
        catch {
            Write-Verbose "ProxyCheck failed for $ip. $($_.Exception.Message)"
        }

        if (-not [string]::IsNullOrWhiteSpace($label)) {
            Write-Output "##### ($label) $ip"
        }
        else {
            Write-Output "##### $ip"
        }

        if (-not [string]::IsNullOrWhiteSpace($location)) {
            Write-Output "- Location: $location"
        }

        if (-not [string]::IsNullOrWhiteSpace($isp)) {
            Write-Output "- ISP: $isp"
        }

        if ($null -ne $score -or -not [string]::IsNullOrWhiteSpace($risk)) {
            $scoreText = if ($null -ne $score) { $score } else { "Unknown" }
            $riskText  = if (-not [string]::IsNullOrWhiteSpace($risk)) { $risk } else { "Unknown" }
            Write-Output "- Risk score: $scoreText ($riskText)"
        }

        if (-not [string]::IsNullOrWhiteSpace($proxyTorDc)) {
            Write-Output "- Proxy/TOR/Datacenter: $proxyTorDc"
        }

        if (-not [string]::IsNullOrWhiteSpace($provider)) {
            Write-Output "- Provider: $provider"
        }

        if (-not [string]::IsNullOrWhiteSpace($proxyCheckVpnProxy)) {
            Write-Output "- ProxyCheck VPN/Proxy: $proxyCheckVpnProxy"
        }

        if (-not [string]::IsNullOrWhiteSpace($firstSeen)) {
            Write-Output "- First seen: $firstSeen"
        }

        Write-Output ""
    }
}
```

## How to use

### Interactive input

```powershell
Get-ScamSpurTriage
```

### Single IP

```powershell
Get-ScamSpurTriage -IPs "1.1.1.1"
```

### Multiple IPs

```powershell
Get-ScamSpurTriage -IPs "1.1.1.1","8.8.8.8"
```

### Verbose logging

```powershell
Get-ScamSpurTriage -IPs "1.1.1.1" -Verbose
```

## Example output

```markdown
##### (VPN) 1.1.1.1
- Location: Santa Clara, United States
- ISP: PacketHub S.A.
- Risk score: 100 (very high)
- Proxy/TOR/Datacenter: True / False / True
- Provider: NordVPN, with additional overlap noted for LunaProxy
- ProxyCheck VPN/Proxy: True / False
- First seen: 2026-02-05
```

### Operational flow

1. Start script/function
2. Unlock vault with password pasted from password manager
3. Secrets retrieved from SecretVault
4. Execute function
5. Triage generated
6. Vault auto-locks after 4 hours or when session is terminated

## Field explanation

**Location**  
Derived from Scamalytics geolocation sources.

**ISP**  
Primary ISP or ASN owner of the IP.

**Risk score**  
Scamalytics fraud score and risk label.

**Proxy/TOR/Datacenter**  
Format is:

VPN / TOR / Datacenter

**Provider**  
Named provider attribution from ProxyCheck.

**ProxyCheck VPN/Proxy**  
Format is:
VPN / Proxy

**First seen**  
First observed VPN/proxy detection timestamp from ProxyCheck.
