# MDE API Calls via RunAzCliReadCommands

## Purpose

This document provides the exact `RunAzCliReadCommands` tool calls to access
Microsoft Defender for Endpoint (MDE) API data that is NOT available through
Log Analytics KQL queries.

These calls replace the Sentinel Triage MCP tools (`GetDefenderIpAlerts`,
`GetDefenderFileInfo`, `ListDefenderIndicators`, `ListDefenderMachinesByVulnerability`, etc.)
which are NOT available in this environment.

---

## ⛔ Critical: Tool Selection

> **ALWAYS** use `RunAzCliReadCommands` for ALL calls in this document.
>
> **NEVER** use `RunAzCliWriteCommands` — even though the calls are `az rest --method GET` (read-only), `RunAzCliWriteCommands` has a different authorization flow:
> 1. It first tries Managed Identity (same as `RunAzCliReadCommands`)
> 2. If MI returns 403, it falls back to **On-Behalf-Of (OBO)** flow
> 3. OBO requires **Delegated permissions** which are NOT configured → **403 error**
>
> `RunAzCliReadCommands` uses MI directly with **Application permissions** → works correctly.
>
> **NEVER** use `RunInTerminal` with `az` commands — the `az` binary is not in the shell PATH.

---

## MDE API Base URL

All MDE API calls use this base URL:

```
https://api.securitycenter.microsoft.com/api/
```

The `--resource` parameter must be set to authenticate against the MDE API scope:

```
--resource "https://api.securitycenter.microsoft.com"
```

---

## Decision Flow

```
Can I use RunAzCliReadCommands tool?
  ├─ YES → Use the calls below (this document)
  │         └─ If 403 on first call → MDE API permissions not granted
  │              └─ Skip ALL MDE API enrichment
  │              └─ Note in report: "MDE API not accessible — KQL-only mode"
  │              └─ Rely on KQL queries from SKILL.md (Q1–Q14)
  └─ NO → Skip MDE API enrichment entirely
           └─ Rely on KQL queries from SKILL.md (Q1–Q14)
```

---

## IP Address Calls

### MDE-IP-ALERTS: Get Alerts for IP

**Replaces:** `GetDefenderIpAlerts` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/ips/<IP_ADDRESS>/alerts" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** All security alerts associated with the IP address.

**Key fields in response:**
- `value[]` array with: `id`, `title`, `severity`, `status`, `category`, `assignedTo`, `investigationState`, `firstEventTime`, `lastEventTime`, `machineId`

---

### MDE-IP-STATS: Get IP Statistics

**Replaces:** `GetDefenderIpStatistics` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/ips/<IP_ADDRESS>/stats" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** Organization prevalence, device count, and communication statistics.

**Key fields in response:**
- `orgPrevalence`, `orgFirstSeen`, `orgLastSeen`

---

### MDE-FIND-MACHINES: Find Devices by IP

**Replaces:** `FindDefenderMachinesByIp` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/machines/findbyip(ip='<IP_ADDRESS>',timestamp=<DATETIME>)" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<IP_ADDRESS>`: Target IP address
- `<DATETIME>`: ISO 8601 timestamp (e.g., `2026-05-30T00:00:00Z`). Returns devices that communicated with the IP ±15 minutes of this timestamp.

**Returns:** Devices that communicated with the IP.

**Key fields:** `id`, `computerDnsName`, `osPlatform`, `osVersion`, `riskScore`, `exposureLevel`, `lastSeen`

---

## File Hash Calls

### MDE-FILE-INFO: Get File Info

**Replaces:** `GetDefenderFileInfo` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<FILE_HASH>`: SHA1 or SHA256 hash of the file

**Returns:** File details including global prevalence, threat determination, signer info.

**Key fields:** `sha1`, `sha256`, `md5`, `size`, `globalPrevalence`, `globalFirstObserved`, `globalLastObserved`, `signer`, `signerHash`, `isPeFile`, `fileType`, `filePublisher`, `fileProductName`, `determinationType`, `determinationValue`

---

### MDE-FILE-STATS: Get File Statistics

**Replaces:** `GetDefenderFileStatistics` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>/stats" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** Organization-level statistics for the file.

**Key fields:** `orgPrevalence`, `orgFirstSeen`, `orgLastSeen`, `topFileNames`

---

### MDE-FILE-ALERTS: Get File Alerts

**Replaces:** `GetDefenderFileAlerts` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>/alerts" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** All alerts associated with the file hash.

**Key fields in response:** `value[]` array with: `id`, `title`, `severity`, `status`, `category`, `machineId`, `firstEventTime`, `lastEventTime`

---

### MDE-FILE-MACHINES: Get Devices with File

**Replaces:** `GetDefenderFileRelatedMachines` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/files/<FILE_HASH>/machines" --resource "https://api.securitycenter.microsoft.com"
```

**Returns:** All devices where the file was observed.

**Key fields in response:** `value[]` array with: `id`, `computerDnsName`, `osPlatform`, `osVersion`, `riskScore`, `exposureLevel`, `lastSeen`

---

## Custom IOC List

### MDE-IOC: Search Custom Indicators

**Replaces:** `ListDefenderIndicators` MCP tool

**Tool:** `RunAzCliReadCommands`

**Primary approach (filtered — preferred for token efficiency):**

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/indicators?\$filter=indicatorValue+eq+'<IOC_VALUE>'" --resource "https://api.securitycenter.microsoft.com"
```

> This returns only matching indicators. If the OData filter is not supported by the tenant's MDE API version, fall back to the unfiltered approach below.

**Fallback approach (unfiltered — use only if filtered query fails):**

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/indicators?\$top=500" --resource "https://api.securitycenter.microsoft.com"
```

> **⚠️ Token spike prevention:** Without `$top`, this endpoint returns ALL custom indicators in the tenant (potentially thousands of items, each with multiple fields). ALWAYS include `$top=500` as a safety cap. Filter the `value` array client-side for the target IoC.

**⚠️ CRITICAL: Processing Custom IOC List Results**

The MDE indicators API returns ALL custom indicators in the tenant (potentially thousands). You MUST filter the results manually.

**MANDATORY Processing Steps:**

1. **Receive the full response** — the `value` array contains all indicators
2. **Manually filter** for the target IoC:
   ```python
   # Filter logic (case-insensitive)
   matches = [ind for ind in response["value"] 
              if ind.get("indicatorValue", "").lower() == target_ioc.lower()]
   ```
3. **Report results:**
   - Found: "Found X custom indicator(s) matching [IoC]: [action], [severity], [title]"
   - Not found: "No custom indicators match [IoC]"

**Key fields per indicator:** `indicatorValue`, `indicatorType`, `action` (Alert/Block/Allow), `severity`, `title`, `description`, `createdBy`, `creationTimeDateTimeUtc`, `expirationTime`

**Indicator types:**
- `IpAddress` — for IP IoCs
- `DomainName` — for domain IoCs
- `Url` — for URL IoCs
- `FileSha1` — for SHA1 hash IoCs
- `FileSha256` — for SHA256 hash IoCs
- `FileMd5` — for MD5 hash IoCs

**🔴 PROHIBITED:**
- ❌ Assuming "large result = no match" without filtering
- ❌ Reporting "Not in IOC list" without verifying the actual content
- ❌ Skipping processing due to result size

---

## Vulnerability Management

### MDE-CVE-MACHINES: Get Devices Affected by CVE

**Replaces:** `ListDefenderMachinesByVulnerability` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/vulnerabilities/<CVE_ID>/machineReferences" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<CVE_ID>`: CVE identifier (e.g., `CVE-2024-1234`)

**Returns:** All devices vulnerable to the specified CVE.

**Key fields in response:** `value[]` array with: `id` (device ID), `computerDnsName`, `osPlatform`, `osVersion`, `rbacGroupName`, `rbacGroupId`

**Usage pattern:**
```
For each CVE_ID extracted from Q12 or Shodan enrichment:
  1. Call MDE-CVE-MACHINES with the CVE_ID
  2. Collect affected devices
  3. Aggregate across all CVEs
  4. Report total unique affected devices
```

---

### MDE-DEVICE-VULNS: Get Vulnerabilities for a Device

**Replaces:** `GetDefenderMachineVulnerabilities` MCP tool

**Tool:** `RunAzCliReadCommands`

```
az rest --method GET --url "https://api.securitycenter.microsoft.com/api/machines/<DEVICE_ID>/vulnerabilities" --resource "https://api.securitycenter.microsoft.com"
```

**Parameters:**
- `<DEVICE_ID>`: MDE device ID (GUID)

**Returns:** All CVEs affecting the specified device.

**Key fields in response:** `value[]` array with: `id` (CVE ID), `name`, `description`, `severity`, `cvssV3`, `exploitTypes`, `exploitUris`, `publicExploit`, `exploitVerified`, `exposedMachines`

---

## Error Handling

| HTTP Status | Meaning | Action |
|-------------|---------|--------|
| **200** | Success | Process the response |
| **400** | Bad request | Check parameters (invalid IP format, hash length, CVE format) |
| **401** | Unauthorized | Token expired — retry once, then skip MDE enrichment |
| **403** | Forbidden | Managed identity lacks MDE API permissions. Skip ALL MDE API calls, note in report |
| **404** | Not found | IoC/CVE not in MDE scope — not an error, just no data. Continue with KQL |
| **429** | Rate limited | Wait and retry with exponential backoff (1s, 2s, 4s) |
| **500+** | Server error | Retry once, then skip and note in report |

### Fallback Strategy

If MDE API is entirely inaccessible (403 on first call):

1. **Skip ALL `az rest` calls** in this document
2. **Rely entirely on KQL queries** from SKILL.md (Q1–Q14)
3. **Note in investigation report:**
   ```
   ⚠️ MDE API not accessible (403 Forbidden). Investigation limited to Log Analytics data.
   Missing: Custom IOC list, file global prevalence, MDE-specific alerts, TVM vulnerability data.
   ```
4. **For CVE correlation:** Note CVEs found in alerts but report "Affected device enumeration unavailable (MDE API required)"
