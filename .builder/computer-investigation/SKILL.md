---
name: computer-investigation
description: >
  Computer/device security investigation skill for environments with Azure Monitor MCP
  (Log Analytics workspace queries) and Azure CLI access — currently without
  Sentinel Data Lake MCP, Sentinel Triage MCP, or Microsoft Graph MCP
  (these cannot be connected to Azure SRE Agent yet; direct API access not yet implemented).
  Device data from Entra ID is collected via Azure CLI (`az rest` for Graph API)
  or KQL fallback queries from DeviceInfo/SigninLogs.
  KQL queries run against Log Analytics tables through the Azure Monitor MCP tool.
  TVM tables (software inventory, vulnerabilities) are NOT available through Log Analytics.
---

# Computer Security Investigation — Monitor MCP + Azure CLI

## Purpose

This skill performs comprehensive security investigations on Windows, macOS, and Linux devices registered in Microsoft Entra ID and/or onboarded to Microsoft Defender for Endpoint, in environments where:

- ✅ **Azure Monitor MCP tool** is available (`monitor-client_monitor_workspace_log_query`) for KQL queries against Log Analytics
- ✅ **Azure CLI** (`az` in shell or `RunAzCliReadCommands` tool) is available for read operations (including `az rest` for Graph API)
- ⚠️ **Graph API permissions** may NOT be granted — KQL-based fallback queries provided
- ❌ **Sentinel Data Lake MCP** — not integrated (no `query_lake`, `list_sentinel_workspaces`, `search_tables`)
- ❌ **Sentinel Triage MCP** — not integrated (no `RunAdvancedHuntingQuery`, `GetDefenderMachine`, `GetDefenderMachineLoggedOnUsers`, etc.)
- ❌ **Microsoft Graph MCP** — not integrated (no `microsoft_graph_get`, `suggest_queries`)

> **Why these MCP servers are absent:** Sentinel Data Lake MCP, Sentinel Triage MCP, and Microsoft Graph MCP cannot currently be connected to Azure SRE Agent. This does **not** mean the underlying data is inaccessible — the data exposed by these servers (Sentinel Data Lake, Defender XDR / Advanced Hunting, Microsoft Graph) can be reached via direct API calls. However, direct API access as a replacement for these MCP servers has not yet been studied and implemented in this skill.

**Data sources (Log Analytics):** DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, SigninLogs, SecurityAlert, SecurityIncident, ThreatIntelIndicators.

**NOT available (require Advanced Hunting):** DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities.

**NOT available (require MDE API):** Defender riskScore (per machine), automated investigations, remediation activities.

**Device types supported:** Entra Joined, Hybrid Joined, and Entra Registered devices.

**Skill files:**
- `SKILL.md` — this file (investigation workflow, KQL queries, report templates)
- `generate_html_report.py` — consolidated HTML report generator (dataclasses + HTML engine + JSON transformer, single self-contained file)
- `enrich_ips.py` — IP enrichment script (source: `user-investigation/enrich_ips.py`, resolved via File Resolution cascade)
- `get-device-context-via-cli.md` — step-by-step Graph API reference for device data collection

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/computer-investigation/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/computer-investigation/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("computer-investigation", "<filename>") from Builder
      (for enrich_ips.py: read_skill_file("user-investigation", "enrich_ips.py"))
   → CreateFile("tmp/computer-investigation/<filename>", <content>)
   → Repeat for ALL companion files referenced by the script
```

**Rules:**
- When a file is found in `codeRefs/`, execute it directly from there — do NOT copy it to `tmp/`.
- When materializing from Builder (step 3), materialize ALL companion files the script depends on, not just the script itself.
- This cascade applies to every file listed in the Skill Files table above.

---

## 📑 TABLE OF CONTENTS

1. **[Prerequisites](#prerequisites)**
2. **[Environment Configuration](#environment-configuration)**
3. **[Secrets Management (API Tokens)](#secrets-management-api-tokens)**
4. **[Phase 0: Investigation Cache Check](#phase-0-investigation-cache-check-mandatory)** — Cache reuse logic
5. **[Critical Workflow Rules](#critical-workflow-rules)**
6. **[Device Types Reference](#device-types-reference)**
7. **[Investigation Types](#investigation-types)**
8. **[Output Modes](#output-modes)**
9. **[Quick Start](#quick-start)**
10. **[Execution Workflow](#execution-workflow)**
11. **[KQL Execution Reference](#kql-execution-reference)**
12. **[Sample KQL Queries](#sample-kql-queries)**
13. **[Entra ID Device Data Collection](#entra-id-device-data-collection)**
14. **[Markdown Report Template](#markdown-report-template)**
15. **[JSON Export Structure](#json-export-structure)**
16. **[Error Handling](#error-handling)**
17. **[Device Trust Type Analysis](#device-trust-type-analysis)**
18. **[Risk Assessment Framework](#risk-assessment-framework)**

**Investigation shortcuts:**
- **Device with behavioral drift**: Q3 (suspicious processes) → Q9 (logon events) → Q7 (incidents) → Q8 (device info)
- **Internet-facing critical asset**: Q8 (device info + internet-facing) → Q4 (outbound connections) → Q9 (logon events)
- **Device in active incident**: Q2 (security alerts) → Q3 (process execution) → Q5 (file events) → Q6 (registry persistence) → Q7 (incidents)
- **Brute-forced endpoint**: Q9 (logon events) → Q4 (outbound connections) → Q10 (TI IP matches)

> **⛔ Shortcut Default Rule:** When a matching shortcut exists, **use it** — don't run the full workflow. Only run the full query set when the user explicitly requests "full investigation", "comprehensive", or "deep dive". Shortcuts render only the report sections relevant to their query chain (plus Executive Summary and Recommendations, always).

---

## Prerequisites

| Dependency | Required | Fallback | Notes |
|------------|----------|----------|-------|
| **Azure Monitor MCP** (`monitor-client_monitor_workspace_log_query`) | ✅ Yes | None — core dependency | Must be configured and connected to the target Log Analytics workspace |
| **Azure CLI / `RunAzCliReadCommands` tool** | ⚠️ Optional | KQL-only mode | Used for Graph API calls via `az rest`. If unavailable, all device context from KQL |
| **Graph API permissions** | ⚠️ Optional | KQL-based fallback (Q0) | `Device.Read.All` for device profile, owners, compliance |
| **Python 3.x** | ⚠️ Optional | Q10 (TI matches) + KQL IP context | `enrich_ips.py` (source: `user-investigation/enrich_ips.py`, materialized to `tmp/computer-investigation/`) for external API enrichment. Requires API tokens. If unavailable, use KQL-only IP analysis. |

---

## Environment Configuration

### Primary: Agent Settings Auto-Discovery (Recommended)

Workspace parameters are automatically available from the agent's system context:

1. **`<log_analytics_access>`** section provides:
   - Workspace name (display name)
   - Workspace ID (GUID) — use as the `workspace` parameter
2. **`<azure_resource_access>`** section provides:
   - Subscription ID
3. **`<agent_identity>`** section provides:
   - Resource group (extractable from the agent's ARM resource ID)

**How to extract parameters from agent context:**

| Parameter | Source | Example |
|-----------|--------|---------|
| `workspace` | `<log_analytics_access>` → workspace GUID | the workspace ID from `<log_analytics_access>` |
| `subscription` | `<azure_resource_access>` → subscription ID | the agent's subscription from `<azure_resource_access>` |
| `resource-group` | `<agent_identity>` → extract from ARM resource ID | the agent's resource group, extracted from its ARM resource ID in `<agent_identity>` |

**When making Monitor MCP calls**, always pass `subscription` from agent settings. The `workspace` parameter accepts the workspace GUID directly.

### Secondary: config.json (Optional)

If a `config.json` file exists at the workspace root, it can provide additional configuration:

| Field | Used By | Purpose |
|-------|---------|---------|
| `azure_mcp.resource_group` | Monitor MCP | Resource group containing the Log Analytics workspace |
| `azure_mcp.workspace_name` | Monitor MCP | Log Analytics workspace display name |
| `azure_mcp.tenant` | Monitor MCP, `az rest` | Entra ID tenant |
| `azure_mcp.subscription` | Monitor MCP | Target Azure subscription |
| `sentinel_workspace_id` | CLI fallback | Log Analytics workspace GUID |
| `tenant_id` | Portal URLs | Entra ID tenant ID |

### Configuration Resolution Order

1. **Agent settings** (`<log_analytics_access>`, `<azure_resource_access>`) — always available
2. **config.json** — read if present, skip if absent
3. **Never prompt the user** for workspace parameters if either source is available

---

## Secrets Management (API Tokens)

`enrich_ips.py` (source: `user-investigation/enrich_ips.py`, materialized to `tmp/computer-investigation/enrich_ips.py`) uses 4 external threat intelligence APIs. See the user-investigation SKILL.md for full token configuration details.

**Quick summary:**

| Variable | API | What it provides |
|----------|-----|------------------|
| `IPINFO_TOKEN` | ipinfo.io | Geolocation, ASN, VPN/proxy/Tor |
| `ABUSEIPDB_TOKEN` | AbuseIPDB | Abuse score, reports |
| `VPNAPI_TOKEN` | vpnapi.io | VPN/proxy/Tor/relay detection |
| `SHODAN_TOKEN` | Shodan | Open ports, services, CVEs |

**Behavior without tokens:** Shodan InternetDB (free, no key) still provides open ports, CVEs, and tags. Q10 (ThreatIntelIndicators) and Q11 (KQL IP context) are SUPPLEMENTS, not replacements for `enrich_ips.py`.

---

## Phase 0: Investigation Cache Check (MANDATORY)

**This phase MUST execute BEFORE any data collection. It determines whether to reuse cached investigation data or start a fresh investigation.**

### 0.1 Cache File Convention

Investigation results are stored as JSON files following this naming pattern:
```
temp/investigation_device_<device_name>_<YYYYMMDD_HHMMSS>.json
```

### 0.2 Cache Check Workflow

```
Step 0.1: Search for existing cache files matching the device name
          → Use: ls temp/investigation_device_<DEVICE_NAME>_*.json
          → If NO cache file exists → proceed to Phase 1 (fresh investigation)

Step 0.2: If one or more cache files exist, select the MOST RECENT one (latest timestamp)

Step 0.3: Calculate the cache age:
          → Extract timestamp from filename (YYYYMMDD_HHMMSS format)
          → age = current_UTC_time − cache_file_timestamp
          → If age > 4 hours → IGNORE cache entirely, proceed to Phase 1 (fresh investigation)
          → If age ≤ 4 hours → proceed to Step 0.4

Step 0.4: Analyze the user's ORIGINAL prompt for implicit intent:

          REDO KEYWORDS (triggers fresh investigation, any language):
            "ripeti", "aggiorna", "rifai", "repeat", "redo", "refresh",
            "update", "re-investigate", "start over", "da capo",
            "from scratch", "ricomincia", "nuovo", "nuova analisi"
          → If ANY redo keyword is detected → IGNORE cache, proceed to Phase 1

          USE-CACHE KEYWORDS (triggers cache reuse, any language):
            "completa", "continua", "complete", "continue", "finish",
            "usa i dati", "use cached", "use existing", "prosegui",
            "riprendi", "resume", "genera report", "generate report",
            "genera il report", "crea report"
          → If ANY use-cache keyword is detected → LOAD cache, skip to Step 0.6

          NO IMPLICIT INTENT DETECTED:
          → Proceed to Step 0.5 (ask the user)

Step 0.5: ASK the user:

          Question: "Ho trovato risultati di un'investigazione precedente per
                     il device <DEVICE_NAME>, completata <TIME_AGO> fa (alle <HH:MM> UTC).
                     Vuoi utilizzare questi dati o preferisci ripetere
                     l'investigazione da zero?"
          Options:
            1. "Usa i dati esistenti" — Riprende dall'investigazione precedente
            2. "Ripeti da zero" — Ignora la cache e ricomincia

          → If user selects "Usa i dati esistenti" → proceed to Step 0.6
          → If user selects "Ripeti da zero" → proceed to Phase 1

Step 0.6: LOAD cached data:
          → Read the JSON file
          → Present a brief inline summary of cached findings
          → Offer HTML/report generation or further investigation
```

### 0.3 Cache Decision Summary

| Cache Exists? | Age | User Prompt | Action |
|---------------|-----|-------------|--------|
| No | — | — | Fresh investigation |
| Yes | > 4 hours | — | Fresh investigation — cache expired |
| Yes | ≤ 4 hours | Contains REDO keyword | Fresh investigation |
| Yes | ≤ 4 hours | Contains USE-CACHE keyword | Load cache |
| Yes | ≤ 4 hours | No implicit intent | ASK user |

### 0.4 Important Rules

- **NEVER silently reuse cached data** — always either detect explicit intent from the prompt or ask the user.
- **NEVER ask the user if the prompt already contains an implicit answer** — detect keywords first.
- **When loading cache, always show what was already completed** — the user must understand what data is from cache vs. new queries.
- **Cache files from a DIFFERENT thread/session are still valid** — the 4-hour TTL is the only expiration criterion.
- **If the user later requests a fresh investigation after loading cache** — discard all cached data and restart from Phase 1.

---

## Critical Workflow Rules

**Before starting ANY computer investigation:**

1. **ALWAYS complete Phase 0 (Cache Check) first** — Before any data collection, check for cached investigation results. See Phase 0 for full logic.
2. **ALWAYS get Device IDs FIRST** — try Graph API via Azure CLI, fall back to KQL (Q0)
3. **ALWAYS determine device type** (Entra Joined, Hybrid Joined, or Entra Registered)
4. **ALWAYS calculate date ranges correctly** — see [Date Range Quick Reference](#date-range-quick-reference)
5. **Default to inline output.** Markdown file, HTML report, and JSON export are generated ONLY if the user explicitly requests them. Do NOT ask — just deliver inline unless told otherwise.
5. **ALWAYS track and report time after each major step**
6. **ALWAYS run independent queries in parallel**
7. **ALWAYS use `create_file` for JSON export and markdown reports** — NEVER use terminal commands for file output
8. **Read workspace parameters** from agent settings first, then config.json if needed
9. **⛔ ALWAYS use `RunAzCliReadCommands` for Graph API calls** — NEVER use `RunAzCliWriteCommands` for `az rest --method GET` requests. The two tools have DIFFERENT authorization flows: `RunAzCliReadCommands` authenticates via Managed Identity directly (works with Application permissions). `RunAzCliWriteCommands` falls back to On-Behalf-Of (OBO) flow when MI fails, and OBO requires Delegated permissions that are NOT configured. Using the wrong tool causes 403 errors.
10. **⛔ ALWAYS run `enrich_ips.py` for IP enrichment** — This is MANDATORY, not optional. Before running: (a) try reading API tokens from Key Vault via `RunAzCliReadCommands`, (b) if Key Vault unavailable, ASK the user for API tokens, (c) if no tokens at all, run anyway — Shodan InternetDB (free, no key) still provides open ports, CVEs, and tags. Q11 (KQL IP context) is a SUPPLEMENT, not a replacement.
11. **⛔ ALWAYS generate the complete formatted report** — Every investigation MUST produce the full report following the [Markdown Report Template](#markdown-report-template), with ALL sections populated (use `✅ No <X> detected...` for empty sections). Never skip the report, never abbreviate, never omit sections.

### Device Context Retrieval Strategy

The skill uses a **cascading strategy** to retrieve device context data:

```
Strategy 1: Azure CLI (az rest) for Graph API
    ↓ If 403/401 or CLI unavailable
Strategy 2: KQL Fallback Queries (Q0a, Q0b) from DeviceInfo + SigninLogs
    ↓ If DeviceInfo empty (device not onboarded)
Strategy 3: Report "Device not onboarded to Defender or not found in Log Analytics"
```

**IMPORTANT:** If Graph API fails with 403, do NOT abort the investigation. Proceed immediately with KQL fallback — DeviceInfo and SigninLogs contain most of the critical device context data.

### Device ID Types

- **Entra Device Object ID**: Used for Graph API queries (owners, users, compliance) — GUID format
- **Entra Device Registration ID** (`deviceId` in Graph): Different GUID from object ID
- **Defender Device ID**: Internal MDE identifier — found in DeviceInfo table (`DeviceId` column). Different from both Entra IDs.
- **Device Name/Hostname**: Human-readable name, use for initial search. Use `startswith` in KQL to match both hostname and FQDN.

---

## Device Types Reference

### Entra Joined Devices
- **trustType**: `AzureAd`
- **Characteristics**: Cloud-only, no on-premises AD connection
- **Identity**: Uses Entra ID for authentication
- **Common scenarios**: Cloud-native organizations, Windows Autopilot deployments

### Hybrid Joined Devices
- **trustType**: `ServerAd` (indicates hybrid join with on-premises AD)
- **Characteristics**: Joined to both on-premises AD and Entra ID
- **Identity**: Uses both on-premises AD and Entra ID
- **Common scenarios**: Traditional enterprise environments migrating to cloud

### Entra Registered Devices
- **trustType**: `Workplace`
- **Characteristics**: Personal/BYOD devices, user adds work account
- **Identity**: User authenticates with Entra ID, device not fully managed
- **Common scenarios**: BYOD policies, personal device access to corporate resources

---

## Investigation Types

### Standard Investigation (7 days)
General security reviews, routine investigations.

### Quick Investigation (1 day)
Urgent cases, active malware alerts, recent suspicious activity.

### Comprehensive Investigation (30 days)
Deep-dive analysis, lateral movement detection, thorough forensics.

**All types include:** Security alerts, device inventory, sign-in patterns from device, logged-on users, process execution, network connections, file events, registry modifications, security incidents, threat intelligence matches, and recommendations.

**NOT included (data not available via Monitor MCP):** Software inventory (TVM), vulnerability assessment (TVM), Defender riskScore, automated investigations, remediation activities.

---

## Output Modes

**Default: Inline.** Always provide the full investigation results inline in chat. Markdown file and HTML report are generated **only if the user explicitly requests them**. Multiple modes may be active simultaneously.

### Mode 1: Inline Chat Summary (Default — always active)
- Render the full analysis directly in the chat response
- No file output — results stay in chat context
- This is ALWAYS the primary output — never skip it

### Mode 2: Markdown File Report (only if explicitly requested)
- Save to `reports/computer-investigations/computer_investigation_<device_name>_<YYYYMMDD_HHMMSS>.md`
- Uses the [Markdown Report Template](#markdown-report-template) below
- Use `create_file` tool — NEVER use terminal commands for file output
- **Trigger:** User says "save markdown", "generate MD", "markdown file", "save report", or similar

### Mode 3: HTML Report (only if explicitly requested — conditional materialization)
- Export investigation data to JSON, then generate a styled HTML report via `generate_html_report.py`
- Self-contained HTML with embedded CSS/JS — dark theme, two-column layout, interactive IP cards, process/network/file/registry sections, timeline modal
- **Single consolidated script:** `generate_html_report.py` — contains dataclasses, HTML generator, and JSON transformer in one file. No external dependencies beyond Python 3 stdlib.
- **Pipeline:** JSON export → materialize `generate_html_report.py` → run → HTML report
- **Output location:** `reports/computer-investigations/Investigation_Report_<device_name>_<timestamp>.html`
- **⚠️ Conditional materialization:** The script is resolved via the [File Resolution cascade](#file-resolution-coderefs-first) ONLY when the user requests HTML output.
  1. Resolve `generate_html_report.py` via cascade (codeRefs → tmp → Builder)
  2. Run: `python3 <resolved_path>/generate_html_report.py temp/investigation_device_<device_name>_<timestamp>.json`
- **Trigger:** User says "generate HTML", "HTML report", "create HTML", or similar

### Mode 4: JSON Export (only if explicitly requested)
- Export to `temp/investigation_device_<device_name>_<timestamp>.json`
- Uses the [JSON Export Structure](#json-export-structure) below
- **Trigger:** User says "export JSON", "JSON file", or similar

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters (`█`, `─`) display correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables (`| col |`) render as formatted tables

---

## Quick Start

1. **Discover workspace parameters** from agent settings (`<log_analytics_access>`, `<azure_resource_access>`). If not found, read `config.json`.

2. **Get Device Context** (cascading strategy):
   - **Try Graph API** via Azure CLI:
     ```
     az rest --method GET --url "https://graph.microsoft.com/v1.0/devices?$filter=displayName eq '<DEVICE_NAME>'&$select=id,deviceId,displayName,operatingSystem,trustType,isCompliant,isManaged,..." --subscription <subId>
     ```
   - **If 403/fails → KQL Fallback** (run Q0a, Q0b in parallel):
     - Q0a: Device identity from DeviceInfo (Defender Device ID, OS, sensor health, exposure)
     - Q0b: Device sign-in context from SigninLogs (trust type, compliance, managed)

3. **Output Mode:** Default to inline. Generate MD/HTML/JSON only if explicitly requested.

4. **Run KQL Queries (via Monitor MCP):**
   - Batch 1: Q1 (sign-ins), Q2 (alerts), Q3 (processes), Q4 (network), Q5 (files), Q6 (registry), Q7 (incidents), Q8 (device info), Q9 (logon events)
   - Batch 2: Q10 (TI matches), Q11 (KQL IP context) — depends on Batch 1 IPs

5. **Run IP Enrichment (MANDATORY):** See [Phase 3](#phase-3-ip-enrichment-mandatory).

6. **Generate Output** based on selected mode — ALWAYS produce inline report. If user requested MD/HTML/JSON, generate those additionally.

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking

```
[MM:SS] ✓ Step description (XX seconds)
```

Report after: Device ID retrieval, parallel data collection, IP enrichment, report generation, and total elapsed time.

---

### Phase 1: Get Device Context (Cascading Strategy)

#### Strategy 1: Graph API via Azure CLI

Use Azure CLI (`az rest`) or `RunAzCliReadCommands` tool to call Graph API. See `get-device-context-via-cli.md` for the full step-by-step reference.

**Step 1a — Find Device:**
```
az rest --method GET --url "https://graph.microsoft.com/v1.0/devices?$filter=displayName eq '<DEVICE_NAME>'&$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,registrationDateTime,approximateLastSignInDateTime,mdmAppId,profileType,manufacturer,model" --subscription <subId>
```

**Steps 1b–1d** (Owners, Registered Users, Intune) — see `get-device-context-via-cli.md`.

> **⛔ CRITICAL — Tool Selection:**
> - **ALWAYS** use `RunAzCliReadCommands` for ALL `az rest --method GET` calls to Graph API.
> - **NEVER** use `RunAzCliWriteCommands` — it has a different auth flow (MI → OBO fallback) that fails without Delegated permissions.
> - **NEVER** use `RunInTerminal` with `az` commands — the `az` binary may not be in the shell PATH.

> **If Step 1a returns 403:** Stop Graph API calls immediately. Proceed to Strategy 2.

#### Strategy 2: KQL Fallback (when Graph API is unavailable)

Run Q0a and Q0b queries in parallel via `monitor-client_monitor_workspace_log_query`. These extract device context from DeviceInfo and SigninLogs.

See [Q0 queries](#q0-kql-based-device-context-extraction-graph-api-fallback) below for the full KQL.

**Data coverage comparison:**

| Data Point | Graph API | KQL Fallback (Q0) | Notes |
|------------|-----------|-------------------|-------|
| Device Name | ✅ `displayName` | ✅ `DeviceName` from DeviceInfo | Identical |
| OS | ✅ `operatingSystem` | ✅ `OSPlatform` from DeviceInfo | Identical |
| OS Version | ✅ `operatingSystemVersion` | ✅ `OSVersion` from DeviceInfo | Identical |
| Trust Type | ✅ `trustType` | ⚠️ `JoinType` from DeviceInfo or SigninLogs | Similar but different field names |
| Compliance | ✅ `isCompliant` | ⚠️ From SigninLogs `DeviceDetail` | Only for devices with sign-in activity |
| Managed | ✅ `isManaged` | ⚠️ From SigninLogs `DeviceDetail` | Only for devices with sign-in activity |
| Manufacturer | ✅ `manufacturer` | ❌ Not in DeviceInfo | Report as "Unknown (Graph unavailable)" |
| Model | ✅ `model` | ❌ Not in DeviceInfo | Report as "Unknown (Graph unavailable)" |
| Registration Date | ✅ `registrationDateTime` | ❌ Not in DeviceInfo | Report as "Unknown (Graph unavailable)" |
| Defender Device ID | ❌ Not in Graph | ✅ `DeviceId` from DeviceInfo | Only from KQL |
| Sensor Health | ❌ Not in Graph | ✅ `SensorHealthState` from DeviceInfo | Only from KQL |
| Exposure Level | ❌ Not in Graph | ✅ `ExposureLevel` from DeviceInfo | Only from KQL |
| Internet Facing | ❌ Not in Graph | ✅ `IsInternetFacing` from DeviceInfo | Only from KQL |
| Device Owners | ✅ `/registeredOwners` | ❌ Not in KQL | Report as "Unknown (Graph unavailable)" |
| Defender riskScore | ❌ Only in MDE API | ❌ Not in DeviceInfo | Data gap — not available in this environment |

**Best practice:** Run BOTH Graph API AND Q0a. Graph provides owners/manufacturer; DeviceInfo provides sensor health/exposure/internet-facing. Merge results.

---

### Phase 2: Parallel KQL Data Collection (Monitor MCP)

Execute KQL queries via `monitor-client_monitor_workspace_log_query`.

**Required parameters for every call** (from agent settings):
- `subscription` — from `<azure_resource_access>`
- `resource-group` — from agent ARM resource ID or config
- `workspace` — workspace GUID from `<log_analytics_access>`
- `table` — primary table for the query
- `query` — KQL query string
- `hours` — time range in hours (168 for 7d, 24 for 1d, 720 for 30d)

#### Batch 1 (run in parallel):
| Query | Description | Table | Depends On |
|-------|-------------|-------|------------|
| Q0a/Q0b | Device context (if Graph failed) | DeviceInfo, SigninLogs | Nothing |
| Q1 | Device sign-in events | SigninLogs | Nothing |
| Q2 | Security alerts | SecurityAlert | Nothing |
| Q3 | Process execution events | DeviceProcessEvents | Nothing |
| Q4 | Network connection events | DeviceNetworkEvents | Nothing |
| Q5 | File events | DeviceFileEvents | Nothing |
| Q6 | Registry events | DeviceRegistryEvents | Nothing |
| Q7 | Security incidents | SecurityAlert, SecurityIncident | Nothing |
| Q8 | Device inventory | DeviceInfo | Nothing |
| Q9 | Logon events | DeviceLogonEvents | Nothing |

#### After Batch 1: Extract IPs
- Extract public IPs from Q4 results (network connections) and Q1 results (sign-in IPs)
- Build IP array: `["ip1", "ip2", "ip3", ...]`

#### Batch 2 (run in parallel, depends on Batch 1):
| Query | Description | Table |
|-------|-------------|-------|
| Q10 | Threat intelligence IP matches | ThreatIntelIndicators, DeviceNetworkEvents |
| Q11 | KQL-based IP context analysis | SigninLogs |

---

### Phase 3: IP Enrichment (⛔ MANDATORY)

> **⚠️ This phase is NOT optional.** Every investigation MUST include IP enrichment via `enrich_ips.py`. Skipping this phase is a critical workflow violation.

#### Step 3a: Retrieve API Tokens

Before running `enrich_ips.py`, attempt to retrieve API tokens from Key Vault using `RunAzCliReadCommands`:

```
az rest --method GET --url "https://<vault-name>.vault.azure.net/secrets/<secret-name>?api-version=7.4" --resource "https://vault.azure.net" --subscription <subId>
```

> **⚠️ Key Vault access:** Use `az rest --resource "https://vault.azure.net"` — NOT `az keyvault` (which is unsupported by `RunAzCliReadCommands`). If Key Vault returns `ForbiddenByConnection`, ask the user to temporarily enable public access or add Azure Services firewall bypass.

- If Key Vault succeeds: extract token value from the JSON response `value` field, pass as env var.
- If Key Vault fails (403/ForbiddenByConnection): **ASK the user** for API tokens.
- If user has no tokens: proceed anyway — Shodan InternetDB (free, no key) still provides open ports, CVEs, and tags.

#### Step 3b: Resolve and Run enrich_ips.py

Resolve `enrich_ips.py` using the [File Resolution cascade](#file-resolution-coderefs-first):
1. Check `codeRefs/sec-sre-ag/computer-investigation/enrich_ips.py` → if found, run from there.
2. Else check `tmp/computer-investigation/enrich_ips.py` → if found, run from there.
3. Else: `read_skill_file("user-investigation", "enrich_ips.py")` → `CreateFile("tmp/computer-investigation/enrich_ips.py", <content>)` → run from `tmp/`.
4. Run:
```bash
# Pass available tokens as environment variables
ABUSEIPDB_TOKEN=<value> IPINFO_TOKEN=<value> python3 <resolved_path>/enrich_ips.py <ip1> <ip2> <ip3>
```

**Output:** JSON file in `temp/ip_enrichment_<timestamp>.json` + text report in `temp/ip_enrichment_<timestamp>.txt`

#### Step 3c: KQL Supplements (already in Batch 2)

Q10 (ThreatIntelIndicators) and Q11 (KQL IP context) — already executed in Batch 2 — are SUPPLEMENTS to `enrich_ips.py`. They do NOT replace it.

---

### Phase 4: Export & Generate Report (⛔ MANDATORY)

> **⚠️ This phase is NOT optional.** Every investigation MUST produce the complete formatted report. Never skip the report, never abbreviate, never omit sections.

#### Mode 1 — Inline Chat Summary
Render analysis directly in chat using the **complete** section structure from the Markdown Report Template. All sections must be present.

#### Mode 2 — Markdown File Report
1. Build the markdown report using the template below — ALL sections must be populated
2. Save: `create_file("reports/computer-investigations/computer_investigation_<device_name>_YYYYMMDD_HHMMSS.md", content)`

#### Mode 3 — HTML Report (Conditional — File Resolution Cascade)

> **⚠️ Resolve `generate_html_report.py` ONLY when the user requests HTML output.**

1. **Export to JSON:** `create_file("temp/investigation_device_<device_name>_<timestamp>.json", content)`
2. **Resolve `generate_html_report.py`** via the [File Resolution cascade](#file-resolution-coderefs-first):
   - Check `codeRefs/sec-sre-ag/computer-investigation/generate_html_report.py` → if found, use that path.
   - Else check `tmp/computer-investigation/generate_html_report.py` → if found, use that path.
   - Else: `read_skill_file("computer-investigation", "generate_html_report.py")` → `CreateFile("tmp/computer-investigation/generate_html_report.py", <content>)`
3. **Run:** `python3 <resolved_path>/generate_html_report.py temp/investigation_device_<device_name>_<timestamp>.json`

#### Mode 4 — JSON Export
1. Export: `create_file("temp/investigation_device_<device_name>_<timestamp>.json", content)`
2. Merge all results into one dict (see [JSON Export Structure](#json-export-structure))

---

## KQL Execution Reference

### Primary: Azure Monitor MCP Tool

Use `monitor-client_monitor_workspace_log_query` for all KQL queries.

**Tool parameters:**

| Parameter | Required | Source |
|-----------|----------|--------|
| `workspace` | Yes | Workspace GUID from `<log_analytics_access>` |
| `resource-group` | Yes | From agent ARM resource ID or config |
| `subscription` | Yes | From `<azure_resource_access>` |
| `table` | Yes | Primary table for the query (e.g., `DeviceInfo`) |
| `query` | Yes | KQL query string |
| `hours` | Optional | Lookback period in hours (overrides in-query time filters) |

### Fallback: Azure CLI

If the Monitor MCP tool fails, use Azure CLI with:

```
az monitor log-analytics query --workspace "<workspace_GUID>" --analytics-query "<KQL_QUERY>" --timespan "P7D" --subscription <subId>
```

> **⚠️ Shell `az` vs Tool:** If `RunAzCliReadCommands` tool is available, prefer it. The `az` CLI binary may NOT be in the shell PATH in some environments.

### Timestamp Column

All tables used in this skill use `TimeGenerated` — no adaptation needed.

### Retention

Log Analytics workspace retention is typically 90 days (configurable). No 30-day cap.

### Known Table Pitfalls (Log Analytics)

| Table | Pitfall | Fix |
|-------|---------|-----|
| **DeviceInfo** | `LoggedOnUsers` is a JSON array, not a simple string | `mv-expand parse_json(LoggedOnUsers)` |
| **DeviceNetworkEvents** | Some columns like `SentBytes`, `ReceivedBytes` may not be present | Handle missing columns gracefully |
| **SigninLogs** | `DeviceDetail`, `LocationDetails`, `Status` may be dynamic OR string | Always use `tostring(parse_json(...))` pattern |
| **SigninLogs** | `Location` is string, not dynamic — `Location.countryOrRegion` fails | Use `parse_json(LocationDetails).countryOrRegion` |
| **SecurityAlert** | `Status` field is **immutable** — always "New" | Join with `SecurityIncident` for real status |
| **SecurityIncident** | `AlertIds` contains alert GUIDs, NOT entity names | Filter SecurityAlert first, then join |
| **ThreatIntelIndicators** | Can be very large (100K+ rows) | Filter `IsActive`/`ValidUntil` **before** string transformations |
| **DeviceProcessEvents** | `ProcessCommandLine` can be very long | Use `strlen()` checks; truncate in output |
| **DeviceRegistryEvents** | `RegistryKey` paths can be very verbose | Focus on persistence-related keys only |

### Common KQL Anti-Patterns

| Anti-Pattern | Fix |
|-------------|-----|
| `mv-expand` on string column containing JSON | `mv-expand parsed = parse_json(StringColumn)` |
| `dcount()` on dynamic column | `dcount(tostring(DynamicColumn))` |
| `bin()` missing argument | Always: `bin(TimeGenerated, 1h)` |
| `iff()` with mismatched branch types | Cast both: `iff(cond, todouble(x), todouble(y))` |
| Joining on dynamic column | Cast before join: `extend AlertId = tostring(AlertId)` |

### Data Gaps (Not Available via Monitor MCP)

| Data | Reason | Alternative |
|------|--------|-------------|
| **Software Inventory** | `DeviceTvmSoftwareInventory` is Advanced Hunting only | Note as data gap in report |
| **Vulnerabilities (CVEs)** | `DeviceTvmSoftwareVulnerabilities` is Advanced Hunting only | Note as data gap in report |
| **Defender riskScore** | Only available via MDE API (`GetDefenderMachine`) | Use `ExposureLevel` from DeviceInfo as proxy |
| **Automated Investigations** | Only via MDE API (`ListDefenderInvestigations`) | Note as data gap |
| **Remediation Activities** | Only via MDE API (`ListDefenderRemediationActivities`) | Note as data gap |

---

## 📅 Date Range Quick Reference

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**
Check the current date from the context header BEFORE calculating date ranges. NEVER use hardcoded years.

**RULE 1: Real-Time/Recent Searches:**
Add +2 days to current date for end range (+1 timezone offset + +1 inclusive end-of-day).

**RULE 2: Historical Searches:**
Add +1 day to user's specified end date.

| User Request | `<StartDate>` | `<EndDate>` | Rule |
|---|---|---|---|
| "Last 7 days" | current − 7d | current + 2d | Rule 1 |
| "Last 30 days" | current − 30d | current + 2d | Rule 1 |
| "May 20 to May 23" | 2026-05-20 | 2026-05-24 | Rule 2 |

---

## Sample KQL Queries

Replace `<DEVICE_NAME>`, `<StartDate>`, `<EndDate>` in these patterns. Execute via Monitor MCP tool.

**⚠️ CRITICAL: START WITH THESE EXACT QUERY PATTERNS**
**These queries have been tested and validated. Use them as your PRIMARY reference.**

---

### Q0. KQL-Based Device Context Extraction (Graph API Fallback)

**When to use:** Graph API is unavailable (403 or CLI missing). These queries extract device context from DeviceInfo and SigninLogs.

**Run Q0a and Q0b in parallel.**

#### Q0a. Device Identity from DeviceInfo

Extracts Defender Device ID, OS, sensor health, exposure level, and key properties.

```kql
let deviceName = '<DEVICE_NAME>';
DeviceInfo
| where DeviceName startswith deviceName
| summarize arg_max(TimeGenerated, *) by DeviceId
| project 
    TimeGenerated,
    DeviceId,
    DeviceName,
    OSPlatform,
    OSVersion,
    OSBuild,
    OSArchitecture,
    MachineGroup,
    OnboardingStatus,
    SensorHealthState,
    ExposureLevel,
    IsAzureADJoined,
    IsInternetFacing,
    JoinType,
    PublicIP,
    DeviceManualTags,
    DeviceDynamicTags,
    RegistryDeviceTag,
    LoggedOnUsers
```

#### Q0b. Device Compliance & Trust from SigninLogs

Extracts compliance status, managed status, and trust type from sign-in activity — useful when Graph API is unavailable.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
SigninLogs
| where TimeGenerated between (start .. end)
| extend DeviceDetailStr = tostring(DeviceDetail)
| where DeviceDetailStr has deviceName
| extend ParsedDevice = parse_json(DeviceDetailStr)
| where ResultType == '0'
| top 1 by TimeGenerated desc
| project 
    TimeGenerated,
    DeviceName = tostring(ParsedDevice.displayName),
    DeviceOS = tostring(ParsedDevice.operatingSystem),
    TrustType = tostring(ParsedDevice.trustType),
    IsCompliant = tostring(ParsedDevice.isCompliant),
    IsManaged = tostring(ParsedDevice.isManaged),
    UserPrincipalName
```

---

### Q1. Device Sign-In Events (Who authenticated on this device)

**Note:** DeviceDetail is `dynamic` in SigninLogs but `string` in AADNonInteractiveUserSignInLogs. Query SigninLogs only for device context (interactive sign-ins contain device info). Do NOT use `union` with DeviceDetail filtering.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
SigninLogs
| where TimeGenerated between (start .. end)
| extend DeviceDetailStr = tostring(DeviceDetail)
| where DeviceDetailStr has deviceName
| extend ParsedDevice = parse_json(DeviceDetailStr)
| extend DeviceName = tostring(ParsedDevice.displayName)
| extend DeviceId = tostring(ParsedDevice.deviceId)
| extend DeviceOS = tostring(ParsedDevice.operatingSystem)
| extend DeviceTrustType = tostring(ParsedDevice.trustType)
| extend DeviceCompliant = tostring(ParsedDevice.isCompliant)
| summarize 
    SignInCount = count(),
    SuccessCount = countif(ResultType == '0'),
    FailureCount = countif(ResultType != '0'),
    UniqueUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10),
    Applications = make_set(AppDisplayName, 10),
    IPAddresses = make_set(IPAddress, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, DeviceOS, DeviceTrustType, DeviceCompliant
| order by SignInCount desc
```

### Q2. Device Security Alerts (SecurityAlert table)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has deviceName or CompromisedEntity has deviceName
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project 
    TimeGenerated,
    AlertName,
    AlertSeverity,
    Status,
    Description,
    ProviderName,
    Tactics,
    Techniques,
    CompromisedEntity,
    RemediationSteps
| order by TimeGenerated desc
| take 20
```

### Q3. Process Execution Events (Suspicious processes)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| where ActionType in ("ProcessCreated", "ProcessCreatedUsingWmiQuery")
| extend CommandLineLength = strlen(ProcessCommandLine)
| extend IsSuspicious = case(
    ProcessCommandLine has_any ("powershell", "cmd", "wscript", "cscript") and ProcessCommandLine has_any ("-enc", "-e ", "bypass", "hidden", "downloadstring", "invoke-expression", "iex"), true,
    ProcessCommandLine has_any ("certutil", "bitsadmin") and ProcessCommandLine has_any ("download", "transfer", "urlcache"), true,
    ProcessCommandLine has_any ("reg", "registry") and ProcessCommandLine has_any ("add", "delete") and ProcessCommandLine has_any ("run", "runonce"), true,
    FileName in~ ("mimikatz.exe", "procdump.exe", "psexec.exe", "cobaltstrike", "beacon.exe"), true,
    CommandLineLength > 500, true,
    false)
| summarize 
    ProcessCount = count(),
    SuspiciousCount = countif(IsSuspicious),
    UniqueProcesses = dcount(FileName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SampleCommands = make_set(ProcessCommandLine, 5)
    by FileName, FolderPath, AccountName, AccountDomain
| where SuspiciousCount > 0 or ProcessCount > 50
| order by SuspiciousCount desc, ProcessCount desc
| take 20
```

### Q4. Network Connection Events (Outbound connections)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private"
| summarize 
    ConnectionCount = count(),
    UniqueRemoteIPs = dcount(RemoteIP),
    UniqueRemotePorts = dcount(RemotePort),
    Protocols = make_set(Protocol, 5),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RemoteIP, RemotePort, RemoteUrl
| order by ConnectionCount desc
| take 30
```

### Q5. File Events (File creation/modification/deletion)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| where ActionType in ("FileCreated", "FileModified", "FileDeleted", "FileRenamed")
| extend FileExtension = tostring(split(FileName, ".")[-1])
| extend IsSuspicious = case(
    FileExtension in~ ("exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "hta", "scr", "pif"), true,
    FolderPath has_any ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp", "\\programdata\\", "\\users\\public\\"), true,
    false)
| summarize 
    FileEventCount = count(),
    SuspiciousCount = countif(IsSuspicious),
    CreatedCount = countif(ActionType == "FileCreated"),
    ModifiedCount = countif(ActionType == "FileModified"),
    DeletedCount = countif(ActionType == "FileDeleted"),
    UniqueFiles = dcount(FileName),
    FileExtensions = make_set(FileExtension, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by FolderPath, InitiatingProcessFileName
| where SuspiciousCount > 0 or FileEventCount > 100
| order by SuspiciousCount desc, FileEventCount desc
| take 20
```

### Q6. Registry Events (Registry modifications)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| extend IsPersistence = case(
    RegistryKey has_any ("\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce", "\\CurrentVersion\\RunServices"), true,
    RegistryKey has_any ("\\Policies\\Explorer\\Run", "\\Active Setup\\Installed Components"), true,
    RegistryKey has_any ("\\Image File Execution Options\\", "\\Winlogon\\", "\\BootExecute"), true,
    RegistryKey has_any ("\\Services\\", "\\Drivers\\"), true,
    false)
| summarize 
    RegistryEventCount = count(),
    PersistenceCount = countif(IsPersistence),
    UniqueKeys = dcount(RegistryKey),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RegistryKey, RegistryValueName, InitiatingProcessFileName
| where PersistenceCount > 0
| order by PersistenceCount desc, RegistryEventCount desc
| take 20
```

### Q7. Security Incidents Containing Device

```kql
let deviceName = '<DEVICE_NAME>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has deviceName or CompromisedEntity has deviceName
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, AlertSeverity, ProviderName, Tactics;
SecurityIncident
| where CreatedTime between (start .. end)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(tostring(Labels) has "Redirected")
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner relevantAlerts on $left.AlertId == $right.SystemAlertId
| extend ProviderIncidentUrl = tostring(AdditionalData.providerIncidentUrl)
| extend OwnerUPN = tostring(Owner.userPrincipalName)
| summarize 
    Title = any(Title),
    Severity = any(Severity),
    Status = any(Status),
    Classification = any(Classification),
    CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime),
    OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl),
    AlertCount = count(),
    Tactics = make_set(Tactics)
    by ProviderIncidentId
| order by LastModifiedTime desc
| take 10
```

### Q8. Device Inventory and Configuration

**Note:** RiskScore is NOT available via DeviceInfo. Use `ExposureLevel` and `SensorHealthState` as indicators.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceInfo
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| summarize arg_max(TimeGenerated, *) by DeviceId
| project 
    TimeGenerated,
    DeviceId,
    DeviceName,
    OSPlatform,
    OSVersion,
    OSBuild,
    OSArchitecture,
    LoggedOnUsers,
    MachineGroup,
    DeviceCategory,
    OnboardingStatus,
    SensorHealthState,
    ExposureLevel,
    IsAzureADJoined,
    IsInternetFacing,
    JoinType,
    PublicIP,
    DeviceManualTags,
    DeviceDynamicTags,
    RegistryDeviceTag
```

### Q9. Logon Events on Device

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
DeviceLogonEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| summarize 
    LogonCount = count(),
    SuccessCount = countif(ActionType == "LogonSuccess"),
    FailureCount = countif(ActionType == "LogonFailed"),
    UniqueAccounts = dcount(AccountName),
    LogonTypes = make_set(LogonType, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    RemoteIPs = make_set(RemoteIP, 10)
    by AccountName, AccountDomain, LogonType
| order by LogonCount desc
| take 20
```

### IP Enrichment via enrich_ips.py (External APIs)

**When to use:** ALWAYS — this is mandatory (see Critical Workflow Rules #10). See [Secrets Management](#secrets-management-api-tokens) for token configuration.

**Execution via RunInTerminal:**
```bash
python3 tmp/computer-investigation/enrich_ips.py <ip1> <ip2> <ip3>
```

**Output:** JSON file in `temp/ip_enrichment_<timestamp>.json` + text report in `temp/ip_enrichment_<timestamp>.txt`

---

### Q10. Threat Intelligence IP Matches (Device Network Traffic)

**Performance notes:** ThreatIntelIndicators can be large. Filter `IsActive`/`ValidUntil` **before** string transformations — reduce data first, transform later.

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let deviceName = '<DEVICE_NAME>';
let device_ips = DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName startswith deviceName
| where RemoteIPType != "Private"
| distinct RemoteIP;
ThreatIntelIndicators
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| where tostring(split(ObservableKey, ":")[0]) in ("ipv4-addr", "ipv6-addr", "network-traffic")
| where ObservableValue in (device_ips)
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| summarize arg_max(TimeGenerated, *) by ObservableValue
| project 
    TimeGenerated,
    IPAddress = ObservableValue,
    ThreatDescription = Description,
    Confidence,
    ValidUntil,
    IsActive
| order by Confidence desc
| take 20
```

### Q11. KQL-Based IP Context Analysis (Supplement to enrich_ips.py)

**When to use:** Always run as a supplement in Batch 2. This provides workspace-specific context (how many users share an IP, failure patterns) that external APIs cannot provide. This does NOT replace `enrich_ips.py`.

```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let ip_user_diversity = 
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where IPAddress in (target_ips)
    | summarize 
        TotalUsers = dcount(UserPrincipalName),
        UserList = make_set(UserPrincipalName, 5),
        TotalSignIns = count(),
        UniqueApps = dcount(AppDisplayName),
        TopApps = make_set(AppDisplayName, 3),
        Locations = make_set(Location, 3)
        by IPAddress;
let ip_failure_patterns =
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where IPAddress in (target_ips)
    | where ResultType != '0'
    | summarize 
        FailedUsers = dcount(UserPrincipalName),
        TotalFailures = count(),
        FailureCodes = make_set(ResultType, 5)
        by IPAddress;
ip_user_diversity
| join kind=leftouter ip_failure_patterns on IPAddress
| extend RiskIndicator = case(
    TotalUsers > 10 and TotalFailures > 50, "🔴 High — shared IP with many failures (possible brute-force source)",
    TotalUsers > 5 and TotalFailures > 20, "🟠 Medium — shared IP with notable failures",
    TotalUsers == 1 and TotalFailures == 0, "🟢 Low — dedicated IP, no failures from other users",
    TotalUsers == 1 and TotalFailures > 0, "🟡 Low — dedicated IP with some failures",
    TotalUsers > 1 and TotalFailures == 0, "🟢 Low — shared corporate/VPN IP, no failures",
    "🟡 Requires review")
| extend IPType = case(
    TotalUsers > 5, "Shared (corporate/VPN/proxy)",
    TotalUsers > 1, "Small group (team/office)",
    "Dedicated (individual)")
| project IPAddress, IPType, TotalUsers, TotalSignIns, UniqueApps, Locations,
    FailedUsers = coalesce(FailedUsers, 0), TotalFailures = coalesce(TotalFailures, 0),
    FailureCodes = coalesce(FailureCodes, dynamic([])),
    RiskIndicator, UserList, TopApps
| order by TotalFailures desc, TotalUsers desc
```

**Interpretation guidance:**
- **Dedicated IP (1 user):** Likely personal or home connection. Low risk if no failures.
- **Small group (2-5 users):** Likely office or small team. Normal.
- **Shared (>5 users):** Corporate VPN, proxy, or NAT. Check failure patterns.
- **Azure IP ranges** (4.x.x.x, 13.x.x.x, 20.x.x.x, 40.x.x.x, 52.x.x.x, 104.x.x.x, 168.x.x.x, 172.x.x.x): Often Azure datacenter IPs. Failures may be automated token refresh, not attacks.

---

## Entra ID Device Data Collection

### Method 1: Azure CLI (Primary)

Use Azure CLI (`az rest`) or `RunAzCliReadCommands` tool to call Microsoft Graph API. This is the preferred method when Graph API permissions are available.

See `get-device-context-via-cli.md` for the complete step-by-step reference with all 5 calls.

**Summary of calls** (Step 1 must complete before Steps 2–5):

| Step | API Call | Key Output |
|------|----------|------------|
| 1 | `az rest --method GET --url ".../v1.0/devices?$filter=displayName eq '...'&$select=..."` | Device IDs, OS, trust type, compliance |
| 2 | `az rest --method GET --url ".../devices/<OBJECT_ID>/registeredOwners"` | Device owners |
| 3 | `az rest --method GET --url ".../devices/<OBJECT_ID>/registeredUsers"` | Registered users |
| 4 | `az rest --method GET --url ".../deviceManagement/managedDevices?$filter=..."` | Intune details (optional) |
| 5 | `az rest --method GET --url ".../informationProtection/bitlocker/recoveryKeys?$filter=..."` | BitLocker keys (optional) |

> **⛔ CRITICAL — Tool Selection:**
> - **ALWAYS** use `RunAzCliReadCommands` for ALL `az rest --method GET` calls.
> - **NEVER** use `RunAzCliWriteCommands` — it triggers an OBO fallback flow that fails without Delegated permissions, causing 403 errors even when Application permissions are correctly assigned.
> - **NEVER** use `RunInTerminal` with `az` commands — the `az` binary may not be in the shell PATH.

> **If Step 1 returns 403:** Stop Graph API calls immediately. Proceed to Method 2.

### Method 2: KQL Fallback (When Graph is Unavailable)

Run Q0a and Q0b in parallel (see [Q0 queries](#q0-kql-based-device-context-extraction-graph-api-fallback)).

DeviceInfo provides most of the critical operational data (sensor health, exposure level, internet-facing status, tags) that Graph API does NOT provide. Always run Q0a/Q8 even when Graph API succeeds.

---

## Markdown Report Template

When outputting to markdown file (Mode 2), use this template. Populate ALL sections with actual query data. For sections with no data, use the explicit absence confirmation pattern.

**Filename:** `reports/computer-investigations/computer_investigation_<device_name>_YYYYMMDD_HHMMSS.md`

````markdown
# Computer Security Investigation Report

**Generated:** YYYY-MM-DD HH:MM UTC
**Workspace:** <workspace_name>
**Device:** `<DEVICE_NAME>`
**OS:** <operating_system> <os_version>
**Trust Type:** <Entra Joined / Hybrid Joined / Entra Registered> (`<trustType>`)
**Compliance:** <Compliant/Non-Compliant/Unknown> | **Managed:** <Yes/No/Unknown>
**Investigation Period:** <start_date> → <end_date> (<N> days)
**Investigation Type:** <Standard (7d) / Quick (1d) / Comprehensive (30d)>
**Data Sources:** DeviceInfo, DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, SigninLogs, SecurityAlert, SecurityIncident, ThreatIntelIndicators
**Device Context Method:** <Graph API / KQL Fallback / Mixed>
**Data Gaps:** Software Inventory (TVM), Vulnerability Assessment (TVM), Defender riskScore (MDE API)

---

## Executive Summary

<2-4 sentence summary: overall device risk level, key findings, most significant alerts, and primary recommendation. Ground every claim in evidence from query results.>

**Overall Risk Level:** 🔴 CRITICAL / 🔴 HIGH / 🟠 MEDIUM / 🟡 LOW / 🟢 INFORMATIONAL

---

## Device Profile

| Property | Value |
|----------|-------|
| **Device Name** | `<device_name>` |
| **OS** | <os_platform> <os_version> (<os_build>) |
| **Architecture** | <os_architecture> |
| **Trust Type** | <Entra Joined / Hybrid Joined / Entra Registered> |
| **Compliant** | 🟢 Yes / 🔴 No / ❓ Unknown |
| **Managed** | 🟢 Yes / 🔴 No / ❓ Unknown |
| **Manufacturer** | <manufacturer or "Unknown (Graph unavailable)"> |
| **Model** | <model or "Unknown (Graph unavailable)"> |
| **Registration Date** | <datetime or "Unknown (Graph unavailable)"> |

### Defender for Endpoint Status (from DeviceInfo)

| Property | Value |
|----------|-------|
| **Onboarding Status** | 🟢 Onboarded / 🔴 Not Onboarded |
| **Sensor Health** | 🟢 Active / 🟠 Inactive / 🔴 Misconfigured |
| **Exposure Level** | 🔴/🟠/🟡/🟢 <None/Low/Medium/High> |
| **Internet Facing** | 🔴 Yes / 🟢 No |
| **Public IP** | <ip_address> |
| **Machine Group** | <group_name> |
| **Device Tags** | <comma-separated list from DeviceManualTags + DeviceDynamicTags, or "None"> |
| **Defender riskScore** | ❓ Not available (requires MDE API) |

### Device Owners & Registered Users

<If owners/users found (from Graph API):>

| User | UPN | Role |
|------|-----|------|
| <display_name> | <upn> | Owner / Registered User |

<If Graph unavailable:>
ℹ️ Device owner and registered user data requires Graph API access (`Device.Read.All`).

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **Security Alerts** | <count> (Critical: <n>, High: <n>, Medium: <n>, Low: <n>) |
| **Security Incidents** | <count> (Open: <n>, Closed: <n>) |
| **Logged-On Users** | <count> unique users |
| **Sign-ins from Device** | <count> (Success: <n>, Failed: <n>) |
| **Suspicious Processes** | <count> flagged |
| **Network Connections** | <count> external IPs |
| **TI Matches** | <count> threat intel hits |
| **Vulnerabilities** | ❓ Not available (TVM table not in Log Analytics) |
| **End-of-Support Software** | ❓ Not available (TVM table not in Log Analytics) |

---

## Security Alerts

<If alerts found:>

| Time | Alert Name | Severity | Status | Provider | Tactics | Compromised Entity |
|------|-----------|----------|--------|----------|---------|---------------------|
| <datetime> | <alert_name> | 🔴/🟠/🟡 <severity> | <status> | <provider> | <tactics> | <entity> |

**Alert Summary:**
- <X> total alerts (<breakdown by severity>)
- <Brief description of most critical alert(s)>
- Remediation steps: <summary of recommended actions from alert data>

<If no alerts:>
✅ No security alerts detected for this device in the investigation period.
- Checked: SecurityAlert filtered by device name (0 matches)

---

## Security Incidents

<If incidents found:>

| ID | Title | Severity | Status | Classification | Created | Owner | Alerts | Link |
|----|-------|----------|--------|----------------|---------|-------|--------|------|
| <provider_incident_id> | <title> | 🔴/🟠/🟡 <severity> | <New/Active/Closed> | <TP/FP/BP/—> | <date> | <owner_upn> | <count> | [View](<url>) |

<If no incidents:>
✅ No security incidents involving this device in the investigation period.

---

## Logged-On Users

<If users found from DeviceLogonEvents:>

| Account | Domain | Logon Type | Logon Count | Success | Failed | First Seen | Last Seen |
|---------|--------|------------|:-----------:|:-------:|:------:|------------|-----------|
| <account_name> | <domain> | <Interactive/RemoteInteractive/Network/etc.> | <count> | <count> | <count> | <date> | <date> |

**User Analysis:**
- <X> unique accounts authenticated on this device
- <Summary of logon patterns — expected vs unexpected accounts, after-hours logons, remote IPs>

<If no logon data:>
✅ No logon events detected for this device in the investigation period.

---

## Sign-in Activity (From Device)

<If sign-in events found:>

| Device Name | OS | Trust Type | Compliant | Users | Applications | IPs | Sign-ins | Success | Failed | First Seen | Last Seen |
|-------------|-----|------------|-----------|:-----:|:------------:|:---:|:--------:|:-------:|:------:|------------|-----------|
| <name> | <os> | <trust> | 🟢/🔴 | <count> | <count> | <count> | <count> | <count> | <count> | <date> | <date> |

**Top Users:** <list of UPNs>
**Top Applications:** <list of apps>
**Top IPs:** <list of IPs>

<If no sign-in events:>
✅ No sign-in events found for this device in the investigation period.

---

## Process Activity

<If suspicious processes found:>

| Process | Path | Account | Process Count | Suspicious | Sample Command Lines |
|---------|------|---------|:------------:|:----------:|----------------------|
| <filename> | <folder_path> | <account_name> | <count> | 🔴 <count> | <truncated_command> |

**Process Analysis:**
- <X> suspicious process executions detected
- <Summary of suspicious patterns — encoded commands, LOLBins, credential dumping tools, long command lines>

<If no suspicious processes:>
✅ No suspicious process activity detected on this device in the investigation period.

---

## Network Connections

<If external connections found:>

| Remote IP | Remote Port | URL | Connections | Protocols | Initiating Processes | First Seen | Last Seen |
|-----------|:-----------:|-----|:-----------:|-----------|----------------------|------------|-----------|
| <ip> | <port> | <url> | <count> | <protocols> | <process_list> | <date> | <date> |

**Network Summary:**
- <X> unique external IPs contacted
- <Top initiating processes>

<If no external connections:>
✅ No external network connections detected for this device in the investigation period.

### Threat Intelligence Matches

<If TI matches found:>

| IP Address | Threat Description | Confidence | Valid Until | Active |
|------------|-------------------|:----------:|------------|:------:|
| <ip> | <description> | <score> | <date> | ✅/❌ |

<If no TI matches:>
✅ No threat intelligence matches found for device network traffic.

---

## File Activity

<If suspicious file events found:>

| Folder Path | Initiating Process | Total Events | Suspicious | Created | Modified | Deleted | Extensions | First Seen | Last Seen |
|-------------|-------------------|:------------:|:----------:|:-------:|:--------:|:-------:|------------|------------|-----------|
| <path> | <process> | <count> | 🔴 <count> | <count> | <count> | <count> | <ext_list> | <date> | <date> |

<If no suspicious file events:>
✅ No suspicious file activity detected on this device in the investigation period.

---

## Registry Modifications

<If persistence-related registry events found:>

| Registry Key | Value Name | Initiating Process | Total Events | Persistence | First Seen | Last Seen |
|-------------|------------|-------------------|:------------:|:-----------:|------------|-----------|
| <key> | <value_name> | <process> | <count> | 🔴 <count> | <date> | <date> |

<If no persistence registry events:>
✅ No persistence-related registry modifications detected on this device in the investigation period.

---

## IP Intelligence

<Table of external IPs from network connections and sign-in data.>

| IP Address | IP Type | Users | Location | Sign-ins | Failures | Risk |
|------------|---------|-------|----------|----------|----------|------|

### External IP Enrichment (enrich_ips.py)

<If run: table with IP, City, Country, Org, AbuseIPDB Score, VPN/Proxy/Tor flags, Shodan ports/CVEs>

<If not run — THIS SHOULD NEVER HAPPEN:>
⚠️ enrich_ips.py was not executed — this is a workflow violation. See Critical Workflow Rules #10.

---

## Data Gaps

The following data points are NOT available in this environment (require Advanced Hunting or MDE API):

| Data | Source Required | Impact |
|------|----------------|--------|
| Software Inventory | DeviceTvmSoftwareInventory (Advanced Hunting) | Cannot assess installed software or end-of-support status |
| Vulnerability Assessment | DeviceTvmSoftwareVulnerabilities (Advanced Hunting) | Cannot assess CVEs on device |
| Defender riskScore | MDE API (GetDefenderMachine) | Using ExposureLevel from DeviceInfo as proxy |
| Automated Investigations | MDE API (ListDefenderInvestigations) | Cannot track automated investigation status |
| Remediation Activities | MDE API (ListDefenderRemediationActivities) | Cannot track remediation task progress |

---

## Risk Assessment

### Risk Score: <XX>/100 — 🔴 CRITICAL / 🔴 HIGH / 🟠 MEDIUM / 🟡 LOW / 🟢 INFORMATIONAL

### Risk Factors

| Factor | Finding |
|--------|---------|
| 🔴/🟠/🟡 **<Factor Name>** | <Evidence-grounded finding with specific numbers> |

### Mitigating Factors

| Factor | Finding |
|--------|---------|
| 🟢 **<Factor Name>** | <Evidence-grounded finding with specific numbers> |

---

## Recommendations

### Critical Actions
<Numbered list of critical actions with evidence. Only include if critical findings exist.>

### High Priority Actions
<Numbered list of high-priority actions with evidence.>

### Monitoring Actions (14-Day Follow-Up)
<Bulleted list of ongoing monitoring recommendations.>

---

## Appendix: Query Details

| # | Query | Table(s) | Records | Status |
|---|-------|----------|--------:|--------|
| Q0 | Device Context (KQL) | DeviceInfo, SigninLogs | <n> | ✓ / Skipped (Graph OK) |
| Q1 | Device Sign-In Events | SigninLogs | <n> | ✓ |
| Q2 | Security Alerts | SecurityAlert | <n> | ✓ |
| Q3 | Process Events | DeviceProcessEvents | <n> | ✓ |
| Q4 | Network Connections | DeviceNetworkEvents | <n> | ✓ |
| Q5 | File Events | DeviceFileEvents | <n> | ✓ |
| Q6 | Registry Events | DeviceRegistryEvents | <n> | ✓ |
| Q7 | Security Incidents | SecurityAlert, SecurityIncident | <n> | ✓ |
| Q8 | Device Inventory | DeviceInfo | <n> | ✓ |
| Q9 | Logon Events | DeviceLogonEvents | <n> | ✓ |
| Q10 | Threat Intelligence | ThreatIntelIndicators, DeviceNetworkEvents | <n> | ✓ |
| Q11 | IP Context (KQL) | SigninLogs | <n> | ✓ |
| — | Graph API (az rest) | Microsoft Graph | — | ✓ / ❌ 403 |
| — | enrich_ips.py | External APIs | <n> IPs | ✓ / ⚠️ No tokens |

*Query definitions: see the Sample KQL Queries section in this SKILL.md file.*

---

**Investigation Timeline:**
- [MM:SS] ✓ Phase 1: Device context retrieval (<X>s)
- [MM:SS] ✓ Phase 2: Parallel data collection (<X>s)
- [MM:SS] ✓ IP Enrichment (<X>s)
- [MM:SS] ✓ Phase 4: Report generation (<X>s)
- **Total Investigation Time:** <duration>
````

### Markdown Report Authoring Guidelines

1. **Populate every section** — even if empty. Use `✅ No <X> detected...` for empty sections.
2. **Never invent data** — every number must come from a query result.
3. **Risk assessment is dynamic** — calculate from available data (see Risk Assessment Framework).
4. **Document data gaps** — always note when data is unavailable due to missing tools or tables.
5. **Emoji consistency:** 🔴 high risk, 🟠 medium, 🟡 low, 🟢 mitigating/positive, ✅ clean, ⚠️ action needed, ❓ data unavailable.
6. **Query appendix** — include record counts but NOT full KQL text. Reference the SKILL.md query numbers.
7. **Trust type context** — always reference the device trust type in the Executive Summary and Risk Assessment.

---

## JSON Export Structure

Export results to a single JSON file with these required keys:

```json
{
  "device_name": "WORKSTATION-001",
  "device_id_defender": "<DEFENDER_DEVICE_ID>",
  "device_id_entra_object": "<ENTRA_OBJECT_ID>",
  "device_id_entra_device": "<ENTRA_DEVICE_ID>",
  "device_type": "HybridJoined",
  "device_context_method": "graph_api | kql_fallback | mixed",
  "investigation_date": "2026-05-30",
  "start_date": "2026-05-23",
  "end_date": "2026-06-01",
  "timestamp": "20260530_143200",
  
  "device_profile": {
    "displayName": "WORKSTATION-001",
    "operatingSystem": "Windows",
    "operatingSystemVersion": "10.0.22621.3007",
    "trustType": "ServerAd",
    "isCompliant": true,
    "isManaged": true,
    "manufacturer": "Dell Inc.",
    "model": "Latitude 5520"
  },
  
  "defender_status": {
    "onboardingStatus": "Onboarded",
    "sensorHealthState": "Active",
    "exposureLevel": "Low",
    "isInternetFacing": false,
    "publicIP": "203.0.113.42",
    "machineGroup": "Default",
    "deviceTags": []
  },
  
  "device_owners": [],
  "device_users": [],
  "signin_events": [],
  "security_alerts": [],
  "process_events": [],
  "network_events": [],
  "file_events": [],
  "registry_events": [],
  "incidents": [],
  "logon_events": [],
  "threat_intel_matches": [],
  "ip_context": [],
  "ip_enrichment": [],
  
  "data_gaps": [
    "software_inventory (DeviceTvmSoftwareInventory — Advanced Hunting only)",
    "vulnerabilities (DeviceTvmSoftwareVulnerabilities — Advanced Hunting only)",
    "defender_riskScore (MDE API only)",
    "automated_investigations (MDE API only)",
    "remediation_activities (MDE API only)"
  ],
  
  "summary": {
    "total_alerts": 0,
    "critical_alerts": 0,
    "high_alerts": 0,
    "medium_alerts": 0,
    "low_alerts": 0,
    "unique_logged_on_users": 0,
    "suspicious_processes": 0,
    "threat_intel_hits": 0,
    "external_ips_contacted": 0
  }
}
```

---

## Error Handling

| Issue | Solution |
|-------|----------|
| **Monitor MCP query fails** | Verify workspace GUID from agent settings; fallback to `az monitor log-analytics query` via CLI |
| **`az rest` returns 403 for Graph** | Graph API permissions not granted — proceed with KQL fallback (Q0). Do NOT retry. |
| **`az` not in shell PATH** | Use `RunAzCliReadCommands` tool if available; otherwise note as tool limitation |
| **Table "Failed to resolve"** | Table not connected to workspace; skip query and note the gap |
| **DeviceName query returns empty** | Use `startswith` instead of `=~` — DeviceName often contains FQDN (e.g., `hostname.domain.com`) |
| **SigninLogs DeviceDetail fails with union** | DeviceDetail is `dynamic` in SigninLogs but `string` in AADNonInteractiveUserSignInLogs — query SigninLogs only |
| **No process events** | Device may not be onboarded to Defender for Endpoint — check DeviceInfo for OnboardingStatus |
| **ThreatIntelIndicators empty** | ThreatIntelligence connector may not be configured — skip Q10, rely on Q11 |
| **Trust type is null** | Device may be partially registered — check JoinType in DeviceInfo as alternative |
| **Query timeout** | Reduce date range or add `| take N` |
| **⛔ Used `RunAzCliWriteCommands` for Graph GET** | **NEVER** use `RunAzCliWriteCommands` for `az rest --method GET` calls. It has a MI → OBO fallback: MI attempts direct auth → if 403 → falls back to On-Behalf-Of flow. OBO fails because only Application permissions are configured, not Delegated. **Always use `RunAzCliReadCommands`** which authenticates via MI directly. |
| **Key Vault `ForbiddenByConnection`** | Key Vault public access may be disabled. Ask user to temporarily enable public access or add Azure Services firewall bypass. Use `az rest --resource "https://vault.azure.net"` via `RunAzCliReadCommands` (NOT `az keyvault` which is unsupported). |
| **`az keyvault` subcommands fail** | `az keyvault` is NOT supported by `RunAzCliReadCommands`. Use `az rest --method GET --url "https://<vault>.vault.azure.net/secrets/<name>?api-version=7.4" --resource "https://vault.azure.net"` instead. |
| **IP enrichment skipped** | `enrich_ips.py` is MANDATORY (see Critical Workflow Rules #10). If no API tokens: try Key Vault → ask user → run with zero tokens (Shodan InternetDB free). Never skip to Q11-only. |

### Required Field Defaults

```json
{
  "trustType": "Workplace",
  "isCompliant": false,
  "isManaged": false,
  "exposureLevel": "Unknown",
  "sensorHealthState": "Unknown"
}
```

---

## Device Trust Type Analysis

### Security Implications by Trust Type

#### Entra Joined (`trustType: AzureAd`)
- **Pros**: Full cloud management, Conditional Access enforcement, BitLocker key escrow
- **Cons**: No access to on-premises resources without VPN/Azure AD Application Proxy
- **Investigation Focus**: Cloud sign-in patterns, Intune compliance, Conditional Access logs

#### Hybrid Joined (`trustType: ServerAd`)
- **Pros**: Access to both cloud and on-premises resources, GPO support
- **Cons**: Complex identity, dual token handling, potential for on-prem compromise to affect cloud
- **Investigation Focus**: BOTH cloud and on-premises sign-ins, logon events, lateral movement

#### Entra Registered (`trustType: Workplace`)
- **Pros**: BYOD support, minimal device management overhead
- **Cons**: Limited compliance enforcement, device not fully controlled
- **Investigation Focus**: User activity on device, data access patterns, potential data exfiltration

---

## Risk Assessment Framework

### Device Risk Scoring (Adapted — No MDE riskScore)

| Factor | Weight | High Risk Indicators |
|--------|--------|---------------------|
| Active Alerts | 30% | Any Critical/High severity alerts |
| Exposure Level (DeviceInfo) | 20% | "High" exposure level |
| Compliance Status | 20% | Non-compliant, not managed |
| Sign-in / Logon Anomalies | 15% | Multiple unexpected users, unusual hours, new IPs |
| Network Activity | 15% | TI matches, high external connection volume, suspicious processes initiating connections |

### Risk Level Determination

- **Critical**: Active critical alert OR active exploitation indicators (suspicious process + TI match)
- **High**: High severity alerts OR high exposure level OR compromised user logged on
- **Medium**: Medium alerts OR non-compliance OR suspicious process activity
- **Low**: Minor alerts, device is compliant and healthy sensor
- **Informational**: No alerts, compliant, healthy sensor

> **Note:** Without TVM data (software inventory, vulnerabilities), the vulnerability factor is excluded from scoring. This may underestimate risk for devices with unpatched critical CVEs. Document this limitation in the report.

---

## Evidence-Based Analysis Rules

Base ALL findings strictly on data returned by queries. Never invent, assume, or extrapolate.

| Scenario | Required Action |
|----------|----------------|
| Query returns 0 results | State: "✅ No [X] found in [time range]" |
| Field is null/missing | Report as "Unknown" — never fabricate |
| Partial data available | State what WAS found and what COULD NOT be verified |
| Graph API unavailable | State: "ℹ️ [field] requires Graph API access ([permission])" |
| TVM data unavailable | State: "❓ Not available (requires Advanced Hunting)" |

### Risk Level Evidence

| Risk Level | Evidence Required |
|------------|-------------------|
| **High** | ≥2 concrete findings (e.g., "3 critical alerts + suspicious encoded PowerShell") |
| **Medium** | ≥1 concrete finding with context (e.g., "Non-compliant device with high exposure") |
| **Low** | Explanation despite investigation (e.g., "Sensor active, no alerts, compliant") |
| **Informational** | Cite what was checked: "No alerts, no suspicious processes, compliant device" |

---

## Remediation Output Policy

Never generate executable commands that change tenant state. Use portal navigation steps instead.

- ✅ Portal deep links with navigation steps
- ✅ Natural-language instructions
- ✅ Read-only verification KQL
- ❌ State-changing commands (`Remove-*`, `Set-*`, `Revoke-*`)
- ❌ Graph API write calls
- ❌ `az` CLI write operations

---

*Last Updated: 2026-06-01*
