---
name: ioc-investigation
description: >
  IoC (Indicator of Compromise) investigation skill for environments with Azure Monitor MCP
  (Log Analytics workspace queries) and Azure CLI access — currently without
  Sentinel Data Lake MCP, Sentinel Triage MCP, or Microsoft Graph MCP
  (not yet connectable to Azure SRE Agent; direct API access to Sentinel Data Lake and Microsoft Graph not yet implemented).
  KQL queries run against Log Analytics tables through the Azure Monitor MCP tool.
  MDE API calls (custom IOC list, TVM) are executed via RunAzCliReadCommands (az rest).
  3rd-party IP enrichment is provided by enrich_ips.py (ipinfo.io, vpnapi.io, AbuseIPDB, Shodan).
threat_pulse_domains: [identity, endpoint, email, exposure]
drill_down_prompt: 'Investigate IoC {entity} — threat intel, organizational exposure, affected devices'
---

# IoC (Indicator of Compromise) Investigation — Monitor MCP + Azure CLI

## Purpose

This skill performs comprehensive security investigations on Indicators of Compromise (IoCs) including:
- **IP Addresses**: Network connections, threat intel matches, geographic analysis, organizational exposure
- **DNS Domains**: Domain reputation, connection events, email-based threats, URL analysis
- **URLs**: URL reputation, phishing detection, email delivery, browser activity
- **File Hashes**: Malware analysis, file prevalence, related alerts, affected devices

The investigation correlates IoCs with threat intelligence, identifies associated CVEs, and enumerates organizational assets affected by those vulnerabilities.

**Environment:** This skill operates in a constrained environment where:

- ✅ **Azure Monitor MCP tool** is available (`monitor-client_monitor_workspace_log_query`) for KQL queries against Log Analytics
- ✅ **`RunAzCliReadCommands` tool** is available for Azure CLI read operations (including `az rest` for MDE API and Graph API)
- ✅ **KQL Search MCP** (`mcp_kql-search-mc_*`) is available for schema validation and query examples
- ✅ **Microsoft Learn MCP** (`mcp_microsoft_lea_*` / `mcp_microsoft_le2_*`) is available for documentation
- ✅ **Azure MCP Server** (`mcp_azure_mcp_ser_*`) is available for Azure resource management
- ✅ **`enrich_ips.py`** is included in this skill folder for 3rd-party IP enrichment
- ❌ **Sentinel Data Lake MCP** — not integrated (no `query_lake`, `list_sentinel_workspaces`, `search_tables`)
- ❌ **Sentinel Triage MCP** — not integrated (no `RunAdvancedHuntingQuery`, `GetDefenderIpAlerts`, `GetDefenderFileInfo`, `ListDefenderIndicators`, etc.)
- ❌ **Microsoft Graph MCP** — not integrated (no `microsoft_graph_get`, `suggest_queries`)

> **Why these MCP servers are absent:** Sentinel Data Lake MCP, Sentinel Triage MCP, and Microsoft Graph MCP cannot currently be connected to Azure SRE Agent. This does **not** mean the underlying data is inaccessible — the data exposed by these servers (Sentinel Data Lake, Defender XDR / Advanced Hunting, Microsoft Graph) can be reached via direct API calls. However, direct API access to Sentinel Data Lake and Microsoft Graph as a replacement for these MCP servers has not yet been studied and implemented in this skill.

**Data sources (Log Analytics via KQL):** ThreatIntelIndicators (new STIX table — ⚠️ NOT legacy ThreatIntelligenceIndicator), DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents, AlertEvidence, AlertInfo, SecurityAlert, SigninLogs, AADNonInteractiveUserSignInLogs, EmailUrlInfo.

**Data sources (MDE API via `az rest`):** Custom IOC list, IP alerts/statistics, File info/stats/alerts/machines, CVE→affected devices (TVM).

**NOT directly available (require Advanced Hunting in portal):** DeviceTvmSoftwareVulnerabilities, DeviceTvmSoftwareInventory.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Prerequisites](#prerequisites)**
3. **[Environment Configuration](#environment-configuration)**
4. **[Phase 0: Investigation Cache Check](#phase-0-investigation-cache-check-mandatory)** — Cache reuse logic
5. **[Investigation Types](#available-investigation-types)** - By IoC type
6. **[Quick Start](#quick-start-tldr)** - 5-step investigation pattern
7. **[Execution Workflow](#execution-workflow)** - Complete process
8. **[KQL Execution Reference](#kql-execution-reference)** - How to run queries
9. **[Sample KQL Queries](#sample-kql-queries)** - Validated query patterns
10. **[MDE API via CLI](#mde-api-via-cli)** - Defender API calls via `az rest`
11. **[JSON Export Structure](#json-export-structure)** - Required fields
12. **[Error Handling](#error-handling)** - Troubleshooting guide

**Investigation shortcuts:**
- **Suspicious IP from spray/brute-force**: **Q2** (network connections) → **Q11** (sign-in analysis) → **Q8** (alert evidence) → **Q1** (TI match)
- **IP from user risk event**: **Q11** (sign-in analysis) → **Q2** (device connections) → **Q9** (security alerts) → `enrich_ips.py`
- **Phishing domain/URL**: **Q4** (DNS/HTTP connections) → **Q6** (email delivery) → **Q8** (alert evidence) → **Q1** (TI match)
- **File hash from incident**: **Q7** (file events across all tables) → **Q9** (security alerts) → **MDE-IOC** (custom indicator check) → **Q12** (CVE extraction)
- **IoC organizational exposure**: **Q2/Q4** (affected devices) → **Q9** (alert correlation) → **Q12** (CVEs from alerts)

> **⛔ Shortcut Default Rule:** When a matching shortcut exists for the investigation context, **use it** — don't run the full workflow. Only run the full query set when the user explicitly requests "full investigation", "comprehensive", or "deep dive". Shortcuts render only the report sections relevant to their query chain (plus Executive Summary and Recommendations, always).

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY IoC investigation:**

1. **ALWAYS identify the IoC type FIRST** (IP, Domain, URL, or File Hash)
2. **ALWAYS normalize the IoC** (lowercase domains, validate IP format, extract domain from URL)
3. **ALWAYS complete Phase 0 (Cache Check) after normalization** — Before any data collection, check for cached investigation results. See Phase 0 for full logic.
4. **ALWAYS calculate date ranges correctly** (use current date from context — see Date Range section)
5. **ALWAYS track and report time after each major step** (mandatory)
6. **ALWAYS run independent queries in parallel** (drastically faster execution)
7. **ALWAYS use `create_file` for JSON export** (NEVER use PowerShell terminal commands)
8. **ALWAYS use Azure Monitor MCP for KQL execution** (see KQL Execution Reference)
9. **ALWAYS use `RunAzCliReadCommands` for MDE API calls** (see defender-api-via-cli.md)

---

## Prerequisites

| Dependency | Required | Fallback | Notes |
|------------|----------|----------|-------|
| **Azure Monitor MCP** (`monitor-client_monitor_workspace_log_query`) | ✅ Yes | None — core dependency | Must be configured and connected to the target Log Analytics workspace |
| **`RunAzCliReadCommands` tool** | ⚠️ Optional | KQL-only mode | Used for MDE API calls via `az rest`. If unavailable, skip MDE API enrichment |
| **KQL Search MCP** (`mcp_kql-search-mc_*`) | ⚠️ Optional | Use queries from this skill directly | Schema validation, query examples |
| **Microsoft Learn MCP** (`mcp_microsoft_lea_*`) | ⚠️ Optional | N/A | Documentation reference |
| **Python 3.x** | ⚠️ Optional | Q13 (KQL IP context) | `enrich_ips.py` requires Python + API tokens. If unavailable, use Q13 KQL fallback |

---

## Skill Files

| File | Purpose |
|------|---------|
| `SKILL.md` | This file — skill instructions, KQL queries, workflow |
| `enrich_ips.py` | 3rd-party IP enrichment (ipinfo.io, vpnapi.io, AbuseIPDB, Shodan) |
| `generate_html_report.py` | HTML report generator — reads JSON export, produces styled HTML |
| `defender-api-via-cli.md` | MDE API reference for `az rest` calls |

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/ioc-investigation/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/ioc-investigation/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("ioc-investigation", "<filename>") from Builder
   → CreateFile("tmp/ioc-investigation/<filename>", <content>)
   → Repeat for ALL companion files referenced by the script
```

**Rules:**
- When a file is found in `codeRefs/`, execute it directly from there — do NOT copy it to `tmp/`.
- When materializing from Builder (step 3), materialize ALL companion files the script depends on, not just the script itself.
- This cascade applies to every file listed in the Skill Files table above.

---

## Output Modes

| Mode | When | What |
|------|------|------|
| **Inline** (DEFAULT — ALWAYS) | Every invocation | Present all findings, threat intel, activity, risk assessment inline in chat |
| **Markdown file** | Only if the user **explicitly** requests | Save investigation report as `.md` file |
| **HTML report** | Only if the user **explicitly** requests | Generate **one HTML report per IoC** investigated. Present only the HTML report links to the user |
| **JSON export** | **Internal only** — created automatically as intermediate step for HTML generation | Save `ioc_investigation_*.json` to `temp/`. **NEVER show JSON file links to the user** unless they explicitly ask for JSON export |

> **Rule:** Always start with inline presentation. Never skip inline output. The other modes are additive, triggered only by explicit user request.
> **Rule:** JSON files are internal artifacts consumed by `generate_html_report.py`. Do NOT present JSON links in the final output — only present HTML report links.

### HTML Report — Conditional Resolution (codeRefs-first)

When the user requests an HTML report:

1. Export investigation data to JSON: `temp/ioc_investigation_{type}_{value}_{ts}.json`
2. Resolve `generate_html_report.py` via the [File Resolution cascade](#file-resolution-coderefs-first):
   - Check `codeRefs/sec-sre-ag/ioc-investigation/generate_html_report.py` → if found, use that path.
   - Else check `tmp/ioc-investigation/generate_html_report.py` → if found, use that path.
   - Else: `read_skill_file("ioc-investigation", "generate_html_report.py")` → `CreateFile("tmp/ioc-investigation/generate_html_report.py", <content>)`
3. Execute: `python3 <resolved_path>/generate_html_report.py temp/ioc_investigation_*.json --output-dir reports/ioc-investigation/`

Do NOT resolve the script unless the user explicitly requests an HTML report.

#### Multi-IoC HTML Reports

When multiple IoCs are investigated together (e.g., an IP + a domain), **generate one separate JSON export and one separate HTML report per IoC**.

- Each IoC gets its own `temp/ioc_investigation_{type}_{value}_{ts}.json` file
- Each IoC gets its own HTML report via `generate_html_report.py`
- Do NOT combine multiple IoCs into a single JSON/HTML — the report generator is designed for one IoC per file
- Run the generator once per IoC:
  ```
  python3 tmp/ioc-investigation/generate_html_report.py temp/ioc_investigation_ip_144.24.28.121_*.json --output-dir reports/ioc-investigation/
  python3 tmp/ioc-investigation/generate_html_report.py temp/ioc_investigation_domain_ms-teams.us.com_*.json --output-dir reports/ioc-investigation/
  ```
- Present all generated HTML report links to the user together at the end
- **NEVER present JSON file links to the user** — JSON is an internal intermediate artifact

### enrich_ips.py — Conditional Resolution (codeRefs-first)

Before running IP enrichment, resolve `enrich_ips.py` via the [File Resolution cascade](#file-resolution-coderefs-first):

1. Check `codeRefs/sec-sre-ag/ioc-investigation/enrich_ips.py` → if found, run from there.
2. Else check `tmp/ioc-investigation/enrich_ips.py` → if found, run from there.
3. Else: `read_skill_file("ioc-investigation", "enrich_ips.py")` → `CreateFile("tmp/ioc-investigation/enrich_ips.py", <content>)` → run from `tmp/`.
4. Run: `ABUSEIPDB_TOKEN=<value> python3 <resolved_path>/enrich_ips.py <ip1> <ip2> ...`

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

`enrich_ips.py` uses 4 external threat intelligence APIs. Each requires an API token. Tokens are resolved by the script in this order of precedence:

1. **Environment variables** (highest priority) — always checked
2. **`.env` file** in the script directory — auto-loaded by python-dotenv
3. **`config.json`** at the workspace root — JSON key/value pairs

| API | Environment Variable | config.json Key | Purpose |
|-----|---------------------|-----------------|---------|
| ipinfo.io | `IPINFO_TOKEN` | `ipinfo_token` | Geolocation, ISP/ASN, VPN detection |
| vpnapi.io | `VPNAPI_TOKEN` | `vpnapi_token` | VPN/proxy/Tor detection |
| AbuseIPDB | `ABUSEIPDB_TOKEN` | `abuseipdb_token` | Abuse confidence score, reports |
| Shodan | `SHODAN_TOKEN` | `shodan_token` | Open ports, services, CVEs, tags |

---

**IoC Type Detection Rules:**

| Pattern | IoC Type | Normalization |
|---------|----------|---------------|
| `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | IPv4 Address | Validate octets ≤255 |
| `[a-fA-F0-9:]+` (with multiple colons) | IPv6 Address | Lowercase, expand if needed |
| `[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}` | Domain | Lowercase, remove trailing dot |
| `https?://.*` or starts with `www.` | URL | Extract domain for separate analysis |
| 32 hex chars | MD5 Hash | Lowercase |
| 40 hex chars | SHA1 Hash | Lowercase |
| 64 hex chars | SHA256 Hash | Lowercase |

**Date Range Rules:**
- **Real-time/recent searches:** Add +2 days to current date for end range
- **Historical ranges:** Add +1 day to user's specified end date
- **Example:** Current date = Jan 23; "Last 7 days" → `datetime(2026-01-16)` to `datetime(2026-01-25)`

---

## Available Investigation Types

### IP Address Investigation
**When to use:** Suspicious inbound/outbound connections, firewall alerts, sign-in anomalies

**Example prompts:**
- "Investigate IP 203.0.113.42"
- "Is 198.51.100.10 malicious?"
- "Check threat intel for 192.0.2.1"

**Data sources:**
- ThreatIntelIndicators (new STIX table via Log Analytics — ⚠️ NOT legacy ThreatIntelligenceIndicator)
- DeviceNetworkEvents (connection history via Log Analytics)
- AlertEvidence + AlertInfo (alert correlation via Log Analytics)
- SecurityAlert (security alerts via Log Analytics)
- SigninLogs (if used for authentication via Log Analytics)
- MDE Custom IOC list (via `az rest` — see defender-api-via-cli.md)
- MDE IP alerts/statistics (via `az rest` — see defender-api-via-cli.md)
- **`enrich_ips.py`** (3rd-party enrichment: ipinfo.io geo/ISP, vpnapi.io VPN/proxy/Tor, AbuseIPDB abuse score & reports, Shodan ports/services/CVEs/tags)

### Domain Investigation
**When to use:** Suspicious DNS queries, phishing domains, C2 communication

**Example prompts:**
- "Investigate domain malware-c2.example.com"
- "Is evil.com in our threat intel?"
- "Check if any devices connected to suspicious.net"

**Data sources:**
- DeviceNetworkEvents (DNS queries, HTTP connections via Log Analytics)
- EmailUrlInfo (email-delivered URLs via Log Analytics)
- ThreatIntelIndicators (domain indicators via Log Analytics — ⚠️ NOT legacy ThreatIntelligenceIndicator)
- MDE Custom IOC list (via `az rest` — see defender-api-via-cli.md)
- AlertEvidence + AlertInfo (alert correlation via Log Analytics)

### URL Investigation
**When to use:** Phishing links, malicious downloads, suspicious redirects

**Example prompts:**
- "Investigate URL https://phishing.example.com/login"
- "Was this URL clicked by anyone?"
- "Check threat intel for http://malware.site/payload.exe"

**Data sources:**
- EmailUrlInfo (URLs in emails via Log Analytics)
- DeviceNetworkEvents (HTTP/HTTPS connections via Log Analytics)
- DeviceFileEvents (downloads from URL via Log Analytics)
- ThreatIntelIndicators (URL patterns via Log Analytics — ⚠️ NOT legacy ThreatIntelligenceIndicator)

### File Hash Investigation
**When to use:** Malware analysis, suspicious executables, file reputation

**Example prompts:**
- "Investigate hash a1b2c3d4e5f6..."
- "Is this SHA256 known malware?"
- "Which devices have this file?"

**Data sources:**
- DeviceFileEvents (file creation/modification via Log Analytics)
- DeviceProcessEvents (process execution with hash via Log Analytics)
- AlertEvidence + AlertInfo (alert correlation via Log Analytics)
- ThreatIntelIndicators (file hash indicators via Log Analytics — ⚠️ NOT legacy ThreatIntelligenceIndicator)
- MDE File info/stats/alerts/machines (via `az rest` — see defender-api-via-cli.md)

---

## Quick Start (TL;DR)

When a user requests an IoC investigation:

1. **Identify & Normalize IoC:**
   ```
   - Detect IoC type (IP/Domain/URL/Hash)
   - Normalize format (lowercase, validate)
   - Extract embedded IoCs (domain from URL)
   ```

2. **Run Parallel KQL Queries (Batch 1 — Threat Intel):**
   - **Q1**: ThreatIntelIndicators query (via Azure Monitor MCP — ⚠️ NOT legacy ThreatIntelligenceIndicator)
   - **MDE-IOC**: Custom IOC list search (via `RunAzCliReadCommands` + `az rest`)
   - **MDE-ALERTS**: IP/File alerts from MDE API (via `RunAzCliReadCommands` + `az rest`)

3. **Run 3rd-Party IP Enrichment (IP IoCs only):**
   ```powershell
   python3 tmp/ioc-investigation/enrich_ips.py <IP_ADDRESS>
   ```
   - ipinfo.io: Geolocation, ISP/ASN, hosting provider
   - vpnapi.io: VPN, proxy, Tor exit node detection
   - AbuseIPDB: Abuse confidence score, recent attack reports
   - Shodan: Open ports, services/banners, CVEs, tags (e.g., `c2`, `eol-os`, `self-signed`)

4. **Run Parallel KQL Queries (Batch 2 — Activity):**
   - **Q2/Q3**: DeviceNetworkEvents (connections involving IoC)
   - **Q8**: AlertEvidence (alerts with IoC as evidence)
   - **Q9**: AlertEvidence + AlertInfo (full alert correlation)
   - **Q10**: SecurityAlert (mentions of IoC)
   - **Q6**: EmailUrlInfo (if domain/URL)
   - **Q11**: SigninLogs (if IP)

5. **CVE & Vulnerability Correlation:**
   - Extract CVE IDs from alert results AND Shodan enrichment
   - For each CVE: query affected devices via MDE API (`az rest`)
   - Aggregate affected devices

6. **Export to JSON & Generate Summary:**
   ```
   temp/ioc_investigation_{ioc_normalized}_{timestamp}.json
   ```

---

## Phase 0: Investigation Cache Check (MANDATORY)

**This phase MUST execute BEFORE any data collection. It determines whether to reuse cached investigation data or start a fresh investigation.**

### 0.1 Cache File Convention

Investigation results are stored as JSON files following this naming pattern:
```
temp/ioc_investigation_{ioc_type}_{ioc_normalized}_{YYYYMMDD_HHMMSS}.json
```

### 0.2 Cache Check Workflow

```
Step 0.1: After IoC normalization (Phase 1), search for existing cache files
          → Use: ls temp/ioc_investigation_{ioc_type}_{ioc_normalized}_*.json
          → If NO cache file exists → proceed to Phase 2 (fresh investigation)

Step 0.2: If one or more cache files exist, select the MOST RECENT one (latest timestamp)

Step 0.3: Calculate the cache age:
          → Extract timestamp from filename (YYYYMMDD_HHMMSS format)
          → age = current_UTC_time − cache_file_timestamp
          → If age > 4 hours → IGNORE cache entirely, proceed to Phase 2 (fresh investigation)
          → If age ≤ 4 hours → proceed to Step 0.4

Step 0.4: Analyze the user's ORIGINAL prompt for implicit intent:

          REDO KEYWORDS (triggers fresh investigation, any language):
            "ripeti", "aggiorna", "rifai", "repeat", "redo", "refresh",
            "update", "re-investigate", "start over", "da capo",
            "from scratch", "ricomincia", "nuovo", "nuova analisi"
          → If ANY redo keyword is detected → IGNORE cache, proceed to Phase 2

          USE-CACHE KEYWORDS (triggers cache reuse, any language):
            "completa", "continua", "complete", "continue", "finish",
            "usa i dati", "use cached", "use existing", "prosegui",
            "riprendi", "resume", "genera report", "generate report",
            "genera il report", "crea report"
          → If ANY use-cache keyword is detected → LOAD cache, skip to summary

          NO IMPLICIT INTENT DETECTED:
          → Proceed to Step 0.5 (ask the user)

Step 0.5: ASK the user:

          Question: "Ho trovato risultati di un'investigazione precedente per
                     l'IoC <IOC_VALUE> (<IOC_TYPE>), completata <TIME_AGO> fa
                     (alle <HH:MM> UTC).
                     Vuoi utilizzare questi dati o preferisci ripetere
                     l'investigazione da zero?"
          Options:
            1. "Usa i dati esistenti" — Riprende dall'investigazione precedente
            2. "Ripeti da zero" — Ignora la cache e ricomincia

          → If user selects "Usa i dati esistenti" → LOAD cache, present summary
          → If user selects "Ripeti da zero" → proceed to Phase 2

Step 0.6: LOAD cached data:
          → Read the JSON file
          → Present a brief inline summary of cached findings
          → Offer HTML/report generation or further analysis
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
- **If the user later requests a fresh investigation after loading cache** — discard all cached data and restart.

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking Pattern

**YOU MUST TRACK AND REPORT TIME AFTER EVERY MAJOR STEP:**

```
[MM:SS] ✓ Step description (XX seconds)
```

**Required Reporting Points:**
1. After IoC normalization and type detection
2. After 3rd-party IP enrichment (IP IoCs)
3. After threat intelligence lookup (KQL + MDE API)
4. After activity/connection analysis
5. After CVE correlation and device enumeration
6. After JSON file creation
7. Final: Total elapsed time

---

### Phase 1: IoC Identification and Normalization (REQUIRED FIRST)

**Step 1.1: Detect IoC Type**
```python
# Regex patterns for IoC detection
IPv4: r'^(\d{1,3}\.){3}\d{1,3}$'
IPv6: r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
Domain: r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
URL: r'^https?://'
MD5: r'^[a-fA-F0-9]{32}$'
SHA1: r'^[a-fA-F0-9]{40}$'
SHA256: r'^[a-fA-F0-9]{64}$'
```

**Step 1.2: Normalize IoC**
- **IP Address:** Validate octets, detect IPv4 vs IPv6
- **Domain:** Lowercase, remove trailing dots, extract from URL if needed
- **URL:** Keep full URL, also extract domain for parallel investigation
- **Hash:** Lowercase

**Step 1.3: Create Investigation Context**
```json
{
  "ioc_type": "ip|domain|url|hash",
  "ioc_value": "<normalized_value>",
  "ioc_original": "<user_provided_value>",
  "extracted_domain": "<if_url>",
  "investigation_start": "<timestamp>",
  "date_range_start": "<StartDate>",
  "date_range_end": "<EndDate>"
}
```

---

### Phase 2: 3rd-Party IP Enrichment (IP Address IoCs)

**MANDATORY for all IP address investigations.** Run `enrich_ips.py` to get external threat intelligence context that is NOT available from Defender/Sentinel native tools.

**Resolve and run:**
1. Resolve `enrich_ips.py` via the [File Resolution cascade](#file-resolution-coderefs-first):
   - Check `codeRefs/sec-sre-ag/ioc-investigation/enrich_ips.py` → if found, run from there.
   - Else check `tmp/ioc-investigation/enrich_ips.py` → if found, run from there.
   - Else: `read_skill_file("ioc-investigation", "enrich_ips.py")` → `CreateFile("tmp/ioc-investigation/enrich_ips.py", <content>)` → run from `tmp/`.
2. Run:
```powershell
ABUSEIPDB_TOKEN=<value> python3 <resolved_path>/enrich_ips.py <IP_ADDRESS_1> <IP_ADDRESS_2> ...
```

**What it provides:**

| Source | Intelligence |
|--------|--------------|
| **ipinfo.io** | Geolocation (city, country, coordinates), ISP/ASN, organization, hosting provider detection |
| **vpnapi.io** | VPN, proxy, Tor exit node, relay detection |
| **AbuseIPDB** | Abuse confidence score (0-100), total reports, last reported date, recent reporter comments with attack categories |
| **Shodan** | Open ports, service/banner details, OS detection, known CVEs, tags (e.g., `c2`, `eol-os`, `self-signed`, `honeypot`), CPEs, hostnames |

**Output:** Per-IP detailed results printed to terminal + JSON export saved to `temp/`.

**Integration with investigation:**
- **AbuseIPDB score ≥ 75:** 🔴 Strong indicator of malicious activity — flag as high risk
- **VPN/Proxy/Tor detected:** 🟠 Potential evasion — note in risk assessment
- **Shodan tags contain `c2`:** 🔴 Known C2 infrastructure — escalate immediately
- **Shodan CVEs found:** Cross-reference with Phase 5 CVE correlation for organizational exposure
- **Hosting provider (not residential ISP):** 🟡 May indicate attacker infrastructure

> **Note:** For domain and URL IoCs, extract the resolved IP(s) from DeviceNetworkEvents results and run enrichment on those IPs as a follow-up step.

> **If `enrich_ips.py` is not available** (no Python, no API tokens): Use **Q13** (KQL IP Context Fallback) to get whatever context is available from Log Analytics tables.

---

### Phase 3: Parallel Threat Intelligence Collection (KQL + MDE API)

**CRITICAL:** Run ALL threat intel queries in parallel for speed!

#### Pre-requisite: Read MDE API Reference (MANDATORY)

Before executing ANY MDE API call (`az rest`), you **MUST** read the reference file:

```
read_skill_file(skill_name="ioc-investigation", file_path="defender-api-via-cli.md")
```

This file contains the **exact `az rest` commands**, the required `--resource` parameter, the correct tool to use (`RunAzCliReadCommands` — NEVER `RunAzCliWriteCommands`), error handling, and the fallback strategy.

- If the file has already been read in this session, skip this step.
- Do NOT attempt MDE API calls from memory — the URLs and `--resource` parameter are precise and must match exactly.
- If the first MDE API call returns 403 → skip ALL remaining MDE API calls and note "MDE API not accessible — KQL-only mode" in the report.

#### Batch 1: KQL Queries via Azure Monitor MCP (Run ALL in parallel)

| Query | Table | IoC Types | Details |
|-------|-------|-----------|---------|
| **Q1** | ThreatIntelIndicators | All | TI indicator match (STIX schema) |
| **Q8** | AlertEvidence | All | IoC in alert evidence |
| **Q10** | SecurityAlert | All | Security alerts mentioning IoC |

#### Batch 2: MDE API Calls via `RunAzCliReadCommands` (Run ALL in parallel)

| Call | Endpoint | IoC Types | Details |
|------|----------|-----------|---------|
| **MDE-IOC** | `/api/indicators` | All | Custom IOC list match |
| **MDE-IP-ALERTS** | `/api/ips/{ip}/alerts` | IP | Alerts for IP |
| **MDE-IP-STATS** | `/api/ips/{ip}/stats` | IP | IP organization prevalence |
| **MDE-FILE-INFO** | `/api/files/{hash}` | Hash | File details, threat determination |
| **MDE-FILE-ALERTS** | `/api/files/{hash}/alerts` | Hash | File-related alerts |
| **MDE-FILE-STATS** | `/api/files/{hash}/stats` | Hash | File organization statistics |
| **MDE-FILE-MACHINES** | `/api/files/{hash}/machines` | Hash | Devices with file |

> See [defender-api-via-cli.md](defender-api-via-cli.md) for exact `az rest` commands.

---

### Phase 4: Activity and Connection Analysis (KQL via Azure Monitor MCP)

**Run ALL activity queries in parallel!**

| Query | Table | IoC Types | Details |
|-------|-------|-----------|---------|
| **Q2** | DeviceNetworkEvents | IP | Connection summary |
| **Q3** | DeviceNetworkEvents | IP | Connection timeline (top 20) |
| **Q4** | DeviceNetworkEvents | Domain | DNS/HTTP connection activity |
| **Q5** | DeviceNetworkEvents | Domain | Connection timeline (top 20) |
| **Q6** | EmailUrlInfo | Domain, URL | Email delivery analysis |
| **Q7** | DeviceFileEvents | Hash | File events across tables |
| **Q7b** | DeviceProcessEvents | Hash | Process events with hash |
| **Q9** | AlertEvidence + AlertInfo | All | Full alert correlation with details |
| **Q11** | SigninLogs | IP | Sign-in analysis (Azure AD) |

---

### Phase 5: CVE Correlation and Vulnerability Management

**Step 5.1: Extract CVE IDs from Results AND Enrichment**
- Parse alert results for CVE references (pattern: `CVE-\d{4}-\d{4,}`)
- Extract from: alert descriptions, attack techniques, MITRE info
- **Extract from Shodan enrichment** (`shodan_vulns` field from `enrich_ips.py` output)
- Run **Q12** (CVE Extraction from Alerts) to collect all CVE IDs

**Step 5.2: Query Affected Devices per CVE**

Use the MDE API via `RunAzCliReadCommands`:

```
For each CVE_ID found:
  → MDE-CVE-MACHINES: az rest to /api/vulnerabilities/{cveId}/machineReferences
  → Collect: deviceId, deviceName, osPlatform, rbacGroupName
```

> See [defender-api-via-cli.md](defender-api-via-cli.md) for exact `az rest` commands.

**Step 5.3: Aggregate Device Exposure**
```json
{
  "cve_correlation": {
    "cve_ids_found": ["CVE-2024-1234", "CVE-2024-5678"],
    "affected_devices_by_cve": {
      "CVE-2024-1234": [
        {"deviceId": "...", "deviceName": "...", "osPlatform": "..."}
      ]
    },
    "total_unique_affected_devices": 15,
    "critical_cves": 2,
    "high_cves": 3
  }
}
```

---

### Phase 6: Export to JSON

Create single JSON file: `temp/ioc_investigation_{ioc_type}_{ioc_normalized}_{timestamp}.json`

---

## KQL Execution Reference

### How to Run KQL Queries

All KQL queries in this skill are executed via the **Azure Monitor MCP tool**:

```
Tool: monitor-client_monitor_workspace_log_query
Parameters:
  workspace: <WORKSPACE_GUID>          # From agent settings <log_analytics_access>
  subscription: <SUBSCRIPTION_ID>      # From agent settings <azure_resource_access>
  query: "<KQL_QUERY>"                 # Query from templates below
  timespan: "P7D"                      # ISO 8601 duration (P7D = 7 days, P30D = 30 days)
```

**Important notes:**
- The `workspace` parameter accepts the Log Analytics workspace GUID
- The `subscription` parameter is REQUIRED
- Date ranges in the query (`datetime(...)` / `between`) take precedence over `timespan`
- Always use `let` variables for IoC values and dates at the start of each query

### Table Availability

| Table | Available in Log Analytics | Notes |
|-------|---------------------------|-------|
| ThreatIntelIndicators | ✅ Yes | New STIX table (active since Apr 2025). ⚠️ Do NOT use legacy `ThreatIntelligenceIndicator` (deprecated July 2025, empty) |
| DeviceNetworkEvents | ✅ Yes | MDE data connector |
| DeviceProcessEvents | ✅ Yes | MDE data connector |
| DeviceFileEvents | ✅ Yes | MDE data connector |
| DeviceRegistryEvents | ✅ Yes | MDE data connector |
| DeviceLogonEvents | ✅ Yes | MDE data connector |
| DeviceImageLoadEvents | ✅ Yes | MDE data connector |
| DeviceEvents | ✅ Yes | MDE data connector |
| AlertEvidence | ✅ Yes | M365 Defender connector |
| AlertInfo | ✅ Yes | M365 Defender connector |
| SecurityAlert | ✅ Yes | Sentinel native |
| SigninLogs | ✅ Yes | Entra ID connector |
| AADNonInteractiveUserSignInLogs | ✅ Yes | Entra ID connector |
| EmailUrlInfo | ✅ Yes | MDO connector |
| DeviceTvmSoftwareVulnerabilities | ❌ No | Use MDE API via `az rest` |
| DeviceTvmSoftwareInventory | ❌ No | Use MDE API via `az rest` |

---

## Sample KQL Queries

Use these exact patterns with Azure Monitor MCP. Replace `<IOC_VALUE>`, `<StartDate>`, `<EndDate>`.

**⚠️ CRITICAL: These queries have been validated against the KQL schema. Use them as your PRIMARY reference.**

---

### 📅 Date Range Quick Reference

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**
- **ALWAYS check the current date from the context header BEFORE calculating date ranges**
- **NEVER use hardcoded years** — the year changes and you WILL query the wrong timeframe

**RULE 1: Real-Time/Recent Searches (Current Activity)**
- **Add +2 days to current date for end range**
- **Why +2?** +1 for timezone offset + +1 for inclusive end-of-day
- **Pattern**: Today is Jan 23 → Use `datetime(2026-01-25)` as end date

**RULE 2: Historical Searches (User-Specified Dates)**
- **Add +1 day to user's specified end date**
- **Why +1?** To include all 24 hours of the final day

---

### Q1. Threat Intelligence Indicator Match

> **⚠️ CRITICAL — Table Migration (June 2026):**
> - **ALWAYS** use `ThreatIntelIndicators` (new STIX table, active since April 2025, fed by Premium MDTI Connector).
> - **NEVER** use `ThreatIntelligenceIndicator` (legacy table, deprecated July 2025, no longer receives data — empty in most workspaces).
> - Schema is completely different: legacy used `NetworkIP`/`DomainName`/`Active`/`ExpirationDateTime`; new table uses `ObservableKey`/`ObservableValue`/`IsActive`/`ValidUntil`/`Confidence`/`Data` (STIX JSON).
> - `ThreatIntelObjects` is a companion table for STIX objects (threat actors, attack patterns) — query it for attribution context.

**Table:** `ThreatIntelIndicators` (Log Analytics — new STIX schema)
**IoC types:** All (IP, Domain, URL, Hash)
**Replaces:** Sentinel `query_lake` TI lookup + legacy `ThreatIntelligenceIndicator`

```kql
let ioc_value = '<IOC_VALUE>';
ThreatIntelIndicators
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| where ObservableValue =~ ioc_value
    or ObservableValue has ioc_value
| extend ParsedData = parse_json(Data)
| extend Description = tostring(ParsedData.description)
| extend IndicatorTypes = tostring(ParsedData.indicator_types)
| extend ThreatLabels = tostring(ParsedData.labels)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| summarize arg_max(TimeGenerated, *) by ObservableValue
| project
    TimeGenerated,
    IoC = ObservableValue,
    IoC_Type = ObservableKey,
    Confidence,
    Tags,
    SourceSystem,
    ValidFrom,
    ValidUntil,
    Description,
    IndicatorTypes,
    ThreatLabels,
    IsActive
| order by Confidence desc
| take 20
```

**⚠️ Schema notes (validated against live workspace 2026-06-01):**
- Table name is `ThreatIntelIndicators` (NOT legacy `ThreatIntelligenceIndicator`)
- Use `IsActive` (NOT `Active`), `ValidUntil` (NOT `ExpirationDateTime`)
- Use `ObservableKey` + `ObservableValue` for IoC matching (NOT `NetworkIP`, `DomainName`, `Url`, `FileHashValue`)
- Use `Confidence` (NOT `ConfidenceScore`), `Data` for full STIX JSON (NOT individual fields)
- `Tags` contains activity group labels (e.g., `activitygroup:storm-2785,type:ipv4`)
- `SourceSystem` identifies the feed (e.g., `Premium Microsoft Defender Threat Intelligence`)
- **Zero-results sanity check:** if Q1 returns 0 results, verify you queried `ThreatIntelIndicators` (NOT the legacy table)

---

### Q2. IP Address — Network Connection Activity

**Table:** `DeviceNetworkEvents` (Log Analytics)
**IoC types:** IP
**Replaces:** `GetDefenderIpStatistics` MCP tool

```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP == target_ip or LocalIP == target_ip
| extend Direction = iff(RemoteIP == target_ip, "Outbound", "Inbound")
| summarize 
    TotalConnections = count(),
    UniqueDevices = dcount(DeviceId),
    UniquePorts = dcount(RemotePort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    Ports = make_set(RemotePort, 20),
    Protocols = make_set(Protocol),
    ActionTypes = make_set(ActionType),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10),
    Directions = make_set(Direction, 2)
```

---

### Q3. IP Address — Detailed Connection Timeline (top 20)

**Table:** `DeviceNetworkEvents` (Log Analytics)
**IoC types:** IP
**Replaces:** `FindDefenderMachinesByIp` MCP tool (partial)

```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP == target_ip or LocalIP == target_ip
| project 
    Timestamp,
    DeviceName,
    DeviceId,
    ActionType,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    LocalIP,
    LocalPort,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessAccountName
| order by Timestamp desc
| take 20
```

---

### Q4. Domain — DNS and HTTP Connection Activity

**Table:** `DeviceNetworkEvents` (Log Analytics)
**IoC types:** Domain

```kql
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteUrl has target_domain
| summarize 
    TotalConnections = count(),
    UniqueDevices = dcount(DeviceId),
    UniqueUsers = dcount(InitiatingProcessAccountName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    URLs = make_set(RemoteUrl, 20),
    Ports = make_set(RemotePort),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10)
```

---

### Q5. Domain — Detailed Connection Timeline (top 20)

**Table:** `DeviceNetworkEvents` (Log Analytics)
**IoC types:** Domain

```kql
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteUrl has target_domain
| project 
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    ActionType,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
| take 20
```

---

### Q6. URL — Email Delivery Analysis

**Table:** `EmailUrlInfo` (Log Analytics)
**IoC types:** Domain, URL

```kql
let target_url = '<URL>';
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
EmailUrlInfo
| where Timestamp between (start .. end)
| where Url == target_url or Url has target_domain or UrlDomain =~ target_domain
| summarize 
    EmailCount = dcount(NetworkMessageId),
    UniqueURLs = make_set(Url, 10),
    UrlLocations = make_set(UrlLocation),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by UrlDomain
| order by EmailCount desc
```

---

### Q7. File Hash — Device File Events

**Table:** `DeviceFileEvents` (Log Analytics)
**IoC types:** Hash

```kql
let target_hash = '<HASH>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceFileEvents
| where Timestamp between (start .. end)
| where SHA1 =~ target_hash or SHA256 =~ target_hash or MD5 =~ target_hash
| summarize 
    EventCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    FileNames = make_set(FileName, 10),
    FolderPaths = make_set(FolderPath, 10),
    ActionTypes = make_set(ActionType),
    InitiatingProcesses = make_set(InitiatingProcessFileName, 10)
```

---

### Q7b. File Hash — Process Events

**Table:** `DeviceProcessEvents` (Log Analytics)
**IoC types:** Hash
**Replaces:** `GetDefenderFileRelatedMachines` MCP tool (partial)

```kql
let target_hash = '<HASH>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where SHA1 =~ target_hash or SHA256 =~ target_hash or MD5 =~ target_hash 
    or InitiatingProcessSHA256 =~ target_hash or InitiatingProcessSHA1 =~ target_hash
| summarize 
    EventCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 10),
    FileNames = make_set(FileName, 10),
    FolderPaths = make_set(FolderPath, 10),
    ProcessCmds = make_set(ProcessCommandLine, 5),
    ActionTypes = make_set(ActionType)
```

---

### Q7c. File Hash — Cross-Table Search (comprehensive)

**Tables:** Multiple Device* tables (Log Analytics)
**IoC types:** Hash

> **⚠️ Note:** The `union` operator may not validate correctly with the KQL Search MCP validator, but is valid KQL and executes correctly.

```kql
let target_hash = '<HASH>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union withsource=SourceTable DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents
| where Timestamp between (start .. end)
| where SHA1 =~ target_hash or SHA256 =~ target_hash or MD5 =~ target_hash or InitiatingProcessSHA256 =~ target_hash
| summarize 
    EventCount = count(),
    UniqueDevices = dcount(DeviceId),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    FileNames = make_set(FileName),
    FolderPaths = make_set(FolderPath, 5)
    by SourceTable, ActionType
| order by EventCount desc
```

---

### Q8. Alert Evidence — IoC in Alerts (top 20)

**Table:** `AlertEvidence` (Log Analytics)
**IoC types:** All
**Replaces:** `GetDefenderIpAlerts` / `GetDefenderFileAlerts` MCP tools (partial)

```kql
let ioc_value = '<IOC_VALUE>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
AlertEvidence
| where Timestamp between (start .. end)
| where RemoteIP == ioc_value 
    or RemoteUrl has ioc_value 
    or SHA1 =~ ioc_value 
    or SHA256 =~ ioc_value
    or FileName has ioc_value
    or Title has ioc_value
| project 
    Timestamp,
    AlertId,
    Title,
    Severity,
    Categories,
    ServiceSource,
    EntityType,
    EvidenceRole,
    RemoteIP,
    RemoteUrl,
    FileName,
    SHA1,
    SHA256,
    DeviceName,
    AccountName
| order by Timestamp desc
| take 20
```

**⚠️ Schema note:** `AlertEvidence` uses `Timestamp` (NOT `TimeGenerated`).

---

### Q9. Security Alerts — Full Alert Correlation

**Tables:** `AlertEvidence` + `AlertInfo` (Log Analytics)
**IoC types:** All
**Replaces:** `GetDefenderIpAlerts` / `GetDefenderFileAlerts` MCP tools (with full context)

```kql
let ioc_value = '<IOC_VALUE>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
AlertEvidence
| where Timestamp between (start .. end)
| where RemoteIP == ioc_value 
    or RemoteUrl has ioc_value 
    or SHA1 =~ ioc_value 
    or SHA256 =~ ioc_value
    or FileName has ioc_value
    or Title has ioc_value
| join kind=inner AlertInfo on AlertId
| summarize 
    AlertCount = dcount(AlertId),
    Alerts = make_set(Title, 10),
    Severities = make_set(Severity),
    Categories = make_set(Category),
    AttackTechniques = make_set(AttackTechniques),
    AffectedDevices = make_set(DeviceName, 10)
```

---

### Q10. Security Alert — Sentinel Native Alerts

**Table:** `SecurityAlert` (Log Analytics)
**IoC types:** All

```kql
let ioc_value = '<IOC_VALUE>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has ioc_value 
    or ExtendedProperties has ioc_value 
    or Description has ioc_value
| summarize 
    AlertCount = count(),
    UniqueAlerts = dcount(AlertName),
    AlertNames = make_set(AlertName, 10),
    Severities = make_set(AlertSeverity),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Providers = make_set(ProviderName),
    Tactics = make_set(Tactics)
| extend SummaryNote = strcat("Total: ", AlertCount, " alerts, ", UniqueAlerts, " unique types")
```

---

### Q11. IP Address — Sign-in Analysis (Azure AD)

**Table:** `SigninLogs` + `AADNonInteractiveUserSignInLogs` (Log Analytics)
**IoC types:** IP

> **⚠️ Note:** The `union isfuzzy=true` operator may not validate correctly with the KQL Search MCP validator, but is valid KQL and executes correctly. If validation fails, run each table separately.

```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where IPAddress == target_ip
| summarize 
    SignInCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    SuccessCount = countif(ResultType == '0'),
    FailureCount = countif(ResultType != '0'),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Users = make_set(UserPrincipalName, 10),
    Apps = make_set(AppDisplayName, 10),
    ResultTypes = make_set(ResultType)
| extend SuccessRate = round(100.0 * SuccessCount / SignInCount, 2)
```

**Fallback (if union fails):** Run against `SigninLogs` only.

---

### Q12. CVE Extraction from Alerts

**Table:** `AlertEvidence` (Log Analytics)
**IoC types:** All

```kql
let ioc_value = '<IOC_VALUE>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
AlertEvidence
| where Timestamp between (start .. end)
| where RemoteIP == ioc_value 
    or RemoteUrl has ioc_value 
    or SHA1 =~ ioc_value 
    or SHA256 =~ ioc_value
    or FileName has ioc_value
    or Title has ioc_value
| extend CVEs = extract_all(@"(CVE-\d{4}-\d{4,})", tostring(AttackTechniques))
| mv-expand CVE = CVEs
| where isnotempty(CVE)
| summarize 
    CVECount = dcount(tostring(CVE)),
    CVEs = make_set(tostring(CVE)),
    AlertCount = dcount(AlertId),
    Alerts = make_set(Title, 5)
```

---

### Q13. KQL IP Context Fallback (when enrich_ips.py is unavailable)

**Table:** `DeviceNetworkEvents` + `SigninLogs` (Log Analytics)
**IoC types:** IP
**Use when:** `enrich_ips.py` is not available (no Python or no API tokens)

```kql
let target_ip = '<IP_ADDRESS>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteIP == target_ip
| summarize 
    TotalConnections = count(),
    UniqueDevices = dcount(DeviceId),
    UniquePorts = dcount(RemotePort),
    UniqueProcesses = dcount(InitiatingProcessFileName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    TopDevices = make_set(DeviceName, 5),
    TopPorts = make_set(RemotePort, 10),
    TopProcesses = make_set(InitiatingProcessFileName, 5),
    TopURLs = make_set(RemoteUrl, 5)
```

---

### Q14. Domain — Resolved IPs Extraction

**Table:** `DeviceNetworkEvents` (Log Analytics)
**IoC types:** Domain
**Use for:** Extracting resolved IPs from domain connections for subsequent IP enrichment

```kql
let target_domain = '<DOMAIN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where RemoteUrl has target_domain
| where isnotempty(RemoteIP)
| summarize 
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP
| order by ConnectionCount desc
```

> **Follow-up:** Use the extracted `RemoteIP` values to run `enrich_ips.py` for 3rd-party enrichment.

---

## MDE API via CLI

For Defender for Endpoint API calls that cannot be replaced by KQL queries, use `RunAzCliReadCommands` with `az rest`.

**See [defender-api-via-cli.md](defender-api-via-cli.md) for the complete reference** with:
- Custom IOC list search
- IP alerts and statistics
- File info, statistics, alerts, and related machines
- Find machines by IP
- CVE → affected devices lookup
- Error handling and fallback strategies

---

## JSON Export Structure

Create file: `temp/ioc_investigation_{ioc_type}_{ioc_normalized}_{timestamp}.json`

```json
{
  "investigation_metadata": {
    "ioc_type": "ip|domain|url|hash",
    "ioc_value": "<normalized_value>",
    "ioc_original": "<user_input>",
    "investigation_timestamp": "<ISO8601>",
    "date_range_start": "<StartDate>",
    "date_range_end": "<EndDate>",
    "elapsed_time_seconds": 45
  },
  "threat_intelligence": {
    "sentinel_ti_matches": [],
    "defender_ioc_matches": [],
    "defender_alerts": [],
    "threat_families": [],
    "confidence_score": 0,
    "verdict": "Malicious|Suspicious|Clean|Unknown"
  },
  "ip_enrichment": {
    "geo": { "city": "", "country": "", "org": "", "isp": "" },
    "vpn_proxy_tor": { "is_vpn": false, "is_proxy": false, "is_tor": false },
    "abuseipdb": { "abuse_confidence_score": 0, "total_reports": 0, "last_reported": "", "recent_categories": [] },
    "shodan": { "ports": [], "services": [], "vulns": [], "tags": [], "os": "", "hostnames": [], "cpes": [] }
  },
  "activity_analysis": {
    "network_connections": {
      "total_connections": 0,
      "unique_devices": 0,
      "unique_users": 0,
      "first_seen": "<datetime>",
      "last_seen": "<datetime>",
      "top_devices": [],
      "top_ports": [],
      "top_processes": []
    },
    "email_delivery": {
      "email_count": 0,
      "unique_urls": [],
      "delivery_locations": []
    },
    "file_activity": {
      "event_count": 0,
      "unique_devices": 0,
      "file_names": [],
      "folder_paths": [],
      "action_types": []
    },
    "signin_activity": {
      "signin_count": 0,
      "unique_users": 0,
      "success_rate": 0,
      "affected_users": []
    }
  },
  "alert_correlation": {
    "total_alerts": 0,
    "severity_breakdown": {
      "high": 0,
      "medium": 0,
      "low": 0,
      "informational": 0
    },
    "alert_titles": [],
    "attack_techniques": [],
    "affected_entities": []
  },
  "cve_correlation": {
    "cve_ids_found": [],
    "affected_devices_by_cve": {},
    "total_unique_affected_devices": 0,
    "cve_severity_breakdown": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    }
  },
  "organizational_exposure": {
    "total_affected_devices": 0,
    "affected_device_list": [],
    "exposure_level": "High|Medium|Low|None",
    "recommended_actions": []
  },
  "risk_assessment": {
    "overall_risk": "Critical|High|Medium|Low|Informational",
    "risk_factors": [],
    "mitigating_factors": [],
    "confidence": "High|Medium|Low"
  }
}
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **No TI matches found** | IoC may be unknown; proceed with activity analysis |
| **Azure Monitor MCP query fails** | Check workspace ID, subscription, and table availability. Retry with corrected params |
| **`az rest` to MDE API returns 403** | Managed identity may lack MDE API permissions. Skip MDE enrichment, note in report |
| **`az rest` to MDE API returns 404** | IoC not in MDE scope; rely on KQL data from Log Analytics |
| **Empty DeviceNetworkEvents** | Expand date range or check if MDE data connector is active |
| **CVE not found in vulnerability DB** | CVE may be too new or not applicable to org assets |
| **Multiple IoC types detected** | Investigate each separately, correlate results |
| **Rate limiting on MDE API** | Add delays between `az rest` calls, batch where possible |
| **`enrich_ips.py` missing or no tokens** | Use Q13 (KQL IP Context Fallback) instead |
| **`union` query fails** | Run queries against individual tables separately |

### Required Field Defaults

If queries return no results, use these defaults:

```json
{
  "threat_intelligence": {
    "sentinel_ti_matches": [],
    "defender_alerts": [],
    "verdict": "Unknown",
    "confidence_score": 0
  },
  "activity_analysis": {
    "network_connections": {
      "total_connections": 0,
      "unique_devices": 0
    }
  },
  "cve_correlation": {
    "cve_ids_found": [],
    "affected_devices_by_cve": {},
    "total_unique_affected_devices": 0
  }
}
```

---

## Example Workflows

### Example 1: IP Address Investigation

**User says:** "Investigate IP 203.0.113.42 for the last 7 days"

**Workflow:**
1. **Identify IoC:** IPv4 Address, normalized: `203.0.113.42`
2. **3rd-Party Enrichment:**
   ```powershell
   python3 tmp/ioc-investigation/enrich_ips.py 203.0.113.42
   ```
   → Get geo, ISP, VPN/proxy/Tor flags, AbuseIPDB score, Shodan ports/CVEs/tags
3. **Phase 1 — Threat Intel (parallel via Azure Monitor MCP + az rest):**
   - **Q1**: ThreatIntelIndicators query (Azure Monitor MCP)
   - **MDE-IOC**: Custom IOC list search (`az rest`)
   - **MDE-IP-ALERTS**: IP alerts from MDE API (`az rest`)
4. **Phase 2 — Activity Analysis (parallel via Azure Monitor MCP):**
   - **Q2**: DeviceNetworkEvents connection summary
   - **Q11**: SigninLogs sign-in analysis
   - **Q8**: AlertEvidence IoC in alerts
   - **Q10**: SecurityAlert mentions
5. **Phase 3 — CVE Correlation:**
   - **Q12**: Extract CVEs from alerts
   - Extract CVEs from Shodan enrichment
   - For each CVE: **MDE-CVE-MACHINES** (`az rest`)
6. **Export JSON and summarize findings** (include enrichment data in JSON export)

### Example 2: Domain Investigation

**User says:** "Is evil-malware.com in our environment?"

**Workflow:**
1. **Identify IoC:** Domain, normalized: `evil-malware.com`
2. **Phase 1 — Threat Intel (parallel):**
   - **Q1**: ThreatIntelIndicators query
   - **MDE-IOC**: Custom IOC list search (`az rest`)
3. **Phase 2 — Activity Analysis (parallel):**
   - **Q4**: DeviceNetworkEvents domain connections
   - **Q6**: EmailUrlInfo email delivery
   - **Q8**: AlertEvidence IoC in alerts
4. **Phase 3 — Resolved IP Enrichment:**
   - **Q14**: Extract resolved IPs from domain connections
   - Run `enrich_ips.py` on resolved IPs
5. **Phase 4 — Exposure Assessment:**
   - List all devices that connected
   - Identify affected users
6. **Export JSON and summarize findings**

### Example 3: File Hash Investigation with CVE Correlation

**User says:** "Investigate SHA256 a1b2c3... and check which devices are vulnerable"

**Workflow:**
1. **Identify IoC:** SHA256 Hash, normalized: `a1b2c3...`
2. **Phase 1 — Threat Intel (parallel):**
   - **Q1**: ThreatIntelIndicators query
   - **MDE-FILE-INFO**: File info from MDE API (`az rest`)
   - **MDE-FILE-ALERTS**: File alerts from MDE API (`az rest`)
   - **MDE-FILE-STATS**: File statistics from MDE API (`az rest`)
3. **Phase 2 — Device Exposure (parallel):**
   - **MDE-FILE-MACHINES**: Devices with file from MDE API (`az rest`)
   - **Q7**: DeviceFileEvents query
   - **Q7b**: DeviceProcessEvents query
4. **Phase 3 — CVE Correlation:**
   - **Q12**: Extract CVEs from alerts
   - For each CVE: **MDE-CVE-MACHINES** (`az rest`)
   - Cross-reference with devices that have the file
5. **Export JSON and summarize with remediation priorities**

---

## Security Notes

- All investigations are logged for audit purposes
- IoC values may be sensitive — handle with care
- Follow organizational data classification policies
- Consider threat actor attribution implications
- Document investigation actions for incident timeline

---

## Integration with Other Skills

This skill can be combined with:
- **user-investigation**: When IoC is found in user's sign-in logs
- **computer-investigation**: When IoC is found on specific device
- **kql-query-authoring**: For custom KQL queries beyond the templates

**Cross-skill pivot example:**
"Investigate IP 203.0.113.42" → Found in user sign-ins → "Investigate user@domain.com" using user-investigation skill