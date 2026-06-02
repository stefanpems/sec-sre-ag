---
name: incident-investigation
description: >
  Use this skill when asked to investigate a security incident by ID from Microsoft
  Defender XDR or Microsoft Sentinel. Triggers on keywords like "investigate incident",
  "incident ID", "incident investigation", "analyze incident", "triage incident", or when
  an incident number/ID is mentioned with investigation context.
  This skill provides comprehensive incident analysis including metadata retrieval,
  alert listing, asset enumeration, evidence filtering, and deep entity investigation
  using KQL queries via Azure Monitor MCP and specialized sub-skills.
  Environment: Azure Monitor MCP + Azure CLI — currently without Sentinel Data Lake MCP,
  Sentinel Triage MCP, or Microsoft Graph MCP (not yet connectable to Azure SRE Agent).
threat_pulse_domains: [incidents]
drill_down_prompt: 'Investigate incident {entity} — alert details, entity extraction, timeline reconstruction'
---

# Incident Investigation — Monitor MCP + Azure CLI

## Purpose

This skill performs comprehensive security investigations on incidents from **Microsoft Defender XDR** and **Microsoft Sentinel**. It retrieves incident details, lists alerts, enumerates assets and evidences, and then performs deep investigation on user-selected entities using appropriate sub-skills.

**Environment:** This skill operates in a constrained environment where:

- ✅ **Azure Monitor MCP tool** is available (`monitor-client_monitor_workspace_log_query`) for KQL queries against Log Analytics
- ✅ **`RunAzCliReadCommands` tool** is available for Azure CLI read operations (including `az rest` for MDE API and Graph API)
- ✅ **KQL Search MCP** (`mcp_kql-search-mc_*`) is available for schema validation and query examples
- ✅ **Microsoft Learn MCP** (`mcp_microsoft_lea_*` / `mcp_microsoft_le2_*`) is available for documentation
- ✅ **Azure MCP Server** (`mcp_azure_mcp_ser_*`) is available for Azure resource management
- ❌ **Sentinel Data Lake MCP** — not integrated (no `query_lake`, `list_sentinel_workspaces`, `search_tables`)
- ❌ **Sentinel Triage MCP** — not integrated (no `RunAdvancedHuntingQuery`, `GetIncidentById`, `ListAlerts`, `GetDefenderMachine`, etc.)
- ❌ **Microsoft Graph MCP** — not integrated (no `microsoft_graph_get`, `suggest_queries`)

> **Why these MCP servers are absent:** Sentinel Data Lake MCP, Sentinel Triage MCP, and Microsoft Graph MCP cannot currently be connected to Azure SRE Agent. This does **not** mean the underlying data is inaccessible — the data exposed by these servers (Sentinel Data Lake, Defender XDR / Advanced Hunting, Microsoft Graph) can be reached via direct API calls. However, direct API access to Sentinel Data Lake and Microsoft Graph as a replacement for these MCP servers has not yet been studied and implemented in this skill.

**Data sources (Log Analytics via KQL):** SecurityIncident, SecurityAlert, AlertEvidence, AlertInfo, DeviceInfo, SigninLogs, SecurityEvent.

**Data sources (MDE API via `az rest`):** Incident details (when KQL is insufficient), alert enrichment.

**Investigation Flow:**
1. **Phase 0: Cache Check** — Check for cached investigation results and determine reuse or fresh start
2. **Phase 1: Incident Description** — Retrieve metadata, alerts, assets, and evidences via KQL
3. **Phase 2: Incident Investigation Menu** — Ask the user to select the incident assets and entities that should be investigated
4. **Phase 2-A: User Investigation** — Follow user-investigation skill workflow
5. **Phase 2-B: Device Investigation** — Follow computer-investigation skill workflow
6. **Phase 2-C: IoC Investigation** — Follow ioc-investigation skill workflow for IPs, URLs, Files, Domains, Hashes
7. **Phase 3: Looping to Phase 2** — Ask the user to select further assets and entities to investigate

## Skill Files

| File | Purpose |
|------|---------|
| [SKILL.md](SKILL.md) | This file — skill instructions |
| [incident-queries.yaml](incident-queries.yaml) | Pre-built KQL queries (Q1–Q10) for incident data extraction |
| [generate_html_report.py](generate_html_report.py) | HTML report generator — reads JSON export, produces styled HTML report |

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/incident-investigation/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/incident-investigation/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("incident-investigation", "<filename>") from Builder
   → CreateFile("tmp/incident-investigation/<filename>", <content>)
   → Repeat for ALL companion files referenced by the script
```

**Rules:**
- When a file is found in `codeRefs/`, execute it directly from there — do NOT copy it to `tmp/`.
- When materializing from Builder (step 3), materialize ALL companion files the script depends on, not just the script itself.
- This cascade applies to every file listed in the Skill Files table above.

### Pre-requisite: Environment Configuration (config.json)

Before executing any script resolved via the File Resolution cascade, the agent MUST ensure that `config.json` exists at the **workspace root** (the top-level directory of the agent workspace, NOT inside `codeRefs/` or skill-specific directories).

**Procedure:**

1. **Check:** Verify that `config.json` exists at the workspace root and contains a non-empty `sentinel_workspace_id` value. If it does, skip to step 3.

2. **If `config.json` is missing or incomplete**, create it:
   a. **Ask the user** for the tenant name using AskUserQuestion with header "Tenant" and question: "What is your tenant name? (e.g., contoso.onmicrosoft.com or contoso.it)?"
   b. **Extract from agent system prompt settings:**
      - `subscription_id` → from the `<azure_resource_access>` section (the subscription ID the agent has access to)
      - `sentinel_workspace_id` → from the `<log_analytics_access>` section (the workspace GUID after `workspace=`)
      - `workspace_name` → from the `<log_analytics_access>` section (the workspace name before the colon)
   c. **Discover** the workspace resource group by running:
      ```
      az monitor log-analytics workspace show --workspace-name <workspace_name> --subscription <subscription_id> --query resourceGroup -o tsv
      ```
   d. **Create** `config.json` at the workspace root with this structure:
      ```json
      {
        "tenant_name": "<tenant_name>",
        "sentinel_workspace_id": "<workspace_guid>",
        "subscription_id": "<subscription_id>",
        "azure_mcp": {
          "subscription_id": "<subscription_id>",
          "resource_group": "<discovered_resource_group>",
          "workspace_name": "<workspace_name>"
        },
        "api_tokens": {}
      }
      ```

3. **Proceed** with the skill workflow. All Python scripts find `config.json` by walking up from their own directory (max 6 levels), so the workspace root is the correct and expected location.

**Rules:**
- Do NOT write `config.json` inside `codeRefs/` or inside skill-specific directories.
- Do NOT hardcode any environment-specific values in this skill file — all values are derived at runtime from the agent's own settings and user input.
- The `api_tokens` object is left empty — API tokens are loaded from Key Vault or environment variables at runtime.

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** — Start here!
2. **[Prerequisites](#prerequisites)**
3. **[Environment Configuration](#environment-configuration)**
4. **[Phase 0: Investigation Cache Check](#phase-0-investigation-cache-check-mandatory)** — Cache reuse logic
5. **[Phase 1: Incident Description](#phase-1-incident-description)** — Metadata, Alerts, Assets, Evidences
6. **[Phase 2: Incident Investigation Menu](#phase-2-incident-investigation-menu)** — Presenting the options
7. **[Phase 2-A: User Investigation](#phase-2-a-user-investigation)** — Using user-investigation skill
8. **[Phase 2-B: Device Investigation](#phase-2-b-device-investigation)** — Using computer-investigation skill
9. **[Phase 2-C: IoC Investigation](#phase-2-c-ioc-investigation)** — Using ioc-investigation skill (IPs, URLs, Files, Domains, Hashes)
10. **[Phase 3: Post Incident Investigation](#phase-3-post-investigation-loop-mandatory)** — Looping to phase 2
11. **[KQL Execution Reference](#kql-execution-reference)** — How to run queries
12. **[Incident KQL Queries](#incident-kql-queries)** — Pre-built queries
13. **[JSON Export Structure](#json-export-structure)** — Required fields
14. **[Error Handling](#error-handling)** — Troubleshooting guide

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY incident investigation:**

1. **ALWAYS complete Phase 0 (Cache Check) first** — Before any data collection, check for cached investigation results. See Phase 0 for full logic.
2. **ALWAYS complete Phase 1 after Phase 0** (unless cache provides complete data) — Retrieve full incident description before any deep investigation
3. **ALWAYS present extracted entities to user** — After Phase 1, ask user which entities to investigate
4. **ALWAYS wait for user confirmation** — Do not proceed with deep investigation until user selects entities
5. **ALWAYS use the correct sub-skills for each entity type:**
   - **Users** → Follow `user-investigation/SKILL.md`
   - **Devices** → Follow `computer-investigation/SKILL.md`
   - **IPs/URLs/Files/Domains/Hashes** → Follow `ioc-investigation/SKILL.md`
6. **ALWAYS track and report time** after each major step
7. **ALWAYS filter evidences** — Remove internal IPs (RFC1918) and tenant domains from investigation scope. Also remove all public IPs from the devices listed as assets involved in the incident.
8. **ALWAYS defang malicious/suspicious URLs and IPs** — NEVER return them as clickable links. Use defang format: `hxxps://evil[.]com`, `203[.]0[.]113[.]42`
9. **ALWAYS use Azure Monitor MCP for KQL execution** — Use `monitor-client_monitor_workspace_log_query` for all KQL queries
10. **ALWAYS use `RunAzCliReadCommands` for MDE API calls** — See `defender-api-via-cli.md` in `ioc-investigation/` for reference
11. **Default to inline output. Do NOT ask** the user for output mode. Present all findings inline in chat. Only generate a markdown file, HTML report, or JSON export if the user explicitly requests it.

**Incident ID Patterns:**
| Pattern | Source | KQL Query |
|---------|--------|-----------|
| Numeric (e.g., `12345`, `98765`) | Defender XDR / Sentinel | Q1: Filter by `IncidentNumber` |
| GUID format | Sentinel (internal) | Q1b: Filter by `IncidentName` |
| `INxx-xxxxx` format | Defender XDR | Q1: Filter by `ProviderIncidentId` |

**⚠️ Sentinel → Defender XDR ID Mapping (Critical):**

When an incident is discovered via Sentinel KQL (e.g., `SecurityIncident` or `SecurityAlert` tables), its IDs are **Sentinel-local** and may not map 1:1:

| Sentinel Field | Use For | Notes |
|---------------|---------|-------|
| `SecurityIncident.IncidentNumber` | KQL queries in this skill | Local Sentinel ID |
| `SecurityIncident.ProviderIncidentId` | Cross-referencing Defender XDR | The Defender XDR incident ID |
| `SecurityIncident.IncidentName` | GUID-based lookups | Sentinel internal GUID |

**Rule:** When querying `SecurityIncident`, **always project `ProviderIncidentId`** alongside `IncidentNumber` for cross-referencing.

**Date Range Rules:**
- **Default analysis window:** 7 days before current date to current date (Standard)
- **Investigation depth options:**
  - **Comprehensive:** 30 days window (for thorough analysis)
  - **Standard:** 7 days window (default)
  - **Quick:** 1 day window (for rapid triage)
- **Format:** ISO 8601 (e.g., `2026-01-17T00:00:00Z` to `2026-01-24T00:00:00Z`)

---

## Prerequisites

| Dependency | Required | Fallback | Notes |
|------------|----------|----------|-------|
| **Azure Monitor MCP** (`monitor-client_monitor_workspace_log_query`) | ✅ Yes | None — core dependency | Must be configured and connected to the target Log Analytics workspace |
| **`RunAzCliReadCommands` tool** | ⚠️ Optional | KQL-only mode | Used for MDE API calls via `az rest`. If unavailable, use KQL-only queries |
| **KQL Search MCP** (`mcp_kql-search-mc_*`) | ⚠️ Optional | Use queries from `incident-queries.yaml` directly | Schema validation, query examples |
| **Microsoft Learn MCP** (`mcp_microsoft_lea_*`) | ⚠️ Optional | N/A | Documentation reference |
| **Python 3.x** | ⚠️ Optional | KQL IP context queries | `enrich_ips.py` for IP enrichment (from `../user-investigation/`) |

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

## Phase 0: Investigation Cache Check (MANDATORY)

**This phase MUST execute BEFORE Phase 1. It determines whether to reuse cached investigation data or start a fresh investigation.**

### 0.1 Cache File Convention

Investigation results are stored as JSON files following this naming pattern:
```
temp/investigation_incident_<INCIDENT_ID>_<YYYYMMDD_HHMMSS>.json
```

### 0.2 Cache Check Workflow

```
Step 0.1: Search for existing cache files matching the incident ID
          → Use: ls temp/investigation_incident_<INCIDENT_ID>_*.json
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

Step 0.5: ASK the user using the AskUserQuestion tool:

          Question: "Ho trovato risultati di un'investigazione precedente per
                     l'incidente <ID>, completata <TIME_AGO> fa (alle <HH:MM> UTC).
                     Fasi completate: <PHASES_LIST>.
                     Vuoi utilizzare questi dati o preferisci ripetere
                     l'investigazione da zero?"
          Header: "Cache"
          Options:
            1. label: "Usa i dati esistenti"
               description: "Riprende dall'investigazione precedente, saltando le fasi già completate"
            2. label: "Ripeti da zero"
               description: "Ignora la cache e ricomincia l'investigazione completa"

          → If user selects "Usa i dati esistenti" → proceed to Step 0.6
          → If user selects "Ripeti da zero" → proceed to Phase 1 (fresh investigation)

Step 0.6: LOAD cached data:
          → Read the JSON file
          → Read investigation_metadata.phases_completed to identify completed phases
          → Present a brief inline summary of cached findings:
             - Incident metadata (title, severity, status, classification)
             - Number of alerts, assets, evidences
             - Investigation results already available (users, devices, IoCs)
          → Proceed to Phase 3 (Post-Investigation Loop) to offer investigation
             of remaining uninvestigated entities
          → If ALL entities were already investigated → present full summary
             and offer HTML/report generation if requested
```

### 0.3 Cache Decision Summary

| Cache Exists? | Age | User Prompt | Action |
|---------------|-----|-------------|--------|
| No | — | — | Fresh investigation (Phase 1) |
| Yes | > 4 hours | — | Fresh investigation (Phase 1) — cache expired |
| Yes | ≤ 4 hours | Contains REDO keyword | Fresh investigation (Phase 1) |
| Yes | ≤ 4 hours | Contains USE-CACHE keyword | Load cache (Step 0.6) |
| Yes | ≤ 4 hours | No implicit intent | ASK user (Step 0.5) |

### 0.4 Important Rules

- **NEVER silently reuse cached data** — always either detect explicit intent from the prompt or ask the user.
- **NEVER ask the user if the prompt already contains an implicit answer** — detect keywords first.
- **When loading cache, always show what was already completed** — the user must understand what data is from cache vs. new queries.
- **Cache files from a DIFFERENT thread/session are still valid** — the 4-hour TTL is the only expiration criterion.
- **If the user later requests a fresh investigation after loading cache** — discard all cached data and restart from Phase 1.

---

## Phase 1: Incident Description

**This phase retrieves and presents all incident information using KQL queries against Log Analytics.**

**All queries are pre-built in `incident-queries.yaml`. Execute them via `monitor-client_monitor_workspace_log_query`.**

### 1.1 Incident Metadata

**Execute Q1 (or Q1b for GUID lookups) from `incident-queries.yaml`.**

Retrieve and present:

| Field | Source Column |
|-------|--------------|
| **Title** | `Title` |
| **Description** | `Description` |
| **Status** | `Status` (New, Active, Closed) |
| **Severity** | `Severity` (High, Medium, Low, Informational) |
| **Classification** | `Classification` |
| **Classification Reason** | `ClassificationReason` |
| **Created Date** | `CreatedTime` |
| **First Activity Date** | `FirstActivityTime` |
| **Last Updated Date** | `LastModifiedTime` |
| **Closed Date** | `ClosedTime` (if closed) |
| **Assigned To** | `Owner` → `assignedTo` field from parsed JSON |
| **Provider** | `ProviderName` |
| **Incident Number** | `IncidentNumber` |
| **Provider Incident ID** | `ProviderIncidentId` (Defender XDR ID) |
| **Labels/Tags** | `Labels` |

**Also execute Q10 from `incident-queries.yaml`** to get MITRE Tactics & Techniques.

### 1.2 Incident Alerts

**Execute Q2 from `incident-queries.yaml`.**

For each alert, present:
- Alert name (`AlertName`)
- Severity (`AlertSeverity`)
- Status (`Status`)
- Tactics (`Tactics`)
- Detection source (`ProviderName` / `ProductName`)
- Compromised entity (`CompromisedEntity`)
- Start time (`StartTime`)
- End time (`EndTime`)

**Presentation Rules:**
1. Return as a table (exclude SystemAlertId from display)
2. Order by end time descending
3. Add row numbers starting from 1
4. If more than 30 alerts exist, note this after the table and provide a Defender portal link
5. NEVER calculate and write the total number of alerts

### 1.3 Incident Assets

**Execute Q5 (users), Q6 (devices), Q3 (all entities) from `incident-queries.yaml` in parallel.**

Present ALL assets involved in the incident by type:

**User Assets:**
| Field | Source |
|-------|--------|
| UPN | Q5 result |
| Display Name | Q5 result |
| Object ID | Q5 result |
| Alert Count | Q5 result |

**Device Assets:**
| Field | Source |
|-------|--------|
| Hostname / FQDN | Q6 result |
| OS | Q6 result |
| Domain Joined | Q6 result |
| Defender Device ID | Q6 result |
| Alert Count | Q6 result |

**Other Assets** (from Q3 — apps, cloud resources, mailboxes, etc.):
| Field | Source |
|-------|--------|
| Entity Type | Q3 result |
| Entity Name | Q3 result |
| Alert Count | Q3 result |

**Count assets by type ONLY after retrieving complete lists.**

### 1.4 Incident Evidences

**Execute Q4 (evidences), Q7 (IPs), Q8 (URLs/Domains), Q9 (file hashes) from `incident-queries.yaml` in parallel.**

Retrieve evidences classified as **malicious or suspicious** only:

**Processes (Top 10):**
- From Q4 results where EntityType is process
- Return only the **10 most probable signs of malicious activity** (use judgment)

**Files (Top 10):**
- From Q4 and Q9 results
- Return only the **10 most probable signs of malicious activity** (use judgment)

**IP Addresses (Top 10, Filtered):**
- From Q7 results (already filtered for RFC1918 private IPs)
- **Additionally filter out public IPs associated with devices listed as assets** (from Q6)
- Return only the first 10 from filtered list
- **DEFANG ALL IPs:** `203[.]0[.]113[.]42` — NEVER output clickable IPs

**URLs and DNS Domains (Top 10, Filtered):**
- From Q8 results
- **Filter out tenant domain URLs** (DNS domains associated with the organization)
- Return only the first 10 from filtered list
- **DEFANG ALL URLs AND DNS DOMAINS:** `hxxps://evil[.]com/path`, `evil[.]com` — NEVER output clickable URLs

**For each evidence type:** If more than 10 exist, note this after the table and provide Defender portal link.

---

## Phase 2: Incident Investigation Menu

### Step 2.1: Present Entity Summary

Show a summary of ALL incident entities and assets from Phase 1:
- Users (with UPN and display name)
- Devices (with hostname and risk context)
- URLs (defanged)
- IPs (defanged, filtered)
- File hashes
- Domains (defanged)

**🔴 DEFANG ALL URLs AND DOMAINS:** When presenting URLs and DNS Domains to the user, ALWAYS use defanged format: `hxxps://evil[.]com/path`, `hxxp://malware[.]net`, `evil[.]com`. NEVER output clickable malicious URLs.

**🔴 DEFANG ALL IPs:** When presenting IPs to the user, ALWAYS use defanged format: `203[.]0[.]113[.]42`. NEVER output clickable malicious indicators.

### Step 2.2: Ask User to Select Entities

Ask the user:

> "Which assets and entities involved in the incident should be investigated in depth? Please select them by providing their numbers or names, or simply ask to analyze all of them. The more entities you select, the longer the analysis will take."

**🔴 DO NOT OFFER OTHER OPTIONS:** Only ask the user whether they want to investigate one or more of the incident entities and assets listed above in more depth.

Read the response.
- If they do not want to proceed with the proposed investigations, ask them what they want to do.
- If they want to proceed with one or more of the proposed investigations, continue with Step 2.3.

### Step 2.3: Start Investigations

Proceed in accordance with the instructions described below for Phase 2-A, Phase 2-B, and Phase 2-C.
When multiple investigation types are selected (users, devices, IoCs) run them in parallel as much as possible.

---

## Phase 2-A: User Investigation

### Pre-requisites (MANDATORY)

**⛔ VERIFY BEFORE PROCEEDING:**
- ✅ User has explicitly selected which user(s) to investigate
- ✅ Phase 1 is complete

**If any pre-requisite is FALSE:** STOP and return to Phase 2.

### User Investigation Workflow

**⚡ PARALLEL EXECUTION:** When multiple users are selected, execute user investigations in parallel as much as possible.

For EACH user selected by the user:

**🔴 REFERENCE THE SKILL FILE:** Read and follow the complete workflow defined in:
```
user-investigation/SKILL.md
```

**Key Steps (summary — see skill file for full details):**
1. Get User Object ID (Graph API via `RunAzCliReadCommands` or KQL fallback Q0)
2. Calculate date ranges based on investigation type (Standard/Quick/Comprehensive)
3. Run parallel data collection:
   - Sign-in anomalies (Signinlogs_Anomalies_KQL_CL)
   - Sign-in statistics (apps, locations, IPs)
   - Audit log events
   - Office 365 activity
   - Security incidents involving user
   - Identity Protection risk detections
   - MFA and authentication methods
   - Device compliance status
4. IP enrichment for flagged addresses
5. Compile and present findings
6. Generate HTML report (if requested)

**DO NOT copy the full workflow here — always read the skill file for the most current instructions.**

---

## Phase 2-B: Device Investigation

### Device Investigation Workflow

**⚡ PARALLEL EXECUTION:** When multiple devices are selected, execute device data collection queries in parallel for ALL devices simultaneously. Run security alerts, compliance, logged-on users, network/process/file events queries concurrently.

For EACH device selected by the user:

**🔴 REFERENCE THE SKILL FILE:** Read and follow the complete workflow defined in:
```
computer-investigation/SKILL.md
```

**Key Steps (summary — see skill file for full details):**
1. Get Device IDs (Entra Device ID + Defender Device ID)
2. Determine device type (Entra Joined, Hybrid Joined, Entra Registered)
3. Run parallel data collection:
   - Security alerts for device
   - Device compliance status
   - Logged-on users
   - Network connections
   - Process events
   - File events
   - Registry modifications
4. Compile and present findings

**DO NOT copy the full workflow here — always read the skill file for the most current instructions.**

---

## Phase 2-C: IoC Investigation

### IoC Investigation Workflow

**⚡ PARALLEL EXECUTION:** When multiple IoCs are selected, execute ALL IoC investigation queries in parallel. Run threat intel lookups, KQL queries, and organizational exposure queries concurrently for all IoCs.

For EACH IoC selected by the user:

**🔴 REFERENCE THE SKILL FILE:** Read and follow the complete workflow defined in:
```
ioc-investigation/SKILL.md
```

**Supported IoC Types:**
| IoC Type | Detection Pattern | Key Investigation Points |
|----------|-------------------|-------------------------|
| **URL** | `https?://` or domain pattern | Malicious indicators, phishing, threat intel, organizational exposure |
| **IPv4 Address** | `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` | Threat intel, network connections, geographic analysis |
| **IPv6 Address** | Contains multiple colons | Same as IPv4 |
| **Domain** | `[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}` | DNS queries, email threats, reputation |
| **MD5 Hash** | 32 hex characters | File prevalence, malware analysis |
| **SHA1 Hash** | 40 hex characters | File prevalence, malware analysis |
| **SHA256 Hash** | 64 hex characters | File prevalence, malware analysis |

**Key Steps (summary — see skill file for full details):**
1. Identify IoC type and normalize
2. Run 3rd-party IP enrichment (for IP IoCs — `enrich_ips.py`)
3. Query Sentinel ThreatIntelligenceIndicator table (KQL via Monitor MCP)
4. Query MDE API via `RunAzCliReadCommands` (IP alerts, file info, custom IOC list)
5. Analyze organizational exposure (DeviceNetworkEvents, AlertEvidence)
6. Correlate with CVEs if applicable
7. Present findings with risk assessment

**DO NOT copy the full workflow here — always read the skill file for the most current instructions.**

---

## Phase 3: Post-Investigation Loop (MANDATORY)

### ⛔ CRITICAL: DO NOT END THE RESPONSE WITHOUT COMPLETING THIS PHASE

**After completing ALL selected entity investigations in Phase 2, you MUST:**

1. **List remaining uninvestigated entities** — Show all entities from Phase 1 that were NOT yet investigated
2. **Ask the user to select additional entities** — Prompt user to continue or conclude
3. **Wait for user response** — Do not assume the investigation is complete

### Phase 3 Checklist (Execute After Every Phase 2 Completion)

```
☐ Step 3.1: Compile list of UNINVESTIGATED entities (exclude already-investigated items)
☐ Step 3.2: Present remaining entities to user with numbered list
☐ Step 3.3: Ask: "Would you like to investigate any of the remaining entities? Select by number/name, or say 'done' to conclude."
☐ Step 3.4: Wait for user response before concluding
```

### Required Prompt Format

After presenting investigation findings, ALWAYS end with:

> **📋 Remaining Uninvestigated Entities:**
>
> | # | Type | Entity | Notes |
> |---|------|--------|-------|
> | 1 | Device | [DEVICE_NAME] | [Risk level or relevant context] |
> | 2 | File | [FILENAME] | [Hash or detection status] |
> | 3 | URL | [DEFANGED_URL] | [Threat assessment] |
> | ... | ... | ... | ... |
>
> **Would you like to investigate any of these remaining entities?** Select by number/name, type "all" to investigate everything, or say "done" to conclude the investigation.

### Rules

- **DO NOT** include entities that were already investigated in the list
- **DO NOT** provide a final summary or recommendations until the user explicitly says "done" or declines further investigation
- **DO NOT** assume the investigation is complete just because selected entities were analyzed

### Loop Behavior

```
IF user selects additional entities:
    → Return to Phase 2 (2-A, 2-B, or 2-C based on entity type)
    → After completion, return to Phase 3 again

ELSE IF user says "done" or declines:
    → Proceed to Final Summary
    → Provide recommendations
    → Offer HTML/MD/JSON report only if the user explicitly requests it
```

### Output Modes

| Mode | When | What |
|------|------|------|
| **Inline** (default) | Always | Present all findings, alerts, assets, evidences, and recommendations directly in chat |
| **Markdown file** | Only if user explicitly requests | Save full investigation report as `.md` file |
| **HTML report** | Only if user explicitly requests | Resolve `generate_html_report.py` via [File Resolution cascade](#file-resolution-coderefs-first) and run: `python3 <resolved_path>/generate_html_report.py <json_file> --output-dir reports/incident-investigation/` |
| **JSON export** | Only if user explicitly requests | Save investigation data using the JSON Export Structure below |

> **Conditional — File Resolution Cascade:** The `generate_html_report.py` script is resolved ONLY when the user requests HTML output.
> 1. Check `codeRefs/sec-sre-ag/incident-investigation/generate_html_report.py` → if found, use that path.
> 2. Else check `tmp/incident-investigation/generate_html_report.py` → if found, use that path.
> 3. Else: `read_skill_file("incident-investigation", "generate_html_report.py")` → `CreateFile("tmp/incident-investigation/generate_html_report.py", <content>)`
> 4. Run: `python3 <resolved_path>/generate_html_report.py <json_file> --output-dir reports/incident-investigation/`
> Resolve via cascade only when the user requests an HTML report.

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
| `table` | Yes | Primary table for the query (e.g., `SecurityIncident`) |
| `query` | Yes | KQL query string |
| `hours` | Optional | Lookback period in hours (overrides in-query time filters) |

### Fallback: Azure CLI via RunAzCliReadCommands

If the Monitor MCP tool fails, use `RunAzCliReadCommands` with:

```
az monitor log-analytics query --workspace "<workspace_GUID>" --analytics-query "<KQL_QUERY>" --timespan "P7D" --subscription <subId>
```

> **⚠️ Shell `az` vs Tool:** The `az` CLI binary may NOT be in the shell PATH. Always use the `RunAzCliReadCommands` tool, not `RunInTerminal` with `az` commands.

### Known Table Pitfalls (Log Analytics)

| Table | Pitfall | Fix |
|-------|---------|-----|
| **SecurityIncident** | `AlertIds` is a JSON array — must `parse_json()` before `mv-expand` | Use `mv-expand AlertId = parse_json(AlertIds)` |
| **SecurityIncident** | `Owner` is a JSON string — must `parse_json()` to extract fields | Use `parse_json(Owner).assignedTo` |
| **SecurityIncident** | Multiple rows per incident (one per status change) | Use `summarize arg_max(TimeGenerated, *) by IncidentNumber` |
| **SecurityAlert** | `Entities` is a JSON array — must `parse_json()` before `mv-expand` | Use `mv-expand Entity = parse_json(Entities)` |
| **SecurityAlert** | `Status` field is **immutable** — always "New" | Join with SecurityIncident for real status |
| **SecurityAlert** | `Tactics` and `Techniques` may be JSON strings | `parse_json()` before extraction |
| **AlertEvidence** | May not be present in all workspaces | Handle "Failed to resolve table" gracefully |

---

## Incident KQL Queries

All incident-related queries are stored in **`incident-queries.yaml`** in this directory. The queries replace the Sentinel Triage MCP tools (`GetIncidentById`, `ListAlerts`, etc.) with equivalent KQL queries against Log Analytics tables.

### Query Index

| ID | Name | Purpose | Primary Table |
|----|------|---------|---------------|
| Q1 | IncidentMetadata | Incident metadata by numeric ID | SecurityIncident |
| Q1b | IncidentMetadataByGuid | Incident metadata by GUID | SecurityIncident |
| Q2 | IncidentAlerts | All alerts correlated to incident | SecurityIncident → SecurityAlert |
| Q3 | IncidentEntities | All entities from alert data | SecurityIncident → SecurityAlert |
| Q4 | IncidentEvidences | Malicious/suspicious evidence | SecurityIncident → AlertEvidence |
| Q5 | IncidentUsers | Distinct user assets | SecurityIncident → SecurityAlert |
| Q6 | IncidentDevices | Distinct device assets | SecurityIncident → SecurityAlert |
| Q7 | IncidentIPs | Distinct public IPs (RFC1918 filtered) | SecurityIncident → SecurityAlert |
| Q8 | IncidentURLsDomains | Distinct URLs and domains | SecurityIncident → SecurityAlert |
| Q9 | IncidentFileHashes | Distinct file hashes | SecurityIncident → SecurityAlert |
| Q10 | IncidentMITRE | MITRE tactics & techniques | SecurityIncident → SecurityAlert |

### Execution Pattern

**Phase 1 Step 1 — Metadata + MITRE (run in parallel):**
```
Q1 (or Q1b) + Q10
```

**Phase 1 Step 2 — Alerts:**
```
Q2
```

**Phase 1 Step 3 — Assets + Evidences (run ALL in parallel):**
```
Q3 + Q4 + Q5 + Q6 + Q7 + Q8 + Q9
```

### How to Use

Read the query from `incident-queries.yaml`, replace the `<INCIDENT_ID>` placeholder with the actual incident number, and execute via `monitor-client_monitor_workspace_log_query`.

**Example:**
```
Tool: monitor-client_monitor_workspace_log_query
Parameters:
  workspace: <WORKSPACE_GUID>
  subscription: <SUBSCRIPTION_ID>
  resource-group: <RESOURCE_GROUP>
  table: SecurityIncident
  query: |
    SecurityIncident
    | where IncidentNumber == 12345 or ProviderIncidentId == "12345"
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project IncidentNumber, ProviderIncidentId, Title, Description, Severity, Status, ...
```

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

## JSON Export Structure

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `investigation_metadata` | object | Incident ID, timestamp, investigation phases completed |
| `incident_details` | object | Metadata, alerts, assets, evidences from Phase 1 |
| `user_investigations` | array | Results from Phase 2-A (user-investigation skill) |
| `device_investigations` | array | Results from Phase 2-B (computer-investigation skill) |
| `ioc_investigations` | array | Results from Phase 2-C (ioc-investigation skill — includes IPs, URLs, Files, Domains, Hashes) |
| `summary` | object | Key findings, risk assessment, recommendations |

### Example JSON Structure

```json
{
  "investigation_metadata": {
    "incident_id": "<INCIDENT_ID>",
    "provider_incident_id": "<DEFENDER_XDR_ID>",
    "investigation_timestamp": "<ISO_TIMESTAMP>",
    "phases_completed": ["incident_description", "user_investigation", "device_investigation", "ioc_investigation"],
    "total_elapsed_time_seconds": 300,
    "workspace_id": "<WORKSPACE_GUID>"
  },
  "incident_details": {
    "metadata": {
      "title": "<INCIDENT_TITLE>",
      "description": "<DESCRIPTION>",
      "severity": "<SEVERITY>",
      "status": "<STATUS>",
      "classification": "<CLASSIFICATION>",
      "classification_reason": "<REASON>",
      "created_date": "<TIMESTAMP>",
      "first_activity_date": "<TIMESTAMP>",
      "last_updated_date": "<TIMESTAMP>",
      "assigned_to": "<ANALYST>",
      "mitre_tactics": ["<TACTIC1>", "<TACTIC2>"],
      "mitre_techniques": ["<TECHNIQUE1>", "<TECHNIQUE2>"],
      "labels": ["<TAG1>", "<TAG2>"]
    },
    "alerts": [
      {
        "name": "<ALERT_NAME>",
        "severity": "<SEVERITY>",
        "status": "<STATUS>",
        "tactics": "<TACTICS>",
        "detection_source": "<SOURCE>",
        "start_time": "<TIMESTAMP>",
        "end_time": "<TIMESTAMP>"
      }
    ],
    "assets": {
      "users": [
        {
          "upn": "user@domain.com",
          "display_name": "<NAME>",
          "object_id": "<GUID>",
          "alert_count": 3
        }
      ],
      "devices": [
        {
          "hostname": "<DEVICE>",
          "fqdn": "<FQDN>",
          "os": "<OS>",
          "defender_device_id": "<ID>",
          "alert_count": 2
        }
      ],
      "other_entities": []
    },
    "evidences": {
      "processes": [],
      "files": [],
      "ip_addresses": [],
      "urls": [],
      "domains": [],
      "file_hashes": []
    }
  },
  "user_investigations": [],
  "device_investigations": [],
  "ioc_investigations": [],
  "summary": {
    "risk_assessment": "High",
    "key_findings": [],
    "recommendations": []
  }
}
```

---

## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Incident not found in SecurityIncident** | Verify incident ID format; try both `IncidentNumber` and `ProviderIncidentId`; expand time range |
| **SecurityIncident table not found** | Table may not be synced to this workspace; check workspace configuration |
| **AlertEvidence table not found** | Table requires M365D data connector; proceed without evidence data |
| **No alerts returned from Q2** | Check if `AlertIds` field is populated in the SecurityIncident record; try Q3 entities approach |
| **User Object ID not found** | Verify UPN is correct; try Graph API via `RunAzCliReadCommands` or KQL Q0 fallback |
| **Device investigation fails** | Verify device exists in DeviceInfo table; try hostname variations |
| **IoC investigation timeout** | Reduce date range; check IoC format |
| **MDE API 403 error** | Check `RunAzCliReadCommands` permissions; fall back to KQL-only mode |

### Table Availability Check

If a query returns "Failed to resolve table", the table is not available in the workspace. Handle gracefully:

```
IF SecurityIncident fails:
    → Report: "SecurityIncident table is not available. Ensure the Sentinel data connector is enabled."
    → STOP investigation

IF AlertEvidence fails:
    → Report: "AlertEvidence table not available — evidence data will be limited."
    → Continue with SecurityAlert Entities extraction only (Q3)

IF DeviceNetworkEvents/DeviceProcessEvents/etc. fail:
    → Report: "Advanced Hunting tables not synced to Log Analytics."
    → Continue with available tables
```

### Time Window Limits

| Tool | Time Window Options |
|------|---------------------|
| User Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |
| Computer Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |
| IoC Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |

---

## Example Investigation Workflow

**User Request:** "Investigate incident 12345"

### Phase 0: Cache Check
```
[00:00] Checking for cached investigation data...
        → Found: temp/investigation_incident_12345_20260601_100000.json
        → Age: 2h 30m (within 4h threshold)
        → User prompt "Investigate incident 12345" — no implicit redo/cache keyword
        → Asking user whether to use cached data or start fresh...
        → User selected: "Ripeti da zero"
        → Proceeding with fresh investigation
```

### Phase 1: Incident Description
```
[00:05] Starting fresh incident investigation for ID: 12345

Step 1: Running Q1 (metadata) + Q10 (MITRE) in parallel via Monitor MCP...
Step 2: Running Q2 (alerts) via Monitor MCP...
Step 3: Running Q3-Q9 (entities, evidences) in parallel via Monitor MCP...

### Incident Metadata
- **Title:** Multi-stage attack with credential theft
- **Severity:** High
- **Status:** Active
- **Classification:** TruePositive
- **Created:** 2026-01-20T10:30:00Z
- **Provider Incident ID:** 12345 (Defender XDR)
- **MITRE Tactics:** Initial Access, Credential Access, Lateral Movement

### Incident Alerts
| # | Alert Name | Severity | Status | Tactics | Last Activity |
|---|------------|----------|--------|---------|---------------|
| 1 | Suspicious sign-in from unusual location | High | New | InitialAccess | 2026-01-23 |
| 2 | Credential theft attempt detected | High | New | CredentialAccess | 2026-01-22 |
| ... | ... | ... | ... | ... | ... |

### Incident Assets
**Users:**
| UPN | Display Name | Alert Count |
|-----|-------------|-------------|
| jsmith@contoso.com | John Smith | 3 |
| admin@contoso.com | Admin Account | 2 |

**Devices:**
| Hostname | OS | Alert Count |
|----------|-----|-------------|
| WORKSTATION-01 | Windows | 4 |
| LAPTOP-EXEC | Windows | 2 |

### Incident Evidences
**IPs (after filtering):**
- `203[.]0[.]113[.]42` (3 alerts — C2 communication)
- `198[.]51[.]100[.]10` (2 alerts — Data exfiltration)

**URLs (after filtering):**
- `hxxps://evil-site[.]com/payload[.]exe` (Malicious)

[01:30] Phase 1 completed (90 seconds)
```

### Phase 2: Investigation Menu
```
Which assets and entities involved in the incident should be investigated in depth?

1. 👤 jsmith@contoso.com (John Smith) — 3 alerts
2. 👤 admin@contoso.com (Admin Account) — 2 alerts
3. 💻 WORKSTATION-01 — 4 alerts
4. 💻 LAPTOP-EXEC — 2 alerts
5. 🌐 203[.]0[.]113[.]42 — 3 alerts
6. 🌐 198[.]51[.]100[.]10 — 2 alerts
7. 🔗 hxxps://evil-site[.]com/payload[.]exe

Select by number/name, type "all" to investigate everything.
```

[Investigation continues following sub-skills...]

---

## Integration with Sub-Skills

This skill orchestrates investigations by referencing specialized skills:

| Investigation Phase | Skill | Location |
|--------------------|-------|----------|
| Phase 0: Cache Check | Built-in logic | This file (SKILL.md) |
| Phase 1: Incident Description | Built-in KQL queries | `incident-queries.yaml` (this directory) |
| Phase 2-A: User Investigation | user-investigation skill | `user-investigation/SKILL.md` |
| Phase 2-B: Device Investigation | computer-investigation skill | `computer-investigation/SKILL.md` |
| Phase 2-C: IoC Investigation | ioc-investigation skill | `ioc-investigation/SKILL.md` |

**🔴 ALWAYS read the referenced skill file before executing that phase to ensure proper workflow execution.**
