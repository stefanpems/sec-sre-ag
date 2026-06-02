---
name: user-investigation
description: >
  User security investigation skill for environments with Azure Monitor MCP
  (Log Analytics workspace queries) and Azure CLI access — currently without
  Sentinel Data Lake MCP, Sentinel Triage MCP, or Microsoft Graph MCP
  (not yet connectable to Azure SRE Agent; direct API access to Sentinel Data Lake and Microsoft Graph not yet implemented).
  Entra ID user data is collected via RunAzCliReadCommands tool (Graph API)
  or KQL fallback queries from SigninLogs.
  KQL queries run against Log Analytics tables through the Azure Monitor MCP tool.
---

# User Security Investigation — Monitor MCP + Azure CLI

## Purpose

This skill performs comprehensive security investigations on Entra ID user accounts in environments where:

- ✅ **Azure Monitor MCP tool** is available (`monitor-client_monitor_workspace_log_query`) for KQL queries against Log Analytics
- ✅ **`RunAzCliReadCommands` tool** is available for Azure CLI read operations (including `az rest` for Graph API)
- ⚠️ **Azure CLI terminal** (`az` in shell) may NOT be available — use `RunAzCliReadCommands` tool instead
- ⚠️ **Microsoft Graph MCP Server for Enterprise** (`mcp_microsoft_ent_*`) is not available for integration with Azure SRE Agent, but access to Entra ID data is possible and implemented in this skill via direct Graph API calls (`az rest` / `RunAzCliReadCommands`). The agent’s User-Assigned Managed Identity must be granted the required Graph API permissions (see the README — Managed Identity Permissions section). KQL-based fallback queries are provided if Graph API permissions are not granted.
- ❌ **Sentinel Data Lake MCP** — not integrated (no `query_lake`, `list_sentinel_workspaces`, `search_tables`)
- ❌ **Sentinel Triage MCP** — not integrated (no `RunAdvancedHuntingQuery`, `GetIncidentById`, `GetDefenderMachine`, etc.)
- ❌ **Microsoft Graph MCP** — not integrated (no `microsoft_graph_get`, `suggest_queries`)

> **Why these MCP servers are absent:** Sentinel Data Lake MCP, Sentinel Triage MCP, and Microsoft Graph MCP cannot currently be connected to Azure SRE Agent. This does **not** mean the underlying data is inaccessible — the data exposed by these servers (Sentinel Data Lake, Defender XDR / Advanced Hunting, Microsoft Graph) can be reached via direct API calls. However, direct API access to Sentinel Data Lake and Microsoft Graph as a replacement for these MCP servers has not yet been studied and implemented in this skill.

**Data sources:** SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, SecurityAlert, SecurityIncident, OfficeActivity, CloudAppEvents, AADUserRiskEvents, ThreatIntelIndicators, Anomalies, Signinlogs_Anomalies_KQL_CL (custom, if present), Identity Protection (via `RunAzCliReadCommands` or KQL fallback).

**Skill files:**
- `SKILL.md` — this file (investigation workflow, KQL queries, report templates)
- `generate_html_report.py` — consolidated HTML report generator (dataclasses + HTML engine + JSON transformer, single self-contained file)
- `enrich_ips.py` — IP enrichment script (AbuseIPDB, ipinfo.io, vpnapi.io, Shodan)
- `get-entra-user-context-via-tool.md` — step-by-step Graph API reference for RunAzCliReadCommands

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/user-investigation/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/user-investigation/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("user-investigation", "<filename>") from Builder
   → CreateFile("tmp/user-investigation/<filename>", <content>)
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

1. **[Prerequisites](#prerequisites)**
2. **[Environment Configuration](#environment-configuration)**
3. **[Secrets Management (API Tokens)](#secrets-management-api-tokens)**
4. **[Critical Workflow Rules](#critical-workflow-rules)**
5. **[Investigation Types](#investigation-types)**
6. **[Output Modes](#output-modes)**
7. **[Quick Start](#quick-start)**
8. **[Execution Workflow](#execution-workflow)**
9. **[KQL Execution Reference](#kql-execution-reference)**
10. **[Sample KQL Queries](#sample-kql-queries)**
11. **[Entra ID Data Collection](#entra-id-data-collection)**
12. **[Markdown Report Template](#markdown-report-template)**
13. **[JSON Export Structure](#json-export-structure)**
14. **[Error Handling](#error-handling)**

**Investigation shortcuts:**
- **Risky user quick triage**: Q6 (incidents) → Q2 (anomalies) → Q12 (UEBA) → Q3d (IPs) → Entra Context
- **Compromised user forensics**: Q3 (sign-ins) → Q5 (Office) → Q3d (IPs) → Q1 (priority IPs for enrichment)
- **Password spray target**: Q3c (failures) → Q3d (IPs) → Q6 (incidents)
- **Post-incident user timeline**: Q4 (audit) → Q5 (O365) → Q10 (DLP) → Q6 (incidents)
- **IP enrichment for user**: Q1 (IP extraction) → Q11 (TI matches) → `enrich_ips.py` (if tokens available) OR Q13 (KQL IP context)
- **UEBA behavioral context**: Q12 (Anomalies table) → Q6 (incidents) → Q4 (audit trail)

> **⛔ Shortcut Default Rule:** When a matching shortcut exists, **use it** — don't run the full workflow. Only run full Batch 1 + Batch 2 when the user explicitly requests "full investigation", "comprehensive", or "deep dive".

---

## Prerequisites

| Dependency | Required | Fallback | Notes |
|------------|----------|----------|-------|
| **Azure Monitor MCP** (`monitor-client_monitor_workspace_log_query`) | ✅ Yes | None — core dependency | Must be configured and connected to the target workspace |
| **`RunAzCliReadCommands` tool** | ⚠️ Optional | KQL-only mode | Used for Graph API calls via `az rest`. If unavailable, all data comes from KQL |
| **Graph API permissions** | ⚠️ Optional | KQL-based fallback (Q0) | `User.Read.All`, `UserAuthenticationMethod.Read.All`, `IdentityRiskEvent.Read.All`, `IdentityRiskyUser.Read.All` |
| **Python 3.x** | ⚠️ Optional | Q13 (KQL IP context) | `enrich_ips.py` is included for external API enrichment (ipinfo, AbuseIPDB, vpnapi, Shodan). Requires API tokens. If unavailable, use Q13 KQL fallback. |

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

### Secondary: config.json (Auto-Generated)

The agent auto-generates `config.json` at the workspace root from its platform settings before running any skill script. See the sentinel-ingestion-report skill for the full Config Auto-Generation procedure.

### Configuration Resolution Order

1. **Agent settings** (`<log_analytics_access>`, `<azure_resource_access>`) — always available
2. **config.json** — auto-generated at workspace root; read if present, skip if absent
3. **Never prompt the user** for workspace parameters if either source is available

> **API tokens:** `enrich_ips.py` reads API tokens from environment variables (`ABUSEIPDB_TOKEN`, `IPINFO_TOKEN`, `VPNAPI_TOKEN`, `SHODAN_TOKEN`) or from `api_tokens` in `config.json`. The agent retrieves these tokens from Azure Key Vault (`slrakv1`) at runtime and sets them as environment variables before executing the script. No manual token configuration is needed in `config.json`.

---

## Secrets Management (API Tokens)

`enrich_ips.py` uses 4 external threat intelligence APIs. Each requires an API token. Tokens are resolved by the script in this order of precedence (highest wins):

1. **Environment variables** (highest priority) — always checked
2. **`.env` file** in the script directory — auto-loaded by python-dotenv
3. **`config.json`** in the script directory — optional fallback, NOT required

**No file is required.** Environment variables alone are sufficient.

### Required Environment Variables

| Variable | API | What it provides |
|----------|-----|------------------|
| `IPINFO_TOKEN` | ipinfo.io | Geolocation, ASN, VPN/proxy/Tor |
| `ABUSEIPDB_TOKEN` | AbuseIPDB | Abuse score, reports, comments |
| `VPNAPI_TOKEN` | vpnapi.io | VPN/proxy/Tor/relay detection |
| `SHODAN_TOKEN` | Shodan | Open ports, services, CVEs, tags |

### Options for Configuring Tokens

| # | Option | Security | How it works |
|---|--------|----------|-------------|
| 1 | **Azure Key Vault** | 🟢 High | Store tokens in a Key Vault. The agent reads them with `az rest --resource "https://vault.azure.net"` via `RunAzCliReadCommands` and sets env vars before running `enrich_ips.py`. |
| 2 | **Environment variables in-session** | 🟡 Medium | Tell the agent the tokens in chat; it sets them as temporary env vars for the duration of the script execution. |
| 3 | **No tokens at all** | 🟢 High | The skill uses **Q13** (KQL-based IP analysis) + **Q11** (ThreatIntelIndicators) + **Shodan InternetDB** (free, no key needed). |

### Behavior Without Tokens

- No tokens at all: only Shodan InternetDB (free, no key) → open ports, CVEs, tags
- Without `SHODAN_TOKEN`: automatic fallback to InternetDB (less data but works)
- Without `ABUSEIPDB_TOKEN`: no reputation/abuse data

---

## Critical Workflow Rules

**Before starting ANY user investigation:**

1. **ALWAYS get User Object ID FIRST** — try Graph API via `RunAzCliReadCommands`, fall back to KQL (Q0)
2. **ALWAYS calculate date ranges correctly** — see [Date Range Quick Reference](#date-range-quick-reference)
3. **ALWAYS ask the user for output mode** if not specified (inline / markdown / HTML)
4. **ALWAYS track and report time after each major step**
5. **ALWAYS use `create_file` for JSON export and markdown reports** — NEVER use terminal commands for file output
6. **Read workspace parameters** from agent settings first, then config.json if needed
7. **⛔ ALWAYS use `RunAzCliReadCommands` for Graph API calls** — NEVER use `RunAzCliWriteCommands` for `az rest --method GET` requests. The two tools have DIFFERENT authorization flows: `RunAzCliReadCommands` authenticates via Managed Identity directly (works with Application permissions). `RunAzCliWriteCommands` falls back to On-Behalf-Of (OBO) flow when MI fails, and OBO requires Delegated permissions that are NOT configured. Using the wrong tool causes 403 errors.
8. **⛔ ALWAYS run `enrich_ips.py` for IP enrichment** — This is MANDATORY, not optional. Before running: (a) try reading API tokens from Key Vault via `RunAzCliReadCommands`, (b) if Key Vault unavailable, ASK the user for API tokens, (c) if no tokens at all, run anyway — Shodan InternetDB (free, no key) still provides open ports, CVEs, and tags. Q13 (KQL) and Q11 (ThreatIntelIndicators) are SUPPLEMENTS, not replacements.
9. **⛔ ALWAYS generate the complete formatted report** — Every investigation MUST produce the full report following the [Markdown Report Template](#markdown-report-template), with ALL sections populated (use `✅ No <X> detected...` for empty sections). Never skip the report, never abbreviate, never omit sections.

### User Context Retrieval Strategy

```
Strategy 1: RunAzCliReadCommands + az rest (Graph API)
    ↓ If 403/401 or tool unavailable
Strategy 2: KQL Fallback Queries (Q0a, Q0b, Q0c) from SigninLogs
    ↓ If SigninLogs empty (user never signed in)
Strategy 3: Report "User has no sign-in activity in retention period"
```

**IMPORTANT:** If Graph API fails with 403, do NOT abort the investigation. Proceed immediately with KQL fallback.

---

## Investigation Types

### Standard Investigation (7 days)
General security reviews, routine investigations.

### Quick Investigation (1 day)
Urgent cases, recent suspicious activity.

### Comprehensive Investigation (30 days)
Deep-dive analysis, compliance reviews, thorough forensics.

---

## Output Modes

**ASK the user which they prefer** if not explicitly specified. Multiple modes may be selected simultaneously.

### Mode 1: Inline Chat Summary (Default)
- Render the full analysis directly in the chat response
- No file output — results stay in chat context

### Mode 2: Markdown File Report
- Save to `reports/user-investigations/user_investigation_<username>_<YYYYMMDD_HHMMSS>.md`
- Uses the [Markdown Report Template](#markdown-report-template) below
- Use `create_file` tool — NEVER use terminal commands for file output

### Mode 3: HTML Report (Conditional Materialization)
- Export investigation data to JSON, then generate a styled HTML report via `generate_html_report.py`
- Self-contained HTML with embedded CSS/JS — dark theme, two-column layout, interactive IP cards, risk-colored visualizations
- **Single consolidated script:** `generate_html_report.py` — contains dataclasses, HTML generator, and JSON transformer in one file. No external dependencies beyond Python 3 stdlib.
- The generator reads pre-enriched investigation JSON (IP enrichment must be completed BEFORE generating HTML), computes dynamic risk assessment, and produces the styled report.
- **Pipeline:** JSON export (with `ip_enrichment` array) → materialize `generate_html_report.py` → run → HTML report
- **Output location:** `reports/user-investigations/Investigation_Report_<username>_<timestamp>.html`
- **⚠️ Conditional materialization:** The script is materialized to disk ONLY when the user requests HTML output. See [Phase 4 → Mode 3](#mode-3--html-report-conditional-materialization) for the workflow.

### Markdown Rendering Notes
- ✅ ASCII tables, box-drawing characters, and bar charts render perfectly in markdown code blocks
- ✅ Unicode block characters render correctly in monospaced fonts
- ✅ Emoji indicators (🔴🟢🟡⚠️✅) render natively in GitHub-flavored markdown
- ✅ Standard markdown tables render as formatted tables

---

## Quick Start

1. **Discover workspace parameters** from agent settings (`<log_analytics_access>`, `<azure_resource_access>`).
2. **Get User Context** (cascading strategy): Try Graph API → KQL Fallback (Q0a, Q0b, Q0c)
3. **Determine Output Mode:** If user specified: use that mode. Otherwise: ASK.
4. **Run KQL Queries (via Monitor MCP):**
   - Batch 1: Q1, Q2, Q12, Q3/3b/3c, Q4, Q5, Q6, Q10
   - After Batch 1: Extract IP array
   - Batch 2: Q3d, Q11, Q13
5. **Run IP Enrichment (MANDATORY):** enrich_ips.py
6. **Generate Output** based on selected mode.

---

## Execution Workflow

### 🚨 MANDATORY: Time Tracking

```
[MM:SS] ✓ Step description (XX seconds)
```

---

### Phase 1: Get User Context (Cascading Strategy)

#### Strategy 1: Graph API via RunAzCliReadCommands tool

See `get-entra-user-context-via-tool.md` for the full step-by-step reference.

**Step 1a — User Profile:**
```
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<UPN>?$select=id,displayName,userPrincipalName,mail,userType,jobTitle,department,officeLocation,accountEnabled,onPremisesSecurityIdentifier" --subscription <subId>
```

> **⛔ CRITICAL — Tool Selection:**
> - **ALWAYS** use `RunAzCliReadCommands` for ALL `az rest --method GET` calls.
> - **NEVER** use `RunAzCliWriteCommands` — different auth flow (MI → OBO fallback) that fails without Delegated permissions.
> - **NEVER** use `RunInTerminal` with `az` commands — `az` binary is not in the shell PATH.
> - **If Step 1a returns 403:** Stop Graph API calls immediately. Proceed to Strategy 2.

#### Strategy 2: KQL Fallback

Run Q0a, Q0b, Q0c queries in parallel. See [Q0 queries](#q0-kql-based-user-context-extraction-graph-api-fallback).

---

### Phase 2: Parallel KQL Data Collection (Monitor MCP)

**Required parameters for every call** (from agent settings):
- `subscription`, `resource-group`, `workspace` (GUID), `table`, `query`, `hours`

#### Batch 1 (run in parallel):
| Query | Description | Table |
|-------|-------------|-------|
| Q0a/Q0b/Q0c | User context (if Graph failed) | SigninLogs |
| Q1 | Priority IP extraction | SigninLogs |
| Q2 | Anomaly detection | Signinlogs_Anomalies_KQL_CL |
| Q12 | UEBA anomaly summary | Anomalies |
| Q3/Q3b/Q3c | Sign-ins by app/location/failures | SigninLogs |
| Q4 | Audit log activity | AuditLogs |
| Q5 | Office 365 activity | OfficeActivity |
| Q6 | Security incidents | SecurityAlert + SecurityIncident |
| Q10 | DLP events | CloudAppEvents |
| — | Risk events | AADUserRiskEvents |

#### After Batch 1: Extract IPs from Q1 or Q3 results

#### Batch 2 (depends on Batch 1):
| Query | Description | Table |
|-------|-------------|-------|
| Q3d | IP sign-in counts + auth details | SigninLogs |
| Q11 | Threat intelligence | ThreatIntelIndicators |
| Q13 | KQL-based IP context | SigninLogs |

---

### Phase 3: IP Enrichment (⛔ MANDATORY)

> **⚠️ This phase is NOT optional.** Every investigation MUST include IP enrichment via `enrich_ips.py`.

#### Step 3a: Retrieve API Tokens
```
az rest --method GET --url "https://<vault-name>.vault.azure.net/secrets/<secret-name>?api-version=7.4" --resource "https://vault.azure.net" --subscription <subId>
```
- If Key Vault fails: ASK user for tokens. If no tokens: proceed anyway (Shodan InternetDB free).

#### Step 3b: Resolve and Run enrich_ips.py

Resolve `enrich_ips.py` using the [File Resolution cascade](#file-resolution-coderefs-first):
1. Check `codeRefs/sec-sre-ag/user-investigation/enrich_ips.py` → if found, run from there.
2. Else check `tmp/user-investigation/enrich_ips.py` → if found, run from there.
3. Else: `read_skill_file("user-investigation", "enrich_ips.py")` → `CreateFile("tmp/user-investigation/enrich_ips.py", <content>)` → run from `tmp/`.
4. Run: `ABUSEIPDB_TOKEN=<value> python3 <resolved_path>/enrich_ips.py <ip1> <ip2> <ip3>`

#### Step 3c: KQL Supplements
Q13 + Q11 (already in Batch 2) are SUPPLEMENTS to enrich_ips.py, NOT replacements.

---

### Phase 4: Export & Generate Report (⛔ MANDATORY)

> **⚠️ Every investigation MUST produce the complete formatted report.**

#### Mode 1 — Inline Chat Summary
Render analysis directly in chat using the complete section structure from the Markdown Report Template.

#### Mode 2 — Markdown File Report
1. Build report using the template — ALL sections must be populated
2. Save: `create_file("reports/user-investigations/user_investigation_<username>_YYYYMMDD_HHMMSS.md", content)`

#### Mode 3 — HTML Report (Conditional Materialization)

> **⚠️ Materialize `generate_html_report.py` ONLY when the user requests HTML output (Mode 3).**
> Do NOT materialize for Mode 1 (inline) or Mode 2 (markdown) — those do not need it.

1. **Export to JSON:**
   Create a single JSON file with ALL investigation data merged into the [JSON Export Structure](#json-export-structure):
   ```
   create_file("temp/investigation_<upn_prefix>_<timestamp>.json", json_content)
   ```
   - Use `create_file` tool — NEVER use terminal commands for file output
   - The JSON MUST include the `ip_enrichment` array (from Phase 3 `enrich_ips.py` output)
   - Include all query results: anomalies, signin_apps, signin_locations, signin_failures, signin_ip_counts, audit_events, office_events, dlp_events, incidents, user_profile, mfa_methods, devices, risk_profile, risk_detections, risky_signins, threat_intel_ips

2. **Resolve `generate_html_report.py`** using the [File Resolution cascade](#file-resolution-coderefs-first):
   - Check `codeRefs/sec-sre-ag/user-investigation/generate_html_report.py` → if found, use that path.
   - Else check `tmp/user-investigation/generate_html_report.py` → if found, use that path.
   - Else: `read_skill_file("user-investigation", "generate_html_report.py")` → `CreateFile("tmp/user-investigation/generate_html_report.py", <content>)`

3. **Run the generator:**
   ```bash
   python3 <resolved_path>/generate_html_report.py temp/investigation_<upn_prefix>_<timestamp>.json
   ```

**What the script does automatically:**
- Reads investigation JSON with all pre-enriched data (does NOT call external APIs)
- Transforms JSON → Python dataclasses (InvestigationResult, IPIntelligence, etc.)
- Loads cached IP enrichment from the `ip_enrichment` array in the JSON
- Assigns IP categories: threat, risky, anomaly, primary, active
- Calculates dynamic risk score: risk_factors × 10 − mitigating_factors × 5 + baseline 30 (capped 0–100)
- Generates self-contained HTML (dark theme, two-column layout, IP cards, incidents, timeline modal)
- Zero external dependencies — only Python 3 stdlib + dataclasses

**Output:** `reports/user-investigations/Investigation_Report_<username>_<timestamp>.html`

**Fallback:** If materialization or execution fails, fall back to Mode 2 (Markdown report).

#### Combining Modes

When multiple modes are selected:
- Run data collection once (Phase 2)
- Generate each output format in sequence

---

## KQL Execution Reference

### Primary: Azure Monitor MCP Tool

Use `monitor-client_monitor_workspace_log_query` for all KQL queries.

| Parameter | Required | Source |
|-----------|----------|--------|
| `workspace` | Yes | Workspace GUID from `<log_analytics_access>` |
| `resource-group` | Yes | From agent ARM resource ID or config |
| `subscription` | Yes | From `<azure_resource_access>` |
| `table` | Yes | Primary table for the query |
| `query` | Yes | KQL query string |
| `hours` | Optional | Lookback period in hours |

### Fallback: Azure CLI via RunAzCliReadCommands

```
az monitor log-analytics query --workspace "<workspace_GUID>" --analytics-query "<KQL_QUERY>" --timespan "P7D" --subscription <subId>
```

> **⚠️** Always use `RunAzCliReadCommands` tool, not `RunInTerminal` with `az` commands.

### Known Table Pitfalls (Log Analytics)

| Table | Pitfall | Fix |
|-------|---------|-----|
| **AuditLogs** | `InitiatedBy`, `TargetResources` are dynamic | Wrap in `tostring()` before `has` |
| **SigninLogs** | `DeviceDetail`, `LocationDetails` may be dynamic OR string | Always use `tostring(parse_json(...))` |
| **SigninLogs** | `Location` is string, not dynamic | Use `parse_json(LocationDetails).countryOrRegion` |
| **AADUserRiskEvents** | IP column is `IpAddress` (lowercase 'p') | Use `IpAddress`, NOT `IPAddress` |
| **AADUserRiskEvents** | Time column is `ActivityDateTime` | NOT `TimeGenerated` |
| **SecurityAlert** | `Status` is immutable — always "New" | Join with `SecurityIncident` for real status |
| **CloudAppEvents** | High-volume; `RawEventData` is large JSON | Filter by `TimeGenerated` → `ActionType` first |
| **CloudAppEvents** | `AccountId` is GUID, NOT UPN | Use `AccountObjectId` or `AccountDisplayName` |
| **Signinlogs_Anomalies_KQL_CL** | Custom table — may not exist | Handle "Failed to resolve" gracefully |
| **Anomalies** | `Tactics`, `Techniques` are JSON strings | `parse_json()` before `make_set()` |

### Common KQL Anti-Patterns

| Anti-Pattern | Fix |
|-------------|-----|
| `mv-expand` on string column containing JSON | `mv-expand parsed = parse_json(StringColumn)` |
| `dcount()` on dynamic column | `dcount(tostring(DynamicColumn))` |
| `iff()` with mismatched branch types | Cast both: `iff(cond, todouble(x), todouble(y))` |
| Joining on dynamic column | Cast before join: `extend AlertId = tostring(AlertId)` |

---

## 📅 Date Range Quick Reference

**🔴 STEP 0: GET CURRENT DATE FIRST (MANDATORY) 🔴**

**RULE 1: Real-Time/Recent Searches:** Add +2 days to current date for end range.
**RULE 2: Historical Searches:** Add +1 day to user's specified end date.

| User Request | `<StartDate>` | `<EndDate>` | Rule |
|---|---|---|---|
| "Last 7 days" | current − 7d | current + 2d | Rule 1 |
| "Last 30 days" | current − 30d | current + 2d | Rule 1 |
| "May 20 to May 23" | 2026-05-20 | 2026-05-24 | Rule 2 |

---

## Sample KQL Queries

Replace `<UPN>`, `<StartDate>`, `<EndDate>` in these patterns. Execute via Monitor MCP tool.

**🚨 You MUST run ALL THREE sign-in queries (Q3, Q3b, Q3c) to populate the full sign-in picture.**

### Q0. KQL-Based User Context Extraction (Graph API Fallback)

**Run all three Q0 queries in parallel.**

#### Q0a. User Identity & Overall Metrics

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| summarize 
    TotalSignIns = count(),
    SuccessCount = countif(ResultType == '0'),
    FailureCount = countif(ResultType != '0'),
    UniqueIPs = dcount(IPAddress),
    UniqueLocations = dcount(Location),
    AllIPs = make_set(IPAddress),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    UserId = take_any(UserId),
    UserDisplayName = take_any(UserDisplayName)
```

#### Q0b. Device & Compliance Context

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
SigninLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where ResultType == '0'
| extend DeviceDetailParsed = parse_json(DeviceDetail)
| extend LocationDetailsParsed = parse_json(LocationDetails)
| summarize 
    DeviceNames = make_set(tostring(DeviceDetailParsed.displayName)),
    OperatingSystems = make_set(tostring(DeviceDetailParsed.operatingSystem)),
    Browsers = make_set(tostring(DeviceDetailParsed.browser)),
    TrustTypes = make_set(tostring(DeviceDetailParsed.trustType)),
    IsCompliant = make_set(tostring(DeviceDetailParsed.isCompliant)),
    IsManaged = make_set(tostring(DeviceDetailParsed.isManaged)),
    ConditionalAccessStatuses = make_set(ConditionalAccessStatus),
    AuthRequirements = make_set(AuthenticationRequirement),
    Countries = make_set(tostring(LocationDetailsParsed.countryOrRegion)),
    Cities = make_set(tostring(LocationDetailsParsed.city))
```

#### Q0c. Single Sign-in Detail Sample

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
SigninLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where ResultType == '0'
| top 1 by TimeGenerated desc
| extend DeviceDetailParsed = parse_json(DeviceDetail)
| extend LocationDetailsParsed = parse_json(LocationDetails)
| project TimeGenerated,
    DeviceName = tostring(DeviceDetailParsed.displayName),
    DeviceOS = tostring(DeviceDetailParsed.operatingSystem),
    Browser = tostring(DeviceDetailParsed.browser),
    IsCompliant = tostring(DeviceDetailParsed.isCompliant),
    IsManaged = tostring(DeviceDetailParsed.isManaged),
    TrustType = tostring(DeviceDetailParsed.trustType),
    City = tostring(LocationDetailsParsed.city),
    State = tostring(LocationDetailsParsed.state),
    Country = tostring(LocationDetailsParsed.countryOrRegion),
    ConditionalAccessStatus, AuthenticationRequirement, AppDisplayName
```

### Q1. Extract Top Priority IPs (Simplified)

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let upn = '<UPN>';
let risky_ips_pool = AADUserRiskEvents
    | where ActivityDateTime between (start .. end)
    | where UserPrincipalName =~ upn
    | where isnotempty(IpAddress)
    | summarize RiskCount = count(), FirstSeen = min(ActivityDateTime) by IPAddress = IpAddress
    | order by RiskCount desc | take 8
    | extend Priority = 1, Source = "RiskyIP";
let frequent_ips_pool = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ upn
    | summarize SignInCount = count(), FirstSeen = min(TimeGenerated) by IPAddress
    | order by SignInCount desc | take 10
    | extend Priority = 2, Source = "Frequent";
let risky_ip_list = risky_ips_pool | project IPAddress;
let risky_slot = risky_ips_pool | extend Count = RiskCount;
let frequent_slot = frequent_ips_pool 
    | join kind=anti risky_ip_list on IPAddress
    | order by SignInCount desc | take 7
    | extend Count = SignInCount;
union risky_slot, frequent_slot
| project IPAddress, Priority, Count, Source
| order by Priority asc, Count desc
| project IPAddress
```

### Q3. Sign-ins by Application

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| summarize SignInCount=count(), SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'), FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated), IPAddresses=make_set(IPAddress),
    UniqueLocations=dcount(Location) by AppDisplayName
| order by SignInCount desc | take 5
```

### Q3b. Sign-ins by Location

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where isnotempty(Location)
| summarize SignInCount=count(), SuccessCount=countif(ResultType == '0'),
    FailureCount=countif(ResultType != '0'), FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated), IPAddresses=make_set(IPAddress),
    Applications=make_set(AppDisplayName, 5) by Location
| order by SignInCount desc | take 5
```

### Q3c. Sign-in Failures

```kql
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where ResultType != '0'
| summarize FailureCount=count(), FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated), Applications=make_set(AppDisplayName, 3),
    Locations=make_set(Location, 3) by ResultType, ResultDescription
| order by FailureCount desc | take 5
```

### Q3d. Sign-in Counts by IP Address

```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let most_recent_signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated between (start .. end)
| where UserPrincipalName =~ '<UPN>'
| where IPAddress in (target_ips)
| summarize arg_max(TimeGenerated, *) by IPAddress;
most_recent_signins
| extend AuthDetails = parse_json(AuthenticationDetails)
| extend HasAuthDetails = array_length(AuthDetails) > 0
| extend AuthDetailsToExpand = iif(HasAuthDetails, AuthDetails, dynamic([{"authenticationStepResultDetail": ""}]))
| mv-expand AuthDetailsToExpand
| extend AuthStepResultDetail = tostring(AuthDetailsToExpand.authenticationStepResultDetail)
| extend AuthPriority = case(
    AuthStepResultDetail has "MFA requirement satisfied", 1,
    AuthStepResultDetail has "Correct password", 2,
    AuthStepResultDetail has "Passkey", 2,
    AuthStepResultDetail has "Phone sign-in", 2,
    AuthStepResultDetail has "SMS verification", 2,
    AuthStepResultDetail has "First factor requirement satisfied", 3,
    AuthStepResultDetail has "MFA required", 4, 999)
| summarize MostRecentTime = any(TimeGenerated), MostRecentResultType = any(ResultType),
    HasAuthDetails = any(HasAuthDetails), MinPriority = min(AuthPriority),
    AllAuthDetails = make_set(AuthStepResultDetail) by IPAddress
| extend LastAuthResultDetail = case(
    MostRecentResultType != "0", "Authentication failed",
    not(HasAuthDetails) and MostRecentResultType == "0", "Token",
    MinPriority == 1 and AllAuthDetails has "MFA requirement satisfied", "MFA requirement satisfied by claim in the token",
    MinPriority == 2 and AllAuthDetails has "Correct password", "Correct password",
    MinPriority == 2 and AllAuthDetails has "Passkey (device-bound)", "Passkey (device-bound)",
    MinPriority == 3 and AllAuthDetails has "First factor requirement satisfied by claim in the token", "First factor requirement satisfied by claim in the token",
    MinPriority == 4 and AllAuthDetails has "MFA required in Entra ID", "MFA required in Entra ID",
    tostring(AllAuthDetails[0]))
| join kind=inner (
    union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where UserPrincipalName =~ '<UPN>'
    | where IPAddress in (target_ips)
    | summarize SignInCount = count(), SuccessCount = countif(ResultType == '0'),
        FailureCount = countif(ResultType != '0'), FirstSeen = min(TimeGenerated),
        LastSeen = max(TimeGenerated) by IPAddress
) on IPAddress
| project IPAddress, SignInCount, SuccessCount, FailureCount, FirstSeen, LastSeen, LastAuthResultDetail
| order by SignInCount desc
```

### Q4. Audit Log Activity

```kql
AuditLogs
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where Identity =~ '<UPN>' or tostring(InitiatedBy) has '<UPN>'
| summarize Count=count(), FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated), Operations=make_set(OperationName, 10)
    by Category, Result
| order by Count desc | take 10
```

### Q5. Office 365 Activity

```kql
OfficeActivity
| where TimeGenerated between (datetime(<StartDate>) .. datetime(<EndDate>))
| where UserId =~ '<UPN>'
| summarize ActivityCount = count() by RecordType, Operation
| order by ActivityCount desc | take 5
```

### Q6. Security Incidents

```kql
let targetUPN = "<UPN>";
let targetUserId = "<USER_OBJECT_ID>";
let targetSid = "<WINDOWS_SID>";
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let relevantAlerts = SecurityAlert
| where TimeGenerated between (start .. end)
| where Entities has targetUPN 
    or (isnotempty(targetUserId) and Entities has targetUserId) 
    or (isnotempty(targetSid) and Entities has targetSid)
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
| extend LastModifiedTime = todatetime(LastModifiedTime)
| summarize Title = any(Title), Severity = any(Severity), Status = any(Status),
    Classification = any(Classification), CreatedTime = any(CreatedTime),
    LastModifiedTime = any(LastModifiedTime), OwnerUPN = any(OwnerUPN),
    ProviderIncidentUrl = any(ProviderIncidentUrl), AlertCount = count()
    by ProviderIncidentId
| order by LastModifiedTime desc | take 10
```

### Q10. DLP Events

```kql
let upn = '<UPN>';
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
CloudAppEvents
| where TimeGenerated between (start .. end)
| where ActionType in ("FileCopiedToRemovableMedia", "FileUploadedToCloud", "FileCopiedToNetworkShare")
| extend ParsedData = parse_json(RawEventData)
| extend DlpAudit = ParsedData["DlpAuditEventMetadata"]
| extend UserId = ParsedData["UserId"]
| where isnotnull(DlpAudit)
| where UserId == upn
| summarize by TimeGenerated, tostring(UserId), tostring(ParsedData["DeviceName"]),
    tostring(ParsedData["ClientIP"]), tostring(ParsedData["PolicyMatchInfo"]["RuleName"]),
    tostring(ParsedData["ObjectId"]), tostring(ParsedData["Operation"]),
    tostring(ParsedData["TargetDomain"]), tostring(ParsedData["TargetFilePath"])
| order by TimeGenerated desc | take 5
```

### Q11. Threat Intelligence

```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>"]);
ThreatIntelIndicators
| where IsActive and (ValidUntil > now() or isempty(ValidUntil))
| where tostring(split(ObservableKey, ":")[0]) in ("ipv4-addr", "ipv6-addr", "network-traffic")
| where ObservableValue in (target_ips)
| extend Description = tostring(parse_json(Data).description)
| where Description !contains_cs "State: inactive;" and Description !contains_cs "State: falsepos;"
| summarize arg_max(TimeGenerated, *) by ObservableValue
| project TimeGenerated, IPAddress = ObservableValue,
    ThreatDescription = Description, Confidence, ValidUntil, IsActive
| order by Confidence desc
```

### Q12. UEBA Anomaly Summary

```kql
let targetUPN = '<UPN>';
Anomalies
| where TimeGenerated > ago(30d)
| where UserPrincipalName =~ targetUPN
| mv-apply reason = AnomalyReasons on (
    where tobool(reason.IsAnomalous) == true
    | project FlagName = tostring(reason.Name))
| summarize Occurrences = dcount(Id), MaxScore = max(Score),
    AvgScore = round(avg(Score), 2),
    Tactics = make_set(parse_json(Tactics)),
    Techniques = make_set(parse_json(Techniques)),
    SourceIPs = make_set(SourceIpAddress, 5),
    AnomalyFlags = make_set(FlagName),
    FirstSeen = min(StartTime), LastSeen = max(EndTime),
    SampleDescription = take_any(Description)
    by AnomalyTemplateName
| order by MaxScore desc, Occurrences desc
```

### Q13. KQL-Based IP Context Analysis

```kql
let target_ips = dynamic(["<IP_1>", "<IP_2>", "<IP_3>"]);
let start = datetime(<StartDate>);
let end = datetime(<EndDate>);
let ip_user_diversity = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where IPAddress in (target_ips)
    | summarize TotalUsers = dcount(UserPrincipalName),
        UserList = make_set(UserPrincipalName, 5), TotalSignIns = count(),
        UniqueApps = dcount(AppDisplayName), TopApps = make_set(AppDisplayName, 3),
        Locations = make_set(Location, 3) by IPAddress;
let ip_failure_patterns = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
    | where TimeGenerated between (start .. end)
    | where IPAddress in (target_ips)
    | where ResultType != '0'
    | summarize FailedUsers = dcount(UserPrincipalName), TotalFailures = count(),
        FailureCodes = make_set(ResultType, 5) by IPAddress;
ip_user_diversity
| join kind=leftouter ip_failure_patterns on IPAddress
| extend RiskIndicator = case(
    TotalUsers > 10 and TotalFailures > 50, "High — shared IP with many failures",
    TotalUsers > 5 and TotalFailures > 20, "Medium — shared IP with notable failures",
    TotalUsers == 1 and TotalFailures == 0, "Low — dedicated IP, no failures",
    TotalUsers == 1 and TotalFailures > 0, "Low — dedicated IP with some failures",
    TotalUsers > 1 and TotalFailures == 0, "Low — shared corporate/VPN IP, no failures",
    "Requires review")
| extend IPType = case(
    TotalUsers > 5, "Shared (corporate/VPN/proxy)",
    TotalUsers > 1, "Small group (team/office)",
    "Dedicated (individual)")
| project IPAddress, IPType, TotalUsers, TotalSignIns, UniqueApps, Locations,
    FailedUsers = coalesce(FailedUsers, 0), TotalFailures = coalesce(TotalFailures, 0),
    FailureCodes = coalesce(FailureCodes, dynamic([])), RiskIndicator, UserList, TopApps
| order by TotalFailures desc, TotalUsers desc
```

---

## Entra ID Data Collection

### Method 1: RunAzCliReadCommands Tool (Primary)

See `get-entra-user-context-via-tool.md` for the complete reference with all 6 API calls.

> **⛔ CRITICAL:** ALWAYS use `RunAzCliReadCommands`. NEVER use `RunAzCliWriteCommands` or `RunInTerminal` with `az`.

### Method 2: KQL Fallback

Run Q0a, Q0b, Q0c in parallel + query `AADUserRiskEvents`:

```kql
AADUserRiskEvents
| where ActivityDateTime > ago(7d)
| where UserPrincipalName =~ '<UPN>'
| project ActivityDateTime, RiskEventType, RiskLevel, RiskState, RiskDetail, IpAddress, Location, Activity
| order by ActivityDateTime desc | take 10
```

---

## Markdown Report Template

**Filename:** `reports/user-investigations/user_investigation_<username>_YYYYMMDD_HHMMSS.md`

The report MUST include ALL of the following sections (use `✅ No <X> detected...` for empty sections):

1. **Header** — User info, investigation period, data sources, context method
2. **Executive Summary** — 2-4 sentences, overall risk level, key findings
3. **Key Metrics** — Total sign-ins, success/failure counts, unique IPs/locations, anomalies, incidents, DLP
4. **MFA & Authentication Status** — Methods, conditional access, last auth method
5. **Identity Protection** — Risk detections from AADUserRiskEvents or Graph
6. **Anomalies** — Signinlogs_Anomalies_KQL_CL (or note if unavailable)
7. **UEBA Anomalies** — Sentinel Anomalies table (or note if unavailable)
8. **IP Intelligence** — IP table + TI matches + external enrichment (enrich_ips.py)
9. **Sign-in Activity** — Top applications, locations, failures
10. **Device & Compliance** — From sign-in logs or Graph
11. **Audit Log Activity** — From AuditLogs
12. **Office 365 Activity** — From OfficeActivity
13. **DLP Events** — From CloudAppEvents
14. **Security Incidents** — From SecurityAlert + SecurityIncident
15. **Risk Assessment** — Dynamic score, risk factors, mitigating factors, data gaps
16. **Recommendations** — Critical, high priority, monitoring (14-day)
17. **Appendix: Query Details** — Table with query status and record counts

### Authoring Guidelines
- Populate every section — even if empty
- Never invent data — every number from a query result
- Risk score: risk_factors × 10 − mitigating × 5 + baseline 30, capped 0–100
- Emoji: 🔴 high, 🟠 medium, 🟡 low, 🟢 positive, ✅ clean, ⚠️ action, ❓ unavailable

---

## JSON Export Structure

For HTML report generation (Mode 3):

```json
{
  "upn": "user@domain.com",
  "user_id": "<USER_OBJECT_ID>",
  "user_sid": "<WINDOWS_SID>",
  "user_context_method": "graph_api | kql_fallback | mixed",
  "investigation_date": "2026-05-30",
  "start_date": "2026-05-23",
  "end_date": "2026-06-01",
  "timestamp": "20260530_120000",
  "anomalies": [], "signin_apps": [], "signin_locations": [],
  "signin_failures": [], "signin_ip_counts": [], "signin_ip_context": [],
  "audit_events": [], "office_events": [], "dlp_events": [],
  "incidents": [], "user_profile": {}, "mfa_methods": {},
  "devices": [], "device_context_from_signins": {},
  "risk_profile": {}, "risk_detections": [], "risky_signins": [],
  "threat_intel_ips": [], "ip_enrichment": [], "data_gaps": []
}
```

---

## Error Handling

| Issue | Solution |
|-------|----------|
| Monitor MCP query fails | Verify workspace GUID; fallback to `RunAzCliReadCommands` with `az monitor log-analytics query` |
| `RunAzCliReadCommands` returns 403 for Graph | Proceed with KQL fallback (Q0). Do NOT retry. |
| `az` not in shell PATH | Use `RunAzCliReadCommands` tool, not `RunInTerminal` |
| Table "Failed to resolve" | Skip query, note the gap |
| Signinlogs_Anomalies_KQL_CL not found | Use simplified Q1; skip Q2 |
| Anomalies table not found | Skip Q12, note in report |
| CloudAppEvents not found | Skip Q10 |
| Missing `department`/`officeLocation` | Use "Unknown" if Graph unavailable |
| No `user_sid` | Q6 works with UPN + user_id only |
| `enrich_ips.py` no API tokens | Shodan InternetDB free works. Try Key Vault → ask user → run with zero tokens. |
| ⛔ Used `RunAzCliWriteCommands` for Graph GET | NEVER. Use `RunAzCliReadCommands` which authenticates via MI directly. |
| Key Vault `ForbiddenByConnection` | Ask user to enable public access. Use `az rest --resource "https://vault.azure.net"` (NOT `az keyvault`). |
| IP enrichment skipped | MANDATORY. Try Key Vault → ask user → run with zero tokens. Never skip. |

### Required Field Defaults

```json
{ "department": "Unknown", "officeLocation": "Unknown", "trustType": "Workplace" }
```

---

## Evidence-Based Analysis Rules

| Scenario | Required Action |
|----------|----------------|
| Query returns 0 results | State: "✅ No [X] found in [time range]" |
| Field is null/missing | Report as "Unknown" — never fabricate |
| Partial data available | State what WAS found and what COULD NOT be verified |
| Graph API unavailable | State: "ℹ️ [field] requires Graph API access" |

### Risk Level Evidence

| Risk Level | Evidence Required |
|------------|-------------------|
| **High** | ≥2 concrete findings |
| **Medium** | ≥1 concrete finding with context |
| **Low** | Explanation despite investigation |
| **Informational** | Cite what was checked |

---

## Remediation Output Policy

- ✅ Portal deep links with navigation steps
- ✅ Natural-language instructions
- ✅ Read-only verification KQL
- ❌ State-changing commands (`Remove-*`, `Set-*`, `Revoke-*`)
- ❌ Graph API write calls
- ❌ `az` CLI write operations

---

*Last Updated: 2026-06-01*
