---
name: mcp-usage-monitoring
description: 'Use this skill when asked to monitor, audit, or analyze MCP (Model Context Protocol) server usage in the environment. Triggers on keywords like "MCP usage", "MCP server monitoring", "MCP activity", "Graph MCP", "Sentinel MCP", "Azure MCP", "MCP audit", "tool usage monitoring", "MCP breakdown", "who is using MCP", or when investigating MCP user activity, Graph API calls from MCP servers, or workspace query governance. This skill provides comprehensive MCP server telemetry analysis across Graph MCP, Sentinel MCP, and Azure MCP servers including usage trends, endpoint access patterns, user attribution, cross-server user analysis, sensitive API detection, workspace query governance, and security risk assessment with inline and markdown file reporting.'
threat_pulse_domains: [admin]
drill_down_prompt: 'Run MCP usage monitoring report — Graph/Sentinel/Azure MCP activity, user attribution'
---

# MCP Server Usage Monitoring — Instructions

## Purpose

This skill monitors and audits **Model Context Protocol (MCP) server usage** across your Microsoft Sentinel and Defender XDR environment. MCP servers are AI-powered tools that enable language models to interact with Microsoft security services — and like any privileged access channel, they require monitoring.

**What this skill tracks:**

| MCP Server | Telemetry Source | Key Identifier |
|------------|-----------------|----------------|
| **Microsoft Graph MCP Server** | `MicrosoftGraphActivityLogs` | AppId = `e8c77dc2-69b3-43f4-bc51-3213c9d915b4` |
| **Sentinel Data Lake MCP** | `CloudAppEvents` | RecordType 403, Interface = `IMcpToolTemplate` |
| **Sentinel Triage MCP** | `MicrosoftGraphActivityLogs` + `SigninLogs` | AppId = `7b7b3966-1961-47b5-b080-43ca5482e21c` ("Microsoft Defender Mcp") — **dedicated AppId** with full user attribution via delegated cert auth |
| **Azure MCP Server** | `AzureActivity` | No dedicated AppId — uses `DefaultAzureCredential` |
| **Sentinel Data Lake — Direct KQL** | `CloudAppEvents` | RecordType 379, Operation = `KQLQueryCompleted` |
| **Workspace Query Sources (Analytics Tier)** | `LAQueryLogs` | All clients querying Log Analytics workspace |

**What this skill detects:**
- Graph API call volume, trends, and endpoint diversity via MCP
- Sensitive/high-risk Graph endpoint access (PIM, credentials, Identity Protection)
- Sentinel workspace query patterns by client application
- **User vs. Service Principal attribution** across all MCP channels
- **Cross-server user analysis** — identifies users with broadest MCP footprint (multiple server types, highest call volume)
- Azure ARM operations potentially originating from Azure MCP Server
- Non-MCP platform query sources for governance context (Sentinel Engine, Logic Apps)
- **Sentinel Data Lake MCP tool usage** — tool call breakdown (`query_lake`, `list_sentinel_workspaces`, `search_tables`, etc.), success/failure rates, execution duration, tables accessed via `CloudAppEvents` (Purview unified audit)
- **MCP-driven vs Direct KQL delineation** — distinguishes Data Lake queries initiated via MCP tools (RecordType 403, Interface `IMcpToolTemplate`) from direct KQL queries (RecordType 379) and Analytics tier queries (`LAQueryLogs`)
- Anomalous access patterns: new users, new endpoints, volume spikes, error surges
- MCP server usage as a proportion of total workspace activity

**Extended landscape awareness:** Beyond these four actively monitored MCP servers, Microsoft's MCP ecosystem includes 30+ additional servers (Copilot Studio built-in catalog, Power BI, Fabric RTI, Playwright, Security Copilot Agent Creation, and more). See [Extended Microsoft MCP Server Landscape](#extended-microsoft-mcp-server-landscape-reference) for the full catalog, telemetry surfaces, and monitoring expansion priorities.

---

## 🛠️ Execution Environment

**This skill runs in an environment where the following MCP servers are NOT integrated with Azure SRE Agent:**
- ❌ **Sentinel MCP Server** (`mcp_microsoft_se2_*` — `query_lake`, `list_sentinel_workspaces`, `search_tables`, etc.)
- ❌ **Sentinel Triage MCP** (`mcp_mtp_mcp_servi_*` — `RunAdvancedHuntingQuery`, `ListIncidents`, etc.)
- ❌ **Microsoft Graph MCP** (`mcp_microsoft_ent_*` — `microsoft_graph_get`, etc.)

> **Note:** These MCP servers cannot currently be connected to Azure SRE Agent. The underlying data they expose (Sentinel Data Lake, Defender XDR, Microsoft Graph) is accessible via direct API calls, but direct API access as a replacement has not yet been studied and implemented in this skill.

**Available MCP servers & tools:**
- ✅ **Azure MCP Server** (`mcp_azure_mcp_ser_*`) — including `mcp_azure_mcp_ser_monitor` for Log Analytics workspace queries
- ✅ **Microsoft Learn MCP** (`mcp_microsoft_lea_*`) — documentation search
- ✅ **KQL Search MCP** (`mcp_kql-search-mc_*`) — KQL query assistance, table schema lookup
- ✅ **Direct Log Analytics access** — via Azure MCP Server's monitor namespace

### How Queries Are Executed

All KQL queries in this skill are pre-authored and saved in the companion file [`queries.md`](queries.md). They are executed via:

1. **Azure MCP Server — `mcp_azure_mcp_ser_monitor`** (preferred) — executes KQL against Log Analytics workspaces directly. Supports all tables: `MicrosoftGraphActivityLogs`, `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs`, `CloudAppEvents`, `AzureActivity`.
2. **`mcp_azure_mcp_ser_kusto`** — fallback for ADX-hosted data if applicable.

**⚠️ Key differences from the original skill:**
- No `RunAdvancedHuntingQuery` — all queries run against Log Analytics workspace directly
- `CloudAppEvents` uses `TimeGenerated` (not `Timestamp`) when queried via Log Analytics
- No `list_sentinel_workspaces` MCP tool — the user must provide the workspace name/ID, or use `mcp_azure_mcp_ser_monitor` to discover workspaces
- No Graph API lookups for SPN enrichment — use `SigninLogs` / `AADServicePrincipalSignInLogs` as proxy

---

## 📑 TABLE OF CONTENTS

1. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Start here!
2. **[Extended MCP Server Landscape](#extended-microsoft-mcp-server-landscape-reference)** - Full Microsoft MCP ecosystem catalog
3. **[Phase 0: Results Cache Check](#phase-0-results-cache-check-mandatory)** — Cache reuse logic
4. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file vs. HTML report
5. **[Scalability & Token Management](#scalability--token-management)** - Guidance for large environments
6. **[Quick Start](#quick-start-tldr)** - 10-step investigation pattern
7. **[MCP Usage Score Formula](#mcp-usage-score-formula)** - Composite health & risk scoring
8. **[Execution Workflow](#execution-workflow)** - Complete 7-phase process
9. **[Sample KQL Queries](#sample-kql-queries)** - Reference to queries.md
10. **[Report Template](#report-template)** - Output format specification
11. **[Proactive Alerting — KQL Data Lake Jobs](#proactive-alerting--kql-data-lake-jobs)** - Scheduled anomaly detection
12. **[Known Pitfalls](#known-pitfalls)** - Edge cases and false positives
13. **[Error Handling](#error-handling)** - Troubleshooting guide
14. **[SVG Dashboard Generation](#svg-dashboard-generation)** - Visual dashboard from completed report

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY MCP usage monitoring analysis:**

1. **ALWAYS complete Phase 0 (Cache Check) first** — Before any data collection, check for cached results. See Phase 0 for full logic.
2. **ALWAYS enforce Sentinel workspace selection** (see Workspace Selection section below)
3. **ALWAYS ask the user for output mode** if not specified: inline chat summary or markdown file report (or both)
4. **ALWAYS ask the user for time range** if not specified: default to 30 days, configurable
5. **ALWAYS query all MCP telemetry surfaces** — do not skip any MCP server type
6. **ALWAYS include non-MCP workspace context** (Sentinel Engine, Logic Apps) for governance proportion analysis
7. **ALWAYS run independent queries in parallel** for performance
8. **ALWAYS attribute activity to specific users** — never present anonymous aggregates
9. **NEVER conflate non-MCP platform activity with MCP activity** — clearly label categories
10. **ALWAYS execute pre-authored queries from [`queries.md`](queries.md) EXACTLY as written** — substitute only the time range parameter (e.g., `ago(30d)` → `ago(90d)`). These queries encode mitigations for schema pitfalls documented in [Known Pitfalls](#known-pitfalls). Writing equivalent queries from scratch is ❌ **PROHIBITED**
10. **ALWAYS execute queries via `mcp_azure_mcp_ser_monitor`** — this is the only query execution path available. Load the tool with `tool_search` for "azure monitor" before first use.

---

### Known AppIds Reference

#### MCP Servers & AI Agents

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `e8c77dc2-69b3-43f4-bc51-3213c9d915b4` | Microsoft Graph MCP Server for Enterprise | `MicrosoftGraphActivityLogs` | Read-only Graph API proxy |
| `7b7b3966-1961-47b5-b080-43ca5482e21c` | Sentinel Triage MCP ("Microsoft Defender Mcp") | `MicrosoftGraphActivityLogs`, `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Microsoft first-party AppId, same across all tenants. **Dedicated AppId** — visible in `MicrosoftGraphActivityLogs` (API calls to `/security/*` endpoints) and `SigninLogs`/`AADNonInteractiveUserSignInLogs` (`AppDisplayName = "Microsoft Defender Mcp"`). Delegated auth with certificate (ClientAuthMethod=2), full user attribution. Scopes: `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `ThreatHunting.Read.All`. Target resources: Microsoft Graph, WindowsDefenderATP. No local SPN — display name only visible in SigninLogs. 🔴 **Confirmed Feb 2026.** |
| `253895df-6bd8-4eaf-b101-1381ec4306eb` | Sentinel Platform Services App Reg | `SigninLogs` | Sentinel-hosted MCP platform |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure MCP Server (local stdio via DefaultAzureCredential → Azure CLI) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Shared AppId with Azure CLI. In LAQueryLogs, `RequestClientApp` is **empty** (not a unique fingerprint). Azure MCP appends `\n\| limit N` to query text — the only query-level differentiator. Read-only ARM ops don't appear in AzureActivity. 🔄 **Updated Feb 2026:** Previously documented as AppId `1950a258` — obsolete. |
| *(none — uses DefaultAzureCredential)* | Azure MCP Server (local stdio) | `AzureActivity` | ARM **write** operations only; read ops not logged. Claims.appid = `04b07795`. |
| *(no AppId — Purview unified audit)* | Sentinel Data Lake MCP | `CloudAppEvents` | RecordType 403; Interface `IMcpToolTemplate`; tools: `query_lake`, `list_sentinel_workspaces`, `search_tables` |

#### Sentinel MCP Collection Endpoints

| Endpoint URL | Collection | Monitored |
|-------------|------------|----------|
| `https://sentinel.microsoft.com/mcp/data-exploration` | Data Exploration (Data Lake MCP) | ✅ Phase 3 |
| `https://sentinel.microsoft.com/mcp/triage` | Triage (Triage MCP) | ✅ Phase 2 |
| `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Security Copilot Agent Creation | ❌ See [Landscape](#extended-microsoft-mcp-server-landscape-reference) |

#### Client Applications

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `aebc6443-996d-45c2-90f0-388ff96faa56` | Visual Studio Code | `SigninLogs` | VS Code as MCP client → Sentinel |
| `9ba5f2e4-6bbf-4df2-b19b-7f1bcb926818` | PowerPlatform-sentinelmcp-Connector | `SigninLogs` | Copilot Studio → Sentinel MCP |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI (DefaultAzureCredential) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | **Primary Azure MCP Server credential path** (field-tested Feb 2026). Shared AppId with manual `az` CLI. |

#### Portal & Platform Applications (Non-MCP — for context)

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `80ccca67-54bd-44ab-8625-4b79c4dc7775` | M365 Security & Compliance Center (Sentinel Portal) | `LAQueryLogs` | `ASI_Portal`, `ASI_Portal_Connectors` — NOT an MCP server |
| `95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5` | Azure Portal — AppInsightsPortalExtension | `LAQueryLogs` | Azure Portal blade. NOT MCP, NOT VS Code. |
| `de8c33bb-995b-4d4a-9d04-8d8af5d59601` | PowerPlatform-AzureMonitorLogs-Connector | `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Logic Apps → Log Analytics (NOT MCP) |
| `fc780465-2017-40d4-a0c5-307022471b92` | Sentinel Engine (analytics rules, UEBA, Advanced Hunting backend) | `LAQueryLogs` | Built-in scheduled query engine (NOT MCP). Also serves as the **execution backend for Advanced Hunting**. |

---

## Extended Microsoft MCP Server Landscape (Reference)

Beyond the four MCP servers actively monitored by this skill, Microsoft's MCP ecosystem includes many additional servers. This section catalogs them for awareness, threat modeling, and future monitoring expansion.

### Sentinel MCP Collections (Microsoft-Hosted)

| Collection | Endpoint URL | Purpose | Monitored by This Skill |
|------------|-------------|---------|-------------------------|
| **Data Exploration** | `https://sentinel.microsoft.com/mcp/data-exploration` | `query_lake`, `search_tables`, `list_sentinel_workspaces`, entity analyzer | ✅ Phase 3 (CloudAppEvents) |
| **Triage** | `https://sentinel.microsoft.com/mcp/triage` | Incident triage, Advanced Hunting, entity investigation | ✅ Phase 2 (MicrosoftGraphActivityLogs + SigninLogs) |
| **Security Copilot Agent Creation** | `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Create Microsoft Security Copilot agents | ❌ Not yet monitored |

**Sentinel Custom MCP Tools:** Organizations can create their own MCP tools by exposing saved KQL queries from Advanced Hunting as MCP tools. These execute through the same Sentinel MCP infrastructure and are audited in `CloudAppEvents` (RecordType 403) alongside built-in tools.

### Power BI MCP Servers

| Server | Type | Endpoint / Repo | Purpose | Telemetry Surface |
|--------|------|----------------|---------|-------------------|
| **Power BI Remote MCP** | Microsoft-hosted | `https://api.fabric.microsoft.com/v1/mcp/powerbi` | Query Power BI datasets, reports, and workspaces remotely | 🟡 `PowerBIActivity` table |
| **Power BI Modeling MCP** | Local (stdio) | [microsoft/powerbi-modeling-mcp](https://github.com/microsoft/powerbi-modeling-mcp) | Local Power BI model operations | ❌ Local only |

### Fabric & Azure Data Explorer MCP Servers

| Server | Type | Endpoint / Repo | Purpose | Telemetry Surface |
|--------|------|----------------|---------|-------------------|
| **Fabric RTI MCP Server** | Local (stdio) | [microsoft/fabric-rti-mcp](https://github.com/microsoft/fabric-rti-mcp/) | Query ADX clusters and Fabric RTI Eventhouses | 🟡 ADX audit logs |
| **Azure MCP Server — Kusto namespace** | Local (stdio) | Part of Azure MCP Server | Manage ADX clusters, databases, tables | ✅ Already covered (Phase 4) |
| **Kusto Query MCP** | Copilot Studio built-in | Copilot Studio catalog | KQL query execution from Copilot Studio agents | 🟡 CloudAppEvents |

### Developer & Productivity MCP Servers

| Server | Type | Repo | Purpose | Telemetry Surface |
|--------|------|------|---------|-------------------|
| **Playwright MCP** | Local (stdio) | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | Browser automation | ❌ Local only |
| **GitHub MCP Server** | Local (stdio) | [github/github-mcp-server](https://github.com/github/github-mcp-server) | GitHub repo operations | ❌ GitHub audit logs only |
| **Microsoft Learn Docs MCP** | Cloud-hosted | Certified Copilot Studio connector | Documentation search | ❌ Public docs |

### Copilot Studio Built-in MCP Servers (19+ servers)

| Category | MCP Servers | Security Relevance |
|----------|-------------|--------------------|
| **Microsoft 365** | Outlook Mail, Outlook Calendar, 365 User Profile, Teams, Word, 365 Copilot (Search) | 🔴 High — email, calendar, user profile access |
| **SharePoint & OneDrive** | SharePoint and OneDrive, SharePoint Lists | 🟠 Medium — file and data access |
| **Administration** | 365 Admin Center | 🔴 High — administrative control plane |
| **Dataverse** | Dataverse MCP | 🟠 Medium — business data access |
| **Dynamics 365** | Sales, Finance, Supply Chain, Service, ERP, Contact Center | 🟡 Low-Medium |
| **Fabric** | Fabric MCP | 🟠 Medium — analytics data access |
| **Office 365 Outlook** | Contact Management, Email Management, Meeting Management | 🔴 High — email and contact data |
| **Meta-Server** | MCP Management MCP | 🟠 Medium — manages other MCP servers |

> ⚠️ **Telemetry gap:** Copilot Studio built-in MCP servers are NOT directly visible in `LAQueryLogs` or `MicrosoftGraphActivityLogs`. Monitor via `CloudAppEvents` (Copilot Studio workload) or M365 unified audit log.

### Azure MCP Server — Full Tool Surface

| Category | Namespaces | Security-Relevant Tools |
|----------|-----------|------------------------|
| **AI & ML** | `foundry`, `search`, `speech` | AI Foundry model access, Search index queries |
| **Identity** | `role` | ⚠️ RBAC role assignments |
| **Security** | `keyvault`, `appconfig`, `confidentialledger` | 🔴 Key Vault secrets/keys/certs |
| **Databases** | `cosmos`, `mysql`, `postgres`, `redis`, `sql` | Database access |
| **Storage** | `storage`, `fileshares`, `storagesync`, `managedlustre` | Blob, file access |
| **Compute** | `appservice`, `functionapp`, `aks` | App Service, Functions, Kubernetes |
| **Networking** | `eventhubs`, `servicebus`, `eventgrid`, `communication`, `signalr` | Messaging |
| **DevOps** | `bicepschema`, `deploy`, `monitor`, `workbooks`, `grafana` | Infrastructure deployment |
| **Governance** | `policy`, `quota`, `resourcehealth`, `cloudarchitect` | Policy management |

### Monitoring Expansion Priorities

| Priority | Server | Why | How to Monitor |
|----------|--------|-----|----------------|
| 🔴 **P1** | Copilot Studio built-in M365 MCPs | Email, Teams, admin center access | `ai-agent-posture` skill + CloudAppEvents |
| 🔴 **P1** | Security Copilot Agent Creation | Creates autonomous security agents | CloudAppEvents |
| 🟠 **P2** | Power BI Remote MCP | Dataset query access via API | `PowerBIActivity` table |
| 🟠 **P2** | Sentinel Custom MCP Tools | User-defined tools, same audit surface | Already visible in Phase 3 CloudAppEvents |
| 🟡 **P3** | Fabric RTI MCP | ADX/Eventhouse data access | ADX diagnostic logs |
| ⚪ **P4** | Playwright, GitHub, Learn Docs MCPs | Local/public, minimal telemetry | Not monitorable from Sentinel |

---

## ⛔ MANDATORY: Sentinel Workspace Selection

**This skill requires a Sentinel workspace to execute queries. Follow these rules STRICTLY:**

### When invoked from another skill (e.g., incident-investigation):
- Inherit the workspace selection from the parent investigation context
- If no workspace was selected in parent context: **STOP and ask user to select**

### When invoked standalone (direct user request):
1. **Ask the user which Log Analytics workspace to target** — provide workspace name and resource ID
2. **If the user doesn't know:** Use `mcp_azure_mcp_ser_monitor` to list available workspaces, then ask the user to select
3. **If multiple workspaces exist:**
   - Display all workspaces with Name and ID
   - ASK: "Which Sentinel workspace should I use for this analysis?"
   - **⛔ STOP AND WAIT** for user response
   - **⛔ DO NOT proceed until user explicitly selects**
4. **If a query fails on the selected workspace:**
   - **⛔ DO NOT automatically try another workspace**
   - STOP and report the error, display available workspaces, ASK user to select

**🔴 PROHIBITED ACTIONS:**
- ❌ Selecting a workspace without user consent when multiple exist
- ❌ Switching to another workspace after a failure without asking
- ❌ Proceeding with analysis if workspace selection is ambiguous

---

## Skill Files

| File | Purpose |
|------|---------|
| `SKILL.md` | This file — skill instructions, workflow, report template |
| `queries.md` | Pre-authored KQL queries (Q1–Q15) — execute exactly as written |
| `anomaly-detection-jobs.md` | Scheduled KQL Data Lake jobs for proactive anomaly detection |
| `generate_html_report.py` | HTML report generator — reads JSON export, produces styled HTML |
| `svg-widgets.yaml` | SVG dashboard widget manifest for visualization |

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/mcp-usage-monitoring/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/mcp-usage-monitoring/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("mcp-usage-monitoring", "<filename>") from Builder
   → CreateFile("tmp/mcp-usage-monitoring/<filename>", <content>)
   → Repeat for ALL companion files referenced by the script
```

**Rules:**
- When a file is found in `codeRefs/`, execute it directly from there — do NOT copy it to `tmp/`.
- When materializing from Builder (step 3), materialize ALL companion files the script depends on, not just the script itself.
- This cascade applies to every file listed in the Skill Files table above.

---

## Phase 0: Results Cache Check (MANDATORY)

**This phase MUST execute BEFORE any KQL queries. It determines whether to reuse cached results or start fresh.**

### 0.1 Cache File Convention

Results are stored as JSON files following this naming pattern:
```
reports/mcp-usage/mcp_usage_report_<workspace>_<YYYYMMDD_HHMMSS>.json
```

### 0.2 Cache Check Workflow

```
Step 0.1: Search for existing cache files matching the workspace
          → Use: ls reports/mcp-usage/mcp_usage_report_<WORKSPACE>_*.json
          → If NO cache file exists → proceed to Phase 1 (fresh execution)

Step 0.2: If one or more cache files exist, select the MOST RECENT one (latest timestamp)

Step 0.3: Calculate the cache age:
          → Extract timestamp from filename (YYYYMMDD_HHMMSS format)
          → age = current_UTC_time − cache_file_timestamp
          → If age > 4 hours → IGNORE cache entirely, proceed to Phase 1 (fresh execution)
          → If age ≤ 4 hours → proceed to Step 0.4

Step 0.4: Analyze the user's ORIGINAL prompt for implicit intent:

          REDO KEYWORDS (triggers fresh execution, any language):
            "ripeti", "aggiorna", "rifai", "repeat", "redo", "refresh",
            "update", "re-run", "start over", "da capo",
            "from scratch", "ricomincia", "nuovo", "nuova analisi"
          → If ANY redo keyword is detected → IGNORE cache, proceed to Phase 1

          USE-CACHE KEYWORDS (triggers cache reuse, any language):
            "completa", "continua", "complete", "continue", "finish",
            "usa i dati", "use cached", "use existing", "prosegui",
            "riprendi", "resume", "genera report", "generate report",
            "genera il report", "crea report", "genera html"
          → If ANY use-cache keyword is detected → LOAD cache, skip to Phase 7

          NO IMPLICIT INTENT DETECTED:
          → Proceed to Step 0.5 (ask the user)

Step 0.5: ASK the user:

          Question: "Ho trovato risultati di un'analisi MCP precedente per
                     il workspace <WORKSPACE>, completata <TIME_AGO> fa
                     (alle <HH:MM> UTC).
                     Vuoi utilizzare questi dati o preferisci rieseguire
                     le query da zero?"
          Options:
            1. "Usa i dati esistenti" — Riprende dall'analisi precedente
            2. "Riesegui da zero" — Ignora la cache e riesegue tutte le query

          → If user selects "Usa i dati esistenti" → LOAD cache, skip to Phase 7
          → If user selects "Riesegui da zero" → proceed to Phase 1

Step 0.6: LOAD cached data:
          → Read the JSON file
          → Present a brief inline summary of cached findings
          → Offer HTML/report generation
```

### 0.3 Cache Decision Summary

| Cache Exists? | Age | User Prompt | Action |
|---------------|-----|-------------|--------|
| No | — | — | Fresh execution (Phase 1) |
| Yes | > 4 hours | — | Fresh execution — cache expired |
| Yes | ≤ 4 hours | Contains REDO keyword | Fresh execution |
| Yes | ≤ 4 hours | Contains USE-CACHE keyword | Load cache → Phase 7 |
| Yes | ≤ 4 hours | No implicit intent | ASK user |

### 0.4 Important Rules

- **NEVER silently reuse cached data** — always either detect explicit intent from the prompt or ask the user.
- **NEVER ask the user if the prompt already contains an implicit answer** — detect keywords first.
- **When loading cache, always show what was already completed** — the user must understand what data is from cache.
- **Cache files from a DIFFERENT thread/session are still valid** — the 4-hour TTL is the only expiration criterion.

---

## Output Modes

This skill supports three output modes. **ASK the user which they prefer** if not explicitly specified. Multiple modes may be active simultaneously.

### Mode 1: Inline Chat Summary (Default)
- Render the full MCP usage analysis directly in the chat response
- Includes ASCII tables, trend charts, endpoint breakdowns, and security assessment
- Best for quick review and interactive follow-up questions

### Mode 2: Markdown File Report
- Save a comprehensive report to `reports/mcp-usage/MCP_Usage_Report_<timestamp>.md`
- All ASCII visualizations render correctly inside markdown code fences
- Use `create_file` tool — NEVER use terminal commands for file output
- **Filename pattern:** `reports/mcp-usage/MCP_Usage_Report_YYYYMMDD_HHMMSS.md`

### Mode 3: HTML Report (only if explicitly requested — conditional materialization)
- Export analysis data to JSON, then generate a styled HTML report via `generate_html_report.py`
- Self-contained HTML with embedded CSS — dark theme, two-column layout, MCP server color-coded sections, score card, daily trends, security assessment
- **Pipeline:** JSON export → materialize `generate_html_report.py` → run → HTML report
- **Output location:** `reports/mcp-usage/MCP_Usage_Report_<workspace>_<timestamp>.html`
- **⚠️ Conditional — File Resolution Cascade:** The script is resolved to disk ONLY when the user requests HTML output.
  1. Export data to JSON: `reports/mcp-usage/mcp_usage_report_<workspace>_<timestamp>.json`
  2. Resolve `generate_html_report.py` via the [File Resolution cascade](#file-resolution-coderefs-first):
     - Check `codeRefs/sec-sre-ag/mcp-usage-monitoring/generate_html_report.py` → if found, use that path.
     - Else check `tmp/mcp-usage-monitoring/generate_html_report.py` → if found, use that path.
     - Else: `read_skill_file("mcp-usage-monitoring", "generate_html_report.py")` → `CreateFile("tmp/mcp-usage-monitoring/generate_html_report.py", <content>)`
  3. Run: `python3 <resolved_path>/generate_html_report.py reports/mcp-usage/mcp_usage_report_*.json --output-dir reports/mcp-usage/`
- **Trigger:** User says "generate HTML", "HTML report", "create HTML", or similar

Do NOT materialize the script unless the user explicitly requests an HTML report.

---

## Scalability & Token Management

This skill was developed in a small lab environment (1–2 users, single workspace). In larger tenants, **query complexity is not a concern** — all queries use `summarize`, `dcount`, `make_set(..., N)`, and `take` operators, so result sets remain bounded. The **primary risk in large environments is LLM token exhaustion**.

### Guardrails for Large Environments

| Parameter | Small Env (default) | Large Env |
|-----------|--------------------|-----------|
| `make_set(..., N)` for users | 10 | 5 |
| `make_set(..., N)` for endpoints | 20–30 | 10 |
| `take` on governance tables | 25 | 15 |
| `take` on endpoint rankings | 25 | 15 |

**Incremental file writes (markdown mode):** Write header first with `create_file`, then append sections with `replace_string_in_file`.

**Two-pass approach for very large tenants:** Pass 1 = summary with aggressive limits. Pass 2 = drill-down on specific sections.

---

## Quick Start (TL;DR)

When a user requests MCP usage monitoring:

1. **Select Workspace** → Ask user, or use `mcp_azure_mcp_ser_monitor` to discover workspaces
2. **Determine Output Mode** → Ask if not specified: inline, markdown file, or both
3. **Determine Time Range** → Ask if not specified; default 30 days
4. **Run Phase 1 (Graph MCP)** → Load queries from [`queries.md`](queries.md), execute Q1 + Q2 via `mcp_azure_mcp_ser_monitor`
5. **Run Phase 2 (Sentinel Triage MCP)** → Execute Q3-Q7
6. **Run Phase 3 (Sentinel Data Lake MCP)** → Execute Q10-Q12
7. **Run Phase 4 (Azure MCP & ARM)** → Execute Q13-Q14
8. **Run Phase 5 (Workspace Governance)** → Execute Q8
9. **Run Phase 6 (Cross-Server User Analysis)** → Execute Q9 + Q15
10. **Run Phase 7 (Assessment)** → Compute MCP Usage Score, security assessment, render report

**Parallel execution:** Phases 1-5 contain independent queries — run all of them in parallel for performance. Phases 6-7 depend on results from 1-5.

**Query execution method:** All queries are executed via `mcp_azure_mcp_ser_monitor` against the user's Log Analytics workspace. Load the tool first with `tool_search` for "azure monitor workspace".

---

## MCP Usage Score Formula

The MCP Usage Score is a composite health and risk indicator that summarizes MCP server activity.

### Scoring Dimensions

$$
\text{MCPUsageScore} = \sum_{i} \text{DimensionScore}_i
$$

Each dimension contributes 0–20 points to a maximum of 100:

| Dimension | Max Points | Green (0-5) | Yellow (6-12) | Red (13-20) |
|-----------|-----------|-------------|---------------|-------------|
| **User Diversity** | 20 | 1-2 known users | 3-5 users or 1 unknown | >5 users or unknown users |
| **Endpoint Sensitivity** | 20 | 0% sensitive endpoints | 1-30% sensitive | >30% calls to sensitive APIs |
| **Error Rate** | 20 | <1% errors | 1-5% errors | >5% errors |
| **Volume Anomaly** | 20 | Within ±50% of daily avg | 50-200% spike | >200% spike vs avg |
| **Off-Hours Activity** | 20 | <5% off-hours | 5-20% off-hours | >20% calls outside business hours |

### Interpretation Scale

| Score | Meaning | Action |
|-------|---------|--------|
| **0–25** | Healthy | ✅ Normal MCP usage, no concerns |
| **26–50** | Elevated | 🟡 Review — minor anomalies detected |
| **51–75** | Concerning | 🟠 Investigate — multiple risk signals present |
| **76–100** | Critical | 🔴 Immediate review — significant security risk |

### Sensitivity Classification

**Sensitive Graph API endpoints** — flag any MCP calls to these patterns:

```
roleManagement, roleAssignments, roleEligibility,
authentication/methods, identityProtection, riskyUsers,
riskDetections, conditionalAccess, servicePrincipals,
appRoleAssignments, oauth2PermissionGrants,
auditLogs, directoryRoles, privilegedAccess,
security/alerts, security/incidents
```

### Off-Hours Definition

Business hours: **08:00–18:00 local time** (derive from user's primary sign-in timezone, or use UTC if unknown). Weekends count as off-hours for all 24 hours.

---

## Execution Workflow

### Phase 1: Graph MCP Server Analysis

**Data source:** `MicrosoftGraphActivityLogs`
**Filter:** `AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"`
**Execution:** `mcp_azure_mcp_ser_monitor` against Log Analytics workspace

Collect:
- **Execute Query 1** (Unified Daily MCP Activity Trend) — returns daily `Server | Day | Calls | Errors | ErrorRate` for ALL 4 MCP servers in one pass. Run this ONCE here; do NOT re-run in Phases 2–4.
- **Execute Query 2** (Endpoint & Activity Summary) — returns per-endpoint rows with call counts, sensitivity flag, off-hours metrics, error rates, and user sets.

### Phase 2: Sentinel Triage MCP Analysis

**Data sources:** `MicrosoftGraphActivityLogs`, `SigninLogs`, `AADNonInteractiveUserSignInLogs`
**Filter:** AppId = `7b7b3966-1961-47b5-b080-43ca5482e21c` ("Microsoft Defender Mcp")

**Detection Method (Confirmed Feb 2026):**
The Sentinel Triage MCP has a **dedicated AppId** (`7b7b3966`) visible in both `MicrosoftGraphActivityLogs` and `SigninLogs`/`AADNonInteractiveUserSignInLogs`. Enables **definitive attribution**.

**Key characteristics:**
- **AppDisplayName:** "Microsoft Defender Mcp"
- **Auth type:** Delegated + certificate (ClientAuthMethod=2)
- **Scopes:** `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `ThreatHunting.Read.All`
- **API endpoints:** POST `/v1.0/security/runHuntingQuery/`, GET `/security/incidents/`, GET `/security/alerts_v2/`

Collect:
- **Execute Query 3** — authentication events by client app
- **Execute Query 4** — client app usage breakdown
- **Execute Query 5** — Triage MCP API usage from `MicrosoftGraphActivityLogs`
- **Execute Query 6** — Triage MCP authentication events from `SigninLogs`/`AADNonInteractiveUserSignInLogs`
- **Execute Query 7** — LAQueryLogs for Advanced Hunting downstream queries

### Phase 3: Sentinel Data Lake MCP Analysis

**Data source:** `CloudAppEvents` (Purview unified audit log)
**Execution:** `mcp_azure_mcp_ser_monitor` — `CloudAppEvents` uses `TimeGenerated` when queried via Log Analytics (not `Timestamp` as in Advanced Hunting).
**Filter:** `ActionType contains "Sentinel"` or `ActionType contains "KQL"`. RecordType is inside `RawEventData` — extract with `parse_json(tostring(RawEventData)).RecordType`.

**⚠️ MANDATORY:** Execute Query 10 before reporting any gap. Do NOT skip this phase based on licensing assumptions.

**MCP vs Direct KQL Delineation:**

| Access Pattern | RecordType | Interface | What It Represents |
|---|---|---|---|
| **MCP Server-driven** | 403 | `IMcpToolTemplate` | Tool calls via Sentinel Data Lake MCP |
| **Direct KQL** | 379 | `KqsService` | KQL queries executed directly |

**⚠️ Known Limitation:** RecordType 403 may not be emitted. Fallback: use Interface breakdown within RecordType 379. `InterfaceNotProvided` contains MCP-driven queries.

Collect:
- **Execute Query 10** — Data Lake MCP access pattern summary
- **Execute Query 11** — interface breakdown with call counts
- **Execute Query 12** — error analysis

### Phase 4: Azure MCP Server Authentication & Queries

**Data sources:** `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs`
**Filter:** AppId = `04b07795-8ddb-461a-bbee-02f9e1bf7b46`

Collect:
- **Execute Query 13** — Azure MCP Server authentication events
- **Execute Query 14** — Azure MCP Server workspace queries from LAQueryLogs

**Detection Method (🔄 Updated Feb 2026):**
Azure MCP Server authenticates via **Azure CLI credential** (`04b07795`), NOT `AzurePowerShellCredential` (`1950a258`) as previously documented. `RequestClientApp` is **empty**. Best differentiator: Azure MCP appends `\n| limit N` to query text.

**🔴 Token Caching Behavior:** Sign-in events appear at **token acquisition time**, NOT at each API call. ~1hr token lifetime means at most ~24 sign-in event clusters per day.

### Phase 5: Workspace Query Governance

**Data source:** `LAQueryLogs` (Analytics tier), `CloudAppEvents` (Data Lake tier)

Collect:
- **Execute Query 8** — all clients querying the Analytics tier workspace
- Data Lake tier query volume from Phase 3 results

### Phase 6: Cross-Server User Analysis

Collect:
- **Execute Query 9** — Graph MCP caller attribution (User vs SPN)
- **Execute Query 15** — Top MCP users ranked by cross-server breadth

**Note:** For SPN enrichment (Query 9 post-processing), since Graph MCP is not integrated with Azure SRE Agent, cross-reference SPNs with `AADServicePrincipalSignInLogs` or `AuditLogs` in the workspace to identify `tags` like `AgenticApp`, `AIAgentBuilder`, etc.

### Phase 7: Score Computation & Report Generation

1. **Compute per-dimension scores** from Phase 1-6 data
2. **Sum dimension scores** for composite MCP Usage Score
3. **Include Top MCP Users table** (Phase 6 — Query 15)
4. **Generate security assessment** with emoji-coded findings
5. **Render output** in the user's selected mode
6. **Validate report completeness** — run the [Report Completeness Checklist](#report-completeness-checklist)

---

## Sample KQL Queries

> 🔴 **All pre-authored queries are in the companion file [`queries.md`](queries.md).** Execute them EXACTLY as written, substituting only the time range parameter.

| Query | Purpose | Phase |
|-------|---------|-------|
| Q1 | Unified Daily MCP Activity Trend (all 4 servers) | 1 |
| Q2 | Graph MCP — Endpoint & Activity Summary | 1 |
| Q3 | Sentinel MCP — Authentication Events | 2 |
| Q4 | Sentinel MCP — Client App Breakdown | 2 |
| Q5 | Sentinel Triage MCP — API Call Activity | 2 |
| Q6 | Sentinel Triage MCP — Authentication Events | 2 |
| Q7 | LAQueryLogs — Advanced Hunting Downstream Queries | 2 |
| Q8 | All Workspace Query Sources — Governance View | 5 |
| Q9 | Graph MCP — Caller Attribution (User vs SPN) | 6 |
| Q10 | Data Lake MCP — Access Pattern Summary | 3 |
| Q11 | Data Lake MCP — Interface Breakdown | 3 |
| Q12 | Data Lake MCP — Error Analysis | 3 |
| Q13 | Azure MCP Server — Authentication Events | 4 |
| Q14 | Azure MCP Server — Workspace Queries | 4 |
| Q15 | Top MCP Users — Cross-Server Breadth | 6 |

**Execution method:** Read the query from [`queries.md`](queries.md), then execute via `mcp_azure_mcp_ser_monitor` against the selected workspace.

---

## Report Template

### Inline Chat Report Structure

The inline report MUST include these sections in order:

1. **Header** — Workspace, analysis period, data sources checked, MCP servers detected
2. **Executive Summary** — 2-3 sentence overview
3. **MCP Footprint Summary** — Server Landscape table + Consolidated KPIs
4. **Graph MCP Server Analysis** — Daily trend, top endpoints, sensitive APIs, caller attribution
5. **Sentinel Triage MCP Analysis** — API calls, auth events, user attribution
6. **Sentinel Data Lake MCP Analysis** — Tool usage, MCP vs Direct KQL, errors
7. **Azure MCP & ARM Analysis** — Auth events, workspace queries, ARM operations
8. **Workspace Query Governance (Two-Tier)** — Analytics + Data Lake tiers
9. **Top MCP Users (Cross-Server Breadth)** — Ranked table
10. **MCP Usage Score** — Per-dimension breakdown
11. **Security Assessment** — Emoji-coded findings
12. **Recommendations** — Prioritized action items

### Report Completeness Checklist

| # | Section | Required Sub-Section | Data Source | Check |
|---|---------|---------------------|-------------|-------|
| 4 | Graph MCP Server | Daily Usage Trend | Q1 → `Server = "Graph MCP"` | ☐ |
| 4 | Graph MCP Server | Top Endpoints table | Q2 | ☐ |
| 4 | Graph MCP Server | Sensitive API access | Q2 `IsSensitive` rows | ☐ |
| 4 | Graph MCP Server | Caller attribution | Q9 | ☐ |
| 5 | Sentinel Triage MCP | Daily Usage Trend | Q1 → `Server = "Triage MCP"` | ☐ |
| 5 | Sentinel Triage MCP | API calls table | Q5 | ☐ |
| 5 | Sentinel Triage MCP | Authentication events | Q6 | ☐ |
| 6 | Data Lake MCP | Daily Activity Trend | Q1 → `Server = "Data Lake MCP"` | ☐ |
| 6 | Data Lake MCP | MCP vs Direct KQL delineation | Q10 | ☐ |
| 6 | Data Lake MCP | Tool breakdown table | Q11 | ☐ |
| 6 | Data Lake MCP | Error analysis | Q12 | ☐ |
| 7 | Azure MCP Server | Daily Auth Trend | Q1 → `Server = "Azure MCP/CLI"` | ☐ |
| 7 | Azure MCP Server | Authentication events | Q13 | ☐ |
| 7 | Azure MCP Server | Workspace queries | Q14 | ☐ |
| 9 | Top MCP Users | Cross-server breadth table | Q15 | ☐ |

### Report Visualization Patterns

#### Daily Usage Trend (ASCII)
```
Graph MCP Usage — Last 30 Days
Day         Calls  Trend
─────────────────────────────────────
2026-02-07  │ 23   ████████████
2026-02-06  │  0   
2026-02-05  │ 45   ██████████████████████
...
─────────────────────────────────────
Avg: 15.2/day  Peak: 45  Total: 152
```

#### MCP Usage Score Card (ASCII)
```
┌──────────────────────────────────────────────────────┐
│               MCP USAGE SCORE: 22/100                │
│                 Rating: ✅ HEALTHY                    │
├──────────────────────────────────────────────────────┤
│ User Diversity     [██░░░░░░░░] 3/20  (1-2 users)   │
│ Endpoint Sensitiv  [████████░░] 14/20 (54% sensitive)│
│ Error Rate         [░░░░░░░░░░] 0/20  (<1% errors)  │
│ Volume Anomaly     [██░░░░░░░░] 3/20  (within norm)  │
│ Off-Hours Activity [█░░░░░░░░░] 2/20  (<5% off-hrs)  │
└──────────────────────────────────────────────────────┘
```

### Markdown File Report Structure

When outputting to markdown file, include everything from the inline format PLUS:

- Full header with generation timestamp, workspace, analysis period, data sources
- All ASCII visualizations wrapped in code fences
- Appendix: Query Details table (query name, tables, records scanned, results, execution time — do NOT include full KQL text, reference [`queries.md`](queries.md) instead)

---

## Proactive Alerting — KQL Data Lake Jobs

This skill provides **on-demand visibility** (Phases 1-7 above). For **continuous, scheduled anomaly detection**, use the companion KQL Data Lake Jobs defined in:

📄 **[`anomaly-detection-jobs.md`](anomaly-detection-jobs.md)**

### Maturity Model

| Tier | Capability | Implementation |
|------|-----------|----------------|
| **1. Visibility** (current skill) | On-demand MCP usage reports | This SKILL.md — Phases 1-7, Queries 1-15 |
| **2. Baselining** | 14-day behavioral baselines per user per MCP server | KQL Jobs 1-8 build baselines automatically |
| **3. Alerting** | Automated anomaly detection → Sentinel incidents | KQL Jobs promote to `_KQL_CL` tables → Analytics Rules fire |
| **4. Enforcement** | Real-time guardrails, scope limits (future) | Not yet available |

### KQL Job Inventory

| Job | Anomaly Type | Source Table(s) | Destination Table | Schedule |
|-----|-------------|-----------------|-------------------|----------|
| **1** | New sensitive Graph endpoint | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **2** | Graph MCP volume spike (3x baseline) | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **3** | Off-hours Graph MCP activity | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **4** | Graph MCP error rate anomaly | `MicrosoftGraphActivityLogs` | `MCPGraphAnomalies_KQL_CL` | Daily |
| **5** | New Azure MCP Server user | `AADNonInteractiveUserSignInLogs` | `MCPAzureAnomalies_KQL_CL` | Daily |
| **6** | New Azure MCP resource target | `AADNonInteractiveUserSignInLogs` | `MCPAzureAnomalies_KQL_CL` | Daily |
| **7** | Sentinel workspace query anomalies | `LAQueryLogs` | `MCPSentinelAnomalies_KQL_CL` | Daily |
| **8** | Cross-MCP activity chains | Multiple (join) | `MCPCrossMCPCorrelation_KQL_CL` | Daily |

### Architecture

```
Data Lake ──[KQL Jobs (daily)]──► _KQL_CL tables (analytics tier) ──[Analytics Rules]──► Incidents
```

For full query definitions, deployment checklist, and companion detection rule templates, see [`anomaly-detection-jobs.md`](anomaly-detection-jobs.md).

---

## Known Pitfalls

### `project ... as` Keyword Fails in Advanced Hunting
**Problem:** The `as` keyword for column aliasing inside `project` fails in AH with `Query could not be parsed at 'as'`.
**Solution:** Always use `=` assignment syntax: `ErrorCode = tostring(parse_json(Status).errorCode)`.

### Azure MCP Server Detection (🔄 Updated Feb 2026)
**Problem:** Azure MCP Server uses `DefaultAzureCredential` → Azure CLI (`04b07795`), NOT `1950a258`.
**Solution:** Filter LAQueryLogs by AADClientId `04b07795` + query text containing `\n| limit` (suffix added by `monitor_workspace_log_query`). Present as "Azure MCP Server / Azure CLI (shared AppId `04b07795`)" in reports.

### MicrosoftGraphActivityLogs Availability
**Problem:** Graph activity logs NOT enabled by default.
**Solution:** If table is empty/missing, report: "⚠️ Microsoft Graph activity logs are not enabled." Skip Graph MCP analysis gracefully.

### LAQueryLogs Diagnostic Settings
**Problem:** `LAQueryLogs` requires diagnostic settings.
**Solution:** If empty, report: "⚠️ LAQueryLogs not available." Skip governance analysis.

### AppId Misclassification History
- **`80ccca67`** = M365 Security & Compliance Center (Sentinel Portal backend, NOT MCP)
- **`95a5d94c`** = Azure Portal — AppInsightsPortalExtension (NOT MCP)

### CloudAppEvents CamelCase Matching (`ActionType` AND `Operation`)
**Problem:** `has` operator requires word boundaries — fails on CamelCase (`SentinelAIToolRunCompleted`).
**Solution:** Always use `contains` (not `has`) for ActionType/Operation filtering.

### CloudAppEvents RawEventData Parsing
**Problem:** Direct property access may return empty.
**Solution:** Always `parse_json(tostring(RawEventData))` then extract fields.

### Data Lake MCP Has No AppId
**Solution:** Filter via `CloudAppEvents` — `ActionType contains "SentinelAITool"` or RecordType 403 from `RawEventData`.

### CloudAppEvents Double-Counting Prevention
**Problem:** Each tool call generates TWO events (Started + Completed).
**Solution:** Filter on `Operation == "SentinelAIToolRunCompleted"` for counts.

### Data Lake MCP ExecutionDuration Format
**Problem:** Stored as string.
**Solution:** Use `todouble(RawData.ExecutionDuration)`.

### SigninLogs `Status` Field Needs `parse_json()` in Data Lake
**Solution:** Always use `tostring(parse_json(Status).errorCode)`.

### `Type` Column Unavailable in Data Lake Union Contexts
**Solution:** Add `| extend SignInType = "Interactive"` within each union leg.

### `AADNonInteractiveUserSignInLogs` Commonly on Data Lake Tier
**Problem:** Union with `SigninLogs` may fail in AH.
**Solution:** All queries in this skill run via Log Analytics (`mcp_azure_mcp_ser_monitor`), which handles cross-table unions natively regardless of tier. `CloudAppEvents` uses `TimeGenerated` in Log Analytics.

### CloudAppEvents Timestamp Column
**Problem:** In Advanced Hunting, `CloudAppEvents` uses `Timestamp`. In Log Analytics, it uses `TimeGenerated`.
**Solution:** Since this skill always queries via Log Analytics (`mcp_azure_mcp_ser_monitor`), ALL queries in [`queries.md`](queries.md) use `TimeGenerated` consistently.

---

## Error Handling

### Common Issues

| Issue | Solution |
|-------|----------|
| `MicrosoftGraphActivityLogs` table not found | Graph activity logs not enabled. Report gap, skip Graph MCP. |
| `LAQueryLogs` table not found | Diagnostic settings not configured. Report gap, skip governance. |
| `CloudAppEvents` table not found | Purview unified audit not available. Report gap, skip Phase 3. |
| `ActionType has "Sentinel"` returns 0 | CamelCase bug — use `contains`. |
| `RawEventData.ToolName` returns empty | Double-parse: `parse_json(tostring(RawEventData))`. |
| Query timeout | Reduce lookback or add `| take 100`. |
| Unknown AppId in LAQueryLogs | Check `RequestClientApp` field first. |
| Azure MCP indistinguishable from CLI | Use `\n| limit N` query text pattern. Present as shared. |
| `mcp_azure_mcp_ser_monitor` not loaded | Run `tool_search` for "azure monitor" first. |

### Validation Checklist

- [ ] All MCP telemetry surfaces queried (Graph, Triage, Data Lake, Azure, LAQueryLogs, CloudAppEvents)
- [ ] Tables that don't exist reported as gaps, not silent omissions
- [ ] Non-MCP sources clearly labeled "Platform/Portal (Non-MCP)"
- [ ] `80ccca67` = Sentinel Portal (NOT MCP); `95a5d94c` = AppInsightsPortalExtension (NOT MCP)
- [ ] MCP proportion excludes non-MCP platform sources
- [ ] Two-tier governance view: Analytics (LAQueryLogs) + Data Lake (CloudAppEvents)
- [ ] CloudAppEvents queries use `contains` (not `has`) for ActionType/Operation
- [ ] CloudAppEvents RawEventData parsed with `parse_json(tostring())` pattern
- [ ] Tool call counts use `Completed` only (no double-counting)
- [ ] Azure MCP detection uses AppId `04b07795` + `\n| limit N` suffix
- [ ] Off-hours analysis states timezone assumption (default: UTC)
- [ ] Empty results explicitly reported with ✅

---

## Prerequisites

| Data Source | Required For |
|-------------|--------------|
| **Microsoft Graph activity logs** | Graph MCP analysis (Q1-2, 5, 9) |
| **CloudAppEvents (Purview unified audit)** | Data Lake MCP analysis (Q10-12) |
| **LAQueryLogs (diagnostic settings)** | Workspace governance (Q7, 8, 14) |
| **AzureActivity** | Azure MCP analysis |
| **SigninLogs** | Sentinel MCP auth events (Q3-4, 6, 13) |

---

## SVG Dashboard Generation

> 📊 **Optional post-report step.** After an MCP Usage report is generated, the user can request a visual SVG dashboard.

**Trigger phrases:** "generate SVG dashboard", "create a visual dashboard", "visualize this report"

### How to Request a Dashboard

- **Same chat:** "Generate an SVG dashboard from the report"
- **New chat:** Attach or reference the report file
- **Customization:** Edit [svg-widgets.yaml](svg-widgets.yaml) before requesting

### Execution

```
Step 1:  Read svg-widgets.yaml (this skill's widget manifest)
Step 2:  Read the SVG dashboard rendering skill (if available)
Step 3:  Read the completed report file (data source)
Step 4:  Render SVG → save to reports/mcp-usage/{report_name}_dashboard.svg
```
