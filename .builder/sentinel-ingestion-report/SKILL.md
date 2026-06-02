---
name: sentinel-ingestion-report
description: 'Sentinel Ingestion Report — YAML-driven Python pipeline gathers all data via az monitor/az rest/Graph API, writes a deterministic scratchpad, LLM renders the report inline. Covers table-level volume breakdown, tier classification (Analytics/Basic/Data Lake), SecurityEvent/Syslog/CommonSecurityLog deep dives, ingestion anomaly detection (24h and WoW), analytic rule inventory via REST API, rule health via SentinelHealth, detection coverage cross-reference, tier migration candidates with DL-eligibility lookup, license benefit analysis (DfS P2 500MB/server/day, M365 E5 data grant). Output always inline; optional md/html export on request.'
---

# Sentinel Ingestion Analysis Report — Instructions

## ⚠️ Environment Constraints — Tool Availability

This skill operates in an environment where the following MCP servers are **not integrated** with Azure SRE Agent and therefore **cannot be used for direct querying**:

| ❌ Not Integrated | Scope | Replacement | Note |
|------------------|-------|-------------|------|
| **Sentinel MCP Server** (`mcp_microsoft_se2_*`) | Data Lake Exploration, `query_lake`, `search_tables`, `analyze_*` | `az monitor log-analytics query` (KQL via Azure CLI) | Cannot currently be connected to Azure SRE Agent. Data reachable via direct API — not yet implemented. |
| **MTP MCP Server** (`mcp_mtp_mcp_servi_*`) | Advanced Hunting, Defender Triage | `az monitor log-analytics query` (KQL via Azure CLI) | Cannot currently be connected to Azure SRE Agent. Data reachable via direct API — not yet implemented. |
| **Microsoft Graph MCP** (`mcp_microsoft_ent_*`) | Graph API queries | `az rest` with Graph API endpoints | Cannot currently be connected to Azure SRE Agent. Data reachable via direct API — not yet implemented. |

The following tools **ARE available** and can be used:

| ✅ Available | Scope | Use Case |
|-------------|-------|----------|
| **Azure MCP Server** (`mcp_azure_mcp_ser_*`) | Azure resource management, Kusto, monitoring | Infrastructure queries, resource health |
| **KQL Search MCP** (`mcp_kql-search-mc_*`) | KQL query examples, table schema lookup, ASIM parser info | Query validation, schema discovery, ASIM verification |
| **Microsoft Learn MCP** (`mcp_microsoft_le*_*`) | Documentation search, code samples | Reference lookups, best practice guidance |
| **Direct Log Analytics** | `az monitor log-analytics query` | All KQL query execution |

**All KQL queries, REST API calls, and Graph API calls are pre-defined in YAML files and executed by `invoke_ingestion_scan.py` via Azure CLI.** No MCP server is needed for data gathering or report generation. The queries are permanent, pre-tested, and stored in `queries.yaml`.

---

## Purpose

This skill generates a comprehensive **Sentinel Ingestion Analysis Report** covering workspace data volume, table-level breakdown, tier classification, ingestion anomalies, detection coverage, and optimization opportunities.

**Entity Type:** Sentinel workspace (from `config.json`)

| Scope | Primary Tables | Use Case |
|-------|----------------|----------|
| Workspace-wide (default) | `Usage`, `SentinelHealth`, `SentinelAudit` | Full ingestion and cost analysis |
| Per-table deep dive | `SecurityEvent`, `Syslog`, `CommonSecurityLog` + any table | Granular breakdown of high-volume tables |

**What this report covers:** Table-level volume breakdown with tier classification (Analytics/Basic/Data Lake), SecurityEvent/Syslog/CommonSecurityLog deep dives, ingestion anomaly detection (24h and week-over-week), analytic rule inventory with detection coverage cross-reference, rule health monitoring, tier migration candidates with DL-eligibility assessment, and license benefit analysis (DfS P2 and M365 E5).

---

## Architecture

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  queries.yaml        Python script               LLM render      │
 │  (23 queries)   ──→  invoke_ingestion_scan.py ──→  Phase 6       │
 │                      • az monitor (KQL)            (SKILL-        │
 │                      • az rest (REST + Graph)       report.md)   │
 │                      • az monitor table list                     │
 │                      ↓                                           │
 │            tmp/sentinel-ingestion-report/                        │
 │              scratchpad_<ws>_<ts>.md                             │
 │              (~50 KB, 64 sections)                               │
 └───────────────────────────────────────────────────────────────────┘
```

**Execution model:**
- **Phases 1-5** (data gathering): Fully automated by `invoke_ingestion_scan.py`. KQL queries run via `az monitor log-analytics query`. Non-KQL data (analytic rules, tier classifications, custom detections) is gathered via REST API (`az rest`) and Azure CLI.
- **Phase 6** (rendering): LLM reads the scratchpad + `SKILL-report.md` and renders the report inline. This is the only phase requiring LLM involvement.
- **HTML export** (optional): `generate_html_report.py` converts the scratchpad to a self-contained dark-theme HTML report.

**File materialization:** All output files (scratchpad, optional exports) are written to `tmp/sentinel-ingestion-report/` under the workspace root, following the same pattern as `mitre-coverage-report`.

**Design decision — TopRecommendations:** The Top 3 Recommendations are computed by the LLM at render time (Phase 6), not pre-computed. Three of the seven Rule E categories (Data loss, DCR filter, Split ingestion) require cross-section reasoning that spans multiple scratchpad sections — this is precisely what the LLM excels at. The Python script provides all the raw data; the LLM applies Rule E scoring across it.

---

## Companion Files — When to Load

This skill spans **4 files**. Load only the file(s) needed for the current phase:

| File | Purpose | When to Load |
|------|---------|--------------|
| **SKILL.md** (this file) | Architecture, workflow, rendering rules, domain reference | Always — primary entry point |
| [SKILL-report.md](SKILL-report.md) | Report templates (§1-§8), section-to-scratchpad mapping, formatting rules | Phase 6 rendering only |
| [SKILL-drilldown.md](SKILL-drilldown.md) | **Post-report drill-down** — rule cross-referencing (AR + CD via Graph API), ASIM parser verification, known pitfalls, error handling | After report is generated, when user asks follow-up questions (see [§13 summary](#post-report-drill-down-reference)) |
| [invoke_ingestion_scan.py](invoke_ingestion_scan.py) | Python data-gathering pipeline (Phases 1-5) | Execution only — no need to read unless debugging |
| [generate_html_report.py](generate_html_report.py) | Scratchpad → HTML report converter (dark theme) | Optional — when user requests HTML export |

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/sentinel-ingestion-report/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. sentinel-ingestion-report/<filename>
   → If found in the repo folder: use/execute from this path
3. tmp/sentinel-ingestion-report/<filename>
   → If found: use from this path
4. None of the above:
   → read_skill_file("sentinel-ingestion-report", "<filename>") from Builder
   → CreateFile("tmp/sentinel-ingestion-report/<filename>", <content>)
   → Repeat for ALL companion files referenced by the script (queries.yaml, etc.)
```

**Rules:**
- When a file is found in `codeRefs/` or the repo folder, execute it directly from there — do NOT copy it to `tmp/`.
- When materializing from Builder (step 4), materialize ALL companion files the script depends on, not just the script itself.
- This cascade applies to `invoke_ingestion_scan.py`, `generate_html_report.py`, and `queries.yaml`.

---

## 📑 TABLE OF CONTENTS

1. **[Quick Start](#quick-start-tldr)** - 3-step execution pattern
2. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Prerequisites and prohibitions
3. **[Execution Workflow](#execution-workflow)** - Phases 0-6
4. **[Query File Reference](#query-file-reference)** - All 23 YAML files
5. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
6. **[Deterministic Rendering Rules](#deterministic-rendering-rules)** - Rules A-G (mandatory for Phase 6)
7. **[Domain Reference](#domain-reference)** - SecurityEvent, Syslog, CommonSecurityLog interpretation
8. **[Tier Classification](#tier-classification)** - Analytics vs Basic vs Data Lake background
9. **[Migration Classification](#migration-classification)** - Zero-rule table categorization for §7a
10. **[Reference: Data Lake Migration](#reference-data-lake-migration)** - DL-eligible tables, decision matrix, trade-off analysis
11. **[Reference: License Benefits](#reference-license-benefits)** - DfS P2 / E5 pool calculations
12. **[Report Template](#report-template)** - JIT pointer → SKILL-report.md
13. **[Post-Report Drill-Down Reference](#post-report-drill-down-reference)** - Rule cross-referencing, Custom Detection API, ASIM verification, error handling
14. **[SVG Dashboard Generation](#svg-dashboard-generation)** - Visual dashboard from completed report

---

## Quick Start (TL;DR)

**3-step execution pattern:**

```
Step 1:  Run invoke_ingestion_scan.py (Phases 1-5 — data gathering)
Step 2:  Read scratchpad + SKILL-report.md (Phase 6 prep)
Step 3:  Render report inline (§1-§8) — always inline, optional md/html export
```

### Step 1: Run Data Gathering

Resolve `invoke_ingestion_scan.py` via the [File Resolution cascade](#file-resolution-coderefs-first), then run:

```bash
# From the resolved path — run all phases (default: 30 days):
python <resolved_path>/invoke_ingestion_scan.py

# Specify a custom window (1, 7, 30, 60, or 90 days):
python <resolved_path>/invoke_ingestion_scan.py --days 7

# Run a specific phase (for re-runs / debugging):
python <resolved_path>/invoke_ingestion_scan.py --phase 3

# Force re-execution (ignore cached scratchpad):
python <resolved_path>/invoke_ingestion_scan.py --redo
```

> **Note:** The script looks for `config.json` by walking up from its location. Place `config.json` at the workspace root with `sentinel_workspace_id`, `subscription_id`, and `azure_mcp.resource_group` / `azure_mcp.workspace_name` fields.

**Output:** Scratchpad file at `tmp/sentinel-ingestion-report/scratchpad_<workspace>_<timestamp>.md` (~50 KB, 64 sections).

**Timing:** Full run takes ~20-25 seconds. Individual phases: 3-8 seconds each.

### Cache Behavior

- If a scratchpad exists with age **< 4 hours**, ask the user whether to use cached results or re-run
- If the user says "redo", "rifai", "re-run", or passes `--redo` → always re-execute regardless of cache age
- If cache is **≥ 4 hours old** or no scratchpad exists → always re-execute

### Step 2: Load Rendering Context

1. Read the scratchpad file (path printed by the script at completion)
2. Read [SKILL-report.md](SKILL-report.md) for rendering templates

### Step 3: Render Report (Always Inline)

Render the **complete report (§1-§8) inline in chat**. This is the default and only initial output mode. Apply SKILL-report.md templates to scratchpad data, following Rules A-G.

**Optional exports (only when user explicitly requests):**
- **Markdown file:** `python invoke_ingestion_scan.py --export md` or user says "export as markdown"
- **HTML file:** Resolve `generate_html_report.py` via the [File Resolution cascade](#file-resolution-coderefs-first), then run: `python <resolved_path>/generate_html_report.py <scratchpad_path>` or user says "export as html" / "generate html"
- HTML export generates a self-contained dark-theme HTML file in `tmp/sentinel-ingestion-report/`

**⛔ Do NOT ask the user for output mode.** Always render inline. Only generate md/html files when explicitly requested.

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY ingestion report:**

1. **Run `invoke_ingestion_scan.py`** — this single script handles ALL data gathering (Phases 1-5). The LLM does NOT run queries, transcribe output, or write scratchpad sections
2. **Read `config.json`** for workspace ID, tenant, subscription, and Azure MCP parameters
3. **Output is always inline** — do NOT ask the user for output mode. Render the report inline in chat. Only generate md/html files when the user explicitly requests export
4. **ALWAYS ask the user for timeframe** if not specified: supported values are 1, 7, 30 (default), 60, or 90 days. The `--days` parameter controls the primary window; deep-dive and comparison windows are derived automatically

### Date Window Model

The `-Days` parameter drives three time windows used across all queries:

| Window | Token | Derivation | Purpose |
|--------|-------|------------|---------|
| **Primary** | `{days}` | = `--days` value | Usage overview (Q1-Q3), alert firing (Q12), license benefits (Q17/Q17b), tier summary (Q10b) |
| **Deep-dive** | `{deepDiveDays}` | ≤7→Days, ≤30→7, ≤60→14, ≤90→30 | Table breakdowns (Q4-Q8), rule health (Q11/Q11d), cross-ref (Q13), migration candidates (Q16), WoW "this period" (Q15) |
| **Comparison** | `{wowTotalDays}` | = deepDiveDays × 2 | Period-over-period total lookback (Q15) |

**Example:** `-Days 60` → primary=60d, deep-dive=14d, comparison=28d

**Dynamic period labels:** Report column headers adapt automatically ("This Week"/"Last Week" for 7d deep-dive, "This Month"/"Last Month" for 30d, "This Period"/"Last Period" for 14d).

**Exception:** Q14 (24h anomaly detection) is unaffected by `-Days` — it uses fixed algorithmic constants (P30D lookback, 29-day weekday baseline).
5. **ALWAYS use `create_file` for markdown reports** (NEVER use terminal commands for file output)
6. **ALWAYS sanitize PII** from saved reports — use generic placeholders for real hostnames, workspace names, and tenant GUIDs in committed files
7. **Read scratchpad + SKILL-report.md** before rendering — the scratchpad is the sole data source for the report
8. **Tier display convention** — Azure CLI reports Data Lake tier tables as plan `Auxiliary` internally, but **always refer to this tier as "Data Lake"** in output — never use "Auxiliary"

### Prerequisites

| Dependency | Required By | Setup |
|------------|-------------|-------|
| **Python 3.9+** | `invoke_ingestion_scan.py`, `generate_html_report.py` | Standard library only — no external packages required |
| **Azure CLI** (`az`) | All KQL queries (`az monitor log-analytics query`), analytic rule inventory (`az rest`), tier classification (`az monitor log-analytics workspace table list`), custom detections (`az rest` + Graph API) | Install: [aka.ms/installazurecli](https://aka.ms/installazurecli). Authenticate: `az login --tenant <tenant_id>` then `az account set --subscription <subscription_id>` |
| **`log-analytics` extension** | `az monitor log-analytics query` (all KQL queries in Phases 1-5) | Install: `az extension add --name log-analytics`. Verify: `az extension list --query "[?name=='log-analytics']"` |
| **Azure RBAC** | Azure CLI calls above | **Log Analytics Reader** on the workspace (KQL queries + table list). **Microsoft Sentinel Reader** on the workspace (analytic rule inventory via `az rest`) |

### 🔴 PROHIBITED

- ❌ Using Sentinel MCP Server (`mcp_microsoft_se2_*`) or MTP MCP Server (`mcp_mtp_mcp_servi_*`) — **not integrated** with Azure SRE Agent (cannot currently be connected). Use `az monitor log-analytics query` for KQL queries instead
- ❌ Using Microsoft Graph MCP (`mcp_microsoft_ent_*`) — **not integrated** with Azure SRE Agent (cannot currently be connected). Use `az rest` for Graph/REST API queries instead
- ❌ Running KQL queries via any MCP tool during data gathering — the Python script handles all queries via `az monitor log-analytics query`
- ❌ Writing or modifying scratchpad sections manually — `invoke_ingestion_scan.py` is the sole writer
- ❌ Reporting cost in dollar amounts — **always use GB savings** (e.g., "~78.7 GB/month savings")
- ❌ Fabricating ingestion volumes, device names, or anomaly percentages
- ❌ Overriding DL eligibility classification from script output based on LLM knowledge
- ❌ Rendering the report without first reading the scratchpad file
- ❌ Asking the user for output mode — always render inline; only export when explicitly requested

**✅ ALLOWED MCP tools for supplementary tasks (NOT for data gathering):**
- **KQL Search MCP** (`mcp_kql-search-mc_*`): Query validation, table schema lookup, ASIM parser info
- **Microsoft Learn MCP** (`mcp_microsoft_le*_*`): Documentation search, best practice guidance
- **Azure MCP Server** (`mcp_azure_mcp_ser_*`): Azure resource management, infrastructure queries

---

## Execution Workflow

### Phase 0: Initialization

1. Read `config.json` for `sentinel_workspace_id`, `subscription_id`, Azure MCP parameters
2. Confirm output mode and timeframe with user (pass `--days` to the script; default 30)
3. Verify prerequisites: `az login` session active, correct subscription set

### Phases 1-5: Data Gathering (automated by Python)

Run `invoke_ingestion_scan.py` — it handles all 5 phases automatically:

| Phase | Queries | Description | Execution Type |
|-------|---------|-------------|----------------|
| **1** | Q1, Q2, Q3 | Core ingestion overview — Usage by DataType, daily trend, workspace summary | KQL (parallel) |
| **2** | Q4, Q5, Q6a, Q6b, Q6c, Q7, Q8 | Table deep dives — SecurityEvent, Syslog, CommonSecurityLog breakdowns | KQL (parallel) |
| **3** | Q9, Q9b, Q10, Q10b | External data — analytic rule inventory (REST), custom detections (Graph via `az rest`), tier classification (CLI), tier summary (KQL) | REST + CLI + KQL (sequential, with `depends_on`) |
| **4** | Q11, Q11d, Q12, Q13 | Detection coverage — rule health (SentinelHealth), alert firing (SecurityAlert), cross-reference (all tables with data vs. rule inventory) | KQL (parallel) + post-processing |
| **5** | Q14, Q15, Q16, Q17, Q17b | Anomaly detection + cost analysis — 24h anomaly, WoW comparison, migration candidates, license benefits, E5 per-table | KQL (parallel) + post-processing |

**Post-processing (automated by the script, Phases 4-5):**

| Task | Phase | Description |
|------|-------|-------------|
| Table cross-reference | 4 | For each table with data (Q13), regex-search all enabled rule queries for that table name |
| ASIM parser detection | 4 | Search all rule queries for ASIM function patterns (`_Im_`, `_ASim_`, `imDns`, etc.) |
| Value-level rule verification | 4 | For each EventID/Facility/ProcessName/Activity/Vendor from deep dives, check if any rules reference it |
| Detection gap detection | 4 | Identify tables on DL/Basic tier that have enabled rules (🔴 critical finding) |
| Anomaly severity classification | 5 | Apply Rule A thresholds to Q14/Q15 results |
| DL eligibility classification | 5 | Classify all tables using hardcoded `$dlYes`/`$dlNo` reference arrays |
| Migration table assembly | 5 | Cross-reference volume × rule count × tier × DL eligibility → category assignment |
| License benefit computation | 5 | Compute DfS P2 pool, E5 grant breakdown |

**Scratchpad output:** The script writes all results to `tmp/sentinel-ingestion-report/scratchpad_<workspace>_<timestamp>.md` (~50 KB, ~64 named sections including PHASE_, PRERENDERED, and META blocks). See SKILL-report.md for the Section-to-Scratchpad Mapping.

### Phase 6: Render Output (LLM)

**🔴 MANDATORY — Load scratchpad + report template before rendering:**

1. **Read the scratchpad file** (path printed by the script). This single file contains ALL data from Phases 1-5.
2. **Read [SKILL-report.md](SKILL-report.md)** for the complete rendering templates and formatting rules.

**Pre-render validation:**
1. Verify scratchpad has all 5 phase sections (PHASE_1 through PHASE_5)
2. Check that `PHASE_5.DL_Script_Output` is populated (proof of DL classification execution)
3. Cross-validate: Q11 `TotalRulesInHealth` against Q9 `AR_Enabled` — if >10% gap, note it

**Render inline — Section-by-Section Checklist:**

Render the report section by section per SKILL-report.md templates. **Do NOT skip any section.** If a section's data returned 0 results, render the section header with a "✅ No anomalies/items found" note.

| Section | Data Source (scratchpad keys) | Required |
|---------|------------------------------|----------|
| §1 | All phases | ✅ Workspace at a Glance, Cost Waterfall, Detection Posture, Top 3 |
| §2 | PHASE_1.Tables, PHASE_3.TierSummary | ✅ Table breakdown + tier summary |
| §3 | PRERENDERED.SE_*, PRERENDERED.Syslog*, PRERENDERED.CSL_* | ✅ Deep dives (skip sub-section only if table not in top 20) |
| §4 | PHASE_5.Anomaly24h/AnomalyWoW, PHASE_1.DailyTrend | ✅ Anomaly table + daily trend chart |
| §5 | PHASE_3.RuleInventory, PHASE_4.* | ✅ Rule inventory + cross-ref + health |
| §6 | PHASE_5.LicenseBenefits/E5_Tables | ✅ DfS P2 + E5 analysis |
| §7 | PHASE_5.Migration, PHASE_4.CrossRef | ✅ Migration candidates + recommendations |
| §8 | All | ✅ Appendix (query reference, methodology) |

**Compute Top 3 Recommendations** using Rule E: scan all scratchpad sections, score each candidate, select the top 3 by score.

**Post-render:**
- The inline report is the primary output — no further action needed unless user requests export
- If user requests markdown or HTML export, generate accordingly

---

## Query File Reference

All queries are defined in `queries.yaml` (single consolidated file). The script discovers, parses, and executes them automatically.

### YAML Format

```yaml
id: ingestion-q1                              # Unique identifier
name: Usage by DataType with Billing Breakdown # Human-readable name
description: Top 20 tables ranked by volume    # What it does
phase: 1                                       # Which phase (1-5)
type: kql                                      # kql | rest | cli | graph
timespan: P{days}D                             # Placeholder — the script substitutes at runtime
query: |                                       # KQL query (multiline block scalar)
  Usage
  | where TimeGenerated > ago({days}d)
  ...
```

**Non-KQL types** have additional fields:

| Type | Additional Fields | Description |
|------|-------------------|-------------|
| `rest` | `url`, `method`, `jmespath` | Sentinel REST API via `az rest` |
| `cli` | `command` | Azure CLI command (e.g., `az monitor log-analytics workspace table list`) |
| `graph` | `uri`, `method` | Microsoft Graph API via `az rest` |

### Complete Query Inventory

| Phase | File | ID | Type | Description |
|-------|------|----|------|-------------|
| 1 | Q1-UsageByDataType.yaml | ingestion-q1 | kql | Top 20 tables by billable volume with solution mapping |
| 1 | Q2-DailyIngestionTrend.yaml | ingestion-q2 | kql | Daily ingestion trend |
| 1 | Q3-WorkspaceSummary.yaml | ingestion-q3 | kql | Executive summary: table count, billable totals, daily average |
| 2 | Q4-SecurityEventByComputer.yaml | ingestion-q4 | kql | SecurityEvent by Computer (top 25) |
| 2 | Q5-SecurityEventByEventID.yaml | ingestion-q5 | kql | SecurityEvent by EventID (top 20) |
| 2 | Q6a-SyslogByHost.yaml | ingestion-q6a | kql | Syslog by source host (top 25) |
| 2 | Q6b-SyslogByFacilitySeverity.yaml | ingestion-q6b | kql | Syslog by Facility × SeverityLevel (top 30) |
| 2 | Q6c-SyslogByProcess.yaml | ingestion-q6c | kql | Syslog top ProcessName by Facility (top 30) |
| 2 | Q7-CSLByVendor.yaml | ingestion-q7 | kql | CommonSecurityLog by DeviceVendor/DeviceProduct (top 20) |
| 2 | Q8-CSLByActivity.yaml | ingestion-q8 | kql | CommonSecurityLog by Activity/LogSeverity/DeviceAction (top 30) |
| 3 | Q9-AnalyticRuleInventory.yaml | ingestion-q9 | rest | Analytic rules (Scheduled + NRT) via Sentinel REST API |
| 3 | Q9b-CustomDetectionRules.yaml | ingestion-q9b | graph | Custom Detection rules via Microsoft Graph SDK |
| 3 | Q10-TableTierClassification.yaml | ingestion-q10 | cli | Table tier classification via Azure CLI |
| 3 | Q10b-TierSummary.yaml | ingestion-q10b | kql | Per-tier volume summary (depends_on: Q10) |
| 4 | Q11-RuleHealthSummary.yaml | ingestion-q11 | kql | SentinelHealth — rule execution health summary |
| 4 | Q11d-FailingRuleDetail.yaml | ingestion-q11d | kql | SentinelHealth — top 20 failing rules detail |
| 4 | Q12-SecurityAlertFiring.yaml | ingestion-q12 | kql | SecurityAlert — top 30 alert-producing rules |
| 4 | Q13-AllTablesWithData.yaml | ingestion-q13 | kql | All tables with data in deep-dive window (for cross-reference) |
| 5 | Q14-IngestionAnomaly24h.yaml | ingestion-q14 | kql | 24h vs same-weekday avg anomaly detection (29d lookback, fallback to flat 7d, >50%, ≥0.01 GB) |
| 5 | Q15-WeekOverWeek.yaml | ingestion-q15 | kql | Period-over-period volume comparison |
| 5 | Q16-MigrationCandidates.yaml | ingestion-q16 | kql | Billable tables with deep-dive volume (for migration analysis) |
| 5 | Q17-LicenseBenefitAnalysis.yaml | ingestion-q17 | kql | DfS P2 + E5 daily ingestion breakdown |
| 5 | Q17b-E5PerTableBreakdown.yaml | ingestion-q17b | kql | E5-eligible per-table volume |

---

## Output Modes

### Default: Inline Chat (always)
The report is always rendered inline in chat. This is the primary and default output.

### Optional: Markdown Export
When the user says "export as markdown", "save as md", or passes `--export md`, save the report to `tmp/sentinel-ingestion-report/sentinel_ingestion_report_<YYYYMMDD_HHMMSS>.md`.

### Optional: HTML Export
When the user says "export as html", "generate html", or "html report":
```bash
python generate_html_report.py <scratchpad_path> --output-dir tmp/sentinel-ingestion-report/
```
Generates a self-contained, dark-theme HTML file with all tables, charts, and badges rendered.

**⛔ Do NOT ask the user for output mode.** Always render inline first. Only generate file exports when explicitly requested.

---

## Deterministic Rendering Rules

**These rules eliminate LLM interpretation variance. Apply them EXACTLY during report rendering (Phase 6). No discretion allowed — the thresholds and formulas below are the sole authority.**

### Rule A: Anomaly Severity Classification

> **⚙️ Pre-computed by the script** → `PRERENDERED.AnomalyTable`. Thresholds below retained for §8 methodology reference and manual verification.

Assign severity to each anomaly row deterministically based on absolute deviation AND volume.

| Condition (both must be true) | Severity | Emoji |
|-------------------------------|----------|-------|
| abs(Deviation%) ≥ 200 AND max(Last24hGB, Avg7dGB) ≥ 0.05 GB | High | 🟠 |
| abs(Deviation%) ≥ 100 AND max(Last24hGB, Avg7dGB) ≥ 0.01 GB | Medium | 🟡 |
| abs(Deviation%) ≥ 50 AND max(Last24hGB, Avg7dGB) ≥ 0.01 GB | Low | ⚪ |
| Below thresholds OR both periods < 0.01 GB volume | Excluded | — |

**Volume floor:** The 0.01 GB minimum is enforced by the KQL queries. Tables below this floor are noise and MUST NOT appear in the anomaly table regardless of deviation percentage.

**Override 1 — Rule-count:** ANY table with ≥5 enabled rules AND an absolute change ≥40% (in either 24h or WoW) is automatically 🟠 regardless of base thresholds — a significant drop on a table feeding multiple rules signals potential connector or TI feed health issues that affect detection coverage. The 24h override catches same-day connector outages; the WoW override catches gradual multi-day degradation.

**Override 2 — Near-zero:** ANY table with deviation ≤ −95% AND max(volume) ≥ 0.05 GB is automatically 🟠 regardless of rule count — a near-complete signal loss on a significant table is an operational emergency (e.g., connector failure, API key expiry) even if no rules reference it directly.

**⛔ PROHIBITED:** Assigning severity based on "judgment", "context", or "this table is important" UNLESS the high-rule-count override above applies. Outside that specific override, the emoji MUST match the threshold table above — no discretionary overrides.

### Rule B: Risk Rating Definition

In the Top 3 Recommendations table (§1), the "Risk" column means:

> **Risk = the security or operational impact of NOT acting on this recommendation.**

| Risk Level | Definition | Examples |
|------------|-----------|----------|
| **High** | Active detection gap or data loss if not addressed | Rules silently failing on DL tier; connector dropping data; 0% detection coverage on critical table |
| **Medium** | Missed optimization with measurable cost/posture impact | Zero-rule high-volume table on Analytics tier; noisy EventID with no detection value |
| **Low** | Minor improvement, no immediate security or cost impact | Small-volume table tier change; informational tuning |

**⛔ PROHIBITED:** Interpreting "Risk" as implementation difficulty, effort, or change management complexity. Those concerns belong in prose recommendations (§7b-d), NOT the Risk column.

### Rule C: Weekday Average Computation

> **⚙️ Pre-computed by the script** → `PRERENDERED.DailyChart`. Logic below retained for §8 methodology reference.

When computing per-weekday averages for the §4b daily trend chart:

1. **Exclude the report-generation day:** If the last day in `PHASE_1.DailyTrend` matches `META.Generated` date, **always exclude it** from weekday averages — the report was generated mid-day so this is a partial day regardless of its volume. This prevents the partial day from non-deterministically dragging down whichever weekday it falls on.
2. **Exclude ingestion gaps:** Any remaining day with total ingestion < 0.1 GB is also excluded. These are ingestion reporting gaps, not representative of normal patterns.
3. **Formula:** `Weekday Avg = sum(GB for that weekday, excluding days per rules 1–2) / count(qualifying days for that weekday)`
4. **Round to 2 decimal places.**

**⛔ PROHIBITED:** Including the report-generation partial day or days with < 0.1 GB in averages — they drag down specific weekdays non-deterministically.

### Rule D: Cross-Validation Denominator

In §5b cross-validation (Q11 vs Q9), always use **AR-only enabled count from Q9** as the denominator:

```
Gap% = (Q9_AR_Enabled - Q11_DistinctRules) / Q9_AR_Enabled × 100
```

**Do NOT use `Combined_Enabled` (AR+CD) as the denominator.** SentinelHealth only tracks AR executions (Scheduled + NRT), not Custom Detection executions. Comparing Q11 against combined AR+CD inflates the gap percentage.

### Rule E: Top 3 Recommendation Ranking

Rank ALL candidate recommendations using this scoring formula. The top 3 by score become the Top 3 in §1. **Computed by the LLM at render time** by cross-referencing all scratchpad sections.

| Category | SeverityWeight | ImpactValue | Scratchpad Source |
|----------|---------------|-------------|-------------------|
| 🔴 Detection gap (rules on wrong tier) | 10 | Number of affected rules | PHASE_4.DetectionGaps — the script emits `Detection gap (XDR)` or `Detection gap (non-XDR)` in §7a Category column |
| 🔴 Data loss / connector failure | 10 | Affected volume in GB/day | PHASE_5.Anomaly24h (large negative deviations) |
| 🟠 DL-eligible migration (zero rules) | 5 | BillableGB from §2a (or deep-dive GB / deepDiveDays × Days if only in §7a) | PHASE_5.Migration (Strong DL-eligible rows) |
| 🟠 DL + KQL Job promotion | 4 | BillableGB (primary window) | High-volume 🟣/🟢 table — can complement split ingestion or stand alone; present both options and note they are combinable |
| 🟠 License benefit activation | 4 | Eligible unclaimed GB/day | PRERENDERED.BenefitSummary + PRERENDERED.E5Tables + PRERENDERED.DfSP2Detail (volume eligible but benefit not yet activated) |
| 🟠 DCR filter / EventID pruning | 4 | Estimated saveable GB (deep dive % × table BillableGB) | PHASE_2.SE_EventID + PHASE_4.ValueRef_EventID |
| 🟠 Health fix (failing rules) | 4 | Number of failing rules | PHASE_4.FailingRules |
| 🟡 Volume spike / cost anomaly | 3 | Spike GB on zero-rule tables | PHASE_5.Anomaly24h (large positive deviations on zero-rule tables — cost spike with no detection value) |
| 🟡 Duplicate ingestion | 3 | Duplicate GB | Cross-ref PRERENDERED.SyslogFacility × PRERENDERED.CSL_Vendor (same-appliance overlap emitting both Syslog and CEF/ASA = double billing) |
| 🟡 Split ingestion | 3 | BillableGB × estimated non-detection fraction | PHASE_2 deep dives + PHASE_4.ValueRef_* (zero-rule values) |
| 🟡 Tier review / unknown eligibility | 2 | BillableGB | PHASE_5.Migration (Unknown rows) |

**Score = SeverityWeight × ImpactValue**

**Sorting: severity-first, then score.** 🔴 items always rank above 🟠 items, which always rank above 🟡 items, regardless of score. Within the same severity tier, rank by descending score. This ensures detection gaps and data loss signals are never buried below cost optimizations.

Tie-breaking within same severity: higher score wins. If scores are equal, higher SeverityWeight wins. If still tied, higher ImpactValue wins.

**⛔ PROHIBITED:** Selecting Top 3 recommendations based on narrative variety, "one from each category", or subjective importance. The formula determines ranking — the LLM renders, it does not curate.

> **License benefit activation:** Surfaces when `PRERENDERED.BenefitSummary` or `PRERENDERED.E5Tables` show E5-eligible or DfS-P2-eligible volume that is **not yet being claimed** (benefit shows 0 or is absent while eligible tables are ingesting). ImpactValue = the eligible GB/day that could be offset.
>
> **Volume spike / cost anomaly:** Surfaces when `PHASE_5.Anomaly24h` shows a **large positive deviation** (>50% above baseline) on a table with **zero detection rules** (per `PHASE_4.CrossRef`). A spiking table with no rules has cost impact but no detection value — a strong signal to investigate and potentially filter or move to DL.
>
> **Duplicate ingestion:** Surfaces when the same network appliance sends data via **both** Syslog and CommonSecurityLog (CEF/ASA). Compare appliance names/IPs in `PRERENDERED.SyslogFacility`/`PRERENDERED.SyslogHost` against `PRERENDERED.CSL_Vendor` — overlapping sources indicate double billing for the same data. ImpactValue = the smaller of the two streams (the duplicate portion).

---

## Domain Reference

**This section provides the domain knowledge needed during Phase 6 rendering.** When writing deep dive sections (§3), anomaly analysis (§4), and recommendations (§7), consult these reference tables for interpretation guidance.

### SecurityEvent — EventID Optimization

Which EventIDs generate the most volume and their detection vs. cost tradeoff:

| EventID | Description | Optimization Potential |
|---------|-------------|----------------------|
| **4663** | Object access (file auditing) | 🔴 High — often excessive. Consider DCR drop filter or scoping SACL |
| **4624** | Successful logon | 🟡 Medium — valuable for hunting/forensics but rarely in analytic rules. Strong split ingestion candidate: send to Data Lake for retention, keep off Analytics tier |
| **4688** | Process creation | 🟡 Medium — consider moving to MDE `DeviceProcessEvents`. If no rules reference it, split to Data Lake |
| **4799** | Security group membership enumeration | 🟡 Medium — often noisy on domain controllers |
| **4672** | Special privileges assigned | 🟡 Medium — high volume on DCs |
| **4625** | Failed logon | 🟢 Low — usually valuable for security detection |

> **🟣 Split ingestion tip:** For any deep-dive table classified as 🟢 Keep Analytics (active detection rules), individual high-volume values with **zero rule references** (verified via Phase 4 value-level check) are strong candidates for sub-table split ingestion. Route those values to Data Lake via DCR transformation — they remain available for hunting while the detection-relevant values stay on Analytics tier. KQL jobs can also run against this split-routed DL data to surface aggregated insights back to Analytics if needed.

### Syslog — Facility Reference

Optimization potential by Syslog facility:

| Facility | Description | Optimization Potential |
|----------|-------------|------------------------|
| **auth** | Authentication events (login, su, getty) | 🟢 Low — always security-relevant. Keep in Analytics tier |
| **authpriv** | Private authentication (PAM, sudo, sshd) | 🟢 Low — critical for security detection. Always keep |
| **kern** | Kernel messages (hardware, driver, critical system) | 🟡 Medium — security-relevant but can be noisy. Consider Error+ only for high-volume servers |
| **cron** | Scheduled task notifications | 🔴 High — rarely security-relevant at Info/Notice. Keep Warning+ only |
| **daemon** | System daemon messages (systemd, sshd, named, httpd) | 🔴 High — typically largest Syslog contributor (50-80% of volume). Contains both security-critical processes (sshd) and noisy infrastructure (systemd). **Drill down with Q6c** to identify filterable processes |
| **syslog** | Internal syslog daemon messages | 🟡 Medium — mostly operational. Keep Warning+ in Analytics |
| **user** | User-space application messages | 🟡 Medium — varies by application. Check ProcessName |
| **mail** | Mail subsystem (postfix, sendmail, dovecot) | 🟡 Medium — relevant if mail is in scope; otherwise DL candidate |
| **local0–local7** | Custom application logs | 🔴 High — most common cost optimization targets. Custom apps often log at Debug/Info verbosity |
| **ftp** | FTP daemon messages | 🟢 Low volume; keep for auditing if FTP in use |
| **lpr** | Print subsystem | 🔴 High — almost never security-relevant. Set to None in DCR |
| **news** | Network news (NNTP) | 🔴 High — almost never security-relevant. Set to None in DCR |
| **uucp** | UUCP subsystem | 🔴 High — almost never security-relevant. Set to None in DCR |
| **mark** | Internal timestamp marker | 🔴 High — operational only. Set to None in DCR |

### Syslog — DCR Severity-per-Facility Recommendations

The Data Collection Rule allows setting a **minimum severity level per facility** — the single most impactful cost control for Syslog:

| Facility | Recommended Minimum | Rationale |
|----------|--------------------|-----------|
| auth, authpriv | **Debug** (collect all) | Security-critical — never filter |
| kern | **Notice** | Kernel module loads (T1547.006) and promiscuous mode (T1040) are `kern.notice`. Volume impact is minimal |
| daemon | **Warning** or **Error** | Major volume reduction. Note: sshd auth events go to `auth`/`authpriv`, not `daemon`. Trade-off: loses `systemd` service stop events at Info (security service tampering) — acceptable if EDR covers this |
| cron | **Warning** | Trade-off: cron job execution events are `cron.info` (T1053.003 persistence). Acceptable if `auditd` or MDE covers cron file monitoring |
| syslog | **Warning** | Internal operational messages are low-value at Info |
| user | **Warning** | Unless specific apps produce security telemetry |
| mail | **Warning** | Info-level mail relay logs are very verbose |
| local0–local7 | **Assess per-app** | No safe default — network appliances, security tools, and databases commonly use local facilities. Review Q6c (Process by Facility) before setting severity filters |
| lpr, news, uucp, mark | **None** | Disable collection entirely |

### Syslog — SeverityLevel Values

| SeverityLevel (string) | Numeric | Meaning | Retention Priority |
|------------------------|---------|---------|-------------------|
| **emerg** | 0 | System unusable | 🔴 Always keep |
| **alert** | 1 | Immediate action required | 🔴 Always keep |
| **crit** | 2 | Critical condition | 🔴 Always keep |
| **err** | 3 | Error condition | 🟡 Keep for most facilities |
| **warning** | 4 | Warning condition | 🟡 Keep for security-relevant facilities |
| **notice** | 5 | Normal but significant | 🟡 Keep for auth/authpriv and kern |
| **info** | 6 | Informational | 🟢 Filter for high-volume facilities |
| **debug** | 7 | Debug-level detail | 🟢 Filter everywhere except auth/authpriv |

### Syslog — ProcessName Security Relevance

| ProcessName | Typical Facility | Security Relevance | Optimization |
|-------------|-----------------|--------------------|--------------|
| **systemd** | daemon | 🟡 Low-Medium — unit start/stop events | 🔴 Often 30-50% of daemon volume. Filter Info/Notice at DCR |
| **systemd-logind** | daemon | 🟡 Medium — session/seat tracking | Keep Warning+ |
| **sshd** | auth, authpriv, daemon | 🟢 High — SSH login detection (brute force, lateral movement) | 🟢 Always keep |
| **sudo** | authpriv | 🟢 High — privilege escalation tracking | 🟢 Always keep |
| **su** | auth, authpriv | 🟢 High — user switching | 🟢 Always keep |
| **CRON** / **crond** | cron | 🟡 Low-Medium — scheduled tasks | Keep Warning+ unless monitoring for T1053 |
| **named** / **bind** | daemon | 🟡 Medium — DNS. Relevant for DNS tunneling | Keep if DNS rules exist; otherwise Warning+ |
| **httpd** / **nginx** | daemon | 🟡 Medium — web server logs | Assess overlap with WAF/CSL data |
| **postfix** / **sendmail** | mail | 🟡 Low-Medium — mail relay | Keep Warning+ |
| **dhclient** / **NetworkManager** | daemon | 🟡 Low — DHCP/network changes | Filter Info/Notice |
| **kernel** | kern | 🟢 Medium-High — kernel events, module loads | Keep Warning+ |
| **auditd** | daemon, user | 🟢 High — Linux Audit Framework | 🟢 Always keep |
| **polkitd** | authpriv | 🟡 Medium — PolicyKit authorization | Keep Warning+ |
| **dbus-daemon** | daemon | 🟡 Low — IPC. Rarely security-relevant | Filter all or keep Error+ |
| **rsyslogd** / **syslog-ng** | syslog | 🟡 Low — internal syslog ops | Keep Warning+ |

> **🟣 Split ingestion tip:** If `daemon` facility accounts for >50% of Syslog and Q6c reveals `systemd` + `systemd-logind` + `dbus-daemon` dominate, consider a DCR transformation routing those processes to Data Lake while keeping `sshd`, `auditd`, and other security-critical processes in Analytics. KQL jobs can complement this by querying the DL-routed portion on schedule.

### Syslog — Log Forwarding Architecture Note

In environments using centralized rsyslog/syslog-ng forwarders:
- `Computer` = the **log forwarder** hostname (many servers collapse to 1-2 forwarders)
- `HostName` = the **actual originating device** (from syslog header)
- `HostIP` = the originating device's IP address

The Q6a query uses `SourceHost = iff(isnotempty(HostName) and HostName != Computer, HostName, Computer)` to prefer the original source. If Q6a shows only 1-2 hosts despite expecting 100+ servers, the environment uses forwarding.

### CommonSecurityLog — Vendor Reference

| DeviceVendor | DeviceProduct | Optimization Potential |
|-------------|---------------|----------------------|
| **Palo Alto Networks** | PAN-OS | 🔴 High — filter `TRAFFIC` activity, keep `THREAT` in Analytics |
| **Check Point** | Firewall / VPN-1 & FireWall-1 | 🔴 High — filter routine `Accept` actions |
| **Fortinet** | Fortigate | 🔴 High — filter `traffic` subtype, keep `utm` and `event` |
| **Cisco** | ASA | 🟡 Medium — filter by message ID ranges |
| **Zscaler** | NSSWeblog | 🟡 Medium — web proxy logs can be high volume |
| **F5** | BIG-IP ASM / LTM | 🟡 Medium — WAF logs can spike during attacks |
| **Trend Micro** | Deep Security | 🟢 Low — typically moderate volume |

> Firewall traffic/session logs often account for 60-80% of CSL volume. These are primarily `TRAFFIC` or `Accept` events with low detection value. Consider DCR transformation, Data Lake tier, split ingestion, or DL + KQL job promotion (these last two can be combined).

### CommonSecurityLog — LogSeverity Values

| Value (string) | Value (int) | Meaning | Retention Priority |
|----------------|-------------|---------|-------------------|
| **Very-High** | 9-10 | Critical security event | 🔴 Always keep in Analytics |
| **High** | 7-8 | Significant security event | 🔴 Keep in Analytics |
| **Medium** | 4-6 | Notable event | 🟡 Review — may be filterable |
| **Low** | 0-3 | Informational event | 🟢 Candidate for DL or DCR filter |
| *(empty/Unknown)* | — | Unmapped severity | ⚠️ Check vendor documentation |

**DeviceAction optimization:** If >70% of events have `DeviceAction` = "Allow" or "Accept", the table is dominated by permitted traffic. Filter at DCR level or move to Data Lake, keeping only denied/blocked/threat events in Analytics.

### Anomaly Interpretation (Q14/Q15)

**24h anomalies (Q14):** Flags tables where last-24h ingestion deviates >50% from the same-weekday daily average AND at least one period has ≥0.01 GB volume. Q14 uses a fixed 29-day lookback (algorithmic constant, not affected by `-Days`).
- **Positive spikes:** May indicate attacks, misconfigured connectors, or bulk imports
- **Negative drops:** May indicate connector failures, agent issues, or collection gaps

**Period-over-period (Q15):** Compares total volume per table between current and prior period (period length = deep-dive window).
- **New tables** (100% change) → appeared only this period (new connector?)
- **Growing tables** → expanding collection scope or increased activity
- **Shrinking tables** → connector removal, collection changes, or seasonal patterns
- **Stable high-volume tables** → included via `ThisWeekMB > 100` filter for visibility

---

## Tier Classification

### Background

The Sentinel `Usage` table does **NOT** contain a `TablePlan` or `Tier` column. There is no KQL-native way to determine whether a table is on Analytics, Basic, or Data Lake tier.

**The script handles this automatically:** Q10 (CLI type) runs `az monitor log-analytics workspace table list` to fetch table plans, then Q10b (KQL, `depends_on: Q10`) computes per-tier volume summaries using the CLI output. The results are written to `PHASE_3.Tiers` and `PHASE_3.TierSummary` in the scratchpad.

### Tier Display Convention

Azure CLI reports Data Lake tier tables as plan `Auxiliary` internally. **Always refer to this tier as "Data Lake" in all output** — never use "Auxiliary". The `_CL` suffix denotes a custom log table, not a copy — describe these as "Custom Data Lake table" (not "Auxiliary copy").

### Q10b Cross-Reference Query

The script automatically populates the `DataLakeTables` and `BasicTables` arrays from CLI output and executes the tier summary KQL query. This computes per-tier `TotalGB`, `BillableGB`, `TableCount`, and `PercentOfTotal` using the **full Usage table** (not limited to Q1 top-20). These values are the authoritative source for `PHASE_3.TierSummary` and §2b rendering.

---

## Migration Classification

**Used when rendering §7a (Tier Migration Candidates).** The script computes the `Category` column using these criteria; the LLM uses this reference for rendering interpretation and recommendation prose.

| Category | Criteria | Action |
|----------|----------|--------|
| 🔵 **KQL Job output** | Table name ends with `_KQL_CL` | **NEVER migrate** — promoted data from Data Lake, essential for detection pipeline |
| 🔵 **Already on Data Lake** | Q10 tier = Data Lake AND zero rules | Already migrated — no action needed |
| 🟢 **Keep Analytics** | ≥1 enabled analytic rule AND healthy executions | Active detection coverage justifies Analytics cost |
| 🟣 **Split ingestion candidate** | 1-2 enabled rules AND high-volume (≥5 GB/week) AND DL-eligible | Few rules need only a subset of events. Route detection-relevant subset to Analytics via DCR, rest to Data Lake |
| ❗ **Detection gap (non-XDR)** | ≥1 enabled rule AND table is on Data Lake tier AND table is NOT an XDR table | **Critical:** Analytic rules cannot execute against DL tables — rules silently failing. Custom Detections also do NOT work because non-XDR tables are not available in Advanced Hunting on Data Lake. Remediation: (1) move table back to Analytics, OR (2) remove/disable the analytic rules referencing the table (accept DL tier). ⛔ **PROHIBITED:** Recommending "convert ARs to Custom Detections" for non-XDR tables — CDs run against Advanced Hunting which only retains **Defender XDR tables** for 30 days. Non-XDR tables on Data Lake are invisible to Advanced Hunting. |
| ❗ **Detection gap (XDR)** | ≥1 enabled rule AND table is on Data Lake tier AND table IS an XDR table | **Partial gap:** Sentinel Analytic Rules (AR) cannot execute against DL tables — ARs silently failing. However, XDR-native tables (Device\*, Email\*, CloudAppEvents, UrlClickEvents) are ALWAYS available in Advanced Hunting for 30 days regardless of Sentinel tier. Custom Detection rules run against Advanced Hunting, so **CD rules continue to work**. Only ARs are broken. Remediation: (1) move table back to Analytics, (2) convert affected ARs to Custom Detections, OR (3) remove/disable the ARs. See [Advanced Hunting data retention](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-limits#data-retention) |
| 🔴 **Strong candidate (DL-eligible)** | 0 rules AND DL classification = `Yes` | Evaluate DCR filtering to reduce unnecessary volume, then migrate remainder to Data Lake |

> **LLM overlay checks (not separate emojis — flag as callout notes in §7b/7c prose):**
> - **Execution issues:** If a 🟢 table's rules appear in `PHASE_4.FailingRules` with 0 executions or failures, add a ⚠️ note: "Rules targeting [table] have execution issues — see §5b. Fix rules before relying on this coverage."
> - **ASIM dependency:** If a 🔴 zero-rule table appears in `PHASE_4.ASIM` as consumed by ASIM parsers, add a ⚠️ note: "[table] is consumed by ASIM parsers ([parser names]) — migrating to Data Lake breaks these detections. Verify ASIM dependency before migrating."
| 🟠 **Not DL-eligible / unknown** | 0 rules AND DL classification = `No` or `Unknown` | Optimize via DCR filtering or add analytic rules. Check [MS docs](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview) for current eligibility |

---

## Reference: Data Lake Migration

This section contains lookup tables and background guidance for DL migration classification. Consult when rendering §7a recommendations and explaining Data Lake trade-offs.

### Known DL-Eligible Tables

The script uses these lists as hardcoded `DL_YES`/`DL_NO` reference arrays. Keep this reference in sync with the script.

| Category | DL-Eligible Tables | Notes |
|----------|-------------------|-------|
| **Defender XDR** | CloudAppEvents, DeviceEvents, DeviceFileCertificateInfo, DeviceFileEvents, DeviceImageLoadEvents, DeviceInfo, DeviceLogonEvents, DeviceNetworkEvents, DeviceNetworkInfo, DeviceProcessEvents, DeviceRegistryEvents, EmailAttachmentInfo, EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, UrlClickEvents | [GA Feb 2025](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/data-lake-tier-ingestion-for-microsoft-defender-advanced-hunting-tables-is-now-g/4494206) |
| **Verified LA tables** | AADManagedIdentitySignInLogs, AADNonInteractiveUserSignInLogs, AADProvisioningLogs, AADServicePrincipalSignInLogs, AADUserRiskEvents, AuditLogs, AWSCloudTrail, AzureDiagnostics, CommonSecurityLog, Event, GCPAuditLogs, LAQueryLogs, McasShadowItReporting, MicrosoftGraphActivityLogs, OfficeActivity, Perf, SecurityAlert, SecurityEvent, SecurityIncident, SentinelHealth, SigninLogs, StorageBlobLogs, Syslog, W3CIISLog, WindowsEvent, WindowsFirewall | ⚠️ Only these LA tables are verified DL-eligible. Unlisted → `Unknown` |
| **Custom tables** | Any table ending in `_CL` (except `_KQL_CL`) | Custom log tables are workspace-managed → DL-eligible |

### Known DL-Ineligible Tables (as of Feb 2026)

| Category | Ineligible Tables | Notes |
|----------|-------------------|-------|
| **XDR — not yet supported** | DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities, AlertEvidence, AlertInfo, IdentityDirectoryEvents, IdentityLogonEvents, IdentityQueryEvents | MDI tables announced for future DL support |
| **Entra ID** ❌ | MicrosoftServicePrincipalSignInLogs, MicrosoftNonInteractiveUserSignInLogs, MicrosoftManagedIdentitySignInLogs | Not yet DL-eligible |
| **Threat Intelligence** ❌ | ThreatIntelIndicators, ThreatIntelligenceIndicator | Required on Analytics for TI matching rules. Never recommend migration |
| **Log Analytics** ❌ | AppDependencies, AppMetrics, AppPerformanceCounters, AppTraces, AzureActivity, AzureMetrics, ConfigurationChange, Heartbeat, SecurityRecommendation | Not yet DL-eligible |

**Fallback rule:** If a table is not in either list, the script classifies it as `Unknown`. Render as `❓ Unknown` with note: *"Verify at [Manage data tiers](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview) before migrating."*

### Decision Matrix

| Enabled Rules | Executions (Health) | Alerts (Q12) | DL-Eligible? | Volume | Recommendation |
|---------------|---------------------|--------------|--------------|--------|----------------|
| 0 | N/A | 0 | ✅ Yes | > 1 GB/week | 🔴 Evaluate DCR filtering to reduce volume, then migrate remainder to Data Lake (confirm no ASIM dependency) |
| 0 | N/A | 0 | ✅ Yes | < 1 GB/week | 🔴 Migrate to Data Lake — minimal savings but cleaner tier alignment. DCR filtering optional at this volume |
| 0 | N/A | 0 | ❌ No / ❓ Unknown | Any | 🟠 Not eligible or unknown — review ingestion necessity, apply DCR filtering |
| 0 | N/A (on DL) | 0 | N/A — already DL | Any | 🔵 Already on Data Lake — no action needed |
| 0 (ASIM-dependent) | N/A | 0 | Any | Any | � Migrate — but LLM adds ⚠️ ASIM dependency callout in §7b |
| ≥1 | 0 or failures | 0 | Any | Any | 🟢 Keep — but LLM adds ⚠️ execution issues callout in §7b |
| ≥1 | 0 (on DL) | Any | N/A — on DL | Any | 🔴 Detection gap — ARs cannot execute against DL. The script emits `Detection gap (XDR)` or `Detection gap (non-XDR)`. **If XDR table:** CDs still work via Advanced Hunting; recommend converting ARs→CDs or moving back to Analytics. **If non-XDR table:** move back to Analytics OR remove/disable rules. ⛔ NEVER recommend CD conversion for non-XDR tables |
| 1-2 | > 0, healthy | Any | ✅ Yes | ≥ 5 GB/week | 🟣 Split ingestion candidate |
| ≥1 | > 0, healthy | 0 | Any | Any | 🟢 Keep Analytics — rules executing, no matches (normal for TI rules) |
| ≥1 | > 0, healthy | > 0 | Any | Any | 🟢 Keep Analytics — active detections generating alerts |

### Data Lake Trade-Off

| Capability | Analytics Tier | Data Lake Tier |
|-----------|---------------|----------------|
| Analytics rules, alerting, hunting | ✅ Full support | ❌ Not available (but see XDR exception below) |
| Custom Detection rules (Advanced Hunting) | ✅ Full support | ⚠️ **XDR tables only:** Still available — AH retains 30 days regardless of Sentinel tier. Non-XDR tables: ❌ |
| Workbooks, playbooks, parsers, watchlists | ✅ Full support | ❌ Not available |
| KQL query performance | ✅ High-performance | ⚠️ Slower |
| Query cost | ✅ Included in ingestion price | ❌ Billed per query (data scanned) |
| KQL Jobs / Summary Rules / Search Jobs | ✅ | ✅ |
| Ingestion cost | Standard | Minimal |
| Default retention | 90 days (Sentinel) / 30 days (XDR) | Matches analytics, extendable to 12 years |

**Primary vs secondary security data:** Primary security data (EDR alerts, auth logs, audit trails) belongs on Analytics. Secondary data (NetFlow, storage access logs, firewall traffic, IoT logs) is ideal for Data Lake.

**Filter before you migrate:** For high-volume zero-rule tables, DL migration and DCR filtering are complementary — not mutually exclusive. Evaluate whether all ingested data serves a hunting, forensic, or compliance purpose. If a portion is noise (e.g., verbose diagnostics, routine health checks, debug-level telemetry), apply DCR transformations to drop or reduce that portion first, then migrate the meaningful remainder to Data Lake. This avoids simply shifting cost from Analytics to Data Lake query charges on data nobody uses.

Even when a table has zero rules, consider whether it serves hunting/forensic purposes. Tables like SigninLogs or AuditLogs should generally remain on Analytics regardless.

### Data Lake Promotion via KQL Jobs

For high-volume tables on Data Lake — whether fully migrated or partially routed via split ingestion — that still need detection coverage:
1. **Ingest** raw logs into Data Lake tier (cheap)
2. **Create KQL jobs** to query Data Lake on schedule, writing aggregated results to Analytics-tier `_KQL_CL` tables
3. **Point analytics rules** at the `_KQL_CL` output table

**KQL Job key facts:** Full KQL (joins, unions, CTEs). Schedules: by-minute through monthly. Lookback up to 12 years. Limits: 3 concurrent / 100 enabled per tenant, 1hr query timeout. Data Lake has ~15-min ingestion latency — jobs should use `now(-15m)` as upper bound. `TimeGenerated` is overwritten if >2 days old — preserve source timestamps in a custom column.

### Split Ingestion and/or DL + KQL Job Promotion

The script auto-classifies 🟣 Split candidates (1-2 rules, ≥5 GB/week, DL-eligible). For these tables (and high-volume 🟢 Keep tables), the report should **present both optimization paths** so the operator can choose — or combine them — based on their knowledge of the rule queries:

| | Split Ingestion (DCR) | DL + KQL Job |
|-|----------------------|---------------|
| **How it works** | DCR routes a detection-relevant subset to Analytics, bulk to DL | Any data on DL (full table or split-routed portion); KQL job promotes aggregated results to `_KQL_CL` on Analytics |
| **Detection latency** | Real-time (subset stays on Analytics) | 15+ min (DL ingestion lag + job schedule) |
| **Rule rewrite needed** | No — rules keep targeting original table | Yes — rules must target `_KQL_CL` output |
| **Volume savings** | Moderate (bulk to DL, subset stays) | Depends on scope — maximum if entire table goes to DL, incremental if applied to split-routed portion |
| **Best when** | Rules filter on specific raw events (EventIDs, facilities) | Rules use aggregation and tolerate latency |

> **These approaches are complementary, not mutually exclusive.** Split ingestion routes bulk data to DL while keeping detection-relevant events on Analytics. KQL jobs can then run against that DL portion to surface additional insights (e.g., aggregated anomalies) back to Analytics via `_KQL_CL` tables — giving you both real-time detection on the split subset AND scheduled analytics on the DL bulk.

**Rendering guidance:** The LLM does NOT have visibility into rule query text (aggregation vs raw filters), so it cannot definitively recommend one over the other. For 🟣 tables and high-volume 🟢 tables, present the comparison and note which approach fits which rule pattern. Do NOT change the script's `Category` emoji in §7a — express as prose in §7b/7c.

*References:*
- [KQL jobs](https://learn.microsoft.com/azure/sentinel/datalake/kql-jobs)
- [Sentinel data lake overview](https://learn.microsoft.com/azure/sentinel/datalake/sentinel-lake-overview)
- [Manage data tiers and retention](https://learn.microsoft.com/azure/sentinel/manage-data-overview)
- [Log retention tiers](https://learn.microsoft.com/azure/sentinel/log-plans)

---

## Reference: License Benefits

### Defender for Servers P2 — 500MB/Server/Day Benefit

- Each server protected by DfS P2 contributes 500 MB/day to a **pooled** daily allowance
- Pool = (number of protected servers) × 500 MB — aggregate across subscription, not per-machine
- Applies to [security data types](https://learn.microsoft.com/azure/defender-for-cloud/data-ingestion-benefit): SecurityAlert, SecurityBaseline, SecurityBaselineSummary, SecurityDetection, SecurityEvent, WindowsFirewall, MaliciousIPCommunication, SysmonEvent, ProtectionStatus, Update, UpdateSummary
- Applied automatically at workspace level — shows as zero cost

| **Pool calculation from Q4:**
```
Potential DfS P2 Pool = (Distinct servers from Q4) × 500 MB/day
```

**Example:** Q4 shows 12 servers → pool = 6 GB/day. If DFSP2-eligible avg is 4.2 GB/day → fully covered.

| Scenario | Condition | Recommendation |
|----------|-----------|---------------|
| Pool far exceeds usage | DfSP2_DailyGB < 50% of PoolGB | Highlight the unused headroom and recommend increasing SecurityEvent logging levels (e.g., "All Events" instead of "Common") to broaden detection coverage at no additional ingestion cost. Note that increased data volume may affect retention storage costs |
| Pool covers usage | DfSP2_DailyGB ≥ 50% and ≤ 100% of PoolGB | Pool covers current need — monitor growth and reference §3a if approaching ceiling |
| Usage exceeds pool | DfSP2_DailyGB > PoolGB | Overage is billed at standard rates — review §3a EventID breakdown for reduction opportunities, or consider onboarding more servers to DfS P2 to expand the pool |

### M365 E5 / Defender XDR Ingestion Benefit

- M365 E5 (or E5 Security, A5, F5, G5) provides **5 MB per user per day** pooled data grant ([offer page](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer))
- Grant = (number of E5 licenses) × 5 MB/day
- Covers: Entra ID sign-in/audit logs, MCAS shadow IT, Purview info protection, M365 advanced hunting data (29 tables in Q17/Q17b)
- Applied automatically — `Free Benefit - M365 Defender Data Ingestion`
- **Always-free** (all Sentinel users): Azure Activity, Office 365 Audit Logs, Defender alerts

**⚠️ Ask user for E5 license count** — not discoverable from Sentinel telemetry.

**Example:** 500 E5 licenses → grant = 2.5 GB/day. If E5-eligible avg exceeds grant, overage billed at standard rates.

*References:*
- [DfS P2 data ingestion benefit](https://learn.microsoft.com/azure/defender-for-cloud/data-ingestion-benefit)
- [Sentinel free data sources](https://learn.microsoft.com/azure/sentinel/billing#free-data-sources)
- [View data allocation benefits](https://learn.microsoft.com/azure/azure-monitor/fundamentals/cost-usage#view-data-allocation-benefits)
- [M365 E5 offer details](https://azure.microsoft.com/en-us/pricing/offers/sentinel-microsoft-365-offer)

---

## Report Template

> 📄 **Just-in-time loading:** Read [SKILL-report.md](SKILL-report.md) at the start of **Phase 6 rendering**. It contains:
> - **Inline Chat Executive Summary** template — Workspace at a Glance, Cost Waterfall, Detection Posture, Overall Assessment, Top 3 Recommendations
> - **Markdown File Structure** — Complete §1–§8 rendering rules, mandatory format requirements, column specifications, validation checks
> - **Section-to-Scratchpad Mapping** — Which scratchpad keys feed each report section
>
> Load ONLY when entering Phase 6 — NOT during Phases 1–5. Combine with scratchpad data for rendering.

---

## Post-Report Drill-Down Reference

> 📄 **Just-in-time loading:** Read [SKILL-drilldown.md](SKILL-drilldown.md) for full instructions when any of these are needed.

### Available Drill-Down Patterns

Use these when the user asks follow-up questions after a report is generated (e.g., *"which rules use EventID 8002?"*, *"look up custom detection rules"*, *"do any ASIM parsers depend on this table?"*).

| Pattern | Purpose | Tool / Method | Trigger Phrases |
|---------|---------|---------------|------------------|
| **1. EventID cross-ref** | Which analytic rules reference a specific EventID? | `az rest` (Sentinel REST API) + JMESPath `contains()` | "which rules use EventID X", "does any rule need this EventID" |
| **2. Syslog facility/process** | Which rules reference a Syslog facility, source, or process? | `az rest` + JMESPath | "which rules use sshd", "any rules for authpriv" |
| **3. CSL vendor/activity** | Which rules reference a CEF vendor, product, or activity? | `az rest` + JMESPath | "rules for Palo Alto TRAFFIC", "which rules use CommonSecurityLog" |
| **4. Full rule query dump** | Export all enabled rule queries for manual analysis | `az rest` → JSON file | "export all rule queries", "build EventID dependency map" |
| **5. ASIM parser verification** | Which ASIM parsers consume a table slated for migration? | `az rest` + regex match for `_Im_`/`_ASim_` patterns | "ASIM dependency", "do parsers use this table" |
| **6. Custom Detection rules** | Inventory CD rules via Graph API (query text, schedule, last run) | `az rest` with Graph API endpoint | "custom detection rules", "CD rules", "lookup custom detections" |

> ⚠️ **Graph MCP not integrated:** The Microsoft Graph MCP server is not integrated with Azure SRE Agent (cannot currently be connected; direct API access not yet implemented as a replacement). For Custom Detection queries, **always use `az rest`** with the Graph API endpoint. For Analytic Rule queries, use `az rest`. See [SKILL-drilldown.md](SKILL-drilldown.md) for the exact endpoint and select fields.

### Also in SKILL-drilldown.md

| Section | Contents |
|---------|----------|
| **Known Pitfalls** | Usage table batching, `_SPLT_CL` naming, case-sensitive custom tables, LogSeverity types, value-level vs table-level coverage confusion |
| **Error Handling** | Common errors from `az rest`, Graph API via `az rest`; graceful degradation for missing tables; re-running individual phases |
| **CloudAppEvents Appendix** | Custom Detection management audit trail (EditCustomDetection events) — distinct from execution telemetry |
| **Additional References** | Microsoft Learn links for cost optimization, DCR configuration, data tiers, ASIM parsers |

---

## SVG Dashboard Generation

> 📊 **Optional post-report step.** After a report is generated, the user can request a visual SVG dashboard.

**Trigger phrases:** "generate SVG dashboard", "create a visual dashboard", "visualize this report", "SVG from the report"

### How to Request a Dashboard

- **Same chat:** "Generate an SVG dashboard from the report" — data is already in context.
- **New chat:** Attach or reference the report file, e.g. `#file:reports/sentinel/sentinel_ingestion_report_<workspace>_<date>.md`
- **Customization:** Edit [svg-widgets.yaml](svg-widgets.yaml) before requesting — the renderer reads it at generation time.

### Execution

```
Step 1:  Read svg-widgets.yaml (this skill's widget manifest)
Step 2:  Read the svg-dashboard SKILL.md (rendering rules — Manifest Mode) if available in the workspace
Step 3:  Read the completed report file (data source)
Step 4:  Render SVG → save to reports/sentinel/{report_name}_dashboard.svg
```

The YAML manifest is the single source of truth for layout, widgets, field mappings, colors, and data source documentation. All customization happens there.
