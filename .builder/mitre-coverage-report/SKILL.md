---
name: mitre-coverage-report
description: 'MITRE ATT&CK Coverage Report — YAML-driven Python pipeline gathers analytic rule MITRE tags, custom detection techniques, SOC Optimization recommendations, and alert/incident operational data via az rest/az monitor/Graph API, writes a deterministic scratchpad, LLM renders the report. Covers tactic-level coverage matrix, technique-level drill-down with rule mapping, coverage gap identification, SOC Optimization threat scenario alignment, untagged rule remediation, ICS/OT technique tracking, and MITRE Coverage Score (5 weighted dimensions). Inline chat and markdown file output.'
---

# MITRE ATT&CK Coverage Report — Instructions

## Purpose

This skill generates a comprehensive **MITRE ATT&CK Coverage Report** analyzing detection coverage across the ATT&CK Enterprise framework. It inventories all analytic rules and custom detections, maps them to MITRE tactics and techniques, identifies coverage gaps, and provides prioritized recommendations for improving detection posture.

**Entity Type:** Sentinel workspace (parameters provided at invocation)

| Scope | Data Sources | Use Case |
|-------|--------------|----------|
| Workspace-wide (default) | Analytic Rules (REST), Custom Detections (Graph), SOC Optimization (REST), SecurityAlert/SecurityIncident (KQL) | Full MITRE coverage analysis |
| Operational correlation | SecurityAlert, SecurityIncident | Which MITRE-tagged rules actually produce alerts and incidents |

**What this report covers:** Tactic-level coverage matrix with per-tactic technique counts and percentages, technique-level drill-down with rule-to-technique mapping, coverage gap identification against the full ATT&CK Enterprise framework, SOC Optimization threat scenario alignment (AiTM, ransomware, BEC, etc.), untagged rule remediation with AI-suggested MITRE tags, ICS/OT technique tracking, operational MITRE correlation (which rules actually fire), and a composite MITRE Coverage Score.

---

## Environment & Data Gathering

> ⚠️ **This skill runs in an environment where Sentinel MCP Server and Microsoft Graph MCP are not integrated with Azure SRE Agent** (these MCP servers cannot currently be connected; the underlying data is accessible via direct API, but this approach has not yet been studied and implemented in this skill).
> All data is gathered exclusively by `invoke_mitre_scan.py` using:
> - **`az rest`** — Sentinel REST API (analytic rules, SOC Optimization) + Microsoft Graph API (Custom Detections)
> - **`az monitor log-analytics query`** — KQL queries against Log Analytics
> - **Azure CLI commands** — Table tier classification
>
> All queries are pre-defined in `queries.yaml` (multi-document). No KQL or REST query generation is needed at runtime — the script reads the YAML definitions and executes them.
>
> Available MCP servers (for ad-hoc reference, NOT for data gathering):
> - **Microsoft Learn MCP** — documentation lookup
> - **KQL Search MCP** — query examples and table schema reference
> - **Azure MCP Server** — Azure resource exploration

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                        TWO EXECUTION MODES                             │
 │                                                                        │
 │  MODE A — Direct (terminal az works)                                   │
 │  queries.yaml → invoke_mitre_scan.py → az rest / az monitor → scratch  │
 │                                                                        │
 │  MODE B — Prefetch (terminal az blocked by MI token cache)             │
 │  LLM gathers data via native tools (RunAzCliReadCommands, MCP monitor) │
 │  → saves to tmp/mitre-prefetch/*.json                                  │
 │  → invoke_mitre_scan.py --prefetch-dir tmp/mitre-prefetch/             │
 │  → reads JSON files instead of running az → scratch                    │
 │                                                                        │
 │  Both modes produce: output/mitre_scratch_<ts>.md (~35 KB)             │
 │  Phase 4: LLM reads scratchpad + SKILL-report.md → renders report      │
 └─────────────────────────────────────────────────────────────────────────┘
```

**Execution model:**
- **Phases 1-3** (data gathering): Two modes depending on environment:
  - **Mode A (Direct):** `invoke_mitre_scan.py` runs `az rest` / `az monitor` directly from the terminal. Works when the terminal `az` CLI has valid credentials with `Microsoft Sentinel Reader` role.
  - **Mode B (Prefetch):** The LLM collects data via native tools (`RunAzCliReadCommands` for REST/CLI, `monitor-client` MCP tools for KQL), saves results to JSON files in `tmp/mitre-prefetch/`, then runs `invoke_mitre_scan.py --prefetch-dir tmp/mitre-prefetch/` for post-processing only. **This is the recommended mode** in agent environments where Managed Identity token caching can block terminal `az` for up to 24 hours after RBAC changes.
- **Phase 4** (rendering): LLM reads the scratchpad + `SKILL-report.md` and renders the report. This is the only phase requiring LLM involvement.

**Static reference:** `mitre-attck-enterprise.json` contains ATT&CK Enterprise v16.1 with 14 tactics, 216 techniques, and 475 sub-techniques. Loaded at startup to compute coverage gaps against the full framework. This file is version-controlled and should be updated when MITRE publishes new ATT&CK releases.

**Platform coverage reference:** `m365-platform-coverage.json` is a compact CTID (Center for Threat-Informed Defense) mapping of M365 Defender product capabilities to ATT&CK techniques. Contains detect/protect/respond coverage for 81 detect techniques across 38 capabilities (7 SecurityAlert product groups). Used for the 3-tier platform coverage classification:
- **Tier 1 (Alert-Proven):** SecurityAlert from M6 query has MITRE technique attribution — highest confidence
- **Tier 2 (Deployed Capability):** Product is active (has alerts) and CTID claims detect coverage for the technique — medium confidence
- **Tier 3 (Catalog Capability):** CTID maps coverage but no alert evidence for the product in this workspace — lowest confidence

---

## Companion Files — When to Load

| File | Purpose | When to Load | Runtime Location |
|------|---------|--------------|------------------|
| **SKILL.md** (this file) | Architecture, workflow, rendering rules, score methodology, domain reference | Always — primary entry point | `read_skill_file` only |
| [SKILL-report.md](SKILL-report.md) | Report templates (§1-§6), section-to-scratchpad mapping, formatting rules | Phase 4 rendering only | `read_skill_file` only |
| [invoke_mitre_scan.py](invoke_mitre_scan.py) | Data-gathering pipeline (Phases 1-3) | Execution only — no need to read unless debugging | **Must be on disk** |
| [generate_html_report.py](generate_html_report.py) | HTML report generator from scratchpad | Post-report HTML rendering | **Must be on disk** |
| [queries.yaml](queries.yaml) | All 9 query definitions (M1–M9), multi-document | Referenced at runtime by invoke_mitre_scan.py | **Must be on disk** (same dir as script) |
| [mitre-attck-enterprise.json](mitre-attck-enterprise.json) | ATT&CK Enterprise v16.1 static reference | Referenced at runtime — no manual loading | **Must be on disk** (same dir as script) |
| [m365-platform-coverage.json](m365-platform-coverage.json) | CTID M365 platform coverage reference (detect/protect/respond) | Referenced at runtime — no manual loading | **Must be on disk** (same dir as script) |
| [known-kql-tables.json](known-kql-tables.json) | Known KQL table names for parser validation | Referenced at runtime — no manual loading | **Must be on disk** (same dir as script) |
| [svg-widgets.yaml](svg-widgets.yaml) | SVG dashboard widget manifest | SVG dashboard generation only | `read_skill_file` only |

> ⚠️ **Runtime Location = "Must be on disk"** means the file must exist on the local filesystem. These files are accessed by `invoke_mitre_scan.py` via `Path(__file__).resolve().parent` at runtime. They are resolved **immediately on skill activation** via the [File Resolution cascade](#file-resolution-coderefs-first--on-skill-activation).

---

## File Resolution (codeRefs-first — On Skill Activation)

`invoke_mitre_scan.py` loads companion data files **from its own directory** at runtime (`script_dir = Path(__file__).resolve().parent`). These files must be co-located with the script on disk.

🔴 **MANDATORY — IMMEDIATE:** The moment this skill is activated (i.e., the agent reads this SKILL.md), the agent MUST resolve ALL files listed below **before doing anything else** — before collecting parameters, before asking the user questions, before any other action. This is not a workflow step; it is a **precondition of the skill being operational**.

### Resolution Cascade

Resolve ALL 6 runtime files using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/mitre-coverage-report/
   → If ALL 6 files exist here: use this directory as <SKILL_DIR>
   → Execute invoke_mitre_scan.py directly from here (companion files are co-located)
   → Do NOT copy files to tmp/

2. tmp/mitre-coverage-report/
   → If ALL 6 files exist here (from previous materialization): use this directory as <SKILL_DIR>

3. Neither location has all files:
   → read_skill_file() from Builder for each missing file
   → CreateFile("tmp/mitre-coverage-report/<filename>", <content>)
   → Use tmp/mitre-coverage-report/ as <SKILL_DIR>
```

All subsequent commands in this skill reference the resolved directory as `<SKILL_DIR>`.

### Files to Resolve

| File | Required By | Format |
|------|-------------|--------|
| `invoke_mitre_scan.py` | Phase 1-3 execution | Python |
| `generate_html_report.py` | HTML report generation | Python |
| `queries.yaml` | `invoke_mitre_scan.py` | YAML (multi-document) |
| `mitre-attck-enterprise.json` | `invoke_mitre_scan.py` | JSON |
| `m365-platform-coverage.json` | `invoke_mitre_scan.py` | JSON |
| `known-kql-tables.json` | `invoke_mitre_scan.py` | JSON |

### Step 1: Check codeRefs

```bash
ls codeRefs/sec-sre-ag/mitre-coverage-report/queries.yaml codeRefs/sec-sre-ag/mitre-coverage-report/mitre-attck-enterprise.json codeRefs/sec-sre-ag/mitre-coverage-report/m365-platform-coverage.json codeRefs/sec-sre-ag/mitre-coverage-report/known-kql-tables.json codeRefs/sec-sre-ag/mitre-coverage-report/invoke_mitre_scan.py codeRefs/sec-sre-ag/mitre-coverage-report/generate_html_report.py 2>/dev/null | wc -l
# If returns 6 → set <SKILL_DIR>=codeRefs/sec-sre-ag/mitre-coverage-report → DONE
```

### Step 2: Check tmp (if codeRefs not found)

```bash
ls tmp/mitre-coverage-report/queries.yaml tmp/mitre-coverage-report/mitre-attck-enterprise.json tmp/mitre-coverage-report/m365-platform-coverage.json tmp/mitre-coverage-report/known-kql-tables.json tmp/mitre-coverage-report/invoke_mitre_scan.py tmp/mitre-coverage-report/generate_html_report.py 2>/dev/null | wc -l
# If returns 6 → set <SKILL_DIR>=tmp/mitre-coverage-report → DONE
```

### Step 3: Materialize from Builder (if neither location has all files)

🔴 **CRITICAL: Write FULL file content. NEVER write placeholders or stubs** (e.g., `{"placeholder": true}` or stub scripts). Writing placeholders then backfilling later wastes multiple round-trips and is the #1 cause of slow materialization.

**Step 3a — Read ALL 6 files in a single parallel batch:**
```
read_skill_file(skill_name="mitre-coverage-report", file_path="invoke_mitre_scan.py")
read_skill_file(skill_name="mitre-coverage-report", file_path="generate_html_report.py")
read_skill_file(skill_name="mitre-coverage-report", file_path="queries.yaml")
read_skill_file(skill_name="mitre-coverage-report", file_path="mitre-attck-enterprise.json")
read_skill_file(skill_name="mitre-coverage-report", file_path="m365-platform-coverage.json")
read_skill_file(skill_name="mitre-coverage-report", file_path="known-kql-tables.json")
```

**Step 3b — Write ALL 6 files in a single parallel batch:**
```
CreateFile(filePath="tmp/mitre-coverage-report/invoke_mitre_scan.py", content=<FULL content>)
CreateFile(filePath="tmp/mitre-coverage-report/generate_html_report.py", content=<FULL content>)
CreateFile(filePath="tmp/mitre-coverage-report/queries.yaml", content=<FULL content>)
CreateFile(filePath="tmp/mitre-coverage-report/mitre-attck-enterprise.json", content=<FULL content>)
CreateFile(filePath="tmp/mitre-coverage-report/m365-platform-coverage.json", content=<FULL content>)
CreateFile(filePath="tmp/mitre-coverage-report/known-kql-tables.json", content=<FULL content>)
```

**Total: 2 tool calls (read batch + write batch).** Do NOT split into more batches. Do NOT write one file at a time.
Set `<SKILL_DIR>=tmp/mitre-coverage-report`.

🔴 **PROHIBITED:** Proceeding to Phase 0 (parameter collection) or any workflow step without completed file resolution. The script will exit immediately if `queries.yaml` or `mitre-attck-enterprise.json` are missing.

---

## 📑 TABLE OF CONTENTS

1. **[Quick Start](#quick-start-tldr)** - 3-step execution pattern (files auto-materialized on activation)
2. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)** - Prerequisites and prohibitions
3. **[Execution Workflow](#execution-workflow)** - Phases 0-4
4. **[Query File Reference](#query-file-reference)** - All 9 YAML files
5. **[Output Modes](#output-modes)** - Inline chat vs. Markdown file
6. **[Deterministic Rendering Rules](#deterministic-rendering-rules)** - Rules A-E (mandatory for Phase 4)
7. **[MITRE Coverage Score](#mitre-coverage-score)** - 5-dimension scoring methodology
8. **[Domain Reference](#domain-reference)** - ATT&CK interpretation, tactic priorities, Sentinel-specific mappings
9. **[SVG Dashboard Generation](#svg-dashboard-generation)** - Visual dashboard from completed report

---

## Quick Start (TL;DR)

**3-step execution pattern** (file resolution happens automatically on skill activation — see [above](#file-resolution-coderefs-first--on-skill-activation)):

```
Step 1:  Run invoke_mitre_scan.py (Phases 1-3 — data gathering)
Step 2:  Read scratchpad + SKILL-report.md (Phase 4 prep)
Step 3:  Render report incrementally (§1 via create_file, then §2–§6 appended via replace_string_in_file)
```

### Step 1: Run Data Gathering

**First, try Mode A (direct execution).** If it fails with `AuthorizationFailed` or `Forbidden`, switch to Mode B (prefetch).

#### Mode A — Direct Execution (terminal `az` works)

```bash
python3 "tmp/mitre-coverage-report/invoke_mitre_scan.py" \
    --workspace-id "<workspace_guid>" \
    --subscription-id "<subscription_id>" \
    --resource-group "<resource_group>" \
    --workspace-name "<workspace_name>" \
    --days 30
```

**Timing:** ~60-90 seconds.

#### Mode B — Prefetch (terminal `az` blocked by MI token cache)

Use this when terminal `az rest` returns `AuthorizationFailed` but `RunAzCliReadCommands` works. This is common after RBAC role assignments (MI token cache can be stale for up to 24h).

**Step 1a — Collect data via native tools** (all in parallel where possible):

| Query | Tool | Notes |
|-------|------|-------|
| M1 (Analytic Rules) | `RunAzCliReadCommands` — `az rest` with Sentinel REST URL | **Include `query:properties.query` in JMESPath** for data readiness |
| M2 (Custom Detections) | `RunAzCliReadCommands` — `az rest` with Graph endpoint | Will SKIP gracefully (needs `CustomDetection.Read.All`) |
| M3 (SOC Optimization) | `RunAzCliReadCommands` — `az rest` with Sentinel REST URL | |
| M4-M8 (KQL) | `monitor-client_monitor_workspace_log_query` MCP tool | Use workspace GUID, resource-group, table, query from queries.yaml |
| M9 (Table tiers) | `RunAzCliReadCommands` — `az monitor log-analytics workspace table list` | |

**Step 1b — Save results** to `tmp/mitre-prefetch/m1.json` through `m9.json`:
```python
# Extract from RunAzCliReadCommands tool output:
import json
with open('tmp/ToolOutputs/<output_id>.json') as f:
    raw = json.load(f)
data = json.loads(raw['cliExecutionResult']['output'])
with open('tmp/mitre-prefetch/m1.json', 'w') as f:
    json.dump(data, f)
```

**Step 1c — Run post-processing** with prefetch:
```bash
python3 "tmp/mitre-coverage-report/invoke_mitre_scan.py" \
    --workspace-id "<workspace_guid>" \
    --subscription-id "<subscription_id>" \
    --resource-group "<resource_group>" \
    --workspace-name "<workspace_name>" \
    --days 30 \
    --prefetch-dir "tmp/mitre-prefetch/"
```

**Output (both modes):** Scratchpad file at `output/mitre_scratch_<timestamp>.md` (~28-38 KB).

### Step 2: Load Rendering Context

1. Read the scratchpad file (path printed by PS1 at completion)
2. Read [SKILL-report.md](SKILL-report.md) for rendering templates

### Step 3: Render Report (Incremental Writes)

Render the report across **multiple tool calls** — one section per call — to avoid single-call output token limits that truncate large reports:

1. `create_file` → header + disclaimer + §1 (Executive Summary, Score, Inventory, Top 3 Recs)
2. `replace_string_in_file` → append §2 (Tactic Coverage Matrix)
3. `replace_string_in_file` → append §3 (Technique Deep Dive — largest section)
4. `replace_string_in_file` → append §4 (Coverage Gap Analysis)
5. `replace_string_in_file` → append §5 (Operational MITRE Correlation)
6. `replace_string_in_file` → append §6 + Appendix

Apply SKILL-report.md templates to scratchpad data, following Rules A–D. See [SKILL-report.md](SKILL-report.md) for full section templates and the anchor pattern for each append.

**⛔ Do NOT render §1–§6 in a single `create_file` call.** The output will truncate silently. The scratchpad is ~60 KB; the rendered report exceeds the single-call output budget.

**🔴 ALL 6 APPENDS ARE MANDATORY.** Do NOT stop after §5 — §6 (Recommendations) and the Appendix (Score Methodology, Limitations) are critical and must be appended. After the 6th append, run `grep_search` for `## 6. Recommendations` and `## Appendix` on the report file to verify both exist. If either is missing, append the missing content immediately.

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

**Before starting ANY MITRE coverage report:**

1. **Run `invoke_mitre_scan.py`** — this single script handles ALL data gathering (Phases 1-3). The LLM does NOT run queries, transcribe output, or write scratchpad sections
2. **Collect workspace parameters** from the user: `WorkspaceId`, `SubscriptionId`, `ResourceGroup`, `WorkspaceName`
3. **ALWAYS ask the user for output mode** if not specified: inline chat summary, markdown file report, or both (default: both)
4. **ALWAYS ask the user for timeframe** if not specified: the `-Days` parameter controls the alert/incident KQL lookback (Phase 3). Default: 30 days. Phases 1-2 (REST API) are not time-bounded
5. **ALWAYS use `create_file` for markdown reports** (never use terminal commands)
6. **ALWAYS sanitize PII** from saved reports — use generic placeholders for real rule names, workspace names, and tenant GUIDs in committed files
7. **Read scratchpad + SKILL-report.md** before rendering — the scratchpad is the sole data source
8. **Custom Detections may be SKIPPED** — the Graph API requires `CustomDetection.Read.All` which needs admin consent. If skipped, the report notes this and shows AR-only analysis. Do NOT treat SKIPPED as an error — it's a graceful degradation

### Prerequisites

| Dependency | Required By | Setup |
|------------|-------------|-------|
| **Azure CLI** (`az`) | All phases (REST + KQL) | Install: [aka.ms/installazurecli](https://aka.ms/installazurecli). Authenticate: `az login --tenant <tenant_id>` then `az account set --subscription <subscription_id>` |
| **Azure RBAC** | Phase 1-2 (REST API) | **Microsoft Sentinel Reader** on the workspace (analytic rule inventory + SOC Optimization) |
| **KQL auth** | Phase 3 (az monitor) | `az login` with `https://api.loganalytics.io/.default` scope (CA policy may enforce re-auth) |
| **Graph auth** | Phase 1 M2 (Custom Detections) | `CustomDetection.Read.All` scope. Uses `az rest` with Graph endpoint. Skips gracefully if unavailable |
| **Python 3.10+** | Script execution | `python3 --version` |
| **MI token freshness** | All phases (terminal az) | Managed Identity tokens are cached by IMDS for up to **24 hours**. After RBAC role assignments, terminal `az` may not see new permissions immediately. `RunAzCliReadCommands` tool uses a different auth path and sees permissions instantly. If terminal `az` returns 403 after a recent role assignment, switch to **Mode B (prefetch)** |

### 🔴 PROHIBITED

- ❌ Proceeding to any workflow step (parameter collection, data gathering, rendering) before file materialization is complete — files are materialized to `tmp/mitre-coverage-report/` immediately on skill activation
- ❌ Running REST/KQL queries via MCP tools **during Mode A (direct) execution** — invoke_mitre_scan.py handles all queries. Exception: **Mode B (prefetch) uses native tools** (`RunAzCliReadCommands`, `monitor-client` MCP) to collect data when terminal `az` is blocked
- ❌ Using `mcp_microsoft_se2_*` (Sentinel MCP) or `mcp_mtp_mcp_servi_*` (Defender MCP) or `mcp_microsoft_ent_*` (Graph MCP) — these are not integrated with Azure SRE Agent (cannot currently be connected; data reachable via direct API, but not yet implemented). Note: `monitor-client_monitor_workspace_log_query` (Azure Monitor MCP) IS available and used for KQL in Mode B prefetch
- ❌ Writing or modifying scratchpad sections manually — the script is the sole writer
- ❌ Fabricating technique counts, rule names, or coverage percentages
- ❌ Inventing ATT&CK technique IDs or names not in the reference JSON
- ❌ Overriding MITRE Coverage Score dimensions — the script computes these deterministically
- ❌ Rendering the report without first reading the scratchpad file
- ❌ Reporting "100% coverage" for any tactic unless the data actually shows every technique covered

---

## Execution Workflow

### Phase 0: Initialization

> ℹ️ File materialization has already completed at skill activation — all scripts and data files are in `tmp/mitre-coverage-report/`. No action needed here.

1. Collect workspace parameters from user: `WorkspaceId`, `SubscriptionId`, `ResourceGroup`, `WorkspaceName`
2. **Verify workspace Resource Group** — the workspace RG may differ from the agent's RG. Always confirm via Resource Graph:
   ```
   az graph query -q "Resources | where type =~ 'Microsoft.OperationalInsights/workspaces' | where name =~ '<workspace_name>' | project name, resourceGroup, subscriptionId" --first 5
   ```
   🔴 **Do NOT assume the workspace is in the same RG as the agent.** This is the most common parameter error.
3. Confirm output mode and timeframe with user (pass `-Days` to PS1; default 30)
4. **Determine execution mode** — try a quick test to decide Mode A vs Mode B:
   ```bash
   az rest --method get --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>/providers/Microsoft.SecurityInsights/alertRules?api-version=2024-03-01" --query "length(value)" -o json 2>&1 | head -1
   ```
   - If returns a number → **Mode A** (direct execution)
   - If returns `AuthorizationFailed` or `Forbidden` → **Mode B** (prefetch via native tools)
5. Verify prerequisites: `az login` session active, correct subscription set

### Phases 1-3: Data Gathering (automated)

Run `invoke_mitre_scan.py` — it handles all 3 phases automatically:

| Phase | Queries | Description | Execution Type |
|-------|---------|-------------|----------------|
| **1** | M1, M2 | Rule inventory — Analytic rules with MITRE tactics/techniques (REST), Custom Detection rules with mitreTechniques (Graph, graceful skip) | REST + Graph |
| **2** | M3 | SOC Optimization — Coverage recommendations with threat scenario context, MITRE tagging suggestions for untagged rules | REST |
| **3** | M4, M5, M6, M7, M8, M9 | Operational correlation — SecurityAlert firing counts per rule with MITRE cross-reference, SecurityIncident volume by tactic, platform-native alert MITRE coverage, table ingestion volume for data readiness validation, data connector health from SentinelHealth, table tier classification | KQL + CLI |

**Post-processing (automated by PS1):**

| Task | Phase | Description |
|------|-------|-------------|
| Tactic coverage matrix | 1 | For each ATT&CK tactic, count enabled rules and covered techniques against the framework reference |
| Technique drill-down | 3 | Map every framework technique to its covering rules AND pre-compute tier/product annotations from CTID cross-reference |
| Untagged rule identification | 1 | Find rules with no MITRE tactics AND no techniques |
| ICS technique extraction | 1 | Separate T0xxx (ICS/OT) technique mappings |
| Threat scenario parsing | 2 | Extract active/recommended detection counts and per-tactic breakdowns from SOC Optimization |
| AI MITRE tagging suggestions | 2 | Extract suggested tactics/techniques for untagged rules. Cross-reference against Phase 1 actual rule tags to verify if suggestions were applied |
| Alert-to-MITRE correlation | 3 | Cross-reference firing alerts with Phase 1 MITRE tags |
| Active tactic coverage | 3 | Compute which tactics have rules that actually fire alerts |
| Platform alert MITRE extraction | 3 | Extract MITRE techniques attributed by platform-native product alerts (M6) |
| Product presence detection | 3 | Derive active M365 Defender products from SecurityAlert ProductName |
| CTID tier classification | 3 | Cross-reference active products with CTID mapping to classify techniques as Tier 1/2/3 |
| Combined tactic coverage | 3 | Merge custom rule and platform Tier 1/2 coverage per tactic |
| Data readiness cross-reference | 3 | Extract KQL table dependencies from rule queries, cross-reference with M7 ingestion volumes, classify rules as Ready/Partial/NoData |
| Connector health enrichment | 3 | Cross-reference M8 SentinelHealth connector status with Data Readiness |
| Table tier classification | 3 | Cross-reference M9 table tier metadata with rule KQL table dependencies — flag rules targeting Basic/Data Lake tier tables as "TierBlocked" (phantom coverage) |
| Coverage Score computation | All | Weighted composite score from 5 dimensions |

**Scratchpad output:** The script writes all results to `output/mitre_scratch_<timestamp>.md` (~28 KB, ~12 named sections). See SKILL-report.md for the Section-to-Scratchpad Mapping.

### Phase 4: Render Output (LLM)

**🔴 MANDATORY — Load scratchpad + report template before rendering:**

1. **Read the scratchpad file** (path printed at completion). This single file contains ALL data from Phases 1-3.
2. **Read [SKILL-report.md](SKILL-report.md)** for the complete rendering templates and formatting rules.

**Pre-render validation:**
1. Verify scratchpad has all 3 phase sections (PHASE_1 through PHASE_3)
2. Check SCORE section has all 5 dimensions
3. If Phase 3 shows FAILED for M4/M5 (token expiry), note this in the report — the Operational dimension defaults to 0

**Render — Section-by-Section:**

| Section | Data Source (scratchpad keys) | Required |
|---------|------------------------------|----------|
| §1 Executive Summary | All phases + SCORE | ✅ Coverage Score, Workspace at a Glance, Top 3 |
| §2 Tactic Coverage | PHASE_1.TacticCoverage | ✅ 14-tactic matrix with coverage % |
| §3 Technique Deep Dive | PHASE_3.TechniqueDetail (enriched with Tier/TierProducts) | ✅ Per-tactic technique tables with pre-computed tier badges |
| §4 Coverage Gap Analysis | PHASE_1.TacticCoverage + PHASE_3.TechniqueDetail + PHASE_2.ThreatScenarios | ✅ Gaps, priorities, threat scenario alignment |
| §5 Operational MITRE Correlation | PHASE_3 AlertFiring, IncidentsByTactic, ActiveTacticCoverage, PlatformAlertCoverage, PlatformTechniquesByTier, PlatformTacticCoverage, DataReadiness, ConnectorHealth | ✅ Which rules fire, platform coverage, combined tactic view, data readiness, connector health |
| §6 Recommendations | All phases | ✅ Untagged rule remediation, Content Hub suggestions, coverage priorities |

---

## Query File Reference

All queries are defined in `queries.yaml` (multi-document, `---` separated). Each document has `id`, `phase`, `type`, and relevant query fields. The script reads these definitions and executes them via the appropriate tool (`az rest`, `az monitor log-analytics query`, or `az monitor log-analytics workspace table list`).

### YAML Format

```yaml
id: mitre-m1                                   # Unique identifier
name: Analytic Rule MITRE Extraction            # Human-readable name
description: Fetch rules with tactics/techniques # What it does
phase: 1                                        # Which phase (1-3)
type: rest                                      # rest | graph | kql | cli
url: https://management.azure.com/...           # REST API URL with placeholders
jmespath: value[].{...}                         # JMESPath projection (REST)
```

### Complete Query Inventory

| Phase | ID | Type | Description |
|-------|----|------|-------------|
| 1 | mitre-m1 | rest | Scheduled + NRT analytic rules with MITRE tactics, techniques, severity, query text |
| 1 | mitre-m2 | graph | Custom Detection rules with mitreTechniques (graceful skip if auth unavailable) |
| 2 | mitre-m3 | rest | SOC Optimization coverage recommendations with threat scenarios and MITRE tagging suggestions |
| 3 | mitre-m4 | kql | SecurityAlert firing counts per rule with severity breakdown (30d lookback) |
| 3 | mitre-m5 | kql | SecurityIncident volume by tactic with classification breakdown |
| 3 | mitre-m6 | kql | Platform-native SecurityAlert detections with MITRE technique attribution (excludes custom rules) |
| 3 | mitre-m7 | kql | 7-day average daily ingestion volume per table from Usage table for data readiness validation |
| 3 | mitre-m8 | kql | SentinelHealth data connector fetch status — latest state, success/failure counts, health % per connector |
| 3 | mitre-m9 | cli | Log Analytics table tier metadata (Analytics/Basic/Data Lake) via `az monitor log-analytics workspace table list` |

---

## Output Modes

### Mode 1: Inline Chat Summary (default for quick requests)
Compact executive summary rendered directly in chat with MITRE Coverage Score and top coverage gaps.

### Mode 2: Markdown File Report
Full detailed report saved to `reports/mitre_coverage_report_<YYYYMMDD_HHMMSS>.md`.

### Mode 3: Both (default when user says "report" or "generate report")
Inline chat executive summary + full markdown file.

**Ask user if not specified:**
> "How would you like the MITRE coverage report? I can provide:
> 1. **Inline chat summary** — MITRE Score + top gaps in chat
> 2. **Markdown file** — detailed report saved to reports/
> 3. **Both** (recommended) — summary in chat + full report file"

---

## Deterministic Rendering Rules

**These rules eliminate LLM interpretation variance. Apply them EXACTLY during Phase 4 rendering.**

### Rule A: Coverage Level Classification

Assign emoji badges to each tactic row in the coverage matrix based on the percentage of techniques covered:

| Coverage % | Badge | Level |
|------------|-------|-------|
| 0% | 🔴 | No coverage |
| 1-15% | 🟠 | Critical gap |
| 16-30% | 🟡 | Partial |
| 31-50% | 🔵 | Moderate |
| 51-75% | 🟢 | Good |
| >75% | ✅ | Strong |

**⛔ PROHIBITED:** Assigning badges based on "importance" or "this tactic is more relevant." The badge MUST match the percentage threshold table above.

### Rule B: Threat Scenario Priority

When rendering SOC Optimization threat scenarios, order by coverage gap (recommended minus active) descending, but assign **badges based on completion rate** (proportional to scenario size):

| Completion Rate | Priority | Badge |
|----------------|----------|-------|
| <15% | 🔴 High | Very early stage — most recommendations unaddressed |
| 15–35% | 🟠 Medium | Work in progress — significant room for improvement |
| 35–60% | 🟡 Low | Approaching healthy coverage for typical environments |
| ≥60% | ✅ Met | Strong coverage — well above realistic implementation targets |

> **Why rate-based?** Recommendation counts reflect the **full Content Hub template catalogue** including templates for vendor products not deployed in the environment. Rate-based badges give proportional, meaningful progress signals.

> **CompletedBySystem note:** `CompletedBySystem` is a SOC Optimization state, not a rate indicator. Always use the **completion rate** for badge assignment.

### Rule C: "Paper Tiger" Detection

When Phase 3 data is available, identify **paper tiger** rules — rules with MITRE tags that have NEVER produced an alert in the lookback period.

| Condition | Classification | Display |
|-----------|---------------|---------|
| Rule tagged with MITRE + 0 alerts in lookback | ⚠️ Paper tiger | Note in technique drill-down |
| Rule tagged with MITRE + ≥1 alert | ✅ Operationally validated | Normal display |
| Phase 3 data unavailable (FAILED/SKIPPED) | — | Skip paper-tiger analysis, note data gap |

**⛔ PROHIBITED:** Reporting coverage percentages as "validated" when Phase 3 data is missing.

### Rule D: Recommendation Ranking

Rank recommendations by impact using this priority order:

| Priority | Category | Criteria |
|----------|----------|----------|
| 1 | 🔴 **Low-rate threat scenarios** | SOC Optimization scenarios with <15% completion rate. **Exclude CompletedByUser scenarios with ≥50% completion rate** (Rule E). Only include ⚠️ Premature CompletedByUser (<50% rate) |
| 2 | 🔴 **Zero-coverage detectable tactics** | Tactics with 0% coverage AND ✅ Detectable classification. **Exclude ⬜ Inherent blind spot tactics** (Reconnaissance, Resource Development) |
| 3 | 🟠 **Untagged rule remediation** | Rules with AI-suggested MITRE tags from SOC Optimization |
| 4 | 🟠 **Paper tiger rules** | MITRE-tagged rules that never fire (if Phase 3 available) |
| 5 | 🟡 **Low-coverage tactics** | Tactics with 1-15% coverage |
| 6 | 🟡 **Content Hub suggestions** | Template-based rules available for uncovered techniques |
| 7 | ⬜ **Inherent blind spot tactics** | Zero-coverage tactics classified as ⬜ Inherent blind spot |

### Rule E: CompletedByUser Completion-Rate Gate

When a SOC Optimization threat scenario has `State == CompletedByUser`, use the **completion rate** (`ActiveDetections / RecommendedDetections × 100`) to determine rendering treatment:

| CompletedByUser + Completion Rate | Treatment | Rationale |
|---|---|---|
| **≥ 50%** | 🟢 **Reviewed & Addressed** — render in separate muted summary. Exclude from §6 recommendations | User has genuinely triaged the scenario |
| **< 50%** | ⚠️ **Premature Completion** — render in main active gaps table with ⚠️ flag. Include in §6 recommendations | Gap too large to be deliberate triage |

---

## MITRE Coverage Score

The MITRE Coverage Score is a composite metric (0-100) computed by the PS1 from 5 weighted dimensions.

### Dimensions

| # | Dimension | Weight | Formula | What It Measures |
|---|-----------|--------|---------|-----------------|
| 1 | **Breadth** | 25% | Readiness-weighted credit / total techniques, blended 60/40 with combined platform coverage | Readiness-weighted technique coverage. Each technique gets fractional credit based on best rule: Fired=1.0, Ready=0.75, Partial=0.50, NoData=0.25, TierBlocked=0.0 |
| 2 | **Balance** | 10% | `(tactics with ≥1 rule / 14 tactics) × 100` | Whether coverage spans all kill chain phases |
| 3 | **Operational** | 30% | `(MITRE-tagged rules that fired / total MITRE-tagged enabled rules) × 100` | Whether tagged rules actually produce detections. Highest weight: rewards purple teaming |
| 4 | **Tagging** | 15% | `(rules with MITRE tags / total rules) × 100` | Completeness of MITRE classification |
| 5 | **SOC Alignment** | 20% | `(completed SOC recommendations / total SOC coverage recommendations) × 100` | Alignment with Microsoft's threat-scenario-driven coverage model |

### Score Interpretation

| Score Range | Assessment | Typical Profile |
|-------------|------------|-----------------|
| 80-100 | 🟢 **Strong** | Broad coverage, balanced tactics, operationally validated, well-tagged, SOC-aligned |
| 60-79 | 🔵 **Good** | Solid coverage with some gaps; may have clustering or unvalidated rules |
| 40-59 | 🟡 **Moderate** | Significant gaps in breadth or operational validation |
| 20-39 | 🟠 **Developing** | Limited coverage across the framework |
| 0-19 | 🔴 **Critical** | Minimal detection coverage; urgent investment needed |

### Score Context Notes

- **Operational = 0** when Phase 3 KQL queries fail (token expiry). Report this as data unavailability.
- **SOC Alignment = 50** (default) when no SOC Optimization recommendations exist. Neutral baseline.
- **Breadth score is naturally low** because the ATT&CK framework contains 216+ techniques. Contextualize: "Prioritize coverage by threat scenario relevance."
- **Custom Detections SKIPPED** affects Breadth and Tagging dimensions (rules not counted). Note the impact.
- **Platform Coverage** is reported supplementary alongside the MITRE Score (not folded into the 5 dimensions).

---

## Domain Reference

### ATT&CK Enterprise Tactic Kill Chain Order

| # | Tactic (Sentinel API name) | Display Name | Cloud/Identity Relevance | Detectability |
|---|----------------------------|--------------|--------------------------|---------------|
| 1 | Reconnaissance | Reconnaissance | 🟡 Low | ⬜ Inherent blind spot |
| 2 | ResourceDevelopment | Resource Development | 🟡 Low | ⬜ Inherent blind spot |
| 3 | InitialAccess | Initial Access | 🔴 High | ✅ Detectable |
| 4 | Execution | Execution | 🟠 Medium | ✅ Detectable |
| 5 | Persistence | Persistence | 🔴 High | ✅ Detectable |
| 6 | PrivilegeEscalation | Privilege Escalation | 🔴 High | ✅ Detectable |
| 7 | DefenseEvasion | Defense Evasion | 🟠 Medium | ✅ Detectable |
| 8 | CredentialAccess | Credential Access | 🔴 High | ✅ Detectable |
| 9 | Discovery | Discovery | 🟡 Medium | ✅ Detectable |
| 10 | LateralMovement | Lateral Movement | 🟠 Medium | ✅ Detectable |
| 11 | Collection | Collection | 🟡 Medium | ✅ Detectable |
| 12 | CommandAndControl | Command and Control | 🟠 Medium | ✅ Detectable |
| 13 | Exfiltration | Exfiltration | 🟠 Medium | ✅ Detectable |
| 14 | Impact | Impact | 🟠 Medium | ✅ Detectable |

**Detectability classification:**
- **✅ Detectable:** Techniques generate observable events in Sentinel data sources. KQL detection rules can be written and deployed.
- **⬜ Inherent blind spot:** Attacker activity occurs *outside* the monitored environment. No KQL detection rules can realistically be created. **Do not recommend deploying rules for inherent blind spot tactics.**

### Sentinel-Specific MITRE Mapping Notes

- **Sentinel uses PascalCase** for tactic names in the REST API: `InitialAccess`, `CommandAndControl`. The ATT&CK STIX data uses kebab-case. The reference JSON maps between these.
- **Sub-techniques (T1xxx.xxx)** are tracked by Sentinel but coverage is measured at the parent technique level.
- **ICS/OT techniques (T0xxx)** use a separate numbering scheme and are reported separately.
- **Custom Detection `mitreTechniques`** uses the same technique ID format but may specify sub-techniques that analytic rules don't.

### Tactic-Specific Detection Guidance

When rendering recommendations (§6), use these cloud/identity-relevant technique priorities:

| Tactic | Key Sentinel-Detectable Techniques | Priority |
|--------|------------------------------------|----------|
| InitialAccess | T1078 (Valid Accounts), T1566 (Phishing), T1133 (External Remote Services) | 🔴 Must-have |
| Persistence | T1098 (Account Manipulation), T1136 (Create Account), T1078 (Valid Accounts) | 🔴 Must-have |
| CredentialAccess | T1110 (Brute Force), T1528 (Steal App Access Token), T1621 (MFA Request Gen) | 🔴 Must-have |
| PrivilegeEscalation | T1484 (Domain/Tenant Policy Mod), T1078 (Valid Accounts), T1098 (Account Manipulation) | 🔴 Must-have |
| DefenseEvasion | T1078 (Valid Accounts), T1484 (Domain/Tenant Policy Mod), T1562 (Impair Defenses) | 🟠 Important |
| Exfiltration | T1567 (Exfil Over Web Service), T1537 (Transfer to Cloud Account) | 🟠 Important |
| Collection | T1114 (Email Collection), T1213 (Data from Info Repos) | 🟠 Important |

### SOC Optimization Threat Scenario Reference

| Scenario | Key Attack Pattern | Priority Tactics |
|----------|--------------------|-----------------|
| AiTM (Adversary in the Middle) | Session token theft, AiTM phishing | InitialAccess, CredentialAccess |
| BEC (Financial Fraud) | Email account takeover for wire fraud | InitialAccess, CredentialAccess, Persistence |
| BEC (Mass Credential Harvest) | Large-scale phishing campaigns | InitialAccess, CredentialAccess, DefenseEvasion |
| Human Operated Ransomware | Post-compromise hands-on keyboard | LateralMovement, CredentialAccess, DefenseEvasion, Impact |
| Credential Exploitation | Credential stuffing, password spray | InitialAccess, CredentialAccess, Discovery |
| IaaS Resource Theft | Cloud compute hijacking (crypto mining) | CredentialAccess, Persistence, Impact |
| Network Infiltration | Traditional network-based attacks | Discovery, LateralMovement, C2 |
| X-Cloud Attacks | Cross-cloud lateral movement | CredentialAccess, PrivilegeEscalation, Persistence |
| ERP (SAP) | SAP financial process manipulation | InitialAccess, DefenseEvasion |

### SOC Optimization Recommendation States

| State | Meaning | Report Treatment |
|-------|---------|-----------------|
| `Active` | Recommendation is open and actionable | Show as gap |
| `InProgress` | User has started addressing | Show as in-progress |
| `CompletedBySystem` | Microsoft's automated assessment found coverage adequate | Use rate-based badge |
| `Completed` / `CompletedByUser` | User manually marked as complete | Apply Rule E gate |

---

## SVG Dashboard Generation

After the report is generated, the user may request an SVG dashboard visualization.

**Trigger:** "generate SVG dashboard", "visualize this report", "SVG from the MITRE report"

**Workflow:**
1. Load the `svg-dashboard` skill
2. Use the rendered report + scratchpad data to build visualization widgets
3. Recommended widget types for MITRE coverage:
   - **Score card** — MITRE Coverage Score with 5 dimension breakdown
   - **Bar chart** — Per-tactic coverage percentages (14 bars)
   - **Donut chart** — Rule inventory breakdown (AR/CD, enabled/disabled, untagged)
   - **Table** — Top 5 coverage gaps
   - **KPI cards** — Total techniques covered, SOC scenarios met, untagged rules

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Phase 3 KQL queries fail (token expired) | Re-authenticate: `az login --tenant <tenant_id> --scope https://api.loganalytics.io/.default` |
| Custom Detections SKIPPED | Normal if Graph API admin consent not granted. Report proceeds with AR-only analysis |
| SOC Optimization returns 0 recs | Workspace may not have SOC Optimization enabled |
| Breadth score seems low (10-20%) | Typical — 216+ techniques. Focus on threat-scenario-aligned priorities |
| ICS techniques appear | Normal if Defender for IoT rules are deployed. Reported separately |
| `az rest` returns 403 | Check RBAC: user needs **Microsoft Sentinel Reader** on the workspace |
| "Sentinel MCP not available" | Expected — this skill uses `az` CLI, not MCP. All queries are executed via `az rest` and `az monitor` |
| `az rest` returns 403 **after** role assignment | MI token caching (up to 24h). **Switch to Mode B (prefetch)**. The `RunAzCliReadCommands` tool sees new permissions immediately — collect data via native tools, save to `tmp/mitre-prefetch/`, run script with `--prefetch-dir`. `az account clear && az login --identity` does NOT help |
| `ResourceNotFound` on workspace | Wrong Resource Group. The workspace RG often differs from the agent RG. Verify via: `az graph query -q "Resources \| where name =~ '<ws>' \| project resourceGroup"` |
| `TypeError: '<' not supported between NoneType and str` | SOC Optimization returned a record with `useCaseName: null`. Fix: change `r.get('useCaseName', '')` to `r.get('useCaseName') or ''` in `invoke_mitre_scan.py` line ~666. This handles both missing key and `None` value |
| DataReadiness = 0% (all rules show no query) | M1 prefetch is missing the `query` field. Re-fetch M1 with `query:properties.query` in the JMESPath projection and re-run post-processing |
| Score = 10.0 with all phases FAILED | All queries returned errors — usually wrong RG or missing RBAC. Check RG first, then permissions |
