---
name: threat-pulse
description: >
  Recommended starting point for new users and daily SOC operations. 15-minute broad security
  scan across 7 domains (incidents, identity, NHI, endpoint, email, admin/cloud, exposure)
  producing a Threat Pulse Dashboard with drill-down recommendations to specialized skills.
  Trigger on getting-started questions like "where do I start", "what can you do",
  "help me investigate", "threat pulse", "run a scan", "security overview".
  This skill operates without Sentinel Data Lake MCP, Advanced Hunting MCP, or Microsoft Graph MCP
  (these cannot currently be connected to Azure SRE Agent; direct API access not yet implemented).
  Queries run against Log Analytics via Azure Monitor MCP; AH-only queries (Q11, Q12) are
  presented to the user for copy/paste execution.
---

# Threat Pulse — Instructions

## Purpose

The Threat Pulse skill is a rapid, broad-spectrum security scan designed for the "if you only had 15 minutes" scenario. It executes 12 queries across 7 security domains, producing a prioritized dashboard of findings with drill-down recommendations to specialized investigation skills.

**What this skill covers:**

| Domain | Key Questions Answered |
|--------|----------------------|
| 🔴 **Incidents** | What incidents are open and unresolved? Severity, age, ownership, MITRE tactics. What was recently resolved — TP rate, severity distribution? |
| 🔐 **Identity (Human)** | Which users have the highest Defender XDR Risk Score? Which are flagged by Identity Protection? What risk events are driving the signals? Password spray / brute-force patterns? |
| 🤖 **Identity (NonHuman)** | Which service principals expanded their resource/IP/location footprint? |
| 💻 **Endpoint** | Which endpoints deviated most from their process behavioral baseline? What singleton process chains exist? |
| 📧 **Email Threats** | Phishing/spam/malware breakdown. Were any phishing emails delivered? |
| 🔑 **Admin & Cloud Ops** | Mailbox rules, OAuth consents, transport rules, mailbox permission changes. MCAS-flagged compromised sign-ins. Human-initiated CA policy changes. High-impact admin operations. |
| 🛡️ **Exposure** | Critical assets internet-facing with RCE? Exploitable CVEs (CVSS ≥ 8) across the fleet? |

**Data sources:** `SecurityIncident`, `SecurityAlert`, `IdentityInfo`, `AADUserRiskEvents`, `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceInfo`, `ExposureGraphNodes`, `AADServicePrincipalSignInLogs`, `EmailEvents`, `CloudAppEvents`, `AuditLogs`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`

**Portal URL patterns** are defined in the [Defender XDR Portal Links](#defender-xdr-portal-links--all-entity-types) table. Append `tid=<tenant_id>` (from `config.json` or agent settings) to ALL `security.microsoft.com` URLs.

## Companion Files

| File | Purpose | When Used |
|------|---------|-----------|
| [threat-pulse-queries.md](threat-pulse-queries.md) | All 12 pre-validated KQL queries with execution notes, verdict logic, and pitfall warnings | Phase 1–2 (query execution) |
| [generate_html_report.py](generate_html_report.py) | HTML report generator from threat-pulse markdown report | Post-report (on explicit request) |
| [svg-widgets.yaml](svg-widgets.yaml) | SVG dashboard widget manifest for visualization | Post-report (optional) |

> ⚠️ **Runtime Location = "Must be on disk"** means the file must exist on the local filesystem. Scripts are accessed at runtime — NOT via `read_skill_file`. They are resolved **immediately on skill activation** via the [File Resolution cascade](#file-resolution-coderefs-first--on-skill-activation).

---

## File Resolution (codeRefs-first — On Skill Activation)

`generate_html_report.py` runs from the local filesystem. Skill files must be resolved to disk before use.

🔴 **MANDATORY — IMMEDIATE:** The moment this skill is activated (i.e., the agent reads this SKILL.md), the agent MUST resolve ALL files listed below **before doing anything else** — before collecting parameters, before asking the user questions, before any other action.

### Resolution Cascade

Resolve ALL 3 runtime files using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/threat-pulse/
   → If ALL 3 files exist here: use this directory as <SKILL_DIR>
   → Execute/read files directly from here (companion files are co-located)
   → Do NOT copy files to tmp/

2. tmp/threat-pulse/
   → If ALL 3 files exist here (from previous materialization): use this directory as <SKILL_DIR>

3. Neither location has all files:
   → read_skill_file() from Builder for each missing file
   → CreateFile("tmp/threat-pulse/<filename>", <content>)
   → Use tmp/threat-pulse/ as <SKILL_DIR>
```

All subsequent commands in this skill reference the resolved directory as `<SKILL_DIR>`.

### Files to Resolve

| File | Required By | Format |
|------|-------------|--------|
| `generate_html_report.py` | HTML report generation | Python |
| `threat-pulse-queries.md` | Phase 1–2 query reference | Markdown |
| `svg-widgets.yaml` | SVG dashboard generation | YAML |

### Step 1: Check codeRefs

```bash
ls codeRefs/sec-sre-ag/threat-pulse/generate_html_report.py codeRefs/sec-sre-ag/threat-pulse/threat-pulse-queries.md codeRefs/sec-sre-ag/threat-pulse/svg-widgets.yaml 2>/dev/null | wc -l
# If returns 3 → set <SKILL_DIR>=codeRefs/sec-sre-ag/threat-pulse → DONE
```

### Step 2: Check tmp (if codeRefs not found)

```bash
ls tmp/threat-pulse/generate_html_report.py tmp/threat-pulse/threat-pulse-queries.md tmp/threat-pulse/svg-widgets.yaml 2>/dev/null | wc -l
# If returns 3 → set <SKILL_DIR>=tmp/threat-pulse → DONE
```

### Step 3: Materialize from Builder (if neither location has all files)

🔴 **CRITICAL: Write FULL file content. NEVER write placeholders or stubs.**

**Step 3a — Read ALL 3 files in a single parallel batch:**
```
read_skill_file(skill_name="threat-pulse", file_path="generate_html_report.py")
read_skill_file(skill_name="threat-pulse", file_path="threat-pulse-queries.md")
read_skill_file(skill_name="threat-pulse", file_path="svg-widgets.yaml")
```

**Step 3b — Write ALL 3 files in a single parallel batch:**
```
CreateFile(filePath="tmp/threat-pulse/generate_html_report.py", content=<FULL content>)
CreateFile(filePath="tmp/threat-pulse/threat-pulse-queries.md", content=<FULL content>)
CreateFile(filePath="tmp/threat-pulse/svg-widgets.yaml", content=<FULL content>)
```

**Total: 2 tool calls (read batch + write batch).** Do NOT split into more batches.
Set `<SKILL_DIR>=tmp/threat-pulse`.

🔴 **PROHIBITED:** Proceeding to Phase 0 without completed file resolution.

---

## Execution Environment Constraints

> **⚠️ READ FIRST — This skill operates in a constrained environment.**

| Capability | Available | Notes |
|------------|-----------|-------|
| **Azure Monitor MCP** (`monitor-client_monitor_workspace_log_query`) | ✅ YES | Execute KQL against Log Analytics workspace tables |
| **KQL Search MCP** (`mcp_kql-search-mc_*`) | ✅ YES | Schema validation, table discovery, query examples |
| **Microsoft Learn MCP** (`mcp_microsoft_lea_*` / `mcp_microsoft_le2_*`) | ✅ YES | Official documentation and code samples |
| **Azure MCP Server** (`mcp_azure_mcp_ser_*`) | ✅ YES | Azure resource management |
| **`RunAzCliReadCommands` tool** | ⚠️ MAYBE | Graph API calls via `az rest`. If unavailable, KQL fallback for user OID/device ID |
| **Sentinel Data Lake** (`mcp_microsoft_se2_*`) | ❌ NO | Not integrated — cannot currently be connected to Azure SRE Agent. Data reachable via direct API (not yet implemented). |
| **Advanced Hunting / Triage MCP** (`mcp_mtp_mcp_servi_*`) | ❌ NO | Not integrated — cannot currently be connected to Azure SRE Agent. Data reachable via direct API (not yet implemented). |
| **Microsoft Graph MCP** (`mcp_microsoft_ent_*`) | ❌ NO | Not integrated — cannot currently be connected to Azure SRE Agent. Data reachable via direct API (not yet implemented). |

### Execution Model (Two-Tier)

| Tier | Queries | How to Execute | Tables |
|------|---------|----------------|--------|
| **Tier 1 — Direct LA** | Q1–Q10 | `monitor-client_monitor_workspace_log_query` | All LA-native or XDR-synced tables |
| **Tier 2 — AH Copy/Paste** | Q11, Q12 | Present query to user → user runs in [Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting) → pastes results back | `ExposureGraphNodes`, `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB` |

**⛔ MANDATORY:** All KQL queries are pre-validated in [threat-pulse-queries.md](threat-pulse-queries.md). Do NOT write ad-hoc KQL — read the query from the file and execute it as-is with parameter substitution only.

### Key Adaptations from AH to LA

| AH Column/Table | LA Equivalent | Notes |
|-----------------|---------------|-------|
| `Timestamp` on XDR tables | `TimeGenerated` | Device*, Email*, Cloud*, Identity* tables |
| `EntraIdSignInEvents` | `union SigninLogs, AADNonInteractiveUserSignInLogs` | Column mapping: `AccountUpn`→`UserPrincipalName`, `ErrorCode`(int)→`ResultType`(string), `Application`→`AppDisplayName`, `Country`→`parse_json(LocationDetails).countryOrRegion` |
| `AADUserRiskEvents.TimeGenerated` | `AADUserRiskEvents.ActivityDateTime` | `TimeGenerated` is ingestion time; `ActivityDateTime` is event time |
| `AADUserRiskEvents.IPAddress` | `AADUserRiskEvents.IpAddress` | Lowercase `p` in LA |

---

## 📑 TABLE OF CONTENTS

1. **[File Resolution](#file-resolution-coderefs-first--on-skill-activation)** — Script & file resolution (codeRefs → tmp → Builder)
2. **[Critical Workflow Rules](#-critical-workflow-rules---read-first-)**
3. **[Execution Workflow](#execution-workflow)** — Phase 0–3
4. **[Phase 4: Interactive Follow-Up Loop](#phase-4-interactive-follow-up-loop)**
5. **[Take Action](#-take-action--portal-ready-remediation-blocks)** — Portal links, AH queries, defanging
6. **[Post-Processing](#post-processing)** — Drift scores, cross-query correlation
7. **[Report Template](#report-template)**
8. **[Known Pitfalls](#known-pitfalls)**
9. **[Quality Checklist](#quality-checklist)**
10. **[HTML Report Generation](#html-report-generation)** — On-demand HTML export
11. **[SVG Dashboard Generation](#svg-dashboard-generation)**

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Workspace discovery** — Read workspace parameters from agent settings (`<log_analytics_access>`, `<azure_resource_access>`) or `config.json`. Never prompt the user for workspace parameters if either source is available.

2. **Read `config.json`** — Load workspace ID, tenant, subscription, and Azure MCP parameters before execution. If absent, rely on agent settings.

3. **Output defaults** — Default to **inline chat** with **7d lookback**. **NEVER ask** the user for output format or preferences. Every execution renders ALL results inline. If the user explicitly requests a file (`"genera HTML"`, `"save as markdown"`, `"scarica MD"`, etc.), generate the requested format **in addition to** inline output. If the user just says "threat pulse", "run a scan", or similar — proceed immediately with defaults.

4. **⛔ MANDATORY: Evidence-based analysis only** — Every finding must cite query results. Every "clear" verdict must cite 0 results.

5. **Parallel execution** — Run all 10 Tier 1 queries in parallel via Azure Monitor MCP. Present the 2 Tier 2 queries to the user simultaneously.

6. **Cross-query correlation** — After all queries complete, check for correlated findings per the [Cross-Query Correlation](#cross-query-correlation) table. Escalate priority when patterns match.

7. **SecurityIncident output rule** — Every incident MUST include a clickable Defender XDR portal URL: `https://security.microsoft.com/incidents/{ProviderIncidentId}?tid=<tenant_id>`.

8. **⛔ MANDATORY: Drill-Down Recommendations (tiered)** — After rendering the main report, append drill-down recommendations. Skip only when ALL verdicts are ✅.

| Highest Verdict | Skills | Report Section |
|----------------|--------|----------------|
| 🔴 or 🟠 | All matching skills + entity-specific prompts | `📂 Recommended Drill-Downs` |
| 🟡 (no 🔴/🟠) | Up to 3 posture skills | `📂 Proactive Hunting Suggestions` |
| All ✅ | Skip | Omit entirely |

9. **⛔ MANDATORY: 30d drill-down lookback** — ALL Phase 4 drill-down queries use **30d** lookback, regardless of the Threat Pulse scan window. Entity-scoped queries have negligible performance difference between 7d and 30d. Substitute `ago(7d)` → `ago(30d)` in all drill-down queries.

10. **⛔ MANDATORY: The follow-up loop is stateful, memory-backed, and self-sustaining.** Three invariants:
    - **(a) Memory is the source of truth.** The prompt pool lives ONLY in `/memories/session/threat-pulse-drilldowns.md`. Create it the first time the pool is built. NEVER reconstruct from conversation history — always `memory view` before each `vscode_askQuestions` call.
    - **(b) The loop re-presents itself automatically.** After EVERY completed drill-down, return to Phase 4 step 2 and call `vscode_askQuestions` again with the updated pool. The only exits are `Skip` or an empty pool.
    - **(c) Quick Pick Call Contract is mechanical.** Run the [Pre-Flight Checklist](#-pre-flight-checklist) and print the Pool Receipt before every call.

11. **⛔ MANDATORY: Read queries from file** — All 12 queries are in [threat-pulse-queries.md](threat-pulse-queries.md). `read_file` the query file BEFORE executing any queries. Do NOT write ad-hoc KQL or rely on memory.

12. **⛔ MANDATORY: Cache management** — Query results are saved to `output/threat-pulse/` during execution. Cache reuse follows strict rules:

    ```
    Cache Check Logic:

    1. If NO data files exist in output/threat-pulse/ → proceed with fresh data collection

    2. If data files exist, calculate their age:
       → age = current_UTC_time − file_modification_timestamp
       → If age > 4 hours → IGNORE cache entirely, proceed with fresh collection

    3. Analyze the user's ORIGINAL prompt for intent:

       REDO KEYWORDS (always re-collect, never ask):
         "ripeti", "aggiorna", "rifai", "repeat", "redo", "refresh",
         "update", "re-analyze", "start over", "da capo",
         "from scratch", "ricomincia", "nuovo", "nuova analisi"
       → If ANY redo keyword is detected → IGNORE cache, proceed with fresh collection

       REPORT-ONLY KEYWORDS (use cache if valid):
         "genera report", "generate report", "genera il report",
         "crea report", "genera HTML", "genera MD", "render",
         "mostra risultati", "show results"
       → If ANY report-only keyword AND cache age ≤ 4h:
         ASK the user:
           "Esistono risultati in cache generati <TIME_AGO> fa (alle <HH:MM> UTC).
            Vuoi usare quelli o rieseguire una nuova raccolta dati?"
           Options: "Usa la cache" / "Raccogli da zero"

       NO IMPLICIT INTENT (default = fresh collection):
       → Proceed with fresh data collection without asking
    ```

    **Key rules:**
    - **NEVER silently reuse cached data** — either detect explicit report-only intent + ask, or re-collect.
    - **Redo keywords bypass everything** — no cache check, no question, just re-collect.
    - **Default behavior is fresh collection** — cache reuse is the exception, not the rule.

13. **⛔ MANDATORY: No PowerShell scripts** — The execution environment does not have `pwsh` or PowerShell. All scripts MUST be Python. Do NOT generate `.ps1` scripts or use `Invoke-RestMethod`, `Invoke-WebRequest`, or other PowerShell cmdlets in any context.

---

## Execution Workflow

### Phase 0: Prerequisites

1. Read workspace parameters from agent settings or `config.json`
2. **Check cache** — Apply the cache check logic from Rule 12:
   - Check `output/threat-pulse/` for existing `tp_results_*.json` files
   - If files exist and age ≤ 4h: check user intent (redo keywords → re-collect; report-only keywords → ask; default → re-collect)
   - If cache is valid and user confirmed reuse: load results from JSON, skip to Phase 3
3. Read [threat-pulse-queries.md](threat-pulse-queries.md) to load all pre-validated KQL queries
4. Use defaults (inline chat, 7d) unless user specified otherwise
5. **⛔ MANDATORY: Display scan summary** before executing any queries:

   🔍 Threat Pulse — Scan Plan

   Workspace: \<WorkspaceName\> (\<WorkspaceId\>)
   Lookback: \<N\>d

   Executing 12 queries across 7 domains:

   🔴 Incidents — Open incidents + 7d closed summary (Q1, Q2)
   🔐 Identity — Identity risk posture, risk event enrichment, auth spray (Q3, Q4)
   🤖 NonHuman ID — Service principal behavioral drift (Q5)
   💻 Endpoint — Device process drift, rare process chains (Q6, Q7)
   📧 Email — Inbound threat snapshot (Q8)
   🔑 Admin & Cloud — Cloud app ops, privileged operations (Q9, Q10)
   🛡️ Exposure — Critical assets, exploitable CVEs (Q11, Q12)

   Direct execution: 10 queries via Log Analytics (parallel)
   User-assisted: 2 queries via Advanced Hunting (Q11, Q12)
   Estimated time: ~3–5 minutes

### Phase 1: Execute Tier 1 Queries (Q1–Q10) — Parallel

**Run all 10 queries in parallel via Azure Monitor MCP (`monitor-client_monitor_workspace_log_query`).**

| Query | Domain | Purpose | Table(s) |
|-------|--------|---------|----------|
| Q1 | 🔴 Incidents | Open incidents (severity-ranked backfill) with MITRE | `SecurityIncident`, `SecurityAlert` |
| Q2 | 🔴 Incidents | 7-day closed incident summary | `SecurityIncident`, `SecurityAlert` |
| Q3 | 🔐 Identity (Human) | Identity risk posture + risk event enrichment | `IdentityInfo`, `AADUserRiskEvents` |
| Q4 | 🔐 Identity (Human) | Password spray / brute-force detection | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `DeviceLogonEvents` |
| Q5 | 🤖 Identity (NonHuman) | Service principal behavioral drift (90d vs 7d) | `AADServicePrincipalSignInLogs` |
| Q6 | 💻 Endpoint | Fleet device process drift (7d baseline vs 1d) | `DeviceProcessEvents`, `DeviceInfo` |
| Q7 | 💻 Endpoint | Rare process chain singletons (30d) | `DeviceProcessEvents` |
| Q8 | 📧 Email | Inbound email threat snapshot | `EmailEvents` |
| Q9 | 🔑 Admin & Cloud Ops | Cloud app suspicious activity | `CloudAppEvents` |
| Q10 | 🔑 Admin & Cloud Ops | High-impact admin operations | `AuditLogs` |

**For Q5 (SPN Drift):** Set the `hours` parameter to at least `2328` (97 days × 24 hours) to cover the 97-day lookback.

### Phase 2: Present Tier 2 Queries (Q11, Q12) — User-Assisted

**While Tier 1 executes, present Q11 and Q12 to the user for execution in Advanced Hunting.**

1. Read Q11 and Q12 from [threat-pulse-queries.md](threat-pulse-queries.md)
2. Replace `<TENANT_ID>` with actual tenant ID from config
3. Present both queries in separate code blocks with clear instructions:
   - "Copy this query and run it in [Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting?tid=<tenant_id>)"
   - "Paste the results back here when complete"
4. If Q11 has a partial LA fallback (internet-facing devices without ExposureGraph), execute that in parallel as Q11-partial
5. If the user declines or cannot run AH queries, mark Q11/Q12 as ❓ No Data and proceed

### Phase 3: Post-Processing & Report

0. **Save query results to cache** — Aggregate all Q1–Q12 results into `output/threat-pulse/tp_results_<YYYYMMDD_HHMMSS>.json` as a JSON object with keys: `scan_timestamp` (ISO8601), `workspace_id`, `workspace_name`, `lookback_days`, and `queries` (dict of Q1–Q12, each with `status` = ok/error/no_data, `row_count`, and `results` array). Use `encoding="utf-8"` and `ensure_ascii=False`. Create the `output/threat-pulse/` directory if it doesn't exist.
1. Interpret device drift scores from Q6 results (see [Post-Processing](#post-processing))
2. Run cross-query correlation checks (see rule 6)
3. Assign verdicts to each domain (🔴 Escalate / 🟠 Investigate / 🟡 Monitor / ✅ Clear)
4. Generate prioritized recommendations with drill-down skill references
5. **Render the report immediately inline** — Dashboard Summary, Detailed Findings, Cross-Query Correlations, and 🎯 Recommended Actions
6. **After the report is rendered**, append the `📂 Recommended Drill-Downs` section. Skip when all verdicts are ✅.
7. **File output (only if explicitly requested):**
   - **Markdown:** Save the rendered report to `reports/threat-pulse/Threat_Pulse_<YYYYMMDD_HHMMSS>.md`
   - **HTML:** First save as markdown (step above), then run: `python3 tmp/threat-pulse/generate_html_report.py "reports/threat-pulse/Threat_Pulse_<ts>.md" --output-dir reports/threat-pulse/`

---

## Phase 4: Interactive Follow-Up Loop

**After rendering the report, present the user with a selectable list of follow-up actions.** Runs when at least one 🔴, 🟠, or 🟡 verdict exists (skip only when ALL are ✅).

**This is a loop, not a one-shot.** After each action completes, re-present the selection list with the updated pool.

> **⛔ Loop invariant — verify before EVERY iteration (per Rule 10):** (a) `/memories/session/threat-pulse-drilldowns.md` exists and was just re-read; (b) re-presenting menu automatically after prior drill-down; (c) Pre-Flight Checklist passed and Pool Receipt printed.

**Prompt types (three categories, one unified list):**

| Type | Icon | Source | Example |
|------|------|--------|---------|
| **Skill investigation** | 🔍 | Per-query drill-down + entities from findings | `🔍 Investigate user jsmith@contoso.com` → `user-investigation` |
| **KQL hunt** | 📄 | KQL query authoring with context | `📄 Hunt for RDP lateral movement from 10.0.0.50` → `kql-query-authoring` |
| **IOC lookup** | 🎯 | Suspicious IPs, domains, hashes from findings | `🎯 Enrich and investigate IP 203.0.113.42` → `ioc-investigation` |

**Skill matching rules — derive from findings:**

| Query | Trigger | Target Skill | Prompt |
|:-----:|---------|--------------|--------|
| Q1 | Incident surfaced | `kql-query-authoring` | `Investigate incident <ProviderIncidentId> — deep dive on alerts and entities` |
| Q3–Q4 | Username/UPN in findings | `user-investigation` | `Investigate <UPN>` |
| Q3 | 3+ risky users, or any ConfirmedCompromised | `identity-posture` | `Run identity posture report` |
| Q4 | Spray source IP | `ioc-investigation` | `Investigate IP <address>` |
| Q5 | SPN with drift | `kql-query-authoring` | `Deep dive SPN drift analysis for <SPN>` |
| Q6 | Device with DriftScore > 130 | `computer-investigation` | `Investigate device <hostname>` |
| Q6–Q7 | Device in findings | `computer-investigation` | `Investigate device <hostname>` |
| Q8 | Phishing delivered or malware detected | `kql-query-authoring` | `Investigate delivered phishing emails — recipients, subjects, sender domains` |
| Q8+Q3 | Phishing recipient in Q3 risky users | `user-investigation` | `Investigate <UPN> — phishing target and identity risk` |
| Q9 | Compromised Sign-In user | `user-investigation` | `Investigate <UPN>` |
| Q9 | Exchange rule change actors | `user-investigation` | `Investigate <UPN>` |
| Q10 | MFA-Registration user | `user-investigation` | `Investigate <UPN>` |
| Q10 | RoleManagement Global/Security Admin or bulk Password resets | `identity-posture` | `Run identity posture report` |
| Q10 | 3+ categories with same actor | `user-investigation` | `Investigate <UPN>` |
| Q11 | Any `IsVerifiedExposed == true` | `computer-investigation` | `Investigate device <hostname>` |
| Q11–Q12 | Device in findings | `computer-investigation` | `Investigate device <hostname>` |

> **Skills not available in this environment** (e.g., `scope-drift-detection`, `email-threat-posture`, `authentication-tracing`, `ca-policy-investigation`, `app-registration-posture`, `exposure-investigation`, `mitre-coverage-report`): Route to `kql-query-authoring` with specific context and entities. The agent will use KQL Search MCP for schema validation and generate targeted queries.

**Procedure:**
1. Build the **initial prompt pool** by combining:
   - Skill prompts: one per unique entity + matching skill from the table above
   - KQL hunt prompts: for domains where no specialized skill exists
   - IOC prompts: suspicious IPs/domains from non-✅ findings not covered by a skill prompt
   - Deduplicate: if skill prompt and IOC prompt target same entity, keep skill prompt
   - **⛔ Persist the pool.** Write to `/memories/session/threat-pulse-drilldowns.md` using the template below.

   ### Memory File Template

   ````markdown
   # Threat Pulse Session — <YYYY-MM-DD>

   **Workspace:** <name> (<id>)
   **Lookback:** <7d|30d|90d>
   **Scan Start:** <YYYY-MM-DD HH:MM UTC>

   ## Active Prompt Pool

   <!-- FORMAT: `- <ICON> <action> <entity> — Q<N>: <finding> → <skill>` -->
   <!-- ` — ` (space-emdash-space) is the REQUIRED label/description split delimiter. -->

   - 🔍 Investigate incident #<IncidentId> — Q1: <brief finding>, <N> alerts → kql-query-authoring
   - 🎯 Enrich and investigate IP <IP> — Q4: <N> spray attempts / <N> users → ioc-investigation
   ...

   ## Pulse Key Findings (quick reference)

   ...

   ## Completed Drill-Downs

   _(none yet)_
   ````

2. **Call `vscode_askQuestions` using the Quick Pick Call Contract below.**

   ### Quick Pick Call Contract

   - `header`: `Follow-Up Investigation`
   - `question`: `Select one or more actions to launch (or skip):`
   - `options`: entity prompts (from memory), then `📋` (if truncated), then `💾 / 🔄 / Skip` as the final three.
     1. `💾 Save full investigation report` — *Save the complete Threat Pulse session as a markdown file*
     2. `🔄 Refresh prompt pool` — *Rebuild follow-up prompts from existing findings (does NOT re-run queries)*
     3. `Skip` — *No follow-up — investigation complete*
   - Allowed Label icons: `🔍 📄 🎯 💾 🆕 🔄 📋`. Verdict emoji (🔴🟠🟡🟢✅) banned from Labels.

   ### 🔴 Pre-Flight Checklist

   ```
   □ 1. memory view → read `## Active Prompt Pool` just now
   □ 2. Count entity prompts (exclude 💾/🔄/📋/Skip) = N
   □ 3. Format integrity: every line starts with `- ` + ONE icon
   □ 4. If N > 12: render top 12 + append `📋 Show full prompt pool (N items)`
   □ 5. Split memory line at FIRST ` — ` → label = before, description = after
   □ 6. Each option Label has exactly ONE icon; Description has at most ONE `→ target`
   □ 7. `multiSelect: true` in call args
   □ 8. ZERO `recommended` keys anywhere in options[]
   □ 9. Tail = 💾 / 🔄 / Skip (or 📋 / 💾 / 🔄 / Skip if truncated)
   □ 10. Print Pool Receipt line to chat BEFORE invoking
   ```

   **Pool Receipt:**
   ```
   📊 Pool: <N> total / rendering <R> (🆕×<a>, 🔍×<b>, 📄×<c>, 🎯×<d>) / truncated <✔|—> | multiSelect=true ✔ | recommended=0 ✔
   ```

3. If user selects **Skip** or pool is empty: end skill execution.
4. **Freeform input routing** — Match to known skills or use `kql-query-authoring` with context.
5. **💾 Save full investigation report:** Compile pulse + drill-downs into `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md`. Drop 💾 from subsequent iterations.
6. **🔄 Refresh prompt pool:** Rebuild prompts from pulse + drill-down findings. Deduplicate against completed prompts.
7. **Execute selected actions sequentially.** For each:
   - **🔍 Skill prompt:** `read_file` the child SKILL.md BEFORE writing ANY query. Use the skill's investigation shortcuts.
   - **📄 KQL hunt prompt:** Load `kql-query-authoring` skill, use KQL Search MCP for schema validation, execute targeted queries.
   - **🎯 IOC prompt:** Load `ioc-investigation` skill with the target indicator.

   After each drill-down, append to `/memories/session/threat-pulse-drilldowns.md` under `## Completed Drill-Downs`:
   ```
   ### <N>. <Prompt Label> (<skill-name>, <YYYY-MM-DD HH:MM>)
   - **Entity:** <target entity>
   - **Trigger:** Q<N> — <original finding>
   - **Key Findings:** <1–8 bullets, evidence-cited>
   - **Risk Assessment:** <emoji> <level> — <1-line justification>
   - **Cross-References:** <overlaps with other drill-downs or pulse queries>
   - **Recommendations:** <top 1–3 actions>
   ```

   **Before returning to step 2:**
   1. New Evidence Scan — review drill-down for entities/TTPs not in prior findings. Add 🆕 prompts only for meaningful leads.
   2. Reload → mutate → write back — `memory view` → delete completed line(s) → prepend 🆕 → `memory str_replace`.
   3. Return to step 2.

**Atomic options — ONE action per option.** Each maps to ONE skill + ONE entity.

### 🔍 Skill Drill-Down Execution Rule

**⛔ MANDATORY — applies to ALL `🔍` drill-down executions.**

1. `read_file` the child skill's SKILL.md
2. Match trigger context (TP Q number) against the skill's **Investigation shortcuts**
3. Execute the shortcut query chain — substitute only entity placeholders and date ranges
4. For quick triage: run only the shortcut chain. For deep investigation: run full skill workflow

| Action | Status |
|--------|--------|
| Writing ad-hoc KQL without loading the child SKILL.md | ❌ **PROHIBITED** |
| Loading SKILL.md then modifying its queries | ❌ **PROHIBITED** |
| Using SKILL.md queries verbatim with entity substitution | ✅ **REQUIRED** |

---

### 🎬 Take Action — Portal-Ready Remediation Blocks

> ⚠️ **AI-generated content may be incorrect. Always review Take Action queries and portal links for accuracy before executing remediation actions.**

After every non-✅ drill-down that surfaces actionable entities, append a **`🎬 Take Action`** section with **direct portal links** (single entities) or **Advanced Hunting queries** (bulk entities).

**Skip when:** verdict is ✅/🔵, or action already taken.

Every `🎬 Take Action` heading MUST be immediately followed by the AI-content warning blockquote above.

#### Single Entity vs Bulk Entity Decision Rule

| Scenario | Format |
|----------|--------|
| **1 entity** | Direct Defender XDR portal link (see Portal Links table) |
| **2+ emails** | AH query with `NetworkMessageId in (...)` |
| **2+ devices** | AH query with `DeviceName in~ (...)` |
| **2+ IPs/domains/hashes** | AH query → click value → Add Indicator |

**⛔ PROHIBITED:** Generating an AH query for a single entity when a portal link suffices.

**ID sources (agent retrieves silently — never ask the user):**
- **User OID:** `RunAzCliReadCommands` → `az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<UPN>?$select=id"`, or KQL fallback from `IdentityInfo.AccountObjectId`
- **MDE DeviceId:** `DeviceInfo` table via LA query (see [threat-pulse-queries.md](threat-pulse-queries.md) → MDE Device ID Lookup)

#### Required Columns per Entity Type

| Entity | Required Columns | Actions | Notes |
|--------|-----------------|---------|-------|
| **📧 Email** | `NetworkMessageId`, `RecipientEmailAddress` | Soft/hard delete, submit to Microsoft | **Do NOT use `project`** — strips undocumented columns |
| **💻 Device** | `DeviceId` | Isolate, collect investigation package, AV scan | Use `summarize arg_max(TimeGenerated, *) by DeviceId` |
| **📁 File** | `SHA1` or `SHA256` + `DeviceId` | Quarantine file | Both hash and device required |
| **🔗 Indicator** | IP, URL/domain, or SHA hash | Add indicator: allow, warn, block | Click value in AH results → Add indicator |
| **🔐 Identity** | *(No AH Take Action)* | Confirm compromised, revoke sessions | Direct Defender XDR Identity page link |

#### Template Queries (for bulk remediation — present to user for AH execution)

**📧 Email — by NetworkMessageId:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where NetworkMessageId in ("<id1>", "<id2>")
```

**💻 Bulk Devices (2+):**
```kql
DeviceInfo
| where Timestamp > ago(1d)
| where DeviceName in~ ("<device1>", "<device2>")
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform, MachineGroup
```

**📁 File — by hash:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where SHA1 == "<hash>" or SHA256 == "<hash>"
| project DeviceId, DeviceName, SHA1, SHA256, FileName, FolderPath
```

**🔗 Bulk Indicators (network-layer IPs):**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("<ip1>", "<ip2>", "<ip3>")
| summarize Connections = count(), Ports = make_set(LocalPort) by RemoteIP
| order by Connections desc
```

**🔗 Auth-layer IPs (from SigninLogs):**
```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where IPAddress in ("<ip1>", "<ip2>", "<ip3>")
| summarize SignIns = count(), Users = dcount(UserPrincipalName), Countries = make_set(tostring(parse_json(LocationDetails).countryOrRegion), 5) by IPAddress
| order by SignIns desc
```

> **Note:** Take Action template queries use `Timestamp` (AH syntax) because the user executes them in Advanced Hunting. LA-executed queries use `TimeGenerated`.

#### Defender XDR Portal Links — All Entity Types

**🔴 Every entity in action/recommendation tables MUST be a clickable portal link.**

| Entity | URL Pattern | Example |
|--------|------------|---------|
| **User** | `https://security.microsoft.com/user?aad=<OID>&upn=<UPN>&tab=overview&tid=<tenant_id>` | `[user@contoso.com](https://security.microsoft.com/user?aad=<OID>&upn=user@contoso.com&tab=overview&tid=<tenant_id>)` |
| **Domain** | `https://security.microsoft.com/domains/overview?urlDomain=<domain>&tid=<tenant_id>` | `[contoso.com](...)`|
| **URL** | `https://security.microsoft.com/url/overview?url=<url-encoded>&tid=<tenant_id>` | `[example.com/path](...)`|
| **IP** | `https://security.microsoft.com/ip/<IP>/overview?tid=<tenant_id>` | `[<IP>](...)`|
| **File Hash** | `https://security.microsoft.com/file/<SHA>/?tid=<tenant_id>` | `[<hash>](...)`|
| **Device** | `https://security.microsoft.com/machines/v2/<MDE_DeviceId>?tid=<tenant_id>` | `[<DeviceName>](...)`|
| **SPN** | `https://security.microsoft.com/identity-inventory?tab=NonHumanIdentities&tid=<tenant_id>` | `[NHI Inventory](...)`|

**User fallbacks:** `?upn=<UPN>` when ObjectId unavailable; `?sid=<SID>&accountName=<Name>&accountDomain=<Domain>` for on-prem AD.

**🔴 Portal URL Allowlist — No Invented Paths.** The 7 patterns above plus `/v2/advanced-hunting?tid=<tenant_id>` are the ONLY `security.microsoft.com` URLs you may emit.

#### Entity Display — Portal Link vs Defang (Mutually Exclusive)

| Context | Treatment |
|---------|-----------|
| **Action / recommendation tables** | Portal link (from table above). Never defang. |
| **Data / results tables** | Defang as plain text. Never portal-link. |

Defang rules: `http://` → `hxxp://`, `https://` → `hxxps://`, `.` in domain → `[.]`.

---

## Post-Processing

### Device Drift Score Interpretation (Q6)

Q6 returns pre-computed drift scores — **no LLM-side math needed**. Apply verdicts using this scale:

| DriftScore | Interpretation | Verdict |
|------------|---------------|---------|
| < 80 | Contracting activity | 🔵 Informational |
| 80–110 | Stable steady-state | ✅ Clear |
| 110–130 | Minor behavioral expansion | 🟡 Monitor |
| 130–180 | Significant deviation | 🟠 Investigate |
| 180+ | Major anomaly | 🔴 Escalate |

**VolDrift cap context:**
- `VolDriftRaw` ≫ 300 but ProcDrift/ChainDrift/AcctDrift near 100 → infrastructure noise
- `VolDriftRaw` > 300 AND diversity metrics elevated → genuine anomaly
- `VolDriftRaw` ≤ 300 → cap not triggered, score reflects true proportions

**Fleet-uniformity rule:** If ALL top-10 devices cluster within 20 points, downgrade verdict one level.

**⛔ DO NOT manually recompute drift scores.** Trust the returned `DriftScore` column.

### Cross-Query Correlation

After all queries complete, check these patterns and escalate when found:

| Pattern | Queries | Implication | Action |
|---------|---------|-------------|--------|
| Incident account matches risky identity | Q1 `Accounts` ∩ Q3 `AccountUpn` | Corroborated signal | Escalate to 🔴 |
| Incident device matches drifting endpoint | Q1 `Devices` ∩ Q6 `DeviceName` | Behavioral anomalies on incident device | Escalate to 🔴 |
| Incident device has exploitable CVE | Q1 `Devices` ∩ Q12 `DeviceName` | Vulnerable device in incident | Escalate to 🔴 |
| Spray target already in incident | Q4 targets ∩ Q1 `Accounts` | Spray target in active incident | Escalate to 🔴 |
| SPN drift AND unusual credential/consent | Q5 + Q10 | App credential abuse | Escalate to 🔴 |
| Device with rare process chain AND CVE | Q7 + Q12 | Potential active exploitation | Escalate to 🔴 |
| Spray IP target already flagged as risky | Q4 + Q3 | Spray target has Identity Protection risk | Escalate to 🔴 |
| Closed TP tactics match active findings | Q2 + Q3/Q7/Q8 | Same attack pattern recurring | Escalate to 🟠 |
| Mailbox rule manipulation AND email threats | Q9 + Q8 | Email exfiltration setup after phishing | Escalate to 🔴 |
| Compromised Sign-In matches risky identity | Q9 `Compromised Sign-In` ∩ Q3 `AccountUpn` | Dual-signal corroboration | Escalate to 🔴 |
| Compromised Sign-In user in open incident | Q9 `Compromised Sign-In` ∩ Q1 `Accounts` | MCAS + incident overlap | Escalate to 🔴 |
| MFA registration from spray target | Q10 `MFA-Registration` ∩ Q4 spray targets | T1556.006 credential takeover | Escalate to 🔴 |
| MFA registration from risky user | Q10 `MFA-Registration` ∩ Q3 `AccountUpn` | Potential credential takeover | Escalate to 🔴 |
| App registration + SPN drift | Q10 `AppRegistration` ∩ Q5 SPN drift | T1098.001 app-based persistence | Escalate to 🔴 |
| CA policy change + spray/compromise | Q9 CA Change + Q4 or Q9 Compromised | Defense weakened during attack | Escalate to 🔴 |
| Phishing recipient is risky user | Q8 delivered ∩ Q3 `AccountUpn` | AiTM chain indicator | Escalate to 🔴 |
| Role management + SPN drift by same actor | Q10 `RoleManagement` ∩ Q5 SPN drift | App-based persistence (T1098) | Escalate to 🔴 |

---

## Report Template

**Output modes:**
- **Inline chat** (default) — render in chat. Truncate data tables to 10 rows.
- **Markdown file** — triggered by `💾 Save`. Full data tables. Path: `reports/threat-pulse/Threat_Pulse_YYYYMMDD_HHMMSS.md`.

**Verdicts:** 🔴 Escalate | 🟠 Investigate | 🟡 Monitor | ✅ Clear | 🔵 Informational | ❓ No Data

- **❓ No Data** — query returned error, table not found, or user declined AH execution. Report the gap.
- **🔵 Informational** — neutral context (e.g., Q2 with 0 closures, Q6 with DriftScore < 80).
- **Zero results:** `✅ No <type> detected in the last <N>d. Checked: <table> (0 matches)`

### Structure

```markdown
# 🔍 Threat Pulse — <Workspace> | <Date>
**Workspace:** <name> (`<id>`)  
**Scan Date:** <YYYY-MM-DD HH:MM UTC>  
**Scan Duration:** <N>min | **Queries:** 12 | **Drill-Downs:** <N>  (file mode only)

## Executive Summary
<2–4 sentences synthesizing findings. State final risk posture.>

## Dashboard Summary
<12-row table (Q1–Q12) — columns: #, Domain, Status (verdict emoji), Key Finding (1-line).>

## Detailed Findings
<One section per query — EVERY query gets a section. Q2 always renders after Q1 even when Q1 is ✅.>

## Cross-Query Correlations
<Table per Post-Processing rules, or `✅ No correlations detected`.>

## 🎯 Recommended Actions
<Prioritized table: action, trigger query, drill-down skill.>

## 📂 Recommended Drill-Downs
<Numbered list with entity-specific prompts. For 🟡-only use "📂 Proactive Hunting Suggestions". Omit when all ✅.>

## Drill-Down Investigation Results       (file mode, when drill-downs executed)
### 1. <Title> — <Skill Name>
**Triggered by:** Q<N> — <finding>  
**Entity:** <target> | **Lookback:** <timerange> | **Risk:** <emoji> <level>
**Key Findings:** <max 8 evidence-cited bullets>
**Recommendations:** <numbered actions>

## Cross-Investigation Correlation        (file mode, when drill-downs executed)
| Connection | Evidence | Drill-Downs | Implication |

## Consolidated Recommendations           (file mode)
| Priority | Recommendation | Source | Risk |

## Appendix: Investigation Timeline       (file mode)
| Time | Action | Key Result |
```

### Column / Format Rules

- **Q1:** `| Incident | Sev | Title | Age | Alerts | Owner | Tactics | Accounts | Devices | Tags |`
  - When `TotalAll > 10`: prepend `**Showing 10 of {TotalAll} open incidents ({TotalHighCritical} High/Critical)**`
  - When `TitleDupCount > 1`: append `(+{TitleDupCount-1} more)` to Title cell
- **Q1 incidents** must include `[#<id>](https://security.microsoft.com/incidents/<ProviderIncidentId>?tid=<tenant_id>)` links.
- **Q2:** Classification breakdown + severity + MITRE. Always render even when Q1 is ✅.

### Rules

| Rule | Status |
|------|--------|
| Every query has a verdict row — no omissions | ✅ **REQUIRED** |
| Drill-down subsections are structured summaries with `Triggered by: Q<N>` | ✅ **REQUIRED** |
| Cross-Investigation Correlation explicitly states "none found" if empty | ✅ **REQUIRED** |
| Consolidated Recommendations deduplicated | ✅ **REQUIRED** |
| Fabricated data | ❌ **PROHIBITED** |

---

## Known Pitfalls

| Pitfall | Mitigation |
|---------|------------|
| **Timestamp vs TimeGenerated** | XDR tables in LA use `TimeGenerated`. Queries in [threat-pulse-queries.md](threat-pulse-queries.md) already use the correct column. Do NOT modify. |
| **AADUserRiskEvents time column** | Use `ActivityDateTime` (event time), NOT `TimeGenerated` (ingestion time). `IpAddress` lowercase `p`. |
| **EntraIdSignInEvents unavailable** | Q4 uses `SigninLogs` + `AADNonInteractiveUserSignInLogs` (LA equivalents). Column mapping applied. |
| **Q5 takes ~35s** (97d lookback) | Acceptable — runs in parallel with other queries |
| **Q7 capped at 30d** | Maximum LA/AH retention for this query pattern |
| **Q6 drift scores** | Computed in-query — do NOT recompute LLM-side |
| **Q11, Q12 require AH** | ExposureGraphNodes, DeviceTvm* are AH-only. Present to user for copy/paste. If declined → ❓ No Data |
| **CloudAppEvents identity filtering** | `AccountId` is GUID, NOT UPN. Use `AccountDisplayName` for display-name matching |
| **CloudAppEvents `RESTSystem`** | Exchange Online backend services appear as AppId GUIDs with `RESTSystem` in ClientInfoString. These are benign system operations |
| **DeviceTvmSoftwareVulnerabilities** | No timestamp column — point-in-time snapshot. Do NOT add `where Timestamp > ago(...)` |
| **Drill-down query error → silent skip** | **⛔ NEVER skip.** Diagnose → fix → re-execute → present corrected results |
| **OfficeActivity for Exchange forensics** | CloudAppEvents only surfaces ActionType summaries. OfficeActivity carries full `Parameters` JSON with `ForwardTo`/`RedirectTo`. Always check both. |

> **Full table pitfalls** are documented in `kql-query-authoring/known-table-pitfalls.md`. Read before querying any table listed there.

---

## Quality Checklist

- [ ] All 12 queries executed (10 direct + 2 AH or ❓ if declined)
- [ ] Every query has a verdict row — no omissions
- [ ] ✅ verdicts cite table + "0 results"; 🔴/🟠 cite specific evidence
- [ ] All incidents have clickable XDR portal URLs
- [ ] Cross-query correlations checked
- [ ] Every non-✅ drill-down has a `🎬 Take Action` block
- [ ] Every `🎬 Take Action` block includes the `⚠️ AI-generated content` warning
- [ ] `📂 Recommended Drill-Downs` present when any non-✅ verdict exists
- [ ] No fabricated data
- [ ] All KQL queries read from [threat-pulse-queries.md](threat-pulse-queries.md), not written ad-hoc
- [ ] Query results saved to `output/threat-pulse/tp_results_*.json` for cache

---

## HTML Report Generation

When the user explicitly requests an HTML report (`"genera HTML"`, `"export HTML"`, `"scarica HTML"`, etc.):

1. **Save the inline report as markdown** to `reports/threat-pulse/Threat_Pulse_<YYYYMMDD_HHMMSS>.md`
2. **Run the HTML generator:**
   ```bash
   python3 tmp/threat-pulse/generate_html_report.py \
       "reports/threat-pulse/Threat_Pulse_<ts>.md" \
       --output-dir reports/threat-pulse/
   ```
3. **Report the result** — provide the path to the generated HTML file and its size.

The script reads the markdown report, parses sections (Executive Summary, Dashboard Summary, Detailed Findings, etc.) and tables, applies verdict badges (🔴🟠🟡✅🔵❓), and produces a self-contained dark-themed HTML file with:
- Fixed header bar with risk level indicator
- Verdict KPI cards (counts per verdict type)
- Collapsible H3 subsections for drill-down details
- Responsive table styling with portal link preservation
- Print-friendly CSS

> ⚠️ The script must be resolved via the [File Resolution cascade](#file-resolution-coderefs-first--on-skill-activation) before use.

---

## SVG Dashboard Generation

After completing the Threat Pulse report, the user may request an SVG visualization. Use the `svg-dashboard` skill in **manifest mode** — the widget manifest is at [svg-widgets.yaml](svg-widgets.yaml).

### Execution

1. Read [svg-widgets.yaml](svg-widgets.yaml) (widget manifest)
2. Read the `svg-dashboard` SKILL.md for component rendering rules
3. Map manifest `field` values to Threat Pulse report data in context
4. Render SVG → save to `temp/threat_pulse_{date}_dashboard.svg`
