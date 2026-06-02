---
name: incident-statistics
description: >
  Use this skill when the user asks for incident statistics, incident metrics, incident reports,
  SOC dashboard data, MTTA/MTTR analysis, incident distribution, or any quantitative analysis
  of security incidents over a given time period.
  ALSO use this skill when the user asks for a high-level view, overview, summary, or status
  of SOC operations, CIRT/CSIRT activities, security operations, or the security posture in general.
  These requests are equivalent to asking for incident statistics because security incidents are
  the primary measurable output of SOC/CIRT/CSIRT work.
  Triggers on keywords like: "incident statistics", "incident report", "incident metrics",
  "how many incidents", "MTTA", "MTTR", "incident trend", "SOC metrics", "incident summary",
  "incident dashboard", "affected users", "affected devices", "incident assignees",
  "MITRE coverage", "true positive incidents", "SOC overview", "SOC status", "SOC activity",
  "CIRT overview", "CSIRT overview", "CIRT status", "CSIRT status", "security overview",
  "security summary", "security posture", "high-level view", "vista di alto livello",
  "panoramica sicurezza", "situazione incidenti", "stato del SOC", "attività del SOC",
  "come va la sicurezza", "com'è la situazione".
---

# Incident Statistics Skill

## Purpose

Generate comprehensive security incident statistics from Microsoft Sentinel, including tabular data and charts. All KQL queries are hardcoded and validated against the `SecurityIncident` and `SecurityAlert` tables. The skill produces 7 analyses with both tabular and graphical output.

> **Broad trigger scope:** This skill is the correct choice not only for explicit "incident statistics" requests, but also for any high-level, overview, or summary question about SOC / CIRT / CSIRT operations and security posture. Security incidents are the primary measurable output of security operations — so a "SOC overview" or "how is our security doing" is answered by this skill.

---

## Prerequisites

- **Log Analytics workspace** connected to Microsoft Sentinel with `SecurityIncident` and `SecurityAlert` tables populated.
- **Python 3** with `matplotlib` available in the workspace (for chart generation).
- **Monitor MCP tools** available for executing KQL queries (`monitor-client_monitor_workspace_log_query`).

---

## Skill Files

| File | Purpose |
|------|---------|
| `SKILL.md` | This file — skill definition, queries, workflow |
| `generate_charts.py` | Pre-built script that generates matplotlib PNG charts from `query_results.json` |
| `generate_html_report.py` | Pre-built script that generates a self-contained HTML report (dark theme, no matplotlib dependency) from `query_results.json` |

### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/incident-statistics/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/incident-statistics/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("incident-statistics", "<filename>") from Builder
   → CreateFile("tmp/incident-statistics/<filename>", <content>)
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

## Output Modes

| Mode | When | What |
|------|------|------|
| **Inline** (DEFAULT — ALWAYS) | Every invocation | Present all 7 analyses as markdown tables + chart images inline in chat |
| **Markdown file** | Only if the user **explicitly** requests a downloadable report / MD file | Generate a `.md` file with all analyses and offer it for download |
| **HTML report** | Only if the user **explicitly** requests an HTML report | Materialize `generate_html_report.py` to disk, execute it, offer the HTML file |
| **JSON export** | Only if the user **explicitly** requests raw data export | Save `query_results.json` and offer for download |

> **Rule:** Always start with inline presentation. Never skip inline output. The other modes are additive, triggered only by explicit user request.

### HTML Report — Conditional Resolution (codeRefs-first)

When the user requests an HTML report:

1. Resolve `generate_html_report.py` via the [File Resolution cascade](#file-resolution-coderefs-first):
   - Check `codeRefs/sec-sre-ag/incident-statistics/generate_html_report.py` → if found, use that path.
   - Else check `tmp/incident-statistics/generate_html_report.py` → if found, use that path.
   - Else: `read_skill_file("incident-statistics", "generate_html_report.py")` → `CreateFile("tmp/incident-statistics/generate_html_report.py", <content>)`
2. Execute: `python3 <resolved_path>/generate_html_report.py {output_dir}/query_results.json --output-dir {output_dir} --lookback "{lookback_label}"`
3. The script generates a self-contained HTML file (dark theme, CSS-only visualizations, no matplotlib dependency)

Do NOT resolve the script unless the user explicitly requests an HTML report.

---

## Phase 0: Results Cache Check (MANDATORY)

**This phase MUST execute BEFORE any KQL queries. It determines whether to reuse cached results or start fresh.**

### 0.1 Cache File Convention

Results are stored as:
```
{output_dir}/query_results.json
```
where `{output_dir}` is `reports/incident-statistics/` or similar.

### 0.2 Cache Check Workflow

```
Step 0.1: Search for existing query_results.json in the output directory
          → If NO cache file exists → proceed to Step 1 (fresh execution)

Step 0.2: If a cache file exists, calculate its age:
          → age = current_UTC_time − file_modification_timestamp
          → If age > 4 hours → IGNORE cache entirely, proceed to Step 1 (fresh execution)
          → If age ≤ 4 hours → proceed to Step 0.3

Step 0.3: Analyze the user's ORIGINAL prompt for implicit intent:

          REDO KEYWORDS (triggers fresh execution, any language):
            "ripeti", "aggiorna", "rifai", "repeat", "redo", "refresh",
            "update", "re-run", "start over", "da capo",
            "from scratch", "ricomincia", "nuovo", "nuova analisi"
          → If ANY redo keyword is detected → IGNORE cache, proceed to Step 1

          USE-CACHE KEYWORDS (triggers cache reuse, any language):
            "completa", "continua", "complete", "continue", "finish",
            "usa i dati", "use cached", "use existing", "prosegui",
            "riprendi", "resume", "genera report", "generate report",
            "genera il report", "crea report", "genera html"
          → If ANY use-cache keyword is detected → LOAD cache, skip to Step 3

          NO IMPLICIT INTENT DETECTED:
          → ASK the user:
            Question: "Ho trovato risultati di un'analisi precedente,
                       completata <TIME_AGO> fa (alle <HH:MM> UTC).
                       Vuoi utilizzare questi dati o preferisci rieseguire
                       le query da zero?"
            Options:
              1. "Usa i dati esistenti" — Riprende dai risultati precedenti
              2. "Riesegui da zero" — Ignora la cache e riesegue tutte le query

          → If user selects "Usa i dati esistenti" → LOAD cache, skip to Step 3
          → If user selects "Riesegui da zero" → proceed to Step 1
```

### 0.3 Cache Decision Summary

| Cache Exists? | Age | User Prompt | Action |
|---------------|-----|-------------|--------|
| No | — | — | Fresh execution (Step 1) |
| Yes | > 4 hours | — | Fresh execution — cache expired |
| Yes | ≤ 4 hours | Contains REDO keyword | Fresh execution |
| Yes | ≤ 4 hours | Contains USE-CACHE keyword | Load cache → Step 3 |
| Yes | ≤ 4 hours | No implicit intent | ASK user |

### 0.4 Important Rules

- **NEVER silently reuse cached data** — always either detect explicit intent from the prompt or ask the user.
- **NEVER ask the user if the prompt already contains an implicit answer** — detect keywords first.
- **When loading cache, always show what was already completed** — the user must understand what data is from cache.
- **Cache files from a DIFFERENT thread/session are still valid** — the 4-hour TTL is the only expiration criterion.

---

## Execution Workflow

### Step 0: Determine Parameters

When the user asks for incident statistics, extract:

1. **Lookback period** — How far back to analyze. Default: `90d`. Common values: `7d`, `30d`, `90d`, `180d`, `365d`.
2. **Workspace details** — Resource group, workspace ID, subscription ID. Use values from the agent's configuration or ask the user.

Replace `<LOOKBACK>` in all queries below with the user's requested period (e.g., `90d`).

### Step 1: Execute All Queries IN PARALLEL

**CRITICAL: All 7 queries are independent — execute them ALL in a single parallel tool call.**

None of the queries depends on the output of another. Launch all 7 `monitor-client_monitor_workspace_log_query` calls simultaneously in the same tool invocation block. Set the `hours` parameter to cover at least `2 × <LOOKBACK>` (needed for MTTA/MTTR period comparison).

**Parallelization groups:**

| Group | Queries | Table(s) | Notes |
|-------|---------|----------|-------|
| **All (parallel)** | Q1, Q2, Q3, Q4, Q5, Q6, Q7 | `SecurityIncident` (+ `SecurityAlert` for Q6, Q7) | Zero dependencies — fire all at once |

```
// Pseudo-code: single tool call block with all 7 queries
tool_call_1: Q1 — Incidents by Title
tool_call_2: Q2 — MITRE Tactics & Techniques
tool_call_3: Q3 — MTTA
tool_call_4: Q4 — MTTR
tool_call_5: Q5 — Incidents by Assignee
tool_call_6: Q6 — Top 5 Affected Users
tool_call_7: Q7 — Top 5 Affected Devices
// All 7 fire simultaneously, results collected when all complete
```

### Step 2: Generate Charts and HTML Table Using Pre-built Script

After collecting all query results:

1. **Construct a JSON file** with all query results using this structure:
   ```json
   {
       "q1": [<Q1 result array>],
       "q2": [<Q2 result array>],
       "q3": [<Q3 result array>],
       "q4": [<Q4 result array>],
       "q5": [<Q5 result array>],
       "q6": [<Q6 result array>],
       "q7": [<Q7 result array>]
   }
   ```
   Save to `{output_dir}/query_results.json`. Use empty arrays `[]` for queries with no data.

2. **Resolve the chart generation script** via the [File Resolution cascade](#file-resolution-coderefs-first):
   - Check `codeRefs/sec-sre-ag/incident-statistics/generate_charts.py` → if found, use that path.
   - Else check `tmp/incident-statistics/generate_charts.py` → if found, use that path.
   - Else:
     ```
     read_skill_file(skill_name="incident-statistics", file_path="generate_charts.py")
     ```
     Save the script content to `tmp/incident-statistics/generate_charts.py`.

3. **Execute the script:**
   ```bash
   python3 <resolved_path>/generate_charts.py {output_dir}/query_results.json {output_dir} "{lookback_label}"
   ```

The script generates all applicable chart PNGs **and** the Q1 heatmap table image (`1_incidents_by_title_table.png`), skipping queries with no data.

**DO NOT write inline Python chart code.** Always use the pre-built `generate_charts.py` script.

### Step 3: Present Results (Inline — ALWAYS)

Present each analysis inline in chat:
1. For **Q1**: present the data as a **Markdown table** (columns: Rank, Incident Title, Severity, Total, New, Active, Closed, Tactics, Techniques), followed by the **heatmap table image** `![Q1 Heatmap Table](/api/files/{output_dir}/1_incidents_by_title_table.png)` which visually highlights the numeric columns
2. For **Q2–Q7**: a **summary table** in Markdown format
3. The **chart image** inline (for all queries that have one)

**CRITICAL — Image path format:** All chart images MUST use the `/api/files/` prefix to be visible in the UI.

- **Correct:** `![Chart Title](/api/files/reports/incident-statistics/1_incidents_by_title.png)`
- **Wrong:** `![Chart Title](reports/incident-statistics/1_incidents_by_title.png)` — WILL NOT RENDER

General pattern: `![description](/api/files/{output_dir}/{filename}.png)`

**Performance impact:** Parallel query execution reduces total wall-clock time from ~7x single-query latency to ~1x (the slowest query). Chart generation via the pre-built script avoids re-creating Python code each session.

### Step 4: Generate HTML Report (ONLY if explicitly requested)

If — and only if — the user explicitly asks for an HTML report:

1. Resolve `generate_html_report.py` via the [File Resolution cascade](#file-resolution-coderefs-first)
2. Execute:
   ```bash
   python3 <resolved_path>/generate_html_report.py {output_dir}/query_results.json --output-dir {output_dir} --lookback "{lookback_label}"
   ```
3. The script produces a self-contained HTML file with dark theme, CSS-only charts, severity heatmaps, MITRE matrix, MTTA/MTTR bars, and top-5 tables — no matplotlib dependency required.


---

## Query 1: Incident Overview by Title (with Severity, Status Breakdown, Tactics & Techniques)

### KQL Query

```kql
let incidents = SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime >= ago(<LOOKBACK>)
| where array_length(AlertIds) > 0;
let base = incidents
| summarize 
    Total = count(),
    New = countif(Status == "New"),
    Active = countif(Status == "Active"),
    Closed = countif(Status == "Closed"),
    Severity = take_any(Severity)
    by Title;
let tactics = incidents
| mv-expand Tactic = parse_json(AdditionalData).tactics to typeof(string)
| summarize Tactics = strcat_array(array_sort_asc(make_set(Tactic)), ", ") by Title;
let techniques = incidents
| mv-expand Technique = parse_json(AdditionalData).techniques to typeof(string)
| summarize Techniques = strcat_array(array_sort_asc(make_set(Technique)), ", ") by Title;
base
| join kind=leftouter tactics on Title
| join kind=leftouter techniques on Title
| project-away Title1, Title2
| extend Tactics = coalesce(Tactics, ""), Techniques = coalesce(Techniques, "")
| order by Total desc
| extend Rank = row_number()
| project Rank, Title, Severity, Total, New, Active, Closed, Tactics, Techniques
```

### Table Format — Markdown Table + Heatmap Image

Present Q1 results as a **Markdown table** with these exact columns:

```
| Rank | Incident Title | Severity | Total | New | Active | Closed | Tactics | Techniques |
|------|---------------|----------|-------|-----|--------|--------|---------|------------|
```

Add a time window header above the table: `Time window: {start_time} to {end_time} (UTC)`

Then, immediately below the Markdown table, include the **heatmap table image** generated by `generate_charts.py`:

```
![Q1 Heatmap Table](/api/files/{output_dir}/1_incidents_by_title_table.png)
```

The heatmap image visually highlights the numeric columns (Total, New, Active, Closed) using color intensity proportional to `value / column_max`:
- **Total**: red gradient `(231, 76, 60)`
- **New**: orange gradient `(230, 126, 34)`
- **Active**: blue gradient `(52, 152, 219)`
- **Closed**: green gradient `(39, 174, 96)`

The image is auto-generated by `generate_charts.py` — do NOT create it manually.

### Chart: 3D Pie Chart

- Show the **top 8 titles** as individual slices (by Total count); group the rest into an **"Other"** slice.
- Apply 3D depth effect using shadow layers offset downward.
- Use distinct colors per slice with `explode` on the largest slice.
- Display percentage and absolute count on each slice.
- Add a legend on the right listing all titles.

> **Note:** Chart generation is handled by `generate_charts.py` — do NOT write inline Python code.


---

## Query 2: MITRE ATT&CK Tactics & Techniques (True Positive Incidents)

### KQL Query

```kql
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime >= ago(<LOOKBACK>)
| where array_length(AlertIds) > 0
| where Classification == "TruePositive"
| extend Tactics = parse_json(AdditionalData).tactics
| extend Techniques = parse_json(AdditionalData).techniques
| mv-expand Tactic = Tactics
| mv-expand Technique = Techniques
| summarize IncidentCount = dcount(IncidentNumber) by Tactic = tostring(Tactic), Technique = tostring(Technique)
| order by IncidentCount desc
```

> **Note:** If no incidents are classified as TruePositive, this query returns 0 results. In that case, inform the user and optionally offer to run the query without the classification filter to show MITRE coverage across all incidents.

### Chart: Heatmap (Tactic × Technique)

- X-axis: MITRE Technique IDs with short descriptions.
- Y-axis: MITRE Tactic names.
- Cell color intensity: number of incidents (use `YlOrRd` colormap).
- Annotate each non-zero cell with the count (white text on dark cells, black on light).
- Include a colorbar labeled "Number of Incidents".

### Python Chart Template

```python
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# data = [(tactic, technique, count), ...] — from query results

# Well-known technique descriptions (extend as needed)
tech_names = {
    "T1543": "T1543\nCreate/Modify\nSystem Process",
    "T1110": "T1110\nBrute Force",
    "T1071": "T1071\nApp Layer\nProtocol",
    "T1550": "T1550\nAlternate Auth\nMaterial",
    "T1114": "T1114\nEmail\nCollection",
    "T1078": "T1078\nValid\nAccounts",
    "T1098": "T1098\nAccount\nManipulation",
    "T1562": "T1562\nImpair\nDefenses",
}

tactics = sorted(set(d[0] for d in data))
technique_ids = sorted(set(d[1] for d in data))

matrix = np.zeros((len(tactics), len(technique_ids)))
for tactic, tech, count in data:
    matrix[tactics.index(tactic)][technique_ids.index(tech)] = count

fig, ax = plt.subplots(figsize=(12, 7))
im = ax.imshow(matrix, cmap=plt.cm.YlOrRd, aspect='auto', vmin=0)
ax.set_xticks(range(len(technique_ids)))
ax.set_xticklabels([tech_names.get(t, t) for t in technique_ids], fontsize=8, ha='center')
ax.set_yticks(range(len(tactics)))
ax.set_yticklabels(tactics, fontsize=9)

for i in range(len(tactics)):
    for j in range(len(technique_ids)):
        val = int(matrix[i][j])
        if val > 0:
            color = 'white' if val > 10 else 'black'
            ax.text(j, i, str(val), ha='center', va='center', fontsize=10, fontweight='bold', color=color)

cbar = plt.colorbar(im, ax=ax, shrink=0.8, pad=0.02)
cbar.set_label('Number of Incidents', fontsize=10)
ax.set_title(f'MITRE ATT&CK Tactics × Techniques — True Positive Incidents\n(Last {lookback_label})',
             fontsize=13, fontweight='bold', pad=15)
ax.set_xlabel('Technique', fontsize=11, fontweight='bold', labelpad=10)
ax.set_ylabel('Tactic', fontsize=11, fontweight='bold')
plt.tight_layout()
plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
```

---

## Query 3: MTTA — Mean Time To Acknowledge (Current vs Previous Period)

### KQL Query

```kql
let LookbackDays = <LOOKBACK>;
let CurrentStart = ago(LookbackDays);
let PreviousStart = ago(2 * LookbackDays);
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where array_length(AlertIds) > 0
| where isnotempty(FirstModifiedTime)
| where CreatedTime >= PreviousStart
| extend Period = iff(CreatedTime >= CurrentStart, "Current", "Previous")
| extend MTTA_hours = datetime_diff('second', FirstModifiedTime, CreatedTime) / 3600.0
| summarize
    AvgMTTA = round(avg(MTTA_hours), 2),
    MedianMTTA = round(percentile(MTTA_hours, 50), 2),
    P90_MTTA = round(percentile(MTTA_hours, 90), 2),
    P99_MTTA = round(percentile(MTTA_hours, 99), 2),
    TotalIncidents = count()
    by Period
| order by Period asc
```

> **Note:** MTTA = `FirstModifiedTime - CreatedTime`. If no incidents have been triaged (`FirstModifiedTime` is empty for all), this query returns 0 results. Inform the user accordingly.

### Chart: Grouped Bar Chart with SLA Target

- 4 metric groups: Average, Median (P50), P90, P99.
- Two bars per group: **grey** = Previous Period, **blue** = Current Period.
- Horizontal dashed line: SLA Target (default 4h, configurable).
- Delta percentage arrows: **green ▼** = improvement (MTTA decreased), **red ▲** = worsened.
- Display value labels on each bar in hours.

### Python Chart Template

```python
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# current = [avg, median, p90, p99] — from "Current" row
# previous = [avg, median, p90, p99] — from "Previous" row
# sla_target = 4.0  # hours, configurable

metrics = ['Average', 'Median (P50)', 'P90', 'P99']
x = np.arange(len(metrics))
width = 0.32

fig, ax = plt.subplots(figsize=(11, 6.5))
bars_prev = ax.bar(x - width/2, previous, width, label='Previous Period',
                   color='#95a5a6', edgecolor='white', linewidth=1.5, zorder=3)
bars_curr = ax.bar(x + width/2, current, width, label='Current Period',
                   color='#3498db', edgecolor='white', linewidth=1.5, zorder=3)
ax.axhline(y=sla_target, color='#e67e22', linestyle='--', linewidth=2.5,
           label=f'SLA Target ({sla_target}h)', zorder=2)

for i, (c, p) in enumerate(zip(current, previous)):
    ax.text(x[i] - width/2, p + 0.25, f'{p:.2f}h', ha='center', va='bottom', fontsize=9, fontweight='bold', color='#555555')
    ax.text(x[i] + width/2, c + 0.25, f'{c:.2f}h', ha='center', va='bottom', fontsize=9, fontweight='bold', color='#2c3e50')
    if p > 0:
        delta_pct = ((c - p) / p) * 100
        arrow = '▼' if delta_pct < 0 else '▲'
        color = '#27ae60' if delta_pct < 0 else '#e74c3c'
        ax.text(x[i] + width/2, c + 1.0, f'{arrow} {abs(delta_pct):.0f}%',
                ha='center', va='bottom', fontsize=9, fontweight='bold', color=color)

ax.set_ylabel('Hours', fontsize=12, fontweight='bold')
ax.set_title(f'MTTA — Mean Time To Acknowledge\nCurrent vs Previous Period ({lookback_label})',
             fontsize=14, fontweight='bold', pad=15)
ax.set_xticks(x); ax.set_xticklabels(metrics, fontsize=11)
ax.legend(fontsize=10, loc='upper left')
ax.grid(axis='y', alpha=0.3, linestyle='--', zorder=0)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
ax.set_ylim(0, max(max(current), max(previous)) * 1.35)
plt.tight_layout()
plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
```

---

## Query 4: MTTR — Mean Time To Resolve (Current vs Previous Period)

### KQL Query

```kql
let LookbackDays = <LOOKBACK>;
let CurrentStart = ago(LookbackDays);
let PreviousStart = ago(2 * LookbackDays);
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where array_length(AlertIds) > 0
| where isnotempty(ClosedTime)
| where CreatedTime >= PreviousStart
| extend Period = iff(CreatedTime >= CurrentStart, "Current", "Previous")
| extend MTTR_hours = datetime_diff('second', ClosedTime, CreatedTime) / 3600.0
| summarize
    AvgMTTR = round(avg(MTTR_hours), 2),
    MedianMTTR = round(percentile(MTTR_hours, 50), 2),
    P90_MTTR = round(percentile(MTTR_hours, 90), 2),
    P99_MTTR = round(percentile(MTTR_hours, 99), 2),
    TotalIncidents = count()
    by Period
| order by Period asc
```

> **Note:** MTTR = `ClosedTime - CreatedTime`. Only closed incidents (`Status == "Closed"`) have a `ClosedTime`. If no incidents have been closed, this query returns 0 results.

### Chart: Grouped Bar Chart with SLA Target

Same format as MTTA chart, but:
- Current Period bars in **purple** (`#9b59b6`) instead of blue to visually distinguish from MTTA.
- Default SLA Target: **12h** (configurable).

Use the same Python template as Query 3, replacing:
- `color='#3498db'` → `color='#9b59b6'`
- `sla_target = 4.0` → `sla_target = 12.0`
- Title: `'MTTR — Mean Time To Resolve'`

---

## Query 5: Incidents by Assignee

### KQL Query

```kql
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime >= ago(<LOOKBACK>)
| where array_length(AlertIds) > 0
| extend OwnerInfo = parse_json(Owner)
| extend Assignee = coalesce(tostring(OwnerInfo.assignedTo), tostring(OwnerInfo.userPrincipalName), tostring(OwnerInfo.email))
| extend Assignee = iff(isempty(Assignee), "Unassigned", Assignee)
| summarize IncidentCount = count() by Assignee
| order by IncidentCount desc
```

### Chart: Horizontal Bar Chart

- One bar per assignee, sorted by count descending (highest at top).
- "Unassigned" bar in **grey** (`#bdc3c7`), assigned users in distinct **blue shades**.
- Display count and percentage on each bar.

### Python Chart Template

```python
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# data = [(assignee, count), ...] — from query results, sorted desc

assignees = [d[0] for d in data]
counts = [d[1] for d in data]
total = sum(counts)

# Color: grey for Unassigned, blue shades for assigned
colors = ['#bdc3c7' if a == 'Unassigned' else '#3498db' for a in assignees]

# Reverse for bottom-to-top display
assignees_r, counts_r, colors_r = assignees[::-1], counts[::-1], colors[::-1]

fig, ax = plt.subplots(figsize=(10, max(4, len(assignees) * 0.6 + 1)))
bars = ax.barh(assignees_r, counts_r, color=colors_r, edgecolor='white', height=0.5, zorder=3)

for bar, count in zip(bars, counts_r):
    pct = count / total * 100
    ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
            f'{count}  ({pct:.1f}%)', va='center', ha='left', fontsize=11, fontweight='bold')

ax.set_xlabel('Number of Incidents', fontsize=12, fontweight='bold')
ax.set_title(f'Incidents by Assignee — Last {lookback_label}', fontsize=14, fontweight='bold', pad=15)
ax.set_xlim(0, max(counts) * 1.25)
ax.grid(axis='x', alpha=0.3, linestyle='--', zorder=0)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
```

---

## Query 6: Top 5 Affected Users

### KQL Query

```kql
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime >= ago(<LOOKBACK>)
| where array_length(AlertIds) > 0
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner (
    SecurityAlert
    | where TimeGenerated >= ago(<LOOKBACK>)
    | where isnotempty(Entities)
    | mv-expand Entity = parse_json(Entities)
    | where tostring(Entity.Type) == "account"
    | extend
        AccountName = tostring(Entity.Name),
        AccountUPN = tostring(Entity.UserPrincipalName),
        AccountUPNSuffix = tostring(Entity.UPNSuffix),
        AccountNTDomain = tostring(Entity.NTDomain)
    | extend UserName = case(
        isnotempty(AccountUPN), AccountUPN,
        isnotempty(AccountUPNSuffix), strcat(AccountName, "@", AccountUPNSuffix),
        isnotempty(AccountNTDomain), strcat(AccountNTDomain, "\\", AccountName),
        isnotempty(AccountName), AccountName,
        ""
    )
    | where isnotempty(UserName)
    | extend NormalizedKey = tolower(AccountName)
    | project SystemAlertId, UserName, NormalizedKey
) on $left.AlertId == $right.SystemAlertId
| summarize IncidentCount = dcount(IncidentNumber), arg_max(strlen(UserName), UserName) by NormalizedKey
| order by IncidentCount desc
| take 5
| project UserName, IncidentCount
```

### Key Design Decisions

- **Entra ID users** resolve to UPN (e.g., `user@domain.com`).
- **Local accounts** resolve to `DOMAIN\alias` format when `NTDomain` is available, otherwise just the account name.
- **Deduplication:** `NormalizedKey = tolower(AccountName)` groups the same account across alerts with varying enrichment levels. `arg_max(strlen(UserName), UserName)` picks the most qualified name.

### Chart: Horizontal Bar Chart

- 5 bars, one per user, sorted by count descending (highest at top).
- Distinct colors per bar.
- Display count and percentage on each bar.

### Python Chart Template

```python
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# data = [(username, count), ...] — from query results (max 5)

users  = [d[0] for d in data]
counts = [d[1] for d in data]
total  = sum(counts)
colors = ['#e74c3c', '#9b59b6', '#e67e22', '#2ecc71', '#3498db']

# Reverse for bottom-to-top display
users_r, counts_r, colors_r = users[::-1], counts[::-1], colors[::-1]

fig, ax = plt.subplots(figsize=(11, 5.5))
bars = ax.barh(users_r, counts_r, color=colors_r, edgecolor='white', height=0.55, zorder=3)

for bar, count in zip(bars, counts_r):
    pct = count / total * 100
    ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
            f'{count}  ({pct:.1f}%)', va='center', ha='left', fontsize=10, fontweight='bold')

ax.set_xlabel('Number of Incidents', fontsize=12, fontweight='bold')
ax.set_title(f'Top 5 Affected Users — Last {lookback_label}', fontsize=14, fontweight='bold', pad=15)
ax.set_xlim(0, max(counts) * 1.25)
ax.grid(axis='x', alpha=0.3, linestyle='--', zorder=0)
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
plt.tight_layout()
plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white')
plt.close()
```

---

## Query 7: Top 5 Affected Devices

### KQL Query

```kql
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime >= ago(<LOOKBACK>)
| where array_length(AlertIds) > 0
| mv-expand AlertId = AlertIds
| extend AlertId = tostring(AlertId)
| join kind=inner (
    SecurityAlert
    | where TimeGenerated >= ago(<LOOKBACK>)
    | where isnotempty(Entities)
    | mv-expand Entity = parse_json(Entities)
    | where tostring(Entity.Type) == "host"
    | extend DeviceName = case(
        isnotempty(tostring(Entity.FQDN)), tostring(Entity.FQDN),
        isnotempty(tostring(Entity.DnsDomain)), strcat(tostring(Entity.HostName), ".", tostring(Entity.DnsDomain)),
        isnotempty(tostring(Entity.HostName)), tostring(Entity.HostName),
        ""
    )
    | where isnotempty(DeviceName)
    | extend NormalizedKey = tolower(tostring(Entity.HostName))
    | project SystemAlertId, DeviceName, NormalizedKey
) on $left.AlertId == $right.SystemAlertId
| summarize IncidentCount = dcount(IncidentNumber), arg_max(strlen(DeviceName), DeviceName) by NormalizedKey
| order by IncidentCount desc
| take 5
| project DeviceName, IncidentCount
```

### Key Design Decisions

- **FQDN preferred** when available (e.g., `server.domain.local`), otherwise short hostname.
- **Deduplication:** Same pattern as affected users — `NormalizedKey` groups, `arg_max(strlen(...))` picks the most qualified name.

### Chart: Horizontal Bar Chart

Same format as Top 5 Affected Users chart, with title "Top 5 Affected Devices".

---

## KQL Design Principles (Applied to All Queries)

These principles are hardcoded into all queries above. They come from the `SecurityIncident` known table pitfalls:

1. **Use `CreatedTime` for time-windowed queries** — NOT `TimeGenerated`. `TimeGenerated` captures old incidents with recent status updates, inflating counts.

2. **Filter phantom incidents** — `where array_length(AlertIds) > 0` excludes Defender XDR-synced incidents with empty alert lists that never appear in the portal.

3. **Deduplicate with `arg_max`** — `summarize arg_max(TimeGenerated, *) by IncidentNumber` gets the latest version of each incident, since `SecurityIncident` stores multiple rows per incident (status updates, reassignments, etc.).

4. **Parse `Owner` as JSON** — The `Owner` field is a dynamic JSON object with `assignedTo`, `userPrincipalName`, `email`, and `objectId` sub-fields.

5. **Parse `AdditionalData` for MITRE** — Tactics and techniques are stored as JSON arrays inside `AdditionalData`, not as top-level columns on `SecurityIncident`.

6. **Entity extraction via SecurityAlert join** — User and device entities live in `SecurityAlert.Entities`, not in `SecurityIncident`. Join on `AlertIds` ↔ `SystemAlertId`.

7. **Account name normalization** — Use `case()` with fallback chain: UPN → Name@UPNSuffix → NTDomain\Name → Name. Group by `tolower(AccountName)` to merge duplicates; pick the most qualified name via `arg_max(strlen(...))`.

---

## Output Summary

| # | Analysis | Table Format | Chart Type | Color Scheme |
|---|----------|-------------|-----------|--------------|
| 1 | Incidents by Title (+ Status, Tactics) | Markdown + heatmap PNG (`1_incidents_by_title_table.png`) | 3D Pie (top 8 + Other) | Multi-color with explode |
| 2 | MITRE Tactics × Techniques (True Positive) | Markdown | Heatmap | YlOrRd colormap |
| 3 | MTTA (Current vs Previous Period) | Markdown | Grouped Bar + SLA line | Grey/Blue + orange SLA |
| 4 | MTTR (Current vs Previous Period) | Markdown | Grouped Bar + SLA line | Grey/Purple + orange SLA |
| 5 | Incidents by Assignee | Markdown | Horizontal Bar | Grey (Unassigned) / Blue |
| 6 | Top 5 Affected Users | Markdown | Horizontal Bar | Multi-color |
| 7 | Top 5 Affected Devices | Markdown | Horizontal Bar | Multi-color |

---

## Handling Edge Cases

| Scenario | Behavior |
|----------|----------|
| No incidents in the lookback period | Report "No incidents found in the last {period}" |
| No True Positive incidents (Query 2) | Inform user; offer to run without classification filter |
| No triaged incidents / empty `FirstModifiedTime` (Query 3) | Report "No MTTA data — no incidents have been triaged yet" |
| No closed incidents / empty `ClosedTime` (Query 4) | Report "No MTTR data — no incidents have been closed yet" |
| All incidents unassigned (Query 5) | Show single "Unassigned" bar with 100% |
| No user entities in alerts (Query 6) | Report "No affected user data available in alert entities" |
| No host entities in alerts (Query 7) | Report "No affected device data available in alert entities" |
| Only one period has data for MTTA/MTTR | Show single period without delta arrows |
