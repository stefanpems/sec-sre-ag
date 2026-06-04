# Known Issues & Platform Learnings

This document collects **platform constraints, KQL pitfalls, and operational patterns** discovered during real skill executions on Azure SRE Agent. The information is generic — it applies to any agent instance running these skills, regardless of tenant or subscription.

> **How to use this file:** see [Using This Guide with the Agent](#using-this-guide-with-the-agent) at the bottom.

---

## Table of Contents

1. [Platform Constraints](#1-platform-constraints)
2. [KQL Pitfalls](#2-kql-pitfalls)
3. [Operational Patterns](#3-operational-patterns)
4. [Using This Guide with the Agent](#using-this-guide-with-the-agent)

---

## 1. Platform Constraints

### 1.1 No PowerShell (`pwsh`) in the Sandbox

The agent sandbox does not include PowerShell. Any `.ps1` script will fail with `command not found`.

**Workaround:** Use `RunAzCliReadCommands` tool for Graph API / REST calls, or Python scripts executed via `RunInTerminal`.

**Affects:** Any skill that historically referenced PowerShell scripts.

### 1.2 Shell `az` CLI Is Not in PATH

Running `az rest ...` via `RunInTerminal` fails — the Azure CLI binary is not available in the sandbox shell.

**Workaround:** Use the `RunAzCliReadCommands` tool (platform-provided, different auth path) for all Azure CLI operations. It provides the same capabilities without requiring `az` in PATH.

**Affects:** All skills that need Azure CLI commands.

### 1.3 `az keyvault` Subcommand Not Supported

The `RunAzCliReadCommands` tool does not support the `az keyvault` family of commands.

**Workaround:** Use the REST API directly:
```bash
az rest --method GET \
  --url "https://<vault-name>.vault.azure.net/secrets/<secret-name>?api-version=7.4" \
  --resource "https://vault.azure.net"
```

**Affects:** `user-investigation`, `ioc-investigation` (IP enrichment API token retrieval).

### 1.4 Managed Identity Token Caching (Up to 24h)

After assigning new RBAC roles or API permissions to the UAMI, the sandbox shell's Managed Identity token (served by Azure IMDS) may retain the **old token without the new permissions** for up to 24 hours. This means:
- `RunAzCliReadCommands` tool → sees new permissions **immediately** (different auth path)
- `RunInTerminal` with `az` or Python scripts using `DefaultAzureCredential` → may **not see** new permissions for hours

**Workaround — the Prefetch pattern:** see [§3.1 Prefetch Workflow](#31-prefetch-workflow-for-mi-token-caching).

**Affects:** All skills that run Python scripts needing Azure access (MITRE, Sentinel Ingestion, Identity Posture).

### 1.5 Sandbox Cannot Make Authenticated ARM Calls (Python urllib)

**Python `urllib` / `requests` / `curl` from `RunInTerminal` CANNOT reach ARM endpoints.**
Tokens obtained via `RunAzCliReadCommands` are IP-bound to the platform's network path.
When used from the sandbox (different network path), ARM returns **401 AuthenticationFailed**.
This is not a token-handling bug — it is a fundamental platform constraint.

**Confirmed behavior:** `RunInTerminal` → Python `urllib.request` → `https://management.azure.com/...` with a valid Bearer token → **401** every time.

**Workaround — Token-via-file pattern:**
1. Get an ARM token via `RunAzCliReadCommands`:
   ```
   az account get-access-token --resource https://management.azure.com --query accessToken -o tsv --subscription <SUB_ID>
   ```
2. Save the token to a file via `RunInTerminal` (heredoc).
3. Use Python `urllib.request` in `RunInTerminal` — read token and JSON body from files, `PUT` with `Authorization: Bearer <token>` and `Content-Type: application/json`.

This bridges the two environments: `RunAzCliReadCommands` (has Azure auth) → file → `RunInTerminal` (has filesystem + network). No body size limits, no shell escaping issues, no approval prompts.

**Do NOT use `RunAzCliWriteCommands` with `az rest --body` for HTML content** — the tool writes the command to a bash script; HTML `<`/`>` cause shell syntax errors, bash strips `"` from JSON, and the tool may trigger approval prompts. Only usable for very short plain-text bodies with no shell metacharacters.

**Affects:** `incident-comment`, any skill that needs to PUT/POST JSON payloads to ARM.

### 1.6 Script Materialization — `read_skill_file` Does Not Write to Disk

The `read_skill_file` API returns file **content** but does **not** place files on the sandbox filesystem. Attempting to run `python3 <script>.py` after calling `read_skill_file` will fail with `No such file or directory` (exit code 2).

**Resolution:** This is handled by the **File Resolution Cascade** documented in the main README — scripts are found first in `codeRefs/`, then `tmp/`, and materialized from the Builder API only as a last resort. With this repository connected to the agent, scripts are always available in `codeRefs/` and this issue does not arise.

**Affects:** Agents that do NOT have this repository connected (fallback to Builder materialization).

### 1.7 `RunAzCliWriteCommands` — Inline Body Size Limit (~4,000 chars)

The `RunAzCliWriteCommands` tool passes the `--body` parameter inline to the `az` CLI argument parser. When the serialized JSON body exceeds approximately 4,000 characters, the parser mis-splits the string on spaces, escaped quotes (`\"`), and braces, causing `ERROR: unrecognized arguments: {message: …` failures. This is a platform constraint of how the tool processes command strings — it cannot be fixed by quoting or escaping.

**Workaround:** `format_comment.py` includes `--max-body-chars 4000` (the default). When the JSON body exceeds this limit, the script automatically:
1. Strips HTML comments
2. Collapses redundant whitespace
3. Strips ALL inline `style=` attributes
4. Hard-truncates with a notice if still too long

The output JSON is always compact (`ensure_ascii=False`, no extra spaces), ensuring it fits within the transport limit. **No manual intervention is required.**

**Affects:** `incident-comment`, and any skill that needs to PUT/POST large JSON payloads via `RunAzCliWriteCommands`.

---

## 2. KQL Pitfalls

### 2.1 `ThreatIntelIndicators` vs `ThreatIntelligenceIndicator` (Critical)

| Table | Status | Schema |
|---|---|---|
| `ThreatIntelligenceIndicator` | **Deprecated** (July 2025), typically empty | Legacy flat columns (`DomainName`, `NetworkIP`, etc.) |
| `ThreatIntelIndicators` | **Active**, fed by Premium MDTI Connector | STIX-based: `ObservableKey` + `ObservableValue`, `Data` column with full STIX JSON |
| `ThreatIntelObjects` | Exists but currently empty | STIX objects |

**Rule:** Always query `ThreatIntelIndicators` (with the final 's'). If a TI query returns 0 results, verify you're using the correct table before reporting "no matches."

**Affects:** `ioc-investigation`, `threat-pulse`.

### 2.2 `SecurityIncident` — Align with Defender XDR Portal

When listing incidents, the KQL query must match what the user sees in the Defender XDR portal:

| Aspect | Defender XDR Portal | Common Mistake | Correct |
|---|---|---|---|
| Time filter | Last modified | `CreatedTime > ago(24h)` | `LastModifiedTime > ago(24h)` |
| Incident ID | Defender XDR ID | `IncidentNumber` | `ProviderIncidentId` |
| Phantom incidents | Hidden | Shown | Filter: `Status != "Closed" or array_length(AlertIds) > 0` |
| Owner | Display name | `OwnerEmail` (doesn't exist) | `tostring(Owner.assignedTo)` |

**Reference query:**
```kql
SecurityIncident
| where LastModifiedTime > ago(24h)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(Status == "Closed" and array_length(AlertIds) == 0)
| project LastModifiedTime, IncidentId = ProviderIncidentId, Title, Severity, Status,
    Owner = tostring(Owner.assignedTo), AlertsCount = array_length(AlertIds)
| order by LastModifiedTime desc
```

**Affects:** `incident-listing`, `incident-statistics`, `incident-investigation`.

### 2.3 `SentinelHealth` — Correct `SentinelResourceType` Value

The field value for analytic rules is **`Analytics Rule`** (with 's', capital 'R').

- Wrong: `"Analytic rule"`, `"AnalyticsRule"`, `"Analytic Rule"`
- Correct: `"Analytics Rule"`
- Recommended: use case-insensitive filter `=~` to be safe: `SentinelResourceType =~ "Analytics Rule"`

**Affects:** `mitre-coverage-report`, `sentinel-ingestion-report` (rule health queries).

### 2.4 Schema Validation Before Every Query

**Always** call `get_table_schema("<table_name>")` (from the `kql-query-authoring` skill) **before** writing any KQL query. Common column-name mistakes caught by this practice:

| Table | Wrong Column | Correct Column |
|---|---|---|
| `SecurityIncident` | `OwnerEmail` | `Owner` (dynamic) |
| `ThreatIntelligenceIndicator` | `IndicatorType` | Doesn't exist in this table |
| `SigninLogs` (in union) | `DeviceDetail` (unresolved) | `parse_json(DeviceDetail)` |
| `IdentityInfo` | `Tags` used as dynamic | String — wrap in `todynamic(Tags)` |

**Affects:** All skills that author KQL queries.

### 2.5 MCP Monitor `--subscription` Parameter Is Mandatory

The `monitor-client_monitor_workspace_log_query` tool **requires** the `subscription` parameter. Without it, the tool returns `{"status":400,"message":"Missing Required options: --subscription"}` which may be silently interpreted as "no data found."

**Rule:** Always pass `subscription` in every MCP monitor call.

**Affects:** All skills that query Log Analytics via MCP.

---

## 3. Operational Patterns

### 3.1 Prefetch Workflow (for MI Token Caching)

When a Python script needs Azure data but the sandbox MI token doesn't yet have the required permissions (see [§1.4](#14-managed-identity-token-caching-up-to-24h)), use this pattern:

1. **Collect data via native tools** (which see permissions immediately):
   - REST API calls → `RunAzCliReadCommands` tool
   - KQL queries → `monitor-client_monitor_workspace_log_query` MCP tool
2. **Save results** to JSON files in a prefetch directory (e.g., `tmp/<skill>-prefetch/m1.json` through `m9.json`)
3. **Run the script** with `--prefetch-dir <path>` — the script reads the pre-collected JSON files instead of making live API calls

Scripts that support `--prefetch-dir`: `invoke_mitre_scan.py`, `invoke_ingestion_scan.py`.

### 3.2 Graph API Calls Must Be Sequential

`RunAzCliReadCommands` shares a token cache across parallel calls. Parallel Graph API calls cause **refresh races** — some calls get stale/invalid tokens, leading to 403 errors or `$select` being silently ignored (returns default fields instead of requested ones).

**Rule:** Execute Graph API calls **sequentially** (one at a time). KQL queries CAN run in parallel (different auth path).

**Affects:** `identity-posture`, `user-investigation`, `computer-investigation`.

---

## Using This Guide with the Agent

### The Problem

Azure SRE Agent has a **per-agent memory system** (`memories/synthesizedKnowledge/`) that persists across conversation threads. When you first deploy the agent and connect this repository, the agent's memory is **empty** — it doesn't know any of the pitfalls and patterns documented above. It will discover them the hard way (failed queries, empty results, permission errors) and gradually learn them, just as the original author's agent did.

### The Solution — Seed the Agent's Memory

You can **bootstrap** the agent's knowledge by asking it to read this file and save the learnings to its memory. This is a one-time operation per agent instance.

**When to do it:** After the initial setup (permissions assigned, connectors enabled), in the **first conversation thread** with the agent — before running any skill.

**What to say:**

```
Read the file codeRefs/sec-sre-ag/docs/known-issues.md and save its contents 
to your memory as operational knowledge. Organize it into your debugging index 
and behavior expectations as you see fit.
```

The agent will:
1. Read this file from the connected repository
2. Extract the durable facts (platform constraints, KQL pitfalls, operational patterns)
3. Save them to `memories/synthesizedKnowledge/` organized by topic
4. Reference them in future investigations automatically

### Do I Need to Repeat This?

**No.** Once the agent has saved the knowledge to its memory, it persists across all future threads. You only need to re-seed if:
- You **delete** the agent and recreate it (new agent = empty memory)
- You manually clear the `memories/synthesizedKnowledge/` directory
- This file is **significantly updated** with new learnings — in that case, ask the agent:
  ```
  Re-read codeRefs/sec-sre-ag/docs/known-issues.md — it has been updated. 
  Merge the new information into your existing memory.
  ```

### Can I Add My Own Learnings?

Yes. If you discover new pitfalls or patterns during your own investigations:
1. Ask the agent to remember them (it will save to its memory automatically)
2. Optionally, submit a PR to add them to this file so other users benefit too

### What If I Don't Seed the Memory?

The agent will still work — it will just take longer to stabilize. Each pitfall listed above was discovered through a real failure (empty results, 403 errors, wrong data). Without seeding, the agent will hit those same failures, learn from them, and eventually converge to the same knowledge. Seeding simply skips that trial-and-error phase.
