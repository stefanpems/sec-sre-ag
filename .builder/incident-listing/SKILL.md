---
name: incident-listing
description: Use this skill when the user asks to list, show, or enumerate recent security incidents. Ensures the KQL query against SecurityIncident is aligned with the Microsoft Defender XDR portal view (correct time filter, incident IDs, and phantom incident exclusion).
---

> 📏 **Result & Token Guardrails** — See [shared-guardrails.md](../shared-guardrails.md) for universal result-cap, time-window, and aggregation rules that apply to all skills.

> ⚠️ **CRITICAL TOOL RULE — ALWAYS PASS --subscription TO MCP MONITOR**
>
> When calling `monitor-client_monitor_workspace_log_query`, the `subscription` parameter is MANDATORY. Without it, the tool returns a 400 error. Always pass it.

# Incident Listing — Aligned with Defender XDR Portal

## Purpose

Produce a list of recent security incidents from the `SecurityIncident` table that matches what the user sees in the Microsoft Defender XDR portal (`https://security.microsoft.com` → Incidents).

## When to Use

Trigger on any request to list, show, or enumerate recent incidents. Examples:
- "elencami gli incidenti"
- "list last incidents"
- "show recent incidents"
- "incidenti delle ultime 24 ore"
- "what incidents do we have?"

## Pre-Flight (MANDATORY)

Before writing the query, call `get_table_schema("SecurityIncident")` to validate column names — **once per session**. If this table's schema was already validated in the current thread, skip this step to save tokens.

## Query Template

Use this exact query structure. Adjust only the time window (`ago(24h)`) based on user request:

```kql
SecurityIncident
| where LastModifiedTime > ago(24h)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where not(Status == "Closed" and array_length(AlertIds) == 0)
| project
    LastModifiedTime,
    IncidentId = ProviderIncidentId,
    Title,
    Severity,
    Status,
    Owner = tostring(Owner.assignedTo),
    AlertsCount = array_length(AlertIds)
| order by LastModifiedTime desc
| take 200
```

### Execution

Run directly against the Log Analytics workspace using the `monitor_workspace_log_query` tool:
- **Table:** `SecurityIncident`
- **Workspace:** use the Sentinel workspace configured for the agent

## Why This Query — Key Design Decisions

| Decision | Rationale |
|---|---|
| **`LastModifiedTime`** (not `CreatedTime`) | Defender XDR filters by "Last update time". Using `CreatedTime` misses old incidents updated recently and includes newly created incidents not yet visible in the portal. |
| **`ProviderIncidentId`** (not `IncidentNumber`) | The Defender portal displays Defender XDR IDs (`ProviderIncidentId`), not Sentinel-local sequence numbers (`IncidentNumber`). Users will look up incidents by these IDs. |
| **`where not(Status == "Closed" and array_length(AlertIds) == 0)`** | Defender auto-hides "phantom" incidents — those synced from XDR that were immediately merged or auto-closed with zero alerts. Without this filter, the list shows extra rows the user cannot find in the portal. |
| **`arg_max(TimeGenerated, *) by IncidentNumber`** | Each incident emits multiple rows as its status changes. This deduplicates to the latest snapshot per incident. |
| **`tostring(Owner.assignedTo)`** | `Owner` is a dynamic column; extracting `.assignedTo` gives the human-readable assignee name. |

## Output Format

Present results as a **table** with these columns:
- **Incident ID** — the `ProviderIncidentId` (Defender XDR ID)
- **Titolo / Title**
- **Severità / Severity**
- **Stato / Status**
- **Assegnato a / Owner**
- **Alert** — count of associated alerts

Follow the table with a brief summary:
- Count by severity (High / Medium / Low / Informational)
- Count of open vs closed
- Highlight the most notable incident (highest alert count or highest severity)

## Common Mistakes to Avoid

| Mistake | Consequence | Correct Approach |
|---|---|---|
| Filtering by `CreatedTime` | Misses old incidents updated recently; includes phantom incidents created and auto-closed | Use `LastModifiedTime` |
| Filtering by `TimeGenerated` | `TimeGenerated` is the ingestion timestamp, changes on every status update — unreliable for time-windowing | Use `LastModifiedTime` |
| Showing `IncidentNumber` | User cannot find the incident in Defender portal with a Sentinel-local ID | Show `ProviderIncidentId` |
| Using `OwnerEmail` or `Owner.email` | Column does not exist — query fails | Use `tostring(Owner.assignedTo)` |
| Not filtering phantom incidents | Extra rows appear that the user cannot see in Defender, causing confusion | Add `where not(Status == "Closed" and array_length(AlertIds) == 0)` |
| Skipping `get_table_schema` entirely | Risk of using wrong column names, wasting a round-trip | Validate schema once per session |

## Guardrails — Result Limits & Time Windows

| Rule | Default | Override |
|------|---------|----------|
| **Result cap** | `\| take 200` appended to every query | User may request "all rows" explicitly — remove cap only then |
| **Max time window** | `ago(30d)` | If the user requests >30d, warn: "Large time windows may return many results. Proceed?" and wait for confirmation |
| **Aggregation threshold** | 50 rows | If results exceed 50 rows, present a severity/status summary first, then offer the full table |
| **Schema validation** | Call `get_table_schema("SecurityIncident")` once per session | Skip if already called in the same thread for the same table |

### Large Result Set Handling

When the query returns more than 50 rows:

1. **First:** Present a summary table:
    ```
    | Severity | Open | Closed | Total |
    ```
2. **Then:** Offer: "Show full incident list?" — only render the row-by-row table if the user confirms.
3. **Always** include a `| take 200` hard cap as a safety net.
