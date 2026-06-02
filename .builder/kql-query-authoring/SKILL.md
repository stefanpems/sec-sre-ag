---
name: kql-query-authoring
description: Use this skill when asked to write, create, or help with KQL (Kusto Query Language) queries for Microsoft Sentinel, Defender XDR, or Azure Data Explorer. Triggers on keywords like "write KQL", "create KQL query", "help with KQL", "query [table]", "KQL for [scenario]", or when a user requests queries for specific data analysis scenarios. This skill uses schema validation, Microsoft Learn documentation, and community examples to generate production-ready KQL queries.
---

# KQL Query Authoring - Instructions

## Purpose

Generate validated, production-ready KQL queries by combining schema validation (331+ indexed tables), Microsoft Learn documentation, community examples, and performance best practices.

---

## Execution Environment Constraints

> **⚠️ READ FIRST — This skill operates in a constrained environment.**

| Capability | Available | Notes |
|------------|-----------|-------|
| **KQL Search MCP** (`mcp_kql-search-mc_*`) | ✅ YES | Schema validation, query examples, table discovery, syntax validation |
| **Microsoft Learn MCP** (`mcp_microsoft_lea_*` / `mcp_microsoft_le2_*`) | ✅ YES | Official documentation and code samples |
| **Azure MCP Server** (`mcp_azure_mcp_ser_*`) | ✅ YES | Azure resource management, Log Analytics workspace queries |
| **Log Analytics direct query** | ✅ YES | Can execute KQL directly against Log Analytics workspace tables |
| **Sentinel Data Lake** (`mcp_microsoft_se2_*`) | ❌ NO | Not integrated — cannot currently be connected to Azure SRE Agent. Data reachable via direct API (not yet implemented). Suggest query for user to copy/paste |
| **Advanced Hunting / Triage MCP** (`mcp_mtp_mcp_servi_*`) | ❌ NO | Not integrated — cannot currently be connected to Azure SRE Agent. Data reachable via direct API (not yet implemented). Suggest query for user to copy/paste |
| **Microsoft Graph MCP** (`mcp_microsoft_ent_*`) | ❌ NO | Not integrated — cannot currently be connected to Azure SRE Agent. Data reachable via direct API (not yet implemented). Suggest API calls or portal steps |

**Execution model:**
- **Log Analytics tables**: Execute directly and present results.
- **Sentinel Data Lake / Advanced Hunting tables**: Generate the query, validate syntax/schema with `mcp_kql-search-mc_validate_kql_query`, then present the query to the user in a code block with instructions to copy and execute it in the appropriate portal (Sentinel Logs blade or Defender XDR Advanced Hunting).

---

## Prerequisites

**Required MCP Servers:**

1. **KQL Search MCP Server** — Schema validation, query examples, table discovery
   - **Install**: `npm install -g kql-search-mcp` ([npm](https://www.npmjs.com/package/kql-search-mcp))

2. **Microsoft Docs MCP Server** — Official Microsoft Learn documentation and code samples
   - **GitHub**: [MicrosoftDocs/mcp](https://github.com/MicrosoftDocs/mcp)

**Verification:** Tools should be available as `mcp_kql-search-mc_*` and `mcp_microsoft_lea_*` / `mcp_microsoft_le2_*`.

---

## ⚠️ Known Issues

### `search_favorite_repos` Bug (v1.0.5)

❌ Broken — `ERROR_TYPE_QUERY_PARSING_FATAL`. Use `mcp_kql-search-mc_search_github_examples_fallback` instead.

---

## ⚠️ CRITICAL WORKFLOW RULES - READ FIRST ⚠️

1. **Validate table schema FIRST** — `mcp_kql-search-mc_get_table_schema` to verify table exists, column names, and data types.

2. **Check platform schema** — Sentinel uses `TimeGenerated`; Defender XDR uses `Timestamp`. Microsoft Learn examples default to XDR syntax — always convert before targeting Sentinel.

3. **Use multiple sources** — Schema (authoritative column names) + Microsoft Learn (official patterns) + community queries (real-world examples).

4. **Know which tables are where** — Follow the Tool Selection Rule below:
   - Sentinel-native tables → Data Lake (Sentinel Logs blade) or AH
   - XDR tables ≤ 30d → Advanced Hunting; > 30d → Data Lake
   - XDR-only tables (DeviceTvm*, Exposure*) → Advanced Hunting only
   - Adapt timestamp column when switching platforms

5. **Validate queries before presenting** — Use `mcp_kql-search-mc_validate_kql_query` for syntax/schema check. For Log Analytics tables, execute directly with `| take 5` to verify.

6. **Provide context** — Explain what the query does, expected results, any limitations, and **where to run it** (Sentinel Logs blade, Advanced Hunting portal, or Log Analytics).

7. **Check Known Table Pitfalls** — Read `known-table-pitfalls.md` before querying any table listed there. This avoids the most common KQL errors (wrong column names, wrong table, string vs dynamic fields, etc.).

8. **Read the complete workflow below** before starting.

---

## Tool Selection Rule: Where to Run the Query

**Key facts:**
- When the LA workspace is connected to the unified Defender portal, Advanced Hunting can query **all** tables — XDR-native tables (Device*, Email*, etc.), Sentinel-native tables (SigninLogs, AuditLogs, etc.), and custom tables (`*_CL`).
- **ASIM parser functions** (`_Im_NetworkSession`, `_Im_WebSession`, etc.) are **fully supported in Advanced Hunting** — they resolve against the connected LA workspace. They may NOT resolve in Data Lake queries.

| Factor | Advanced Hunting (AH) | Sentinel Data Lake |
|--------|----------------------|---------------------|
| **Retention** | 30 days (Graph API cap — silently truncates) | 90+ days (workspace-configured) |
| **Cost** | Free for Analytics-tier tables | Billed per query |
| **Safety filter** | MCP-level filter may block offensive-security keywords | No additional filter |
| **Negation syntax** | `!has_any` / `!in~` may fail in `let` blocks — use `not()` | Standard operators work |
| **Workspace functions** | Supports ASIM parsers and workspace-level functions | Cannot resolve workspace-level functions |

| Lookback | Recommended Tool | Why |
|----------|-----------------|-----|
| **≤ 30 days** | Advanced Hunting | Default; free for Analytics-tier tables |
| **> 30 days** | Sentinel Data Lake (Logs blade) | AH silently truncates results to 30d |

**Timestamp adaptation when switching AH → Data Lake:**
- XDR-native tables (`Device*`, `Email*`, `Cloud*`, `Alert*`, `Identity*`, `Entra*`): change `Timestamp` → `TimeGenerated`
- Sentinel/LA tables (`SigninLogs`, `AuditLogs`, `SecurityAlert`, etc.): already use `TimeGenerated` in both tools
- Column name differences (e.g., `EntraIdSignInEvents.AccountUpn` ↔ `SigninLogs.UserPrincipalName`)

**When presenting a query to the user, always specify where to run it:**
- 🔵 **Advanced Hunting**: `https://security.microsoft.com` → Hunting → Advanced Hunting
- 🟢 **Sentinel Logs**: Azure Portal → Microsoft Sentinel → Logs
- 🟡 **Log Analytics**: Azure Portal → Log Analytics workspace → Logs (can be executed directly by this skill)

---

## KQL Pre-Flight Checklist

**This checklist applies to EVERY KQL query — whether the user said "query", "hunt", "search", "look for", "find", "do we have X", "is there any Y", or just pasted an IoC/keyword/tool name.**

Before writing any KQL query, complete these steps **in order**:

### Step 0: Pick the Right Platform for the Lookback Window

Check the user's requested lookback:
- **≤ 30 days** → Advanced Hunting (suggest user runs in AH portal)
- **> 30 days** → Sentinel Data Lake (suggest user runs in Sentinel Logs blade)
- **Log Analytics tables** (non-security, operational) → Can execute directly

### Step 1: Verify Table Schema (MANDATORY)

Before querying any table for the first time in a session, verify the schema:
- Use `mcp_kql-search-mc_search_tables` or `mcp_kql-search-mc_get_table_schema`
- Confirm column names, types, and which columns contain GUIDs vs human-readable values
- **⚠️ Column name hallucination:** LLMs frequently use column names from one table on a different table. Common confusions: `Severity` vs `AlertSeverity`, `OS` vs `OSPlatform`, `IPAddress` vs `RemoteIP`, `Entities` (SecurityAlert only — not on SecurityIncident). Always verify.

### Step 2: Check Known Table Pitfalls

**Review `known-table-pitfalls.md` before querying any table listed there.** The file documents 20+ table-specific gotchas including wrong column names, dynamic vs string field types, AH-only tables, deprecated tables, and more.

### Step 3: Validate Before Presenting

- Use `mcp_kql-search-mc_validate_kql_query` to check syntax/schema
- Ensure datetime filter is the FIRST filter in the query
- Use `take` or `summarize` to limit results
- For Log Analytics tables: execute directly with `| take 5` to verify results
- For Sentinel/AH tables: validate with KQL Search MCP, then present as a copyable code block

### Step 4: Sanity-Check Zero Results

**If a query returns 0 results for a commonly-populated table (Log Analytics execution), STOP and verify:**

| Check | Action |
|-------|--------|
| Is the query logic correct? | Review join conditions, filter values, and field types |
| Am I filtering on GUIDs where I used a name? | Check schema for field content type |
| Is the date range appropriate? | Ensure the time filter covers the expected data window |
| Does the table exist in this data source? | Verify table availability on the target platform |

⛔ **DO NOT report "no results found" until you have verified the query itself is correct.**

---

## Query Authoring Workflow

### Step 1: Understand User Requirements

**Extract key information:**
- **Table(s) needed**: Which data source? (e.g., `EntraIdSignInEvents`, `EmailEvents`, `SecurityAlert`)
- **Time range**: How far back? (e.g., last 7 days, specific date range)
- **Filters**: What specific conditions? (e.g., user, IP, threat type)
- **Output**: Statistics, detailed records, time series, aggregations?
- **Platform**: Sentinel or Defender XDR? (affects column names)
- **Deployment target**: Custom detection rule? (see CD-Aware Output below)

**Custom Detection Intent Detection:**

If the user mentions "custom detection", "detection rule", "deploy as detection", "CD rule":

1. **Design queries with CD constraints** — row-level output, mandatory columns (`TimeGenerated`, `DeviceName`, `ReportId`), no bare `summarize`
2. **Include `cd-metadata` blocks** in the output (see CD-Aware Output section)
3. **Still write queries in Sentinel format** (with `let` variables, 7d lookback) — adaptation to CD format happens at deployment time

### Step 2: Get Table Schema (MANDATORY)

```
mcp_kql-search-mc_get_table_schema("<table_name>")
```

Returns: category, description, all columns with data types, and example queries. Use this to verify column names and understand data types.

### Step 3: Get Official Code Samples

```
mcp_microsoft_lea_microsoft_code_sample_search(
  query: "<table_name> <scenario description>",
  language: "kusto"
)
```

Include table name + scenario in the query (e.g., `"EmailEvents phishing detection"`).

### Step 4: Get Community Examples

```
mcp_kql-search-mc_search_github_examples_fallback(
  table_name: "<table_name>",
  description: "<goal description>"
)
```

Also available: `mcp_kql-search-mc_search_kql_repositories` to find KQL-focused repos.

### Step 5: Generate Query

Combine insights: schema for column names, Learn for patterns, community for techniques.

**Standalone queries rule:** When generating MULTIPLE separate queries, each must start directly with the table name — never use shared `let` variables across separate queries (they run independently). Use `let` variables only within a single complex query.

### Step 6: Validate and Test (MANDATORY)

**Different validation paths based on table type:**

#### Path A: Log Analytics Tables (Direct Execution)

1. Convert `Timestamp` → `TimeGenerated` if adapting MS Learn examples for Sentinel
2. Execute directly against Log Analytics with `| take 5`
3. Verify results are sensible — check for empty results (wrong table/time/filters)
4. Fix schema mismatches or syntax errors, re-test
5. Remove test limits, present to user

#### Path B: Sentinel Data Lake / Advanced Hunting Tables (No Direct Execution)

1. Convert timestamp columns as needed for the target platform
2. Validate with `mcp_kql-search-mc_validate_kql_query("<query>")` — syntax/schema check
3. Present the query to the user in a KQL code block
4. Specify **where to run it**: Advanced Hunting portal or Sentinel Logs blade
5. Explain expected results and any caveats

**Common errors:**

| Error | Fix |
|-------|-----|
| `Failed to resolve column 'Timestamp'` | Use `TimeGenerated` (Sentinel) |
| `Failed to resolve column 'TimeGenerated'` | Use `Timestamp` (XDR AH) |
| `Table not found` | Verify with `get_table_schema`; check if AH-only or Data Lake-only |
| `expected string expression` | Add `tostring()` after `mv-expand` or `parse_json` |
| Query timeout / too many results | Add datetime filter + `take` or `summarize` |

### Step 7: Format and Deliver Output

**Single query:** Provide directly in chat with brief explanation and expected results.

**Multiple queries (3+):** Create a markdown file with the standardized metadata header.

**Required metadata header template** (first 10 lines of every query file):

```markdown
# <Descriptive Title>

**Created:** YYYY-MM-DD  
**Platform:** Microsoft Sentinel | Microsoft Defender XDR | Both  
**Tables:** <comma-separated exact KQL table names>  
**Keywords:** <comma-separated searchable terms — attack techniques, scenarios, field names>  
**MITRE:** <comma-separated technique IDs, e.g., T1098.001, T1136.003, TA0008>  
**Domains:** <comma-separated domain tags from the valid set below>  
**Timeframe:** Last N days (configurable)  
```

**Valid domain tags:** `incidents`, `identity`, `spn`, `endpoint`, `email`, `admin`, `cloud`, `exposure`

| Field | Purpose |
|-------|---------|
| `Tables:` | Exact KQL table names for discovery |
| `Keywords:` | Searchable terms for attack scenarios, operations, field names |
| `MITRE:` | ATT&CK technique/tactic IDs for cross-referencing |
| `Domains:` | Domain tags for cross-referencing |

Include per-query documentation with Purpose, Thresholds, Expected Results, and Tuning guidance.

**Heading format:** Use `### Query N: <Title>` or `## Query N: <Title>` for query headings — the number prefix ensures proper ordering.

**Execution instructions:** For each query, include an annotation indicating where to run it:

```markdown
> 🔵 **Run in:** Advanced Hunting (`https://security.microsoft.com` → Hunting → Advanced Hunting)
```
or
```markdown
> 🟢 **Run in:** Sentinel Logs (Azure Portal → Microsoft Sentinel → Logs)
```
or
```markdown
> 🟡 **Run in:** Log Analytics (can be executed directly)
```

### CD-Aware Output

When CD intent is detected (Step 1), each query MUST include a `<!-- cd-metadata -->` HTML comment block.

**Valid cd-metadata fields (exhaustive list):**

| Field | Required | Notes |
|-------|----------|-------|
| `cd_ready` | Always | `true` or `false` |
| `schedule` | If cd_ready | `"0"` (NRT), `"1H"`, `"3H"`, `"12H"`, `"24H"` |
| `category` | If cd_ready | MITRE tactic (e.g., `Persistence`, `CredentialAccess`) |
| `title` | Optional | Dynamic title with `{{Column}}` placeholders (max 3 unique columns across title + description) |
| `impactedAssets` | If cd_ready | Array of `type` + `identifier` pairs |
| `recommendedActions` | Optional | Triage and response guidance string |
| `adaptation_notes` | Optional | What needs to change for CD format |

**⛔ `responseActions` is NOT a valid cd-metadata field.** It shares a name with the Graph API field that is **explicitly prohibited** in LLM-authored detections (`"responseActions": []` is mandatory). Do not include it. Put incident response guidance in `recommendedActions` instead.

```markdown
<!-- cd-metadata
cd_ready: true
schedule: "1H"
category: "Persistence"
title: "Suspicious Scheduled Task on {{DeviceName}}"
impactedAssets:
  - type: device
    identifier: DeviceName
recommendedActions: "Investigate the task XML and decode any encoded payloads."
adaptation_notes: "Remove let blocks, add mandatory columns"
-->
```

For queries not suitable for CD (baseline/statistical):
```markdown
<!-- cd-metadata
cd_ready: false
adaptation_notes: "Statistical baseline — requires bare summarize, not CD-compatible"
-->
```

**Summary table:** Include a `CD` column in any Implementation Priority table: `✅ 1H` / `❌`.

---

## Tool Quick Reference

| Tool | Purpose |
|------|---------|
| `mcp_kql-search-mc_get_table_schema` | Get table columns, types, example queries (Step 2) |
| `mcp_microsoft_lea_microsoft_code_sample_search` | Official MS Learn KQL samples — use `language: "kusto"` (Step 3) |
| `mcp_kql-search-mc_search_github_examples_fallback` | Community KQL examples by table name (Step 4) |
| `mcp_kql-search-mc_search_kql_repositories` | Find GitHub repos with KQL collections |
| `mcp_kql-search-mc_validate_kql_query` | Syntax/schema validation (Step 6) |
| `mcp_kql-search-mc_find_column` | Find which tables contain a specific column |
| `mcp_kql-search-mc_generate_kql_query` | Auto-generate schema-validated query from natural language |
| `mcp_kql-search-mc_search_tables` | Discover tables using natural language |
| `mcp_kql-search-mc_get_query_documentation` | Get documentation for a KQL query |
| `mcp_kql-search-mc_list_table_categories` | List available table categories |
| `mcp_kql-search-mc_get_tables_by_category` | Get tables within a specific category |
| `mcp_microsoft_lea_microsoft_docs_search` | Search Microsoft Learn documentation |
| `mcp_microsoft_lea_microsoft_docs_fetch` | Fetch full content from a Microsoft Learn page |

**Not integrated with Azure SRE Agent** (these MCP servers cannot currently be connected — data reachable via direct API, but not yet implemented):

| Tool | Alternative |
|------|-------------|
| `mcp_microsoft_se2_query_lake` (Sentinel Data Lake) | Generate query → present to user → user runs in Sentinel Logs blade |
| `mcp_mtp_mcp_servi_RunAdvancedHuntingQuery` (AH) | Generate query → present to user → user runs in AH portal |
| `mcp_microsoft_ent_microsoft_graph_*` (Graph API) | Suggest Graph API calls or portal steps to user |

---

## Schema Differences

| Platform | Timestamp Column | Notes |
|----------|-----------------|-------|
| **Sentinel / Log Analytics** | `TimeGenerated` | All ingested logs |
| **Defender XDR (Advanced Hunting)** | `Timestamp` | XDR-native tables only; Sentinel tables in AH still use `TimeGenerated` |

**Other common differences:** `Identity`/`UserPrincipalName` (Sentinel) vs `AccountUpn`/`AccountName` (XDR); `IPAddress` (Sentinel) vs `RemoteIP`/`LocalIP` (XDR). Always verify with `get_table_schema`.

### Sign-In Table Selection (High-Frequency Queries)

Sign-in queries are the most common query type. Use this decision rule:

| Scenario | Table | Key Differences |
|----------|-------|-----------------|
| **AH query, ≤30d** | **`EntraIdSignInEvents`** (single table) | Covers both interactive + non-interactive. `ErrorCode` (int), `AccountUpn`, `Country`/`City` (direct strings), `LogonType` (JSON array — use `has`), `Timestamp` |
| **Data Lake / >30d** | **`SigninLogs` + `AADNonInteractiveUserSignInLogs`** (union) | `ResultType` (string), `UserPrincipalName`, `parse_json(LocationDetails)` needed for geo, `IsInteractive` (bool), `TimeGenerated` |

**Common mistakes:**
- Using `union SigninLogs, AADNonInteractiveUserSignInLogs` in AH queries — unnecessary, `EntraIdSignInEvents` covers both
- Using `LogonType == "nonInteractiveUser"` — values are JSON arrays (`["nonInteractiveUser"]`), use `has`
- Using `ResultType` on `EntraIdSignInEvents` — column is `ErrorCode` (int), not string

---

## Best Practices

### Performance Optimization

> **Reference:** [KQL Best Practices — Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/best-practices?view=microsoft-fabric)

#### 1. Filter on datetime columns first

The most important optimization. Datetime predicates use efficient index-based shard elimination, skipping entire data partitions without scanning.

```kql
// ✅ Correct — datetime first, then selective string filters
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName =~ "user@domain.com"

// ❌ Wrong — string filter before datetime
SigninLogs
| where UserPrincipalName =~ "user@domain.com"
| where TimeGenerated > ago(7d)
```

#### 2. Use `has` over `contains` for token matching

`has` uses the term index for full-token lookup. `contains` scans every character — dramatically slower on large tables.

```kql
// ✅ Faster — term-level index lookup
| where UserPrincipalName has "admin"

// ❌ Slower — full substring scan
| where UserPrincipalName contains "admin"
```

Use `contains` only when you genuinely need substring matching (e.g., fragments inside URL paths).

#### 3. Prefer case-sensitive operators

Case-sensitive comparisons (`==`, `in`, `has_cs`) are faster than case-insensitive (`=~`, `in~`, `has`). Use case-insensitive only when casing is unpredictable.

```kql
// ✅ Faster — ActionType, Operation, OfficeWorkload have consistent casing
| where ActionType == "LogonFailed"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where OfficeWorkload == "Exchange"

// 🔵 Use =~ only when casing varies (e.g., user-entered UPNs)
| where UserPrincipalName =~ "user@domain.com"
```

**Common fields with consistent casing** (always use `==` / `in`): `ActionType`, `Operation`, `OfficeWorkload`, `EventID`, `ResultType`, `DeliveryAction`, `EmailDirection`, `LogonType`, `Severity`, `Status`, `Classification`.

#### 4. Filter tables BEFORE joins

Pre-filter both sides of a join to reduce data volume. Move `where` clauses into subqueries.

```kql
// ✅ Correct — filter KB table before joining
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | where CvssScore >= 8.0
) on CveId

// ❌ Wrong — joins full tables, filters after
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where IsExploitAvailable == true
```

**Join sizing rules:**
- Smaller table on the left (or `hint.strategy=broadcast` when left is small)
- `in` instead of `left semi join` for single-column filtering
- `lookup` instead of `join` when right side is small (<50 MB)
- `hint.shufflekey=<key>` when both sides are large with high-cardinality join key

#### 5. Use `materialize()` for multi-referenced `let` statements

Without `materialize()`, the engine may recompute the `let` expression each time it's referenced.

```kql
// ✅ Computed once, reused twice
let SprayFailures = materialize(
    EntraIdSignInEvents
    | where Timestamp > ago(7d)
    | where ErrorCode in (50126, 50053, 50057)
    | summarize FailedAttempts = count(), TargetUsers = dcount(AccountUpn)
        by SourceIP = IPAddress
    | where TargetUsers >= 5);
```

#### 6. Narrow `arg_max` to only needed columns

`arg_max(TimeGenerated, *)` materializes every column. Specify only what you use.

```kql
// ✅ Only 5 columns materialized
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, Entities, Tactics, Techniques, AlertName, AlertSeverity) by SystemAlertId

// ❌ Materializes all 30+ columns
SecurityAlert
| summarize arg_max(TimeGenerated, *) by SystemAlertId
```

#### 7. Pre-filter before JSON parsing

For rare key/value lookups in dynamic columns, use `has` to eliminate rows before expensive `parse_json()`.

```kql
// ✅ Term filter first, JSON parse on survivors
AuditLogs
| where tostring(TargetResources) has "MyApp"
| extend Target = tostring(parse_json(tostring(TargetResources[0])).displayName)
| where Target == "MyApp"
```

#### 8. Filter on table columns, not calculated columns

Filtering on native columns enables index usage; calculated columns force full scans.

```kql
// ✅ Filter on native column
SecurityEvent | where EventID == 4625

// ❌ Filter on calculated column
SecurityEvent | extend Cat = case(EventID == 4625, "Fail", ...) | where Cat == "Fail"
```

#### 9. Project only needed columns early

Drop unnecessary columns before expensive operators (`join`, `summarize`, `mv-expand`) to reduce memory and shuffling.

#### 10. Use `take` or `summarize` to limit results

Unbounded queries on large tables consume excessive resources.

#### 11. Platform-specific dynamic column access

In AH, `AuditLogs.InitiatedBy` and `TargetResources` are native dynamic — use direct dot-notation. In Data Lake, they may be string-typed requiring `parse_json()`.

```kql
// ✅ Advanced Hunting — direct access
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)

// ✅ Data Lake — parse_json wrapper
| extend Actor = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)

// 🔵 Safe in both — stringify full field
| where tostring(InitiatedBy) has "user@domain.com"
```

### Security and Privacy

- **Limit sensitive data exposure** — redact PII with `strcat(substring(UPN, 0, 3), "***")` when appropriate
- **Filter early** — reduce dataset before projecting sensitive columns

### Code Quality

- **Comments** — explain what the query does and why key filters are applied
- **Meaningful variable names** — `let SuspiciousIPs = ...` not `let x = ...`
- **Standalone queries** — when providing multiple separate queries, each MUST start with the table name directly. Never share `let` variables across queries the user will run independently

---

## Common KQL Anti-Patterns (All Tables)

These universal KQL mistakes are frequent LLM errors regardless of which table is queried:

| Anti-Pattern | Error | Fix |
|-------------|-------|-----|
| `mv-expand` on string column containing JSON | `expanded expression expected to have dynamic type` | `mv-expand parsed = parse_json(StringColumn)` — parse_json() BEFORE mv-expand |
| `dcount()` on dynamic column | `argument #1 cannot be dynamic` | `dcount(tostring(DynamicColumn))` — cast to scalar |
| `bin()` missing argument | `bin(): function expects 2 argument(s)` | Always provide both: `bin(TimeGenerated, 1h)` |
| `iff()` with mismatched branch types | `@then data type (real) must match @else (long)` | Cast both branches: `iff(cond, todouble(x), todouble(y))` |
| Joining on dynamic column | `join key 'X' is of a 'dynamic' type` | Cast before join: `| extend AlertId = tostring(AlertId) | join ...` |
| Duplicate column in `union` | `column named 'X' already exists` | Use `project-away` or `project-rename` before union |
| `prev()`/`next()` on unserialized rowset | `Function 'prev' cannot be invoked in current context` | Add `| serialize` before `prev()`, `next()`, `row_cumsum()`, `row_number()` |

---

## Dynamic Type Casting

**Common "expected string expression" error:** After `mv-expand`, `parse_json`, or `split`, values are `dynamic` — string functions fail. Always convert first:

```kql
// After mv-expand
| mv-expand AuthDetails
| extend AuthMethod = tostring(AuthDetails.authenticationMethod)

// After split
| extend Parts = split(UPN, "@")
| extend Domain = tostring(Parts[1])
```

**Rule of thumb:** If you get "expected string expression", add `tostring()`.

---

## Companion Reference Files

- **`known-table-pitfalls.md`** — 20+ table-specific gotchas (column names, dynamic vs string, AH-only tables, deprecated tables). **Read before querying any listed table.**
- **`ad-hoc-query-examples.md`** — Canonical query patterns (SecurityAlert→SecurityIncident join, AuditLogs best practices, etc.).
