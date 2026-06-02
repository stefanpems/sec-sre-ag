# MCP Usage Monitoring — Pre-Authored KQL Queries

> 🔴 **MANDATORY: Execute these queries EXACTLY as written.** Substitute only the time range parameter (e.g., `ago(30d)` → `ago(90d)`).
> These queries are schema-verified and encode mitigations for pitfalls documented in [SKILL.md](SKILL.md#known-pitfalls).
>
> **Execution method:** All queries run via `mcp_azure_mcp_ser_monitor` against the user's Log Analytics workspace.
> All tables use `TimeGenerated` (not `Timestamp`).
>
> **⚠️ Before executing any query:** Load the Azure MCP monitor tool with `tool_search` for "azure monitor workspace".

| Action | Status |
|--------|--------|
| Rewriting a pre-authored query from scratch | ❌ **PROHIBITED** |
| Removing `parse_json()` / `tostring()` wrappers | ❌ **PROHIBITED** |
| Substituting column names without schema verification | ❌ **PROHIBITED** |
| Using `has` instead of `contains` for CamelCase fields | ❌ **PROHIBITED** |

---

## Query 1: Unified Daily MCP Activity Trend

**Purpose:** Daily `Server | Day | Calls | Errors | ErrorRate` for ALL 4 MCP servers in one pass. Run ONCE in Phase 1.
**Feeds:** SVG dashboard Row 5 line chart, volume anomaly detection.

```kql
// Unified Daily MCP Activity Trend — all 4 MCP servers in one pass
// Configurable: replace 30d with desired lookback
let lookback = 30d;
// --- Graph MCP (AppId e8c77dc2) ---
let graph_mcp = MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(lookback)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| summarize Calls = count(),
    Errors = countif(ResponseStatusCode >= 400)
    by Day = bin(TimeGenerated, 1d)
| extend Server = "Graph MCP";
// --- Triage MCP (AppId 7b7b3966) ---
let triage_mcp = MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(lookback)
| where AppId == "7b7b3966-1961-47b5-b080-43ca5482e21c"
| summarize Calls = count(),
    Errors = countif(ResponseStatusCode >= 400)
    by Day = bin(TimeGenerated, 1d)
| extend Server = "Triage MCP";
// --- Data Lake MCP (CloudAppEvents RecordType 379 + InterfaceNotProvided) ---
let data_lake_mcp = CloudAppEvents
| where TimeGenerated >= ago(lookback)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend RecordType = toint(RawData.RecordType),
    Interface = tostring(RawData.Interface),
    FailureReason = tostring(RawData.FailureReason)
| where RecordType == 379 and (Interface == "InterfaceNotProvided" or isempty(Interface))
| summarize Calls = count(),
    Errors = countif(isnotempty(FailureReason) and FailureReason != "")
    by Day = bin(TimeGenerated, 1d)
| extend Server = "Data Lake MCP";
// --- Azure MCP/CLI (AppId 04b07795 — shared with Azure CLI) ---
let azure_interactive = SigninLogs
| where TimeGenerated >= ago(lookback)
| where AppId == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
| project TimeGenerated, ResultType;
let azure_noninteractive = AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(lookback)
| where AppId == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
| project TimeGenerated, ResultType;
let azure_mcp = union azure_interactive, azure_noninteractive
| summarize Calls = count(),
    Errors = countif(ResultType != "0" and ResultType != "")
    by Day = bin(TimeGenerated, 1d)
| extend Server = "Azure MCP/CLI";
// --- Union all servers ---
union graph_mcp, triage_mcp, data_lake_mcp, azure_mcp
| extend ErrorRate = iff(Calls > 0, round(100.0 * Errors / Calls, 1), 0.0)
| project Server, Day, Calls, Errors, ErrorRate
| order by Day asc, Server asc
```

---

## Query 2: Graph MCP — Endpoint & Activity Summary

**Purpose:** Per-endpoint rows with call counts, sensitivity flag, off-hours metrics, error rates, and user sets.
**Replaces:** former Q2 (Top Endpoints), Q3 (Sensitive API Access), Q11 (Off-Hours Activity).
**Derivation:** Top endpoints = `order by CallCount desc`. Sensitive endpoints = `where IsSensitive`. Off-hours % = `sum(OffHoursCalls)/sum(CallCount)`.

```kql
// Graph MCP — single-pass endpoint analysis with sensitivity + off-hours enrichment
let sensitive_patterns = dynamic([
    "roleManagement", "roleAssignments", "roleEligibility",
    "authentication/methods", "identityProtection", "riskyUsers",
    "riskDetections", "conditionalAccess", "servicePrincipals",
    "appRoleAssignments", "oauth2PermissionGrants",
    "auditLogs", "directoryRoles", "privilegedAccess",
    "security/alerts", "security/incidents"
]);
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| extend Endpoint = tostring(split(RequestUri, "?")[0])
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| extend DayOfWeek = dayofweek(TimeGenerated) / 1d
| extend IsOffHours = HourOfDay < 8 or HourOfDay >= 18 or DayOfWeek >= 5
| extend IsSensitive = RequestUri has_any (sensitive_patterns)
| summarize 
    CallCount = count(),
    DistinctUsers = dcount(UserId),
    ErrorCount = countif(ResponseStatusCode >= 400),
    AvgDurationMs = round(avg(DurationMs), 0),
    OffHoursCalls = countif(IsOffHours),
    Methods = make_set(RequestMethod, 5),
    Users = make_set(UserId, 10),
    LastUsed = max(TimeGenerated)
    by Endpoint, IsSensitive
| extend 
    ErrorRate = round(100.0 * ErrorCount / CallCount, 1),
    OffHoursPct = round(100.0 * OffHoursCalls / CallCount, 1)
| order by CallCount desc
| take 50
```

---

## Query 3: Sentinel MCP — Authentication Events

**Purpose:** Who is authenticating to Sentinel MCP (via VS Code, Copilot Studio, browser).

```kql
// Who is authenticating to Sentinel MCP
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResourceDisplayName =~ "Sentinel Platform Services"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress, 
    ErrorCode = tostring(parse_json(Status).errorCode),
    ConditionalAccessStatus, AuthenticationRequirement, ClientAppUsed,
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

---

## Query 4: Sentinel MCP — Client App Breakdown

**Purpose:** Which client apps (VS Code, Copilot Studio, browser) are accessing Sentinel MCP.

```kql
// Client apps accessing Sentinel MCP
SigninLogs
| where TimeGenerated >= ago(30d)
| where ResourceDisplayName =~ "Sentinel Platform Services"
| summarize 
    SignInCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10),
    LastSeen = max(TimeGenerated)
    by AppDisplayName, AppId, ClientAppUsed
| order by SignInCount desc
```

---

## Query 5: Sentinel Triage MCP — API Call Activity (Dedicated AppId)

**Purpose:** Measure Sentinel Triage MCP API calls via its dedicated AppId `7b7b3966`.

```kql
// Triage MCP API calls via dedicated AppId in MicrosoftGraphActivityLogs
let triage_mcp_appid = "7b7b3966-1961-47b5-b080-43ca5482e21c";
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == triage_mcp_appid
| extend Endpoint = extract(@"/v\d\.\d/(.+?)(\?|$)", 1, RequestUri)
| summarize 
    Calls = count(),
    DistinctUsers = dcount(UserId),
    Users = make_set(UserId, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by RequestMethod, Endpoint
| order by Calls desc
| take 25
```

---

## Query 6: Sentinel Triage MCP — Authentication Events (SigninLogs)

**Purpose:** Triage MCP authentication events from SigninLogs + AADNonInteractiveUserSignInLogs.

```kql
// Triage MCP authentication events
let triage_mcp_appid = "7b7b3966-1961-47b5-b080-43ca5482e21c";
let signinlogs_interactive = SigninLogs
| where TimeGenerated >= ago(30d)
| where AppId == triage_mcp_appid
| extend SignInType = "Interactive"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress,
    ResultType = tostring(ResultType),
    ResultDescription = tostring(ResultDescription),
    SignInType,
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Browser = tostring(parse_json(DeviceDetail).browser),
    Country = tostring(parse_json(LocationDetails).countryOrRegion),
    City = tostring(parse_json(LocationDetails).city);
let signinlogs_noninteractive = AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(30d)
| where AppId == triage_mcp_appid
| extend SignInType = "NonInteractive"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress,
    ResultType = tostring(ResultType),
    ResultDescription = tostring(ResultDescription),
    SignInType,
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Browser = tostring(parse_json(DeviceDetail).browser),
    Country = tostring(parse_json(LocationDetails).countryOrRegion),
    City = tostring(parse_json(LocationDetails).city);
union signinlogs_interactive, signinlogs_noninteractive
| summarize
    SignIns = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 10),
    IPs = make_set(IPAddress, 10),
    Countries = make_set(Country, 10),
    LastSeen = max(TimeGenerated)
    by AppDisplayName, SignInType, ResourceDisplayName
| order by SignIns desc
```

---

## Query 7: LAQueryLogs — Advanced Hunting Downstream Queries

**Purpose:** SUPPLEMENTARY signal — AH queries that hit connected Log Analytics workspace tables.

```kql
// Advanced Hunting downstream queries
LAQueryLogs
| where TimeGenerated >= ago(30d)
| where AADClientId == "fc780465-2017-40d4-a0c5-307022471b92" and RequestClientApp == "M365D_AdvancedHunting"
| summarize 
    QueryCount = count(),
    DistinctUsers = dcount(AADEmail),
    Users = make_set(AADEmail, 10),
    AvgCPUMs = avg(StatsCPUTimeMs),
    TotalRowsReturned = sum(ResponseRowCount),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AADClientId, RequestClientApp
| order by QueryCount desc
```

---

## Query 8: All Workspace Query Sources — Complete Governance View

**Purpose:** Every client querying the workspace — MCP and non-MCP combined.

```kql
// All workspace query sources
LAQueryLogs
| where TimeGenerated >= ago(30d)
| summarize 
    QueryCount = count(),
    DistinctUsers = dcount(AADEmail),
    AvgCPUMs = avg(StatsCPUTimeMs),
    TotalRowsReturned = sum(ResponseRowCount)
    by AADClientId
| order by QueryCount desc
```

---

## Query 9: Graph MCP — Caller Attribution (User vs SPN)

**Purpose:** Attribute Graph MCP calls to User, Service Principal, or SPN subtype.

```kql
// Graph MCP caller attribution
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(30d)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| extend CallerType = case(
    isnotempty(ServicePrincipalId) and isempty(UserId), "ServicePrincipal/Agent (App-Only)",
    isnotempty(UserId) and isnotempty(ServicePrincipalId), "Delegated (User+SPN/Agent OBO)",
    isnotempty(UserId) and isempty(ServicePrincipalId), "User (Delegated)",
    "Unknown")
| extend AuthMethod = case(
    ClientAuthMethod == 0, "Public Client",
    ClientAuthMethod == 1, "Client Secret",
    ClientAuthMethod == 2, "Client Certificate",
    "Unknown")
| summarize
    CallCount = count(),
    DistinctEndpoints = dcount(tostring(split(RequestUri, "?")[0])),
    SuccessRate = round(100.0 * countif(ResponseStatusCode >= 200 and ResponseStatusCode < 300) / count(), 1),
    SampleEndpoints = make_set(tostring(split(RequestUri, "?")[0]), 5),
    IPs = make_set(IPAddress, 5)
    by CallerType, AuthMethod, UserId, ServicePrincipalId
| order by CallCount desc
```

**Post-processing:** For `ServicePrincipal/Agent (App-Only)` rows, since Microsoft Graph MCP is not integrated with Azure SRE Agent, cross-reference SPNs with `AADServicePrincipalSignInLogs` in the workspace:
```kql
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(30d)
| where ServicePrincipalId == "<SPN_ID_FROM_Q9>"
| summarize arg_max(TimeGenerated, *) by ServicePrincipalId
| project ServicePrincipalId, ServicePrincipalName, AppId, ResourceDisplayName
```

---

## Query 10: Data Lake MCP — Access Pattern Summary

**Purpose:** Single-pass access pattern delineation + tool/table/workspace inventory.
**⚠️ Pitfall-aware:** Uses `contains` (not `has`), `parse_json(tostring())`, filters `Completed` only.

```kql
// Data Lake MCP — access pattern delineation
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    RecordType = toint(RawData.RecordType),
    ToolName = tostring(RawData.ToolName),
    Interface = tostring(RawData.Interface),
    ExecutionDuration = todouble(RawData.ExecutionDuration),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead),
    DatabasesRead = tostring(RawData.DatabasesRead),
    TotalRows = toint(RawData.TotalRows),
    UserId_raw = tostring(RawData.UserId),
    InputParams = tostring(RawData.InputParameters)
| extend 
    AccessPattern = case(
        RecordType == 403 and Interface == "IMcpToolTemplate", "MCP Server-Driven",
        RecordType == 379 and (Interface == "InterfaceNotProvided" or isempty(Interface)), "MCP-Driven (Probable)",
        RecordType == 379 and Interface has "msglakeexplorer", "Portal (Data Lake Explorer)",
        RecordType == 379 and Interface has "msgjobmanagement", "Scheduled Jobs",
        RecordType == 379, "Other Direct KQL",
        "Other"),
    IsSuccess = isempty(FailureReason) or FailureReason == "",
    HasKQLQuery = InputParams has "query"
| where Operation contains "Completed" or RecordType == 379
| summarize
    TotalCalls = count(),
    SuccessCount = countif(IsSuccess),
    FailureCount = countif(not(IsSuccess)),
    DistinctTools = dcount(ToolName),
    Tools = make_set(ToolName, 20),
    DistinctTables = dcount(TablesRead),
    Tables = make_set(TablesRead, 30),
    Workspaces = make_set(DatabasesRead, 5),
    AvgDurationSec = round(avg(ExecutionDuration), 2),
    TotalRowsReturned = sum(TotalRows),
    DistinctUsers = dcount(UserId_raw),
    Users = make_set(UserId_raw, 10),
    KQLQueryCount = countif(HasKQLQuery),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccessPattern
| extend ErrorRate = round(100.0 * FailureCount / TotalCalls, 1)
| order by TotalCalls desc
```

**Post-processing:**
- If `MCP Server-Driven` (RecordType 403) has results → use directly.
- If 0 rows but `MCP-Driven (Probable)` has results → report with audit gap caveat.

---

## Query 11: Data Lake MCP — Interface Breakdown

**Purpose:** Breakdown by Interface — MCP vs Portal vs Jobs.

```kql
// Data Lake access by Interface
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    RecordType = toint(RawData.RecordType),
    ToolName = tostring(RawData.ToolName),
    Interface = tostring(RawData.Interface),
    ExecutionDuration = todouble(RawData.ExecutionDuration),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead),
    UserId_raw = tostring(RawData.UserId)
| where Operation contains "Completed" or RecordType == 379
| extend 
    GroupKey = iff(RecordType == 403, coalesce(ToolName, "unknown_tool"), coalesce(Interface, "InterfaceNotProvided")),
    IsSuccess = isempty(FailureReason) or FailureReason == "",
    Source = iff(RecordType == 403, "MCP Tool (RecordType 403)", "Interface (RecordType 379)")
| summarize
    CallCount = count(),
    SuccessCount = countif(IsSuccess),
    FailureCount = countif(not(IsSuccess)),
    AvgDurationSec = round(avg(ExecutionDuration), 2),
    MaxDurationSec = round(max(ExecutionDuration), 2),
    TablesAccessed = make_set(TablesRead, 20),
    DistinctUsers = dcount(UserId_raw),
    Users = make_set(UserId_raw, 10),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by GroupKey, Source
| extend ErrorRate = round(100.0 * FailureCount / CallCount, 1)
| order by CallCount desc
```

---

## Query 12: Data Lake MCP — Error Analysis

**Purpose:** Analyze failed Data Lake queries grouped by AccessPattern and ErrorCategory.

```kql
// Data Lake MCP error analysis
CloudAppEvents
| where TimeGenerated >= ago(30d)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| extend 
    Operation = tostring(RawData.Operation),
    RecordType = toint(RawData.RecordType),
    ToolName = tostring(RawData.ToolName),
    Interface = tostring(RawData.Interface),
    FailureReason = tostring(RawData.FailureReason),
    TablesRead = tostring(RawData.TablesRead),
    UserId_raw = tostring(RawData.UserId)
| where Operation contains "Completed" or RecordType == 379
| where isnotempty(FailureReason) and FailureReason != ""
| extend 
    AccessPattern = case(
        RecordType == 403 and Interface == "IMcpToolTemplate", "MCP Server-Driven",
        RecordType == 379 and (Interface == "InterfaceNotProvided" or isempty(Interface)), "MCP-Driven (Probable)",
        RecordType == 379 and Interface has "msglakeexplorer", "Portal (Data Lake Explorer)",
        RecordType == 379 and Interface has "msgjobmanagement", "Scheduled Jobs",
        RecordType == 379, "Other Direct KQL",
        "Other"),
    ErrorCategory = case(
        FailureReason has "SemanticError", "Schema/Semantic Error",
        FailureReason has "SyntaxError", "KQL Syntax Error",
        FailureReason has "Unauthorized" or FailureReason has "403", "Permission Denied",
        FailureReason has "Timeout", "Query Timeout",
        FailureReason has "NotFound", "Table/Resource Not Found",
        "Other Error")
| summarize
    ErrorCount = count(),
    Tools = make_set(ToolName, 10),
    Tables = make_set(TablesRead, 10),
    Users = make_set(UserId_raw, 10),
    SampleErrors = make_set(substring(FailureReason, 0, 150), 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by AccessPattern, ErrorCategory
| order by AccessPattern asc, ErrorCount desc
```

---

## Query 13: Azure MCP Server — Authentication Events (SigninLogs)

**Purpose:** Detect Azure MCP Server authentication events via Azure CLI AppId.
**⚠️ SHARED APPID:** `04b07795` is shared with manual Azure CLI. This query returns ALL Azure CLI sign-ins.

```kql
// Azure MCP Server / Azure CLI authentication events
let azure_mcp_appid = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
let signinlogs_interactive = SigninLogs
| where TimeGenerated >= ago(90d)
| where AppId == azure_mcp_appid
| extend SignInType = "Interactive"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress, 
    ResultType = tostring(ResultType),
    ResultDescription = tostring(ResultDescription),
    UserAgent, SignInType,
    ConditionalAccessStatus = tostring(ConditionalAccessStatus),
    AuthenticationRequirement = tostring(AuthenticationRequirement),
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Country = tostring(parse_json(LocationDetails).countryOrRegion);
let signinlogs_noninteractive = AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(90d)
| where AppId == azure_mcp_appid
| extend SignInType = "Non-Interactive"
| project TimeGenerated, UserPrincipalName, AppDisplayName, AppId,
    ResourceDisplayName, IPAddress,
    ResultType = tostring(ResultType),
    ResultDescription = tostring(ResultDescription),
    UserAgent, SignInType,
    ConditionalAccessStatus = tostring(ConditionalAccessStatus),
    AuthenticationRequirement = tostring(AuthenticationRequirement),
    OS = tostring(parse_json(DeviceDetail).operatingSystem),
    Country = tostring(parse_json(LocationDetails).countryOrRegion);
union signinlogs_interactive, signinlogs_noninteractive
| order by TimeGenerated desc
```

---

## Query 14: Azure MCP Server — Workspace Queries (LAQueryLogs)

**Purpose:** Detect Azure MCP Server workspace queries. Best differentiator: `\n| limit N` suffix.

```kql
// Azure MCP Server / Azure CLI workspace queries
let azure_cli_appid = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
LAQueryLogs
| where TimeGenerated >= ago(90d)
| where AADClientId == azure_cli_appid
| extend HasLimitSuffix = QueryText has "\n| limit" or QueryText has "\r\n| limit"
| project TimeGenerated, AADEmail, AADClientId,
    RequestClientApp,
    QueryTextTruncated = substring(QueryText, 0, 300),
    ResponseCode, ResponseRowCount,
    StatsCPUTimeMs,
    RequestTarget,
    HasLimitSuffix
| order by TimeGenerated desc
```

> **Post-processing:** `HasLimitSuffix = true` → highly likely Azure MCP Server queries.

---

## Query 15: Top MCP Users — Cross-Server Breadth

**Purpose:** Identifies users with broadest MCP footprint — ranking by distinct MCP server types and total call volume.
**Note:** Uses `TimeGenerated` for all tables (Log Analytics execution, not Advanced Hunting).

```kql
let lookback = 7d;
let graph_mcp = MicrosoftGraphActivityLogs
| where TimeGenerated > ago(lookback)
| where AppId == "e8c77dc2-69b3-43f4-bc51-3213c9d915b4"
| where isnotempty(UserId)
| summarize Calls = count() by UserId
| project UserId, Server = "Graph MCP", Calls;
let triage_mcp = MicrosoftGraphActivityLogs
| where TimeGenerated > ago(lookback)
| where AppId == "7b7b3966-1961-47b5-b080-43ca5482e21c"
| where isnotempty(UserId)
| summarize Calls = count() by UserId
| project UserId, Server = "Triage MCP", Calls;
let datalake_mcp = CloudAppEvents
| where TimeGenerated > ago(lookback)
| where ActionType contains "Sentinel" or ActionType contains "KQL"
| extend RawData = parse_json(tostring(RawEventData))
| where tostring(RawData.Interface) == "InterfaceNotProvided" or isempty(tostring(RawData.Interface))
| where isnotempty(AccountObjectId)
| summarize Calls = count() by UserId = AccountObjectId
| project UserId, Server = "Data Lake MCP", Calls;
let azure_mcp = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where AppId == "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
| where isnotempty(UserId)
| summarize Calls = count() by UserId
| project UserId, Server = "Azure CLI/MCP", Calls;
let upn_map = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(lookback)
| where isnotempty(UserPrincipalName)
| summarize arg_max(TimeGenerated, UserPrincipalName) by UserId
| project UserId, UPN = UserPrincipalName;
union graph_mcp, triage_mcp, datalake_mcp, azure_mcp
| summarize Servers = make_set(Server), ServerCount = dcount(Server), TotalCalls = sum(Calls) by UserId
| join kind=leftouter upn_map on UserId
| project UPN = coalesce(UPN, UserId), ServerCount, Servers, TotalCalls
| sort by ServerCount desc, TotalCalls desc
| take 25
```

---

## SPN Enrichment Query (Ad-hoc — replaces Graph API lookup)

**Purpose:** Since Microsoft Graph MCP is not integrated with Azure SRE Agent, use this query to enrich Service Principal IDs from Query 9.

```kql
// SPN enrichment via AADServicePrincipalSignInLogs (replaces Graph API lookup)
AADServicePrincipalSignInLogs
| where TimeGenerated >= ago(30d)
| where ServicePrincipalId in ("<SPN_ID_1>", "<SPN_ID_2>")
| summarize arg_max(TimeGenerated, *) by ServicePrincipalId
| project ServicePrincipalId, ServicePrincipalName, AppId, ResourceDisplayName
```

> **Note:** This does not return `tags` (e.g., `AgenticApp`). For full agent identity analysis, check `AuditLogs` for service principal creation/modification events with `tags` in `targetResources`.
