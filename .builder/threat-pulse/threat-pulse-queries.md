# Threat Pulse — Pre-Validated KQL Queries

> **All queries below are validated against Sentinel / Log Analytics schemas. Use them exactly as written.**
> Lookback periods use `ago(Nd)` — substitute the user's preferred lookback where noted.

## Execution Model

| Tier | Queries | Execution Tool | Notes |
|------|---------|----------------|-------|
| **Tier 1 — Direct LA** | Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10 | `monitor-client_monitor_workspace_log_query` (Azure Monitor MCP) | Execute directly, present results |
| **Tier 2 — AH Copy/Paste** | Q11, Q12 | User copies query to Advanced Hunting portal | Tables only available in AH (ExposureGraphNodes, DeviceTvm*) |

**Parallelization:** Run all Tier 1 queries in parallel (no dependencies). Present Tier 2 queries to the user simultaneously.

---

## Query 1: Open Incidents with Severity-Ranked Backfill & MITRE Techniques

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `SecurityIncident`, `SecurityAlert` (both LA-native)

```kql
let OpenIncidents = SecurityIncident
| where TimeGenerated > ago(30d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status in ("New", "Active");
let TotalHighCritical = toscalar(OpenIncidents | where Severity in ("High", "Critical") | count);
let TotalAll = toscalar(OpenIncidents | count);
OpenIncidents
| extend SevRank = case(Severity == "Critical", 0, Severity == "High", 1, Severity == "Medium", 2, Severity == "Low", 3, 4)
| extend ParsedLabels = parse_json(Labels)
| mv-apply Label = ParsedLabels on (
    summarize Tags = make_set(tostring(Label.labelName), 5)
)
| extend Tags = set_difference(Tags, dynamic([""]))
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, Entities, Tactics, Techniques, AlertName, AlertSeverity) by SystemAlertId
    | extend ParsedEntities = parse_json(Entities)
    | mv-expand Entity = ParsedEntities
    | extend EntityType = tostring(Entity.Type),
        AccountUPN = case(
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.UPNSuffix)),
            tolower(strcat(tostring(Entity.Name), "@", tostring(Entity.UPNSuffix))),
            tostring(Entity.Type) == "account" and isnotempty(tostring(Entity.AadUserId)),
            tostring(Entity.AadUserId),
            ""),
        HostName = iff(tostring(Entity.Type) == "host", tolower(tostring(Entity.HostName)), "")
    | project SystemAlertId, Tactics, Techniques, AlertName, AlertSeverity, AccountUPN, HostName
) on $left.AlertId == $right.SystemAlertId
| mv-expand Technique = parse_json(Techniques)
| extend Technique = tostring(Technique)
| extend TacticsSplit = split(Tactics, ", ")
| mv-expand Tactic = TacticsSplit
| extend Tactic = tostring(Tactic)
| summarize 
    Tactics = make_set(Tactic),
    Techniques = make_set(Technique),
    AlertNames = make_set(AlertName, 5),
    AlertCount = dcount(AlertId),
    Accounts = make_set(AccountUPN, 5),
    Devices = make_set(HostName, 5),
    Tags = take_any(Tags)
    by ProviderIncidentId, Title, Severity, SevRank, Status, CreatedTime,
       OwnerUPN = tostring(Owner.userPrincipalName)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
| extend Accounts = set_difference(Accounts, dynamic([""]))
| extend Devices = set_difference(Devices, dynamic([""]))
| extend AgeDisplay = case(
    datetime_diff('minute', now(), CreatedTime) < 60, strcat(datetime_diff('minute', now(), CreatedTime), "m ago"),
    datetime_diff('hour', now(), CreatedTime) < 24, strcat(datetime_diff('hour', now(), CreatedTime), "h ago"),
    strcat(datetime_diff('day', now(), CreatedTime), "d ago"))
| extend PortalUrl = strcat("https://security.microsoft.com/incidents/", ProviderIncidentId, "?tid=<TENANT_ID>")
| extend TotalHighCritical = TotalHighCritical, TotalAll = TotalAll
| project TotalHighCritical, TotalAll, ProviderIncidentId, Title, Severity, SevRank, AgeDisplay, AlertCount, 
    OwnerUPN, Tactics, Techniques, Accounts, Devices, Tags, PortalUrl, AlertNames, CreatedTime
| as AllOpenIncidents
| join kind=leftouter (
    AllOpenIncidents | summarize TitleDupCount = count() by Title
) on Title
| project-away Title1
| order by Title asc, SevRank asc, bin(CreatedTime, 1d) desc, AlertCount desc
| extend _rn = row_number(1, prev(Title) != Title)
| where _rn == 1
| project-away _rn
| order by SevRank asc, bin(CreatedTime, 1d) desc, AlertCount desc
| take 10
```

**Purpose:** Top 10 open incidents with severity-ranked backfill (Critical→High→Medium→Low). `TotalHighCritical` and `TotalAll` drive the adaptive report header. Deduplicated by `Title` — `TitleDupCount` preserves volume signal. Joins SecurityAlert for MITRE tactics/techniques. Extracts `Accounts` (UPN or AAD ObjectId, lowercased), `Devices` (hostname, lowercased), and `Tags` — each capped at 5 per incident — for cross-query correlation.

**Verdict logic:**
- 🔴 Escalate: 5+ new High/Critical in 24h, OR any incident with `AlertCount > 50`, OR any unassigned High/Critical with CredentialAccess/LateralMovement tactics
- 🟠 Investigate: Any unassigned High/Critical, OR `AlertCount > 10`, OR multiple High/Critical in <6h
- 🟡 Monitor: Only Medium/Low incidents exist (no High/Critical), OR High/Critical assigned with low alert count
- ✅ Clear: 0 open incidents of any severity

---

## Query 2: Closed Incident Summary (7-Day Lookback)

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `SecurityIncident`, `SecurityAlert` (both LA-native)

```kql
SecurityIncident
| where CreatedTime > ago(7d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == "Closed"
| where array_length(AlertIds) > 0
| mv-expand AlertId = AlertIds | extend AlertId = tostring(AlertId)
| join kind=leftouter (
    SecurityAlert
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, Tactics, Techniques) by SystemAlertId
    | project SystemAlertId, Tactics, Techniques
) on $left.AlertId == $right.SystemAlertId
| mv-expand Technique = parse_json(Techniques)
| extend Technique = tostring(Technique)
| extend TacticsSplit = split(Tactics, ", ")
| mv-expand Tactic = TacticsSplit
| extend Tactic = tostring(Tactic)
| summarize
    Total = dcount(IncidentNumber),
    TruePositive = dcountif(IncidentNumber, Classification == "TruePositive"),
    BenignPositive = dcountif(IncidentNumber, Classification == "BenignPositive"),
    FalsePositive = dcountif(IncidentNumber, Classification == "FalsePositive"),
    Undetermined = dcountif(IncidentNumber, Classification == "Undetermined"),
    HighCritical = dcountif(IncidentNumber, Severity in ("High", "Critical")),
    MediumLow = dcountif(IncidentNumber, Severity in ("Medium", "Low")),
    Tactics = make_set(Tactic),
    Techniques = make_set(Technique)
| extend Techniques = set_difference(Techniques, dynamic([""]))
| extend Tactics = set_difference(Tactics, dynamic([""]))
// Safety cap — remove only if user explicitly requests all rows
| take 200
```

**Purpose:** 7-day closed incident summary: classification breakdown (TP/BP/FP/Undetermined), severity distribution, aggregated MITRE tactics and technique IDs. Uses `CreatedTime` (not `TimeGenerated`) to match portal "created in last 7 days" semantics. Filters `array_length(AlertIds) > 0` to exclude phantom incidents synced from XDR with empty AlertIds.

**Verdict logic:**
- 🟠 Investigate: `TruePositive / Total > 0.5` (majority of closures are real threats)
- 🟡 Monitor: Any TruePositive closures exist, or `Undetermined > 0`
- ✅ Clear: 0 TruePositive closures; all closures are BenignPositive or FalsePositive
- 🔵 Informational: 0 closed incidents in 7d

---

## Query 3: Identity Risk Posture & Risk Event Enrichment

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `IdentityInfo` (MDI-synced to LA), `AADUserRiskEvents` (LA-native)

> **⚠️ Pitfall — AADUserRiskEvents:** Use `ActivityDateTime` for event time filtering, NOT `TimeGenerated` (ingestion time). `IpAddress` uses lowercase `p`.
> **⚠️ Pitfall — IdentityInfo:** Uses `TimeGenerated` in LA (not `Timestamp` which is AH-only). `RiskScore` may not be populated if Defender XDR is not fully connected — fall back to AADUserRiskEvents for risk assessment if always 0/null.

```kql
let lookback = 7d;
// Layer 1: IdentityInfo — hybrid filter (Defender RiskScore + IdP RiskLevel/Status + Criticality)
let IdentityPosture = IdentityInfo
| where TimeGenerated > ago(lookback)
| summarize arg_max(TimeGenerated, *) by AccountUpn
| where RiskScore >= 71
    or RiskLevel in ("High", "Medium")
    or RiskStatus in ("AtRisk", "ConfirmedCompromised")
    or CriticalityLevel >= 3;
// Layer 2: AADUserRiskEvents — enrichment (the why)
let UserRiskEvents = AADUserRiskEvents
| where ActivityDateTime > ago(lookback)
| extend Country = tostring(parse_json(Location).countryOrRegion)
| summarize
    RiskDetections = count(),
    HighCount = countif(RiskLevel == "high"),
    TopRiskEventTypes = make_set(RiskEventType, 8),
    TopCountries = make_set(Country, 5),
    LatestDetection = max(ActivityDateTime)
    by UserPrincipalName;
// IdentityInfo drives, AADUserRiskEvents enriches
IdentityPosture
| join hint.strategy=broadcast kind=leftouter (UserRiskEvents) 
    on $left.AccountUpn == $right.UserPrincipalName
| extend 
    DisplayName = coalesce(AccountDisplayName, AccountName, AccountUpn),
    PortalUrl = strcat("https://security.microsoft.com/user?",
        case(
            isnotempty(AccountObjectId), strcat("aad=", AccountObjectId, "&upn=", AccountUpn),
            isnotempty(OnPremSid), strcat("sid=", OnPremSid, "&accountName=", AccountName,
                                         "&accountDomain=", AccountDomain),
            isnotempty(AccountUpn), strcat("upn=", AccountUpn),
            ""),
        "&tab=overview&tid=<TENANT_ID>")
| project DisplayName, PortalUrl, RiskScore, RiskLevel, RiskStatus, CriticalityLevel,
    RiskDetections = coalesce(RiskDetections, long(0)),
    HighCount = coalesce(HighCount, long(0)),
    TopRiskEventTypes, TopCountries, LatestDetection
| order by RiskScore desc, HighCount desc, RiskDetections desc, CriticalityLevel desc
| take 15
```

**Purpose:** Hybrid two-signal query: `IdentityInfo.RiskScore` (Defender XDR composite, 0-100) + `RiskLevel`/`RiskStatus` (Identity Protection). `AADUserRiskEvents` enriches with specific detections.

**Portal URL resolution:** Three-tier fallback:
- Cloud/Hybrid (Entra ObjectId): `aad=<ObjectId>&upn=<UPN>`
- On-prem AD (SID only): `sid=<SID>&accountName=<Name>&accountDomain=<Domain>`
- External IdP (UPN only): `upn=<UPN>`

**Verdict logic:**
- 🔴 Escalate: Any user with `RiskScore >= 91`, or `ConfirmedCompromised` status, or `HighCount > 3`, or multiple users with `HighCount > 0`
- 🟠 Investigate: `RiskScore >= 71`, or `HighCount > 0`, or any user `AtRisk` with `impossibleTravel`, `maliciousIPAddress`, `aiCompoundAccountRisk`
- 🟡 Monitor: Only `Medium` risk users with low-severity event types (e.g., `unfamiliarFeatures`)
- ✅ Clear: 0 users matching the hybrid filter

**⚠️ Risk Event Type Routing Guard (Phase 4 drill-down):**
- `suspiciousAuthAppApproval` → **T1621 MFA Fatigue** (suspicious Authenticator push approval), **NOT** OAuth app consent. Route to `user-investigation`.
- `mcasSuspiciousInboxManipulationRules` → T1114.003 email exfiltration via inbox rules. Route to `user-investigation`.

---

## Query 4: Password Spray / Brute-Force Detection

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `SigninLogs` + `AADNonInteractiveUserSignInLogs` (LA-native), `DeviceLogonEvents` (XDR synced to LA)

> **⚠️ Adaptation:** Original uses `EntraIdSignInEvents` (AH-only). This version uses the LA equivalents: `SigninLogs` (interactive) + `AADNonInteractiveUserSignInLogs` (non-interactive), with column mapping: `AccountUpn`→`UserPrincipalName`, `ErrorCode`(int)→`ResultType`(string), `Application`→`AppDisplayName`, `Country`→`parse_json(LocationDetails).countryOrRegion`.

```kql
// Step 1: Union interactive + non-interactive sign-ins, filter spray error codes
let SignInUnion = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where ResultType in ("50126", "50053", "50057");
// Step 2: Count spray-specific failures per IP (materialized — referenced twice)
let SprayFailures = materialize(SignInUnion
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(UserPrincipalName),
    SampleTargets = make_set(UserPrincipalName, 5),
    FailedApps = make_set(AppDisplayName, 3),
    Countries = make_set(tostring(parse_json(LocationDetails).countryOrRegion), 3)
    by SourceIP = IPAddress
| where TargetUsers >= 5);
// Step 3: Get full traffic profile for flagged IPs (success context)
let IPTrafficProfile = union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where IPAddress in ((SprayFailures | project SourceIP))
| summarize
    TotalSignIns = count(),
    Successes = countif(ResultType == "0"),
    TotalDistinctUsers = dcount(UserPrincipalName),
    TotalDistinctApps = dcount(AppDisplayName)
    by SourceIP = IPAddress;
// Step 4: Join and filter — eliminate shared infrastructure false positives
let EntraResults = SprayFailures
| join kind=inner IPTrafficProfile on SourceIP
| extend 
    SprayRatio = round(FailedAttempts * 100.0 / max_of(TotalSignIns, 1), 1),
    SuccessRate = round(Successes * 100.0 / max_of(TotalSignIns, 1), 1)
| where SprayRatio >= 1.0 and TotalDistinctApps < 50
| extend Surface = "Entra ID"
| project SourceIP, FailedAttempts, TargetUsers, SampleTargets, 
    Protocols = FailedApps, Countries, Surface,
    TotalSignIns, Successes, SprayRatio, SuccessRate, TotalDistinctApps;
// Endpoint brute-force — Surface label by LogonType
let EndpointBrute = DeviceLogonEvents
| where TimeGenerated > ago(7d)
| where ActionType == "LogonFailed"
| where LogonType in ("RemoteInteractive", "Network")
| where isnotempty(RemoteIP)
| summarize
    FailedAttempts = count(),
    TargetUsers = dcount(AccountName),
    SampleTargets = make_set(AccountName, 5),
    Protocols = make_set(strcat(LogonType, " → ", DeviceName), 3),
    Countries = dynamic(["—"]),
    LogonTypes = make_set(LogonType)
    by SourceIP = RemoteIP
| where FailedAttempts >= 10
| extend Surface = iff(array_length(LogonTypes) == 1 and LogonTypes[0] == "RemoteInteractive", "Endpoint (RDP)", "Endpoint (Network Logon)"),
    TotalSignIns = FailedAttempts, Successes = long(0), 
    SprayRatio = 100.0, SuccessRate = 0.0, TotalDistinctApps = long(0)
| project-away LogonTypes;
union EntraResults, EndpointBrute
| order by SprayRatio desc, TargetUsers desc, FailedAttempts desc
| take 15
```

**Purpose:** Detects password spray (1 IP → many users, T1110.003) and brute-force (1 IP → high failure count, T1110.001) across two surfaces with shared-infrastructure false-positive filtering.

**False positive filters:**
- `SprayRatio >= 1.0` — spray failures must be ≥1% of the IP's total sign-in volume
- `TotalDistinctApps < 50` — IPs serving 50+ distinct applications are shared infrastructure

**Verdict logic:**
- 🔴 Escalate: Any IP targeting >25 Entra users OR >100 endpoint failures from a single IP
- 🟠 Investigate: Any spray/brute-force pattern detected (meets thresholds)
- 🟡 Monitor: Spray activity detected but below thresholds
- ✅ Clear: 0 results

---

## Query 5: SPN Behavioral Drift (90d Baseline vs 7d Recent)

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `AADServicePrincipalSignInLogs` (LA-native, uses `TimeGenerated`)

> **Note:** This query needs >30d lookback (97d). Use Azure Monitor MCP with `hours` parameter set to at least `97 * 24 = 2328`.

```kql
let BL_Start = ago(97d); let BL_End = ago(7d);
let RC_Start = ago(7d); let RC_End = now();
let BL = AADServicePrincipalSignInLogs
| where TimeGenerated between (BL_Start .. BL_End)
| extend NormalizedIP = case(
    IPAddress has ":", strcat_array(array_slice(split(IPAddress, ":"), 0, 3), ":"),
    IPAddress)
| summarize 
    BL_Vol = count(),
    BL_Res = dcount(ResourceDisplayName),
    BL_IPs = dcount(NormalizedIP),
    BL_Loc = dcount(Location),
    BL_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
let RC = AADServicePrincipalSignInLogs
| where TimeGenerated between (RC_Start .. RC_End)
| extend NormalizedIP = case(
    IPAddress has ":", strcat_array(array_slice(split(IPAddress, ":"), 0, 3), ":"),
    IPAddress)
| summarize 
    RC_Vol = count(),
    RC_Res = dcount(ResourceDisplayName),
    RC_IPs = dcount(NormalizedIP),
    RC_Loc = dcount(Location),
    RC_Fail = dcountif(ResultType, ResultType != "0" and ResultType != 0)
    by ServicePrincipalId, ServicePrincipalName;
RC | join kind=inner BL on ServicePrincipalId
| extend 
    VolDrift = round(RC_Vol * 100.0 / max_of(BL_Vol, 10), 0),
    ResDrift = round(RC_Res * 100.0 / max_of(BL_Res, 3), 0),
    IPDriftRaw = round(RC_IPs * 100.0 / max_of(BL_IPs, 3), 0),
    IPDrift = min_of(round(RC_IPs * 100.0 / max_of(BL_IPs, 3), 0), 300),
    LocDrift = round(RC_Loc * 100.0 / max_of(BL_Loc, 2), 0),
    FailDrift = round(RC_Fail * 100.0 / max_of(BL_Fail, 5), 0)
| extend DriftScore = round((VolDrift*0.20 + ResDrift*0.25 + IPDrift*0.25 + LocDrift*0.15 + FailDrift*0.15), 0)
| where DriftScore > 120
| order by DriftScore desc
| take 10
```

**Purpose:** Composite drift score across 5 dimensions. IPv6 /64 normalization prevents Azure PaaS pod rotation from inflating IPDrift. IPDrift capped at 300%.

**Verdict logic:**
- 🔴 Escalate: Any SPN with `DriftScore > 250` or `IPDriftRaw > 400%`
- 🟠 Investigate: `DriftScore > 150`
- 🟡 Monitor: `DriftScore 120–150`
- ✅ Clear: No SPNs above threshold

---

## Query 6: Fleet-Wide Device Process Drift

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `DeviceProcessEvents`, `DeviceInfo` (XDR tables synced to LA — use `TimeGenerated`)

```kql
let uptime = DeviceInfo
| where TimeGenerated > ago(7d)
| extend IsRecent = TimeGenerated >= ago(1d)
| summarize
    BaselineHours = dcountif(bin(TimeGenerated, 1h), not(IsRecent)),
    RecentHours   = dcountif(bin(TimeGenerated, 1h), IsRecent)
    by DeviceName;
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where not(
    InitiatingProcessFileName in ("gc_worker", "gc_linux_service", "dsc_host")
    or (InitiatingProcessFileName == "dash" and InitiatingProcessParentFileName in ("gc_worker", "gc_linux_service"))
  )
| extend IsRecent = TimeGenerated >= ago(1d), DayBucket = bin(TimeGenerated, 1d)
| summarize
    BL_Events = countif(not(IsRecent)),
    RC_Events = countif(IsRecent),
    BL_Procs = dcountif(FileName, not(IsRecent)),
    RC_Procs = dcountif(FileName, IsRecent),
    BL_Accts = dcountif(AccountName, not(IsRecent)),
    RC_Accts = dcountif(AccountName, IsRecent),
    BL_Chains = dcountif(strcat(InitiatingProcessFileName, "→", FileName), not(IsRecent)),
    RC_Chains = dcountif(strcat(InitiatingProcessFileName, "→", FileName), IsRecent),
    BL_Comps = dcountif(ProcessVersionInfoCompanyName, not(IsRecent)),
    RC_Comps = dcountif(ProcessVersionInfoCompanyName, IsRecent),
    BaselineDays = dcountif(DayBucket, not(IsRecent))
    by DeviceName
| where RC_Events > 0 and BL_Events > 0 and BaselineDays >= 4
| join kind=inner uptime on DeviceName
| where BaselineHours >= 48 and RecentHours >= 4
| extend
    VolDriftRaw = round(RC_Events * 600.0 / max_of(BL_Events, 1), 0),
    VolDrift = min_of(round(RC_Events * 600.0 / max_of(BL_Events, 1), 0), 300),
    ProcDrift = round(RC_Procs * 100.0 / max_of(BL_Procs, 1), 0),
    AcctDrift = round(RC_Accts * 100.0 / max_of(BL_Accts, 1), 0),
    ChainDrift = round(RC_Chains * 100.0 / max_of(BL_Chains, 1), 0),
    CompDrift = round(RC_Comps * 100.0 / max_of(BL_Comps, 1), 0)
| extend DriftScore = round(VolDrift * 0.30 + ProcDrift * 0.25 + ChainDrift * 0.20 + AcctDrift * 0.15 + CompDrift * 0.10, 0)
| order by DriftScore desc
| take 10
| project DeviceName, DriftScore, BaselineDays, BaselineHours, RecentHours, VolDriftRaw, VolDrift, ProcDrift, AcctDrift, ChainDrift, CompDrift
```

**Purpose:** Top 10 devices by composite drift score (pre-computed in KQL — no LLM-side math). Weights: Volume 30%, Processes 25%, Chains 20%, Accounts 15%, Companies 10%. VolDrift capped at 300%.

**Verdict logic:** See [Device Drift Score Interpretation](#device-drift-score-interpretation) below.

---

## Query 7: Rare Process Chain Singletons

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `DeviceProcessEvents` (XDR synced to LA — use `TimeGenerated`)

```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| summarize 
    Count = count(),
    UniqueDevices = dcount(DeviceName),
    SampleDevice = take_any(DeviceName),
    SampleUser = strcat(take_any(AccountDomain), "\\", take_any(AccountName)),
    SampleChildCmd = take_any(ProcessCommandLine),
    GrandparentProcess = take_any(InitiatingProcessParentFileName),
    LastSeen = max(TimeGenerated)
    by ParentProcess = InitiatingProcessFileName, ChildProcess = FileName
| where Count < 3
| order by Count asc, UniqueDevices asc
| take 20
```

**Purpose:** 20 rarest process chains — singletons and near-singletons. Effective for LOLBin abuse, malware execution, novel attack tooling.

**Verdict logic:**
- 🟠 Investigate: Any singleton with suspicious parent (cmd.exe, powershell.exe, wscript.exe, mshta.exe, rundll32.exe) or child in temp/user profile directories
- 🟡 Monitor: Rare chains from system/update processes
- ✅ Clear: All rare chains are explainable infrastructure artifacts

---

## Query 8: Inbound Email Threat Snapshot

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `EmailEvents` (XDR synced to LA — use `TimeGenerated`)

> **⚠️ Availability:** `EmailEvents` requires the Microsoft Defender for Office 365 data connector. If the table doesn't exist, verdict = ❓ No Data.

```kql
EmailEvents
| where TimeGenerated > ago(7d)
| where EmailDirection == "Inbound"
| summarize
    TotalInbound = count(),
    Clean = countif(isempty(ThreatTypes)),
    Phish = countif(ThreatTypes has "Phish"),
    Malware = countif(ThreatTypes has "Malware"),
    Spam = countif(ThreatTypes has "Spam"),
    HighConfPhish = countif(ConfidenceLevel has "High" and ThreatTypes has "Phish"),
    Blocked = countif(DeliveryAction == "Blocked"),
    Delivered = countif(DeliveryAction == "Delivered"),
    PhishDelivered = countif(ThreatTypes has "Phish" and DeliveryAction == "Delivered"),
    DistinctSenders = dcount(SenderFromAddress),
    DistinctRecipients = dcount(RecipientEmailAddress)
// Safety cap — remove only if user explicitly requests all rows
| take 200
```

**Purpose:** Instant email posture briefing. Key escalation metric: `PhishDelivered`.

**Verdict logic:**
- 🔴 Escalate: `PhishDelivered > 5` or `Malware > 0` delivered
- 🟠 Investigate: `PhishDelivered > 0`
- 🟡 Monitor: Phishing detected but 100% blocked/junked
- ✅ Clear: 0 phishing, 0 malware

---

## Query 9: Cloud App Suspicious Activity

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `CloudAppEvents` (XDR synced to LA — use `TimeGenerated`)

> **⚠️ Pitfall — CloudAppEvents:** High-volume table. `AccountId` is a GUID (Entra ObjectId), NOT a UPN. Use `AccountObjectId` for user lookups. Pre-filter aggressively.

```kql
let PlatformServicePrefix = @"NT SERVICE\";
CloudAppEvents
| where TimeGenerated > ago(7d)
| where ActionType in (
    // Exchange — Mail flow manipulation
    "New-InboxRule", "Set-InboxRule", "Set-Mailbox",
    "Add-MailboxPermission", "New-TransportRule", "Set-TransportRule", "New-Mailbox",
    // Exchange — Anti-forensic
    "Remove-MailboxPermission", "Remove-InboxRule",
    // Conditional Access manipulation (human-initiated only)
    "Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy",
    // Compromise signals
    "CompromisedSignIn"
)
| extend RawUserId = tostring(parse_json(tostring(RawEventData)).UserId)
| extend EffectiveActor = iff(isnotempty(AccountDisplayName), AccountDisplayName, RawUserId)
| where not(EffectiveActor startswith PlatformServicePrefix)
| where not(ActionType in ("Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy")
            and isempty(EffectiveActor))
| extend Category = case(
    ActionType in ("New-InboxRule", "Set-InboxRule", "Remove-InboxRule",
                   "Set-Mailbox", "Add-MailboxPermission", "Remove-MailboxPermission",
                   "New-TransportRule", "Set-TransportRule", "New-Mailbox"),
    "Exchange Admin/Rule Change",
    ActionType in ("Set-ConditionalAccessPolicy", "New-ConditionalAccessPolicy"),
    "Conditional Access Change",
    ActionType == "CompromisedSignIn",
    "Compromised Sign-In",
    "Other")
| summarize
    Count = count(),
    UniqueActors = dcount(EffectiveActor),
    TopActors = make_set(EffectiveActor, 5),
    Actions = make_set(ActionType, 5),
    LatestTime = max(TimeGenerated)
    by Category
| order by Count desc
// Safety cap — remove only if user explicitly requests all rows
| take 200
```

**Purpose:** Three-category view: Exchange rule changes, Conditional Access mutations, MCAS compromised sign-ins. `CompromisedSignIn` is an MCAS signal independent from Q3's Identity Protection. Actor resolution falls back to `RawEventData.UserId` when `AccountDisplayName` is empty.

**Verdict logic:**
- 🔴 Escalate: `Compromised Sign-In` with 5+ users, OR `Conditional Access Change` by human actor, OR forwarding rules (`New-InboxRule`, `Set-InboxRule`, `New-TransportRule`)
- 🟠 Investigate: `Compromised Sign-In` (any count), OR anti-forensic cleanup (`Remove-InboxRule`, `Remove-MailboxPermission`)
- 🟡 Monitor: Low-count `Set-Mailbox` from system actors
- ✅ Clear: 0 results

**Drill-down note:** For any Exchange-related Q9 finding, also query `OfficeActivity | where OfficeWorkload == "Exchange"` — CloudAppEvents only surfaces ActionType summaries; OfficeActivity carries the full `Parameters` JSON with `ForwardTo` / `RedirectTo` / `ForwardingSmtpAddress`.

---

## Query 10: High-Impact Privileged Operations

**Execution:** Tier 1 — Azure Monitor MCP
**Tables:** `AuditLogs` (LA-native, uses `TimeGenerated`)

```kql
let PrivOps = AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has_any (
    "role", "credential", "consent", "Conditional Access", "password", "certificate",
    "security info", "owner", "application"
)
| where Result == "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| where not(OperationName has "conditional access" and isempty(Actor))
| extend Target = tostring(TargetResources[0].displayName)
| extend Category = case(
    OperationName has "security info", "MFA-Registration",
    OperationName has "owner", "Ownership",
    OperationName has "application", "AppRegistration",
    OperationName has "role", "RoleManagement",
    OperationName has "credential" or OperationName has "certificate", "Credentials",
    OperationName has "consent", "Consent",
    OperationName has "Conditional Access", "ConditionalAccess",
    OperationName has "password", "Password",
    "Other");
PrivOps
| summarize 
    Count = count(),
    UniqueActors = dcount(Actor),
    TopActors = make_set(Actor, 5),
    Operations = make_set(OperationName, 5),
    Targets = make_set(Target, 5),
    LatestTime = max(TimeGenerated)
    by Category
| order by Count desc
// Safety cap — remove only if user explicitly requests all rows
| take 200
```

**Purpose:** Category-aggregated privileged operations: role assignments, PIM, credentials, consent, CA, password, MFA registration, app registration, ownership.

**Verdict logic:**
- 🔴 Escalate: MFA-Registration deletions + re-registrations (method swap), OR unexpected consent grants, OR ownership grants to external accounts, OR CA changes by non-admin actors
- 🟠 Investigate: MFA-Registration from external accounts, OR Global/Security Admin role assignments, OR bulk password resets from single actor
- 🟡 Monitor: Normal PIM activations, self-service password resets
- ✅ Clear: 0 results or only system-driven operations

---

## Query 11: Critical Assets with Verified Internet Exposure

**Execution:** ⚠️ Tier 2 — **Advanced Hunting ONLY** (ExposureGraphNodes is AH-only)

> **User instruction:** Copy this query and run it in the [Defender XDR Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting) portal, then paste the results back.

```kql
let InternetFacing = DeviceInfo
    | where Timestamp > ago(7d)
    | where IsInternetFacing == true
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceName,
        Reason = extractjson("$.InternetFacingReason", AdditionalFields, typeof(string)),
        PublicIP = extractjson("$.InternetFacingPublicScannedIp", AdditionalFields, typeof(string)),
        ExposedPort = extractjson("$.InternetFacingLocalPort", AdditionalFields, typeof(int));
let CriticalAssets = ExposureGraphNodes
    | where set_has_element(Categories, "device")
    | where isnotnull(NodeProperties.rawData.criticalityLevel)
    | extend critLevel = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
    | where critLevel < 4
    | project DeviceName = NodeName, CriticalityLevel = critLevel,
        ExposureScore = tostring(NodeProperties.rawData.exposureScore);
CriticalAssets
| join kind=leftouter InternetFacing on DeviceName
| extend IsVerifiedExposed = isnotempty(PublicIP) or isnotempty(Reason)
| project DeviceName, CriticalityLevel, IsVerifiedExposed,
    Reason, PublicIP, ExposedPort, ExposureScore
| order by IsVerifiedExposed desc, CriticalityLevel asc
| take 25
```

> **Note:** This query uses `Timestamp` (AH syntax). Do NOT change to `TimeGenerated` — it runs in Advanced Hunting, not Log Analytics.

**Partial LA Fallback** (internet-facing devices only, without ExposureGraph criticality data):

```kql
DeviceInfo
| where TimeGenerated > ago(7d)
| where IsInternetFacing == true
| summarize arg_max(TimeGenerated, *) by DeviceId
| project DeviceName,
    Reason = extractjson("$.InternetFacingReason", AdditionalFields, typeof(string)),
    PublicIP = extractjson("$.InternetFacingPublicScannedIp", AdditionalFields, typeof(string)),
    ExposedPort = extractjson("$.InternetFacingLocalPort", AdditionalFields, typeof(int)),
    OSPlatform, MachineGroup
| order by DeviceName asc
| take 25
```

**Purpose:** Critical asset inventory (criticality 0–3) enriched with MDE internet-facing classification. `IsVerifiedExposed` checks both `PublicIP` (Microsoft external scan) and `Reason` (observed inbound traffic).

**Verdict logic:**
- 🔴 Escalate: Any `IsVerifiedExposed == true` with `CriticalityLevel == 0` (internet-facing DC/CA)
- 🟠 Investigate: Any `IsVerifiedExposed == true`
- 🟡 Monitor: Critical assets exist but none verified internet-facing
- ✅ Clear: All critical assets properly segmented

---

## Query 12: Exploitable CVEs (CVSS ≥ 8.0) Across Fleet

**Execution:** ⚠️ Tier 2 — **Advanced Hunting ONLY** (DeviceTvm* tables are AH-only)

> **User instruction:** Copy this query and run it in the [Defender XDR Advanced Hunting](https://security.microsoft.com/v2/advanced-hunting) portal, then paste the results back.

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | where IsExploitAvailable == true
    | where CvssScore >= 8.0
) on CveId
| summarize 
    AffectedDevices = dcount(DeviceName),
    SampleDevices = make_set(DeviceName, 3),
    Software = make_set(SoftwareName, 3)
    by CveId, VulnerabilitySeverityLevel, CvssScore
| order by AffectedDevices desc, CvssScore desc
| take 15
```

> **Note:** DeviceTvm* tables are point-in-time snapshots with NO timestamp column — do NOT add `where Timestamp > ago(...)`.

**Purpose:** Top exploitable CVEs ranked by fleet impact. Focus on CVEs with public exploits affecting the most devices.

**Verdict logic:**
- 🔴 Escalate: Any CVE with `CvssScore >= 9.0` AND `AffectedDevices > 10`
- 🟠 Investigate: CVE with `CvssScore >= 8.0` AND `AffectedDevices > 5`
- 🟡 Monitor: Exploitable CVEs exist but affect < 5 devices
- ✅ Clear: No exploitable CVEs with CVSS ≥ 8.0

---

## Device Drift Score Interpretation

| DriftScore | Interpretation | Verdict |
|------------|---------------|---------|
| < 80 | Contracting activity (idle/decommissioned) | 🔵 Informational |
| 80–110 | Stable steady-state | ✅ Clear |
| 110–130 | Minor behavioral expansion | 🟡 Monitor |
| 130–180 | Significant deviation | 🟠 Investigate |
| 180+ | Major anomaly — multi-dimensional | 🔴 Escalate |

**VolDrift cap context:**
- `VolDriftRaw` ≫ 300 but ProcDrift/ChainDrift/AcctDrift near 100 → infrastructure noise, low concern
- `VolDriftRaw` > 300 AND ProcDrift/ChainDrift/AcctDrift also elevated → genuine multi-dimensional anomaly
- `VolDriftRaw` ≤ 300 → cap not triggered, score reflects true proportions

**Fleet-uniformity rule:** If ALL top-10 devices cluster within 20 points of each other, downgrade verdict one level.

**⛔ DO NOT manually recompute drift scores.** Trust the returned `DriftScore` column.

---

## Graph API Queries (User OID Lookup)

For portal URL generation (e.g., user entity links), retrieve User Object IDs via `RunAzCliReadCommands`:

```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/users/<UPN>?\$select=id,displayName,userPrincipalName" --headers "Content-Type=application/json"
```

**Fallback (KQL):** If Graph API is unavailable:
```kql
IdentityInfo
| where TimeGenerated > ago(30d)
| where AccountUpn =~ "<UPN>"
| summarize arg_max(TimeGenerated, AccountObjectId, AccountDisplayName) by AccountUpn
| project AccountUpn, AccountObjectId, AccountDisplayName
```

---

## MDE Device ID Lookup (for Portal URLs)

For device portal links, retrieve the MDE DeviceId:

**Via KQL (preferred):**
```kql
DeviceInfo
| where TimeGenerated > ago(7d)
| where DeviceName startswith '<hostname>'
| summarize arg_max(TimeGenerated, *) by DeviceId
| project DeviceId, DeviceName, OSPlatform
```

**Via Graph API fallback:**
```bash
az rest --method GET --url "https://graph.microsoft.com/v1.0/devices?\$filter=displayName eq '<hostname>'&\$select=id,displayName,deviceId" --headers "Content-Type=application/json"
```

> **Note:** The `DeviceId` from `DeviceInfo` is the MDE machine identifier — NOT the Entra Device Object ID (which is different). Portal URL: `https://security.microsoft.com/machines/v2/<MDE_DeviceId>?tid=<tenant_id>`.
