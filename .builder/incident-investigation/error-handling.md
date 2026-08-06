## Error Handling

### Common Issues and Solutions

| Issue | Solution |
|-------|----------|
| **Incident not found in SecurityIncident** | Verify incident ID format; try both `IncidentNumber` and `ProviderIncidentId`; expand time range |
| **SecurityIncident table not found** | Table may not be synced to this workspace; check workspace configuration |
| **AlertEvidence table not found** | Table requires M365D data connector; proceed without evidence data |
| **No alerts returned from Q2** | Check if `AlertIds` field is populated in the SecurityIncident record; try Q3 entities approach |
| **User Object ID not found** | Verify UPN is correct; try Graph API via `RunAzCliReadCommands` or KQL Q0 fallback |
| **Device investigation fails** | Verify device exists in DeviceInfo table; try hostname variations |
| **IoC investigation timeout** | Reduce date range; check IoC format |
| **MDE API 403 error** | Check `RunAzCliReadCommands` permissions; fall back to KQL-only mode |

### Table Availability Check

If a query returns "Failed to resolve table", the table is not available in the workspace. Handle gracefully:

```
IF SecurityIncident fails:
    → Report: "SecurityIncident table is not available. Ensure the Sentinel data connector is enabled."
    → STOP investigation

IF AlertEvidence fails:
    → Report: "AlertEvidence table not available — evidence data will be limited."
    → Continue with SecurityAlert Entities extraction only (Q3)

IF DeviceNetworkEvents/DeviceProcessEvents/etc. fail:
    → Report: "Advanced Hunting tables not synced to Log Analytics."
    → Continue with available tables
```

### Time Window Limits

| Tool | Time Window Options |
|------|---------------------|
| User Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |
| Computer Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |
| IoC Investigation | 30 days (Comprehensive), 7 days (Standard), 1 day (Quick) |