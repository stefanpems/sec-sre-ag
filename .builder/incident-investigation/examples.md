## Example Investigation Workflow

**User Request:** "Investigate incident 12345"

### Phase 0: Cache Check
```
[00:00] Checking for cached investigation data...
        → Found: temp/investigation_incident_12345_20260601_100000.json
        → Age: 2h 30m (within 4h threshold)
        → User prompt "Investigate incident 12345" — no implicit redo/cache keyword
        → Asking user whether to use cached data or start fresh...
        → User selected: "Repeat from scratch"
        → Proceeding with fresh investigation
```

### Phase 1: Incident Description
```
[00:05] Starting fresh incident investigation for ID: 12345

Step 1: Running Q1 (metadata) + Q10 (MITRE) in parallel via Monitor MCP...
Step 2: Running Q2 (alerts) via Monitor MCP...
Step 3: Running Q3-Q9 (entities, evidences) in parallel via Monitor MCP...

### Incident Metadata
- **Title:** Multi-stage attack with credential theft
- **Severity:** High
- **Status:** Active
- **Classification:** TruePositive
- **Created:** 2026-01-20T10:30:00Z
- **Provider Incident ID:** 12345 (Defender XDR)
- **MITRE Tactics:** Initial Access, Credential Access, Lateral Movement

### Incident Alerts
| # | Alert Name | Severity | Status | Tactics | Last Activity |
|---|------------|----------|--------|---------|---------------|
| 1 | Suspicious sign-in from unusual location | High | New | InitialAccess | 2026-01-23 |
| 2 | Credential theft attempt detected | High | New | CredentialAccess | 2026-01-22 |
| ... | ... | ... | ... | ... | ... |

### Incident Assets
**Users:**
| UPN | Display Name | Alert Count |
|-----|-------------|-------------|
| jsmith@contoso.com | John Smith | 3 |
| admin@contoso.com | Admin Account | 2 |

**Devices:**
| Hostname | OS | Alert Count |
|----------|-----|-------------|
| WORKSTATION-01 | Windows | 4 |
| LAPTOP-EXEC | Windows | 2 |

### Incident Evidences
**IPs (after filtering):**
- `203[.]0[.]113[.]42` (3 alerts — C2 communication)
- `198[.]51[.]100[.]10` (2 alerts — Data exfiltration)

**URLs (after filtering):**
- `hxxps://evil-site[.]com/payload[.]exe` (Malicious)

[01:30] Phase 1 completed (90 seconds)
```

### Phase 2: Investigation Menu
```
Which assets and entities involved in the incident should be investigated in depth?

1. 👤 jsmith@contoso.com (John Smith) — 3 alerts
2. 👤 admin@contoso.com (Admin Account) — 2 alerts
3. 💻 WORKSTATION-01 — 4 alerts
4. 💻 LAPTOP-EXEC — 2 alerts
5. 🌐 203[.]0[.]113[.]42 — 3 alerts
6. 🌐 198[.]51[.]100[.]10 — 2 alerts
7. 🔗 hxxps://evil-site[.]com/payload[.]exe

Select by number/name, type "all" to investigate everything.
```

[Investigation continues following sub-skills...]