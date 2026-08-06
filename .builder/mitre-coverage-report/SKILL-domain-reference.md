# MITRE Coverage Report — Domain Reference

Load this file only during Phase 4 rendering when writing §4 (Coverage Gap Analysis) or §6 (Recommendations).

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
