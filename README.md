# sec-sre-ag — SRE Agent Custom Skills

This repository contains the custom skills — along with their supporting scripts, data files, and configurations — for the **Azure SRE Agent** `sec-sre-ag`. The agent performs security operations across Microsoft Sentinel, Microsoft Defender XDR, and Microsoft Entra ID, leveraging KQL queries via Azure Monitor MCP, Graph API calls via Azure CLI, and third-party threat-intelligence APIs.

Each skill is a self-contained capability that the agent can invoke in response to natural-language prompts. Skills cover the full spectrum of SOC operations: from broad-spectrum threat dashboards and incident triage, through deep forensic investigations on users, devices, and IoCs, to governance reporting on MITRE ATT&CK coverage, data ingestion, identity posture, and MCP usage monitoring.

---

## Skills

### computer-investigation

Performs comprehensive security investigations on Windows, macOS, and Linux devices registered in Microsoft Entra ID and onboarded to Microsoft Defender for Endpoint. Collects device context, process execution history, network connections, registry persistence, file activity, vulnerability assessment, and risk scoring.

| # | Example prompt |
|---|---|
| 1 | *Investigate device YOURPC for suspicious process execution* |
| 2 | *What network connections did device prod-server-01 make in the last 7 days?* |
| 3 | *Show me all vulnerabilities on device my-laptop and their exploitation risk* |
| 4 | *Is device WIN-12345 internet-facing and what ports are exposed?* |
| 5 | *Analyze device my-mac for anomalous logon patterns* |

### identity-posture

Audits organization-wide identity security posture using Microsoft Graph API and Log Analytics. Covers user inventory, directory roles, PIM assignments, Identity Protection risk signals, MFA registration, deleted accounts, stale account detection, password posture, and department-level breakdowns. Produces an HTML report with a composite posture score.

| # | Example prompt |
|---|---|
| 1 | *Run an identity posture audit for the organization* |
| 2 | *Which accounts don't have MFA enabled and pose the highest risk?* |
| 3 | *Audit our service accounts for stale passwords and privilege assignments* |
| 4 | *What's the distribution of privileged roles across the tenant?* |
| 5 | *Show me risky users flagged by Entra ID Identity Protection* |

### incident-investigation

Deep-dives into individual security incidents from Microsoft Defender XDR / Microsoft Sentinel. Retrieves incident metadata, associated alerts, affected assets, and evidence, then orchestrates sub-investigations for involved users, devices, and IoCs. Includes cache management for reusable investigation data across sessions.

| # | Example prompt |
|---|---|
| 1 | *Investigate incident 12345 and show me all associated alerts with timeline* |
| 2 | *Which users and devices are involved in incident 98765?* |
| 3 | *Deep dive into incident 54321 to identify root cause and lateral movement* |
| 4 | *Show me the complete forensic timeline for incident 11111* |
| 5 | *Extract all IoCs from incident 22222 and enrich them* |

### incident-listing

Lists recent security incidents from the Sentinel `SecurityIncident` table aligned with the Defender XDR portal view. Filters by last modification time, excludes phantom incidents (auto-closed with no alerts), and projects ID, title, severity, status, owner, and alert count.

| # | Example prompt |
|---|---|
| 1 | *Show me all incidents modified in the last 24 hours* |
| 2 | *List open incidents ranked by severity and alert count* |
| 3 | *What incidents were created this week?* |
| 4 | *Give me a quick overview of the top 10 incidents* |
| 5 | *Which high-severity incidents are currently unassigned?* |

### incident-statistics

Generates comprehensive incident statistics and SOC metrics from Microsoft Sentinel: severity distribution, MTTA/MTTR analysis, affected users and devices, assignee breakdown, MITRE tactics correlation, true-positive rate, and operational trends. Produces tabular data plus graphical charts.

| # | Example prompt |
|---|---|
| 1 | *Generate incident statistics for the last 90 days* |
| 2 | *What are our MTTA and MTTR metrics?* |
| 3 | *Show me incident distribution by MITRE tactics* |
| 4 | *How many incidents affected users vs. devices in the last 30 days?* |
| 5 | *Create a SOC metrics report with severity distribution and true-positive rate* |

### ioc-investigation

Investigates Indicators of Compromise — IP addresses, domains, URLs, and file hashes. Correlates IoCs with threat intelligence, identifies associated CVEs, enumerates affected organizational assets, and provides third-party enrichment via ipinfo.io, vpnapi.io, AbuseIPDB, and Shodan.

| # | Example prompt |
|---|---|
| 1 | *Investigate IP 203.0.113.42 for connections in our environment* |
| 2 | *What devices are communicating with this malicious file hash?* |
| 3 | *Check if 192.0.2.100 matches any threat intelligence indicators* |
| 4 | *Analyze domain evil.example.com for email delivery and user interactions* |
| 5 | *Find all devices affected by CVE-2024-1234* |

### kql-query-authoring

Generates validated, production-ready KQL queries for Microsoft Sentinel, Defender XDR Advanced Hunting, and Azure Data Explorer. Combines schema validation, official Microsoft Learn documentation, and community examples with platform-specific adaptation and known table-pitfall mitigation.

| # | Example prompt |
|---|---|
| 1 | *Write a KQL query to detect password spray attacks in SigninLogs* |
| 2 | *Create an Advanced Hunting query for phishing detection in EmailEvents* |
| 3 | *How do I query DeviceLogonEvents for failed auth attempts by user and IP?* |
| 4 | *Write a Sentinel detection rule for suspicious process spawning* |
| 5 | *Optimize this KQL query for Data Lake execution* |

### mcp-usage-monitoring

Monitors and audits Model Context Protocol (MCP) server usage across Sentinel and Defender XDR. Tracks Graph MCP, Data Lake MCP, Triage MCP, and Azure MCP activity with user attribution, endpoint access patterns, sensitive API detection, cross-MCP footprint analysis, and usage scoring.

| # | Example prompt |
|---|---|
| 1 | *Show me MCP server usage over the last 30 days* |
| 2 | *Which users have the broadest MCP footprint across server types?* |
| 3 | *Audit Graph API calls initiated via MCP servers for sensitive endpoints* |
| 4 | *Identify the highest-volume MCP tool users* |
| 5 | *Detect anomalous MCP usage patterns compared to baseline* |

### mitre-coverage-report

Generates a comprehensive MITRE ATT&CK coverage analysis. Maps analytic rules and custom detections to tactics and techniques, identifies gaps against the full Enterprise matrix, correlates operational alerts and incidents, and scores coverage across five dimensions. Includes SOC Optimization threat-scenario alignment and untagged-rule remediation recommendations.

| # | Example prompt |
|---|---|
| 1 | *Generate a MITRE ATT&CK coverage report* |
| 2 | *Which tactics have the best and worst detection coverage?* |
| 3 | *What are the top coverage gaps and how can we improve them?* |
| 4 | *Show me untagged detection rules and suggest MITRE mappings* |
| 5 | *Analyze our coverage against ransomware threat scenarios* |

### sentinel-ingestion-report

Analyzes Sentinel workspace data ingestion: table-level volume breakdown, tier classification (Analytics / Basic / Data Lake), deep dives into high-volume tables, ingestion anomaly detection with 24-hour and week-over-week trending, analytic rule health monitoring, tier migration candidates, and license benefit analysis for Defender for Servers P2 and Microsoft 365 E5.

| # | Example prompt |
|---|---|
| 1 | *Generate a Sentinel ingestion report with volume and cost analysis* |
| 2 | *Which tables consume the most data and should move to Data Lake tier?* |
| 3 | *Show me SecurityEvent and Syslog ingestion trends with anomaly detection* |
| 4 | *What cost savings could we achieve with Data Lake migration?* |
| 5 | *Analyze our Defender for Servers P2 license ingestion benefits* |

### threat-pulse

Performs a rapid, broad-spectrum security scan across seven domains — incidents, identity, nonhuman identities, endpoint, email, admin/cloud, and exposure — in roughly 15 minutes. Presents findings as a prioritized dashboard with drill-down recommendations to specialized investigation skills. Ideal as a daily SOC starting point.

| # | Example prompt |
|---|---|
| 1 | *Run a Threat Pulse scan* |
| 2 | *Where should I start investigating security issues today?* |
| 3 | *Generate a quick threat dashboard across all domains* |
| 4 | *What can you do for me right now to assess our security posture?* |
| 5 | *Show me a Threat Pulse overview with drill-down recommendations* |

### user-investigation

Performs comprehensive security investigations on Entra ID user accounts. Collects identity context, sign-in activity analysis, email and Office 365 activity, audit trail events, UEBA behavioral anomalies, and IP enrichment via third-party APIs. Provides risk assessment, incident correlation, and forensic timeline reconstruction.

| # | Example prompt |
|---|---|
| 1 | *Investigate user john.smith@contoso.com for suspicious sign-in activity* |
| 2 | *Show me sign-in timeline, Office 365 activity, and audit events for this user* |
| 3 | *What locations and IPs has this user signed in from in the last 30 days?* |
| 4 | *Enrich user IP addresses with geolocation and threat intelligence* |
| 5 | *Generate a complete forensic report for this potentially compromised account* |

---

## Repository Structure

```
sec-sre-ag/
├── shared/                    ← Scripts shared across multiple skills
├── <skill-name>/              ← Scripts and data to materialize for each skill
└── .builder/                  ← Reference copies of SKILL.md files and LLM docs
    └── <skill-name>/             (the authoritative version is in the Builder)
```

### Convention

| Location | Content | Read by |
|---|---|---|
| `<skill>/` (root) | `.py` scripts, `.json` / `.yaml` data files read by scripts | Python interpreter |
| `shared/` | Scripts shared across skills | Python interpreter |
| `.builder/<skill>/` | SKILL.md, reference docs, KQL queries, svg-widgets.yaml | LLM via `read_skill_file` API |

### Builder-only Files

The files in `.builder/` are **backup / reference copies**. The authoritative version
of all SKILL.md and LLM instruction files is the one in the agent's **Builder**
(SRE Agent portal → Builder → Skills).

### Secrets

API tokens and environment parameters are NOT in the repo.
See `shared/.env.example` for the template of required environment variables.
