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

## Setup

### 1. API Permissions (Graph + MDE)

The agent's **User-Assigned Managed Identity (UAMI)** needs read-only **Application permissions** on Microsoft Graph and WindowsDefenderATP APIs.

#### Microsoft Graph

| Permission | Skills | Notes |
|---|---|---|
| `User.Read.All` | user-investigation, identity-posture | |
| `Device.Read.All` | computer-investigation | |
| `Directory.Read.All` | identity-posture | |
| `RoleManagement.Read.Directory` | identity-posture | |
| `UserAuthenticationMethod.Read.All` | user-investigation, identity-posture | |
| `IdentityRiskyUser.Read.All` | user-investigation, identity-posture | Requires Entra ID P2 |
| `IdentityRiskEvent.Read.All` | user-investigation, identity-posture | Requires Entra ID P2 |
| `AuditLog.Read.All` | user-investigation, identity-posture | |
| `Reports.Read.All` | identity-posture | |

#### WindowsDefenderATP (MDE)

| Permission | Skills | Notes |
|---|---|---|
| `Machine.Read.All` | computer-investigation, ioc-investigation | |
| `Alert.Read.All` | incident-investigation, ioc-investigation | |
| `File.Read.All` | ioc-investigation | |
| `Ip.Read.All` | ioc-investigation | |
| `Url.Read.All` | ioc-investigation | |
| `Ti.Read.All` | ioc-investigation | |
| `AdvancedQuery.Read.All` | computer-investigation, ioc-investigation | Advanced Hunting queries |
| `Vulnerability.Read.All` | computer-investigation, ioc-investigation | |

All permissions are **read-only** (Application type, not Delegated).

#### How to assign

Run the setup script from **Azure Cloud Shell (Bash)** with an account that has **Global Administrator** or **Privileged Role Administrator** role:

```bash
git clone https://github.com/stefanpems/sec-sre-ag.git
cd sec-sre-ag/setup
chmod +x assign-permissions.sh
./assign-permissions.sh <UAMI_OBJECT_ID>
```

Where `<UAMI_OBJECT_ID>` is the Object ID of the agent's User-Assigned Managed Identity (Azure Portal → Managed Identities → *your-identity* → Overview).

The script is idempotent — it skips permissions already assigned. After running, wait up to 1 hour for the Entra ID token cache to refresh.

> **Note:** Skills that depend on Graph API (`user-investigation`, `computer-investigation`, `identity-posture`) include KQL-based fallback queries that work even when Graph API permissions are not yet effective.

### 2. Azure RBAC Roles

The UAMI also needs Azure RBAC roles for Sentinel workspace access and (optionally) Key Vault secret retrieval.

| Role | Scope | Purpose |
|---|---|---|
| **Microsoft Sentinel Reader** | Log Analytics workspace | All skills querying Sentinel tables via Azure Monitor MCP (includes Log Analytics Reader) |
| **Key Vault Secrets User** | Key Vault resource | Optional — only needed for IP enrichment API tokens |

Assign with Azure CLI:

```bash
# Sentinel Reader (required)
az role assignment create \
  --assignee <UAMI_PRINCIPAL_ID> \
  --role "Microsoft Sentinel Reader" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<WORKSPACE_RG>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE_NAME>"

# Key Vault Secrets User (optional — only if using IP enrichment)
az role assignment create \
  --assignee <UAMI_PRINCIPAL_ID> \
  --role "Key Vault Secrets User" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<KEYVAULT_RG>/providers/Microsoft.KeyVault/vaults/<KEYVAULT_NAME>"
```

Replace the `<PLACEHOLDERS>` with your actual values.

### 3. Key Vault Setup (optional — IP enrichment)

The `shared/enrich_ips.py` script enriches IP addresses with third-party threat intelligence. If you want to use it, store API tokens as secrets in an Azure Key Vault and grant the UAMI **Key Vault Secrets User** role (see §2 above).

| Secret name | Service | Required |
|---|---|---|
| `ABUSEIPDB-TOKEN` | [AbuseIPDB](https://www.abuseipdb.com/) | Recommended |
| `IPINFO-TOKEN` | [ipinfo.io](https://ipinfo.io/) | Recommended |
| `VPNAPI-TOKEN` | [vpnapi.io](https://vpnapi.io/) | Optional |
| `SHODAN-TOKEN` | [Shodan](https://www.shodan.io/) | Optional |

Skills affected: `user-investigation`, `ioc-investigation`.

### 4. Data Connector Prerequisites

The skills query tables that are populated by **Microsoft Sentinel data connectors**. Enable the relevant connectors in your Sentinel workspace:

| Connector | Key tables | Skills |
|---|---|---|
| Microsoft Entra ID | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` | user-investigation, identity-posture, incident-statistics |
| Microsoft Defender XDR | `AlertInfo`, `AlertEvidence`, `SecurityIncident`, `SecurityAlert` | incident-investigation, incident-listing, incident-statistics, threat-pulse |
| Microsoft Defender for Endpoint | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceFileEvents`, `DeviceInfo` | computer-investigation, ioc-investigation |
| Microsoft Defender for Identity | `IdentityLogonEvents`, `IdentityDirectoryEvents` | user-investigation |
| Microsoft Defender for Cloud Apps | `CloudAppEvents` | user-investigation |
| Office 365 | `OfficeActivity` | user-investigation |
| Entra ID Identity Protection | `AADRiskyUsers`, `AADUserRiskEvents` | user-investigation, identity-posture |
| Threat Intelligence — MDTI | `ThreatIntelIndicators` | ioc-investigation |

### 5. Diagnostic Settings (optional)

For MCP usage monitoring and audit capabilities, enable these diagnostic settings on the Log Analytics workspace:

| Diagnostic setting | Table | Used by |
|---|---|---|
| **Audit** → `Log Analytics workspace queries` | `LAQueryLogs` | mcp-usage-monitoring |
| **Audit** → `Microsoft Graph activity logs` | `MicrosoftGraphActivityLogs` | mcp-usage-monitoring |

These are optional — all other skills work without them.

---

## Sandbox Architecture & Script Retrieval

### How the Sandbox Works

In Azure SRE Agent, when a new conversation is started, a new thread is created. The agent's tool execution runs inside an isolated sandbox — a micro VM powered by Azure Dedicated Compute (ADC), separate from the reasoning engine. In the sandbox's workspace filesystem, under `codeRefs/`, the content of the GitHub or Azure DevOps repositories connected to the agent is cloned and made available for reading.

This means that when a skill needs to execute a Python script or load a companion data file (JSON, YAML), the file already exists on the sandbox filesystem at a predictable path such as `codeRefs/sec-sre-ag/<skill-name>/<filename>`.

### File Resolution Cascade (`codeRefs`-first)

Every SKILL.md in this repository instructs the agent to resolve script and data files using a **mandatory three-step cascade** before execution:

```
1. codeRefs/sec-sre-ag/<skill-name>/<filename>
   → If found: use / execute directly from this path.
     Companion files (queries.yaml, JSON reference data, etc.) are co-located here.

2. tmp/<skill-name>/<filename>
   → If found: use from this path (left over from a previous materialization
     in the same conversation).

3. Neither found → materialize from Builder:
   → read_skill_file("<skill-name>", "<filename>") — returns file content via API
   → CreateFile("tmp/<skill-name>/<filename>", <content>)
   → Repeat for ALL companion files the script depends on.
```

**Rules enforced in every SKILL.md:**
- When a file is found in `codeRefs/`, execute it directly from there — do **not** copy it to `tmp/`.
- When materializing from Builder (step 3), materialize **all** companion files the script depends on, not just the script itself.
- The `read_skill_file` tool returns file content via API but does **not** place files on the local filesystem. Running `python3 <script>.py` directly will fail with `No such file or directory` (exit code 2) unless the file has been resolved first.

### Why the Cascade?

`codeRefs/` contains the latest version-controlled scripts with companion files co-located. Because the repository is cloned into the sandbox automatically, step 1 succeeds in the vast majority of cases, making execution fast and reliable. Steps 2 and 3 exist as fallbacks: step 2 reuses files already materialized earlier in the conversation, and step 3 fetches content from the Builder API as a last resort.

### How Scripts Locate Their Own Files at Runtime

Once the agent has resolved a script to a filesystem path and invokes it with `python3`, the scripts themselves use two patterns to find companion files:

| Pattern | Used by | Mechanism |
|---|---|---|
| **`Path(__file__).resolve().parent`** | Data-gathering scripts (`invoke_mitre_scan.py`, `invoke_ingestion_scan.py`, `analyze-identity-posture.py`, `enrich_ips.py`) | Resolves the directory containing the running script, then opens co-located files like `queries.yaml`, `mitre-attck-enterprise.json`, `known-kql-tables.json` via `script_dir / 'filename'`. Also walks up parent directories (6–10 levels) to find the root `config.json`. |
| **`sys.argv[1]`** | HTML report generators (`generate_html_report.py` in every skill), chart generators (`generate_charts.py`) | Receives the path to a JSON data file (or directory) as a positional CLI argument. The agent passes the path of the JSON it produced in the previous step. |

No script manipulates `sys.path` or imports modules from other skill directories. Every script is self-contained. Shared utilities (e.g., `shared/enrich_ips.py`) are invoked as subprocesses, not imported.

### Dynamic `config.json` Creation

Every skill's SKILL.md includes a **Pre-requisite: Environment Configuration** section that instructs the agent to ensure `config.json` exists at the workspace root before running any script. The agent creates this file dynamically at the start of each session by:

1. **Checking** whether `config.json` already exists at the workspace root with a non-empty `sentinel_workspace_id`.
2. **If missing**, extracting environment values from the agent's own platform settings (`<azure_resource_access>`, `<log_analytics_access>`), asking the user for the tenant name, and discovering the resource group via `az monitor log-analytics workspace show`.
3. **Writing** `config.json` at the workspace root with `tenant_name`, `sentinel_workspace_id`, `subscription_id`, and `azure_mcp` fields.

At runtime, every Python script finds `config.json` by walking up from its own directory (up to 6 levels of parent directories). Because the workspace root is always an ancestor of both `codeRefs/sec-sre-ag/<skill>/` and `tmp/<skill>/`, the file is found regardless of which File Resolution cascade step resolved the script. The `api_tokens` object is left empty — API tokens are loaded from Key Vault or environment variables independently.

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

---

## Configuration

The SRE Agent auto-generates `config.json` at the workspace root from its platform
settings (`<agent_settings>`, `<log_analytics_access>`) before running any skill script.
No manual configuration file is needed.

### config.json schema (auto-generated)

```json
{
  "tenant_name": "<short tenant name for report filenames>",
  "sentinel_workspace_id": "<Log Analytics workspace GUID>",
  "subscription_id": "<Azure subscription ID>",
  "azure_mcp": {
    "subscription_id": "<same as above>",
    "resource_group": "<resource group containing the LA workspace>",
    "workspace_name": "<Log Analytics workspace name>"
  },
  "api_tokens": {
    "abuseipdb": "<retrieved from Key Vault at runtime>",
    "ipinfo": "<retrieved from Key Vault at runtime>",
    "vpnapi": "<retrieved from Key Vault at runtime>",
    "shodan": "<optional>"
  }
}
```

The agent reads these values from:
- `sentinel_workspace_id`, `subscription_id`, `azure_mcp.*` → from `<agent_settings>` and `<log_analytics_access>` injected by the platform
- `tenant_name` → from agent memory or user prompt
- `api_tokens.*` → from Azure Key Vault at runtime (for `enrich_ips.py` only)

Scripts also accept CLI arguments (`--workspace-id`, `--subscription-id`, etc.)
which override `config.json` values.
