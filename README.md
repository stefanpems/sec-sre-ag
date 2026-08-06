# sec-sre-ag — SRE Agent Custom Skills

This repository provides custom skills and runtime scripts that turn Azure SRE
Agent into a security operations assistant. It integrates with Microsoft
Sentinel, Microsoft Defender XDR, Microsoft Entra ID, Microsoft Graph, Azure
Monitor, and selected threat-intelligence services. Supported use cases include
daily threat posture scans, incident listing, investigation, statistics, and
commenting; forensic investigation of users, endpoints, and indicators of
compromise; identity posture assessment; KQL query authoring and validation;
MITRE ATT&CK coverage analysis; Sentinel ingestion optimization; and MCP usage
monitoring. Skills accept natural-language requests, collect evidence through
approved agent tools, run repository scripts through Code Access, and produce
structured findings, charts, and HTML reports. Top-level skill directories hold
Python runtime code and data, while `.builder` holds deployable Skill Builder
instructions and supporting documents. The setup assets create or update the
skills and configure the identities, permissions, connectors, and data sources
required for customer-owned Azure SRE Agent deployments.

## Contents

| Section | What it contains |
|---|---|
| [Skills](#skills) | Supported security operations use cases, capabilities, and example prompts |
| [Setup](#setup) | Customer repository, agent creation, connectors, skill deployment, IDs, permissions, RBAC, and data prerequisites |
| [Deploy or update skills](#d-deploy-or-update-skills) | Initial creation and idempotent updates with `deploy_skills.py` |
| [Sandbox Architecture & Script Retrieval](#sandbox-architecture--script-retrieval) | Code Access, file resolution, script execution, and runtime configuration behavior |
| [Repository Structure](#repository-structure) | Separation between runtime scripts, shared code, and Skill Builder content |
| [Configuration](#configuration) | Generated `config.json` schema and value sources |

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

### incident-comment

Posts content as a comment on a Microsoft Sentinel incident. Accepts plain text, Markdown, or HTML. Plain text is posted as-is; Markdown is converted to HTML optimized for the narrow Activities panel; HTML is adapted for single-column display. All input content is preserved in full — no summarization or truncation — unless the user explicitly requests it.

| # | Example prompt |
|---|---|
| 1 | *Post this investigation summary as a comment on incident 12345* |
| 2 | *Post the report as a comment on incident 98765* |
| 3 | *Add a comment to incident 54321 with the analysis results* |
| 4 | *Add this text as a comment on the incident* |
| 5 | *Comment on the incident with the HTML report* |

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

Complete the bootstrap stages below before assigning API permissions or Azure
roles. The detailed, customer-ready procedure is in
[`docs/azure-sre-agent-setup.md`](docs/azure-sre-agent-setup.md).

### A. Create a customer-owned repository

Create a private repository owned by the customer by forking this repository,
importing it through GitHub, or cloning it and pushing it to a new empty
repository. Do not deploy directly from `stefanpems/sec-sre-ag`: the customer
copy is the configuration and change-control boundary for its agent.

Grant access only to the administrators and operators who maintain the agent.
Enable branch protection and pull-request review if the agent is allowed to
write code. Never commit PATs, connector credentials, `config.json`, generated
reports, or investigation output.

### B. Create the Azure SRE Agent

If the customer does not already have an agent, create one at
<https://sre.azure.com>. Register the `Microsoft.App` resource provider, choose
a supported region, and start with **Reader** access to only the required
resource groups. Use a user-assigned managed identity when the identity must be
shared across connectors or retained independently of the agent.

Creating the agent and its role assignments requires **Owner**, **User Access
Administrator**, or an equivalent role with
`Microsoft.Authorization/roleAssignments/write`. Connector setup additionally
requires **SRE Agent Author** or **Administrator** on the agent.

### C. Configure Code Access and connectors

In the agent portal, connect the customer repository under **Builder > Code
Access**. For `github.com`, prefer GitHub OAuth for interactive Code Access; it
does not require a PAT. Code Access provides repository search, reads, and
context; it does not create file changes or commits. If the agent must maintain
customer-specific skills and scripts, add a separately governed **GitHub MCP**
connector with only the required branch, file, commit, and pull-request tools.
Protect `main` and require changes through reviewed pull requests. Then add the
connectors below under **Builder > Connectors**:

| Connector | Configuration | Minimum enabled tools |
|---|---|---|
| **Outlook Tools (Office 365 Outlook)** | OAuth sign-in plus managed identity | `Send an email` |
| **Microsoft Teams** | OAuth sign-in plus managed identity | `Post Message in a Chat or Channel`; `Post Message to myself`; `Get message details input metadata`; `Get message details response schema`; `Get response schema` |
| **Log Analytics Workspace** | Customer subscription, resource group, Sentinel workspace, and managed identity | Connector-provided query operation |
| **kql-search-mcp** | Stdio; command `npx`; arguments `-y`, `kql-search-mcp`; `GITHUB_TOKEN`; optional `FAVORITE_REPOS` | The 10 tools listed in the detailed guide |
| **ms-learn-mcp** | Streamable HTTP; `https://learn.microsoft.com/api/mcp`; no authentication | Select all 3 tools |
| **GitHub MCP** (only when repository writes are required) | GitHub MCP partner connector; separate fine-grained PAT | Only branch, file-content, commit, and pull-request tools required by the approved workflow |

The published `kql-search-mcp` package requires `GITHUB_TOKEN`. Use a separate,
fine-grained, read-only PAT scoped only to the repositories searched by the MCP
server. A single PAT can technically serve PAT-authenticated Code Access and
`kql-search-mcp` on `github.com` when its repository scope and permissions cover
both, but this is not recommended. OAuth for Code Access plus separate PATs for
KQL search and write-capable GitHub MCP provides smaller blast radius and
independent rotation.

Follow the detailed guide for exact fields, PAT permissions, governance
settings, validation prompts, and the required response when a credential is
exposed.

### D. Deploy or update skills

Use [`.builder/deploy/deploy_skills.py`](.builder/deploy/deploy_skills.py) both
for the initial creation of the agent's custom skills and for every subsequent
update. The `deploy` command is idempotent: it sends a `PUT` for each selected
skill, creating it when absent and replacing the existing skill definition and
supporting files when present.

```bash
cd .builder/deploy
python deploy_skills.py deploy --dry-run
python deploy_skills.py deploy
python deploy_skills.py list
```

To update only selected skills, pass their folder names:

```bash
python deploy_skills.py deploy --skills identity-posture,incident-investigation
```

The deployer uploads only Skill Builder content from `.builder/<skill>/`. Python
runtime scripts remain in the top-level skill folders and are obtained through
Code Access; they must not be copied into `.builder`. See the
[deployment tool guide](.builder/deploy/README.md) for target configuration,
cross-tenant deployment, and delete operations.

### E. Discover the required IDs

Run [`setup/discover-setup-ids.sh`](setup/discover-setup-ids.sh) from **Azure Cloud Shell (Bash)** before assigning permissions. The script uses read-only Azure CLI commands to list the values required by the assignment scripts:

- UAMI **Object ID** for `assign-permissions.sh`
- UAMI **Client ID** for `assign-azure-roles.sh`
- Microsoft Sentinel workspace **Resource ID**
- Key Vault **Resource ID**, when IP enrichment is enabled

```bash
git clone https://github.com/stefanpems/sec-sre-ag.git
cd sec-sre-ag/setup
chmod +x discover-setup-ids.sh
./discover-setup-ids.sh [SUBSCRIPTION_ID]
```

The subscription argument is optional. When omitted, the script reads the active Azure CLI subscription. It does not call `az account set`; the selected subscription is passed explicitly to every resource query. If exactly one UAMI and one Sentinel workspace are found, the output includes ready-to-run commands for both assignment scripts. Otherwise, select the intended resources from the displayed list.

### 0. Runtime `config.json` (created on first skill execution)

`config.json` is runtime configuration for the SRE Agent sandbox. It is **not**
created by the Cloud Shell setup scripts or by the skill deployment tool, and it
must not be committed to this repository. Do not confuse it with
`.builder/deploy/deploy.config.json`, which only identifies the agent targeted by
the deployment tool.

After connecting this repository and deploying the skills, invoke any skill in
the table below. Before it runs its first script, the skill instructions require
the agent to:

1. Locate the root of the agent's runtime workspace (the parent of `codeRefs/`
   and `tmp/`), not the root of a local deployment clone.
2. Check for `config.json` and validate the required workspace fields.
3. If the file is missing or incomplete, ask only for the tenant name; derive
   the subscription ID, Log Analytics workspace GUID, and workspace name from
   the platform-injected `<azure_resource_access>` and
   `<log_analytics_access>` settings.
4. Discover the Log Analytics workspace resource group with the sandbox Azure
   CLI read tool. The agent must not invoke `az` in the sandbox terminal.
5. Create and then re-read `config.json` before continuing. If the platform
   settings are unavailable or discovery fails, the agent must stop and report
   the missing value instead of guessing it.

The following deployed skills contain this bootstrap procedure and can create
and populate the shared file on their first execution:

| Skill | Runtime use of `config.json` |
|---|---|
| `computer-investigation` | Workspace and subscription fallback for orchestration |
| `identity-posture` | Workspace context; `tenant_name` is also read by the analysis script |
| `incident-investigation` | Workspace and subscription fallback for orchestration |
| `incident-statistics` | Shared workspace bootstrap before script execution |
| `ioc-investigation` | Workspace context and optional IP-enrichment configuration |
| `mcp-usage-monitoring` | Workspace context for Log Analytics queries |
| `mitre-coverage-report` | Read directly by `invoke_mitre_scan.py` |
| `sentinel-ingestion-report` | Read directly by `invoke_ingestion_scan.py` |
| `threat-pulse` | Workspace, subscription, and tenant context |
| `user-investigation` | Workspace context and optional IP-enrichment configuration |

This is **instruction-driven bootstrap**: the agent creates the file through its
file and Azure tools. The Python scripts do not create it themselves; they only
read it when needed. The first skill invoked in a new sandbox creates the shared
file, and later skills reuse it. A new sandbox or conversation may have a fresh
workspace, so the same existence check is performed again.

Expected runtime schema:

```json
{
  "tenant_name": "<tenant name, for example contoso.onmicrosoft.com>",
  "sentinel_workspace_id": "<Log Analytics workspace GUID>",
  "subscription_id": "<Azure subscription ID>",
  "azure_mcp": {
    "subscription_id": "<same Azure subscription ID>",
    "resource_group": "<resource group containing the Log Analytics workspace>",
    "workspace_name": "<Log Analytics workspace name>"
  },
  "api_tokens": {}
}
```

`api_tokens` remains empty. IP-enrichment tokens are loaded from Key Vault or
environment variables at runtime. `config.json`, output, and report directories
are excluded by `.gitignore`.

### 1. API Permissions (Entra ID — Graph + MDE)

The agent's **User-Assigned Managed Identity (UAMI)** needs **Application permissions** on Microsoft Graph and WindowsDefenderATP APIs.

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
| `SecurityIncident.ReadWrite.All` | incident-comment | Write comments on Sentinel incidents |

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

All permissions above are **Application** type (not Delegated). All are read-only except `SecurityIncident.ReadWrite.All` which is read-write (required to post incident comments).

#### How to assign

Run [`setup/assign-permissions.sh`](setup/assign-permissions.sh) from **Azure Cloud Shell (Bash)** with an account that has **Global Administrator** or **Privileged Role Administrator** role:

```bash
git clone https://github.com/stefanpems/sec-sre-ag.git
cd sec-sre-ag/setup
chmod +x assign-permissions.sh
./assign-permissions.sh <UAMI_OBJECT_ID>
```

The script takes a single argument — the **Object ID** of the UAMI (Azure Portal → Managed Identities → *your-identity* → Overview). It is idempotent (skips permissions already assigned). After running, wait up to 1 hour for the Entra ID token cache to refresh.

> **Note:** Skills that depend on Graph API (`user-investigation`, `computer-investigation`, `identity-posture`) include KQL-based fallback queries that work even when Graph API permissions are not yet effective.

### 2. Azure RBAC Roles

The UAMI also needs Azure RBAC roles for Sentinel workspace access and (optionally) Key Vault secret retrieval.

| Role | Scope | Required | Purpose |
|---|---|---|---|
| **Microsoft Sentinel Reader** | Log Analytics workspace | Yes | All skills querying Sentinel tables via Azure Monitor MCP (includes Log Analytics Reader) |
| **Microsoft Sentinel Responder** | Log Analytics workspace | Yes (incident-comment) | Post comments on incidents via ARM/Sentinel API |
| **Key Vault Secrets User** | Key Vault resource | Optional | Only needed for IP enrichment API tokens |

> **Why is Sentinel Responder required?** The Graph API `SecurityIncident.ReadWrite.All` permission is assigned to the UAMI as an Application permission, but the agent's sandbox uses a **delegated user token** for Graph API calls — which does not carry Application-level scopes. The ARM/Sentinel REST API uses the UAMI's own token (where RBAC roles apply), making it the reliable path for posting incident comments.

#### How to assign

Run [`setup/assign-azure-roles.sh`](setup/assign-azure-roles.sh) from **Azure Cloud Shell (Bash)** with an account that has **Owner** or **User Access Administrator** on the target scope:

```bash
cd sec-sre-ag/setup
chmod +x assign-azure-roles.sh
./assign-azure-roles.sh <UAMI_CLIENT_ID> <WORKSPACE_RESOURCE_ID> [KEYVAULT_RESOURCE_ID]
```

| Argument | Required | Where to find it |
|---|---|---|
| `UAMI_CLIENT_ID` | Yes | Azure Portal → Managed Identities → *your-identity* → Properties → **Client ID** |
| `WORKSPACE_RESOURCE_ID` | Yes | Azure Portal → Log Analytics workspace → Properties → **Resource ID** |
| `KEYVAULT_RESOURCE_ID` | Optional | Azure Portal → Key Vault → Properties → **Resource ID** |

The script is idempotent (skips roles already assigned). RBAC roles typically propagate within 5–10 minutes.

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

### 5. Sign-in Anomaly KQL Job (recommended)

The `user-investigation` and `incident-investigation` skills use the optional
`Signinlogs_Anomalies_KQL_CL` table to prioritize new sign-in IP addresses,
device combinations, and geographic novelty against a 90-day baseline. Without
it, the skills continue with raw `SigninLogs` fallbacks but provide less precise
anomaly prioritization.

The table is created and populated by an hourly Microsoft Sentinel Data Lake KQL
job. Follow [`setup/signin-anomalies-kql-job.md`](setup/signin-anomalies-kql-job.md)
and use the included
[`setup/signin-anomalies-kql-job.kql`](setup/signin-anomalies-kql-job.kql). The
Data Lake managed identity (`msg-resources-<guid>`) must have **Log Analytics
Contributor** on the destination workspace; this identity is separate from the
agent UAMI configured in sections 1 and 2.

### 6. Diagnostic Settings (optional)

For MCP usage monitoring and audit capabilities, enable these diagnostic settings on the Log Analytics workspace:

| Diagnostic setting | Table | Used by |
|---|---|---|
| **Audit** → `Log Analytics workspace queries` | `LAQueryLogs` | mcp-usage-monitoring |
| **Audit** → `Microsoft Graph activity logs` | `MicrosoftGraphActivityLogs` | mcp-usage-monitoring |

These are optional — all other skills work without them.

### 7. Known Issues & Memory Seeding

The skills have been tested extensively and several **platform constraints, KQL pitfalls, and operational patterns** have been documented in [`docs/known-issues.md`](docs/known-issues.md). These include:

- Sandbox limitations (no PowerShell, no shell `az`, MI token caching up to 24h)
- KQL column-name gotchas (`ThreatIntelIndicators` vs deprecated `ThreatIntelligenceIndicator`, `SecurityIncident` alignment with Defender XDR portal, `SentinelHealth` casing)
- Operational patterns (prefetch workflow, sequential Graph API calls)

**First-time setup:** After connecting this repository to your agent, ask it to seed its memory with these learnings in the first conversation:

```
Read the file codeRefs/sec-sre-ag/docs/known-issues.md and save its contents 
to your memory as operational knowledge. Organize it into your debugging index 
and behavior expectations as you see fit.
```

This is a one-time operation — the agent remembers across threads. See the guide's [full instructions](docs/known-issues.md#using-this-guide-with-the-agent) for details.

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

Ten runtime skills listed in [Setup section 0](#0-runtime-configjson-created-on-first-skill-execution) include a **Pre-requisite: Environment Configuration** section that instructs the agent to ensure `config.json` exists at the workspace root before running a script. The agent bootstraps the file on the first applicable skill execution in a sandbox by:

1. **Checking** that `config.json` contains all required workspace fields.
2. **If missing or incomplete**, extracting environment values from the agent's own platform settings (`<azure_resource_access>`, `<log_analytics_access>`), asking the user for the tenant name, and discovering the resource group through the sandbox Azure CLI read tool.
3. **Writing and validating** `config.json` at the runtime workspace root with `tenant_name`, `sentinel_workspace_id`, `subscription_id`, and `azure_mcp` fields.

Scripts that consume the file find it by walking up from their own directory (up to 6–10 levels of parent directories). Because the runtime workspace root is an ancestor of both `codeRefs/sec-sre-ag/<skill>/` and `tmp/<skill>/`, the file is found regardless of which File Resolution cascade step resolved the script. The `api_tokens` object is left empty; API tokens are loaded from Key Vault or environment variables independently.

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

The applicable SRE Agent skill instructions generate `config.json` at the
runtime workspace root from platform settings before running their first script.
No manually maintained or repository-tracked runtime configuration file is
needed. See [Setup section 0](#0-runtime-configjson-created-on-first-skill-execution)
for timing, ownership, eligible skills, and failure behavior.

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
  "api_tokens": {}
}
```

The agent reads these values from:
- `sentinel_workspace_id`, `subscription_id`, `azure_mcp.*` → from `<agent_settings>` and `<log_analytics_access>` injected by the platform
- `tenant_name` → from agent memory or user prompt
- IP-enrichment tokens → from Azure Key Vault or environment variables at runtime; they are not persisted in `config.json`

Scripts also accept CLI arguments (`--workspace-id`, `--subscription-id`, etc.)
which override `config.json` values.
