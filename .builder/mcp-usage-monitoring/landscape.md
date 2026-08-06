# Extended Microsoft MCP Server Landscape (Reference)

Beyond the four MCP servers actively monitored by this skill, Microsoft's MCP ecosystem includes many additional servers. This section catalogs them for awareness, threat modeling, and future monitoring expansion.

## Sentinel MCP Collections (Microsoft-Hosted)

| Collection | Endpoint URL | Purpose | Monitored by This Skill |
|------------|-------------|---------|-------------------------|
| **Data Exploration** | `https://sentinel.microsoft.com/mcp/data-exploration` | `query_lake`, `search_tables`, `list_sentinel_workspaces`, entity analyzer | ✅ Phase 3 (CloudAppEvents) |
| **Triage** | `https://sentinel.microsoft.com/mcp/triage` | Incident triage, Advanced Hunting, entity investigation | ✅ Phase 2 (MicrosoftGraphActivityLogs + SigninLogs) |
| **Security Copilot Agent Creation** | `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Create Microsoft Security Copilot agents | ❌ Not yet monitored |

**Sentinel Custom MCP Tools:** Organizations can create their own MCP tools by exposing saved KQL queries from Advanced Hunting as MCP tools. These execute through the same Sentinel MCP infrastructure and are audited in `CloudAppEvents` (RecordType 403) alongside built-in tools.

## Power BI MCP Servers

| Server | Type | Endpoint / Repo | Purpose | Telemetry Surface |
|--------|------|----------------|---------|-------------------|
| **Power BI Remote MCP** | Microsoft-hosted | `https://api.fabric.microsoft.com/v1/mcp/powerbi` | Query Power BI datasets, reports, and workspaces remotely | 🟡 `PowerBIActivity` table |
| **Power BI Modeling MCP** | Local (stdio) | [microsoft/powerbi-modeling-mcp](https://github.com/microsoft/powerbi-modeling-mcp) | Local Power BI model operations | ❌ Local only |

## Fabric & Azure Data Explorer MCP Servers

| Server | Type | Endpoint / Repo | Purpose | Telemetry Surface |
|--------|------|----------------|---------|-------------------|
| **Fabric RTI MCP Server** | Local (stdio) | [microsoft/fabric-rti-mcp](https://github.com/microsoft/fabric-rti-mcp/) | Query ADX clusters and Fabric RTI Eventhouses | 🟡 ADX audit logs |
| **Azure MCP Server — Kusto namespace** | Local (stdio) | Part of Azure MCP Server | Manage ADX clusters, databases, tables | ✅ Already covered (Phase 4) |
| **Kusto Query MCP** | Copilot Studio built-in | Copilot Studio catalog | KQL query execution from Copilot Studio agents | 🟡 CloudAppEvents |

## Developer & Productivity MCP Servers

| Server | Type | Repo | Purpose | Telemetry Surface |
|--------|------|------|---------|-------------------|
| **Playwright MCP** | Local (stdio) | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | Browser automation | ❌ Local only |
| **GitHub MCP Server** | Local (stdio) | [github/github-mcp-server](https://github.com/github/github-mcp-server) | GitHub repo operations | ❌ GitHub audit logs only |
| **Microsoft Learn Docs MCP** | Cloud-hosted | Certified Copilot Studio connector | Documentation search | ❌ Public docs |

## Copilot Studio Built-in MCP Servers (19+ servers)

| Category | MCP Servers | Security Relevance |
|----------|-------------|--------------------|
| **Microsoft 365** | Outlook Mail, Outlook Calendar, 365 User Profile, Teams, Word, 365 Copilot (Search) | 🔴 High — email, calendar, user profile access |
| **SharePoint & OneDrive** | SharePoint and OneDrive, SharePoint Lists | 🟠 Medium — file and data access |
| **Administration** | 365 Admin Center | 🔴 High — administrative control plane |
| **Dataverse** | Dataverse MCP | 🟠 Medium — business data access |
| **Dynamics 365** | Sales, Finance, Supply Chain, Service, ERP, Contact Center | 🟡 Low-Medium |
| **Fabric** | Fabric MCP | 🟠 Medium — analytics data access |
| **Office 365 Outlook** | Contact Management, Email Management, Meeting Management | 🔴 High — email and contact data |
| **Meta-Server** | MCP Management MCP | 🟠 Medium — manages other MCP servers |

> ⚠️ **Telemetry gap:** Copilot Studio built-in MCP servers are NOT directly visible in `LAQueryLogs` or `MicrosoftGraphActivityLogs`. Monitor via `CloudAppEvents` (Copilot Studio workload) or M365 unified audit log.

## Azure MCP Server — Full Tool Surface

| Category | Namespaces | Security-Relevant Tools |
|----------|-----------|------------------------|
| **AI & ML** | `foundry`, `search`, `speech` | AI Foundry model access, Search index queries |
| **Identity** | `role` | ⚠️ RBAC role assignments |
| **Security** | `keyvault`, `appconfig`, `confidentialledger` | 🔴 Key Vault secrets/keys/certs |
| **Databases** | `cosmos`, `mysql`, `postgres`, `redis`, `sql` | Database access |
| **Storage** | `storage`, `fileshares`, `storagesync`, `managedlustre` | Blob, file access |
| **Compute** | `appservice`, `functionapp`, `aks` | App Service, Functions, Kubernetes |
| **Networking** | `eventhubs`, `servicebus`, `eventgrid`, `communication`, `signalr` | Messaging |
| **DevOps** | `bicepschema`, `deploy`, `monitor`, `workbooks`, `grafana` | Infrastructure deployment |
| **Governance** | `policy`, `quota`, `resourcehealth`, `cloudarchitect` | Policy management |

## Monitoring Expansion Priorities

| Priority | Server | Why | How to Monitor |
|----------|--------|-----|----------------|
| 🔴 **P1** | Copilot Studio built-in M365 MCPs | Email, Teams, admin center access | `ai-agent-posture` skill + CloudAppEvents |
| 🔴 **P1** | Security Copilot Agent Creation | Creates autonomous security agents | CloudAppEvents |
| 🟠 **P2** | Power BI Remote MCP | Dataset query access via API | `PowerBIActivity` table |
| 🟠 **P2** | Sentinel Custom MCP Tools | User-defined tools, same audit surface | Already visible in Phase 3 CloudAppEvents |
| 🟡 **P3** | Fabric RTI MCP | ADX/Eventhouse data access | ADX diagnostic logs |
| ⚪ **P4** | Playwright, GitHub, Learn Docs MCPs | Local/public, minimal telemetry | Not monitorable from Sentinel |
