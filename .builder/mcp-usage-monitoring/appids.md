# Known AppIds Reference

## MCP Servers & AI Agents

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `e8c77dc2-69b3-43f4-bc51-3213c9d915b4` | Microsoft Graph MCP Server for Enterprise | `MicrosoftGraphActivityLogs` | Read-only Graph API proxy |
| `7b7b3966-1961-47b5-b080-43ca5482e21c` | Sentinel Triage MCP ("Microsoft Defender Mcp") | `MicrosoftGraphActivityLogs`, `SigninLogs`, `AADNonInteractiveUserSignInLogs` | Microsoft first-party AppId, same across all tenants. **Dedicated AppId** — visible in `MicrosoftGraphActivityLogs` (API calls to `/security/*` endpoints) and `SigninLogs`/`AADNonInteractiveUserSignInLogs` (`AppDisplayName = "Microsoft Defender Mcp"`). Delegated auth with certificate (ClientAuthMethod=2), full user attribution. Scopes: `SecurityAlert.Read.All`, `SecurityIncident.Read.All`, `ThreatHunting.Read.All`. Target resources: Microsoft Graph, WindowsDefenderATP. No local SPN — display name only visible in SigninLogs. 🔴 **Confirmed Feb 2026.** |
| `253895df-6bd8-4eaf-b101-1381ec4306eb` | Sentinel Platform Services App Reg | `SigninLogs` | Sentinel-hosted MCP platform |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure MCP Server (local stdio via DefaultAzureCredential → Azure CLI) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Shared AppId with Azure CLI. In LAQueryLogs, `RequestClientApp` is **empty** (not a unique fingerprint). Azure MCP appends `\n\| limit N` to query text — the only query-level differentiator. Read-only ARM ops don't appear in AzureActivity. 🔄 **Updated Feb 2026:** Previously documented as AppId `1950a258` — obsolete. |
| *(none — uses DefaultAzureCredential)* | Azure MCP Server (local stdio) | `AzureActivity` | ARM **write** operations only; read ops not logged. Claims.appid = `04b07795`. |
| *(no AppId — Purview unified audit)* | Sentinel Data Lake MCP | `CloudAppEvents` | RecordType 403; Interface `IMcpToolTemplate`; tools: `query_lake`, `list_sentinel_workspaces`, `search_tables` |

## Sentinel MCP Collection Endpoints

| Endpoint URL | Collection | Monitored |
|-------------|------------|----------|
| `https://sentinel.microsoft.com/mcp/data-exploration` | Data Exploration (Data Lake MCP) | ✅ Phase 3 |
| `https://sentinel.microsoft.com/mcp/triage` | Triage (Triage MCP) | ✅ Phase 2 |
| `https://sentinel.microsoft.com/mcp/security-copilot-agent-creation` | Security Copilot Agent Creation | ❌ See [`landscape.md`](landscape.md) |

## Client Applications

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `aebc6443-996d-45c2-90f0-388ff96faa56` | Visual Studio Code | `SigninLogs` | VS Code as MCP client → Sentinel |
| `9ba5f2e4-6bbf-4df2-b19b-7f1bcb926818` | PowerPlatform-sentinelmcp-Connector | `SigninLogs` | Copilot Studio → Sentinel MCP |
| `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Azure CLI (DefaultAzureCredential) | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | **Primary Azure MCP Server credential path** (field-tested Feb 2026). Shared AppId with manual `az` CLI. |

## Portal & Platform Applications (Non-MCP — for context)

| AppId | Service | Telemetry Table | Notes |
|-------|---------|----------------|-------|
| `80ccca67-54bd-44ab-8625-4b79c4dc7775` | M365 Security & Compliance Center (Sentinel Portal) | `LAQueryLogs` | `ASI_Portal`, `ASI_Portal_Connectors` — NOT an MCP server |
| `95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5` | Azure Portal — AppInsightsPortalExtension | `LAQueryLogs` | Azure Portal blade. NOT MCP, NOT VS Code. |
| `de8c33bb-995b-4d4a-9d04-8d8af5d59601` | PowerPlatform-AzureMonitorLogs-Connector | `AADNonInteractiveUserSignInLogs`, `LAQueryLogs` | Logic Apps → Log Analytics (NOT MCP) |
| `fc780465-2017-40d4-a0c5-307022471b92` | Sentinel Engine (analytics rules, UEBA, Advanced Hunting backend) | `LAQueryLogs` | Built-in scheduled query engine (NOT MCP). Also serves as the **execution backend for Advanced Hunting**. |
