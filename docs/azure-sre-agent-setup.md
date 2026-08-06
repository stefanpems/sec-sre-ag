# Azure SRE Agent Customer Deployment

This guide creates a customer-owned deployment of the security operations
skills in this repository. Complete the stages in order. Use customer-owned
Azure resources, identities, Microsoft 365 accounts, and GitHub credentials.

## 1. Create the Customer Repository

Create a private repository in the customer's GitHub organization. This copy is
the source connected to Azure SRE Agent and the boundary for customer-specific
configuration, reviews, and change history.

Choose one of these methods:

1. **Fork** the repository when the organization permits private forks and the
   desired visibility and upstream relationship are supported.
2. Use GitHub **Import repository** to create an independent copy from
   `https://github.com/stefanpems/sec-sre-ag.git`.
3. Clone and push to a new empty customer repository:

   ```bash
   git clone https://github.com/stefanpems/sec-sre-ag.git
   cd sec-sre-ag
   git remote rename origin upstream
   git remote add origin https://github.com/<customer-org>/<customer-repo>.git
   git push -u origin main
   ```

Keep the `upstream` remote only if the customer intends to review and merge
future updates. Do not automate upstream merges into production without review.

Apply these repository controls:

- Limit repository access to agent administrators and security operators.
- Protect `main`; require pull requests and reviews for production changes.
- Enable secret scanning and push protection where available.
- Do not store PATs, OAuth tokens, connector secrets, runtime `config.json`,
  generated reports, or investigation output in Git.
- Treat every token visible in a screenshot, chat, log, or committed file as
  compromised. Revoke it immediately, create a replacement, and update the
  connector that used it.

**Checkpoint:** The customer repository contains the project, `main` is the
default branch, and the intended agent administrators can read it.

## 2. Create the Azure SRE Agent

Skip this stage only when the customer already has a running Azure SRE Agent
that will own this deployment.

### Prerequisites

- An active Azure subscription.
- The `Microsoft.App` resource provider registered in that subscription.
- A resource group for the agent and its supporting resources.
- **Owner**, **User Access Administrator**, or equivalent permission containing
  `Microsoft.Authorization/roleAssignments/write` for agent provisioning and
  role assignment.
- Browser and network access to `sre.azure.com`, `*.azuresre.ai`, Azure Resource
  Manager, Microsoft Entra ID, and the Azure Monitor query endpoints.
- A currently supported Azure SRE Agent region. Confirm the list in the portal;
  current Microsoft documentation lists Sweden Central, East US 2, and
  Australia East.

### Provision the agent

1. Open <https://sre.azure.com> and select **Create agent**.
2. Select the customer subscription and resource group.
3. Enter a customer-specific agent name and choose a supported region.
4. Select only the resource groups required by the security operations use
   cases. Start with **Reader** access.
5. Complete deployment and wait until the agent state is **Running**.
6. Record the agent's managed identity. The system-assigned identity is the
   simplest choice. Use a user-assigned managed identity (UAMI) when the
   identity must be shared across connectors, managed independently, or retain
   its lifecycle outside the agent.

Agent provisioning creates the SRE Agent resource, a managed identity, role
assignments, Application Insights, and a Log Analytics workspace for agent
telemetry. That telemetry workspace is not automatically the customer's
Microsoft Sentinel workspace.

**Checkpoint:** Deployment succeeded, the agent is **Running**, and a test chat
can list the Azure resources within its assigned scope.

## 3. Connect the Customer Repository

Code Access gives the agent repository context for skills and scripts. It is
separate from a GitHub managed connector or GitHub MCP server, which expose
issue, pull-request, workflow, and other GitHub operations.

1. In the agent portal, open **Builder > Code Access**.
2. Add GitHub Code Access and authenticate.
3. For repositories on `github.com`, prefer **OAuth**. OAuth Code Access does
   not require a PAT.
4. Select only the customer repository created in stage 1.
5. Wait until repository status is **Ready**.

Code Access is read/search/context access. Microsoft documents code search,
file reads, branch selection, error correlation, and semantic search; it does
not document file edits, commits, or branch creation as Code Access operations.
Do not describe a Ready Code Access connection as read/write.

GitHub Enterprise Cloud repositories using a `<tenant>.ghe.com` endpoint
require a customer-owned GitHub App rather than OAuth or PAT authentication.

**Checkpoint:** Code Access shows the customer repository as **Ready**, and the
agent can identify the repository README and `.builder` directory.

### Add write access when required

If the customer wants the agent to maintain skills or scripts, add the
**GitHub MCP** partner connector separately. The managed GitHub connector
documents issue, pull-request, and workflow operations, but not file edits or
commits; GitHub MCP is the integration intended to expose the full GitHub tool
catalog.

1. Open **Builder > Connectors > Add connector > MCP** and select the GitHub MCP
   partner connector.
2. Authenticate with a separate fine-grained PAT scoped only to the customer
   repository.
3. Enable only the catalog's current equivalents for creating a branch,
   creating or updating file content, creating commits, and creating or
   updating pull requests. Tool labels come from the GitHub MCP server and can
   change between server versions; verify their descriptions before enabling
   them.
4. Set file, commit, branch, and pull-request write tools to **Ask** for
   interactive operation.
5. Protect `main` and require the MCP workflow to write to a branch and open a
   reviewed pull request. Do not enable direct production-branch writes.

For GitHub Enterprise Cloud at `<tenant>.ghe.com`, Code Access requires a
customer-owned GitHub App. Support for a particular GitHub MCP endpoint is
server-dependent; do not assume a `github.com` PAT configuration works for GHE.

## 4. Plan GitHub Credentials

The recommended design uses two independent authentication paths:

| Consumer | Recommended authentication | Minimum repository permission |
|---|---|---|
| Code Access, read-only | GitHub OAuth | Grant access only to the customer repository |
| `kql-search-mcp` | Separate fine-grained PAT | Metadata: Read; Contents: Read on searched private repositories |
| GitHub MCP, write workflow | Separate fine-grained PAT plus protected branches | Metadata: Read; Contents: Read and write; Pull requests: Read and write when PR tools are enabled |

The `kql-search-mcp` version verified for this guide is `1.0.5`. Its published
entry point exits when `GITHUB_TOKEN` is absent. `FAVORITE_REPOS` is optional
and accepts a comma-separated list of `owner/repository` values.

For a fine-grained PAT:

1. Set the resource owner to the customer organization.
2. Select only repositories that the KQL search server must inspect.
3. Grant **Metadata: Read** and **Contents: Read**.
4. Add **Contents: Read and write** only to the separate GitHub MCP credential
   when its enabled tools modify files or create commits.
5. Add **Pull requests: Read and write** only to that credential when PR tools
   are enabled.
6. Use a short expiration, record an owner, and define a rotation process.
7. Complete organization approval if the organization requires approval for
   fine-grained PATs.

A classic token needs the package-documented `public_repo` scope for public
repository search or `repo` for private repositories, but a fine-grained token
is preferred because it can be restricted to selected repositories and read
permissions.

One PAT can technically serve PAT-authenticated Code Access,
`kql-search-mcp`, and a PAT-authenticated GitHub MCP on `github.com` if every
consumer accepts it and the token covers the union of their repositories and
permissions. This is an interoperability inference, not a Microsoft
recommendation. Do not use it as the default: sharing the token couples
rotation, forces the read-only KQL server to share a write-capable credential,
and increases the impact of disclosure. Prefer OAuth for Code Access, a
read-only PAT for `kql-search-mcp`, and a separate write-capable PAT for GitHub
MCP.

Never place a real PAT in this repository. Enter it only in the Azure SRE Agent
connector's protected environment-variable field.

## 5. Add Notification Connectors

Connector creation requires **SRE Agent Author** or **Administrator** on the
agent. Outlook and Teams also require a Microsoft 365 account and permission to
create the connection and role assignment in the agent resource group. The
OAuth account is the identity that sends notifications; the selected managed
identity lets the agent access the connector through Azure Resource Manager at
runtime.

### Outlook

1. Open **Builder > Connectors > Add connector**.
2. Select **Outlook Tools (Office 365 Outlook)**.
3. Sign in with the customer account that is permitted to send reports.
4. Select the agent managed identity. Prefer the deployment UAMI when one is
   used consistently across connectors.
5. Enable at least **Send an email**.
6. Configure write operations as **Ask** for interactive use. Review autonomous
   workflows separately because autonomous mode executes `Ask` tools without a
   human approval prompt.
7. Add the connector and verify its status is **Connected**.

Test with:

```text
Send an email to <test-address> with subject "SRE Agent connector test" and an HTML body stating that the Outlook connector is working.
```

The agent supports HTML email and attachments. For repository report delivery,
follow [email-html-report.md](email-html-report.md).

### Microsoft Teams

The connector catalog is a preview surface and operation labels can change.
Select the following operations when these labels are present:

- **Post Message in a Chat or Channel**
- **Post Message to myself**
- **Get message details input metadata**
- **Get message details response schema**
- **Get response schema**

Then:

1. Sign in with a customer Teams account that can access the intended team,
   channel, or chat.
2. Select the agent managed identity.
3. Set posting operations to **Ask** for interactive use. Leave schema and
   metadata reads as **Allow**.
4. Lock a channel or recipient parameter only when this agent must never send
   outside that destination. Leave it agent-defined when users choose the
   destination at runtime.
5. Add the connector and verify its status is **Connected**.

The current Microsoft documentation describes the stable capabilities as post
message, reply to thread, and get messages. The five labels above are the
operation names observed in the managed connector catalog used by this project;
reselect their current equivalents if the preview catalog renames them.

Test with a nonproduction destination:

```text
Post an HTML message to <test-channel-or-chat> stating that the SRE Agent Teams connector is working.
```

For exact channel, group-chat, direct-message, and self-message payloads, follow
[teams-delivery.md](teams-delivery.md).

## 6. Add the Log Analytics Connector

The agent's built-in Azure tools can query Log Analytics without this connector.
The connector is still recommended for the primary Sentinel workspace because
it removes repeated discovery, lowers query latency, and reduces token use.

1. Open **Builder > Connectors > Add connector**.
2. Select **Log Analytics Workspace** under **Telemetry**.
3. Enter a descriptive name such as `sentinel-primary`.
4. Select the customer subscription and the Microsoft Sentinel Log Analytics
   workspace. The portal may display its resource group with the workspace.
5. Select the agent managed identity.
6. Add the connector. The portal assigns the required RBAC roles to the
   selected identity.
7. If the workspace is not discovered, enter its ARM resource ID, workspace
   name, and customer/workspace ID manually.

Creating the role assignment requires Owner, User Access Administrator, or an
equivalent role. A 403 at query time usually means that the managed identity is
missing **Log Analytics Reader** or **Monitoring Reader** on the target scope.
The repository's later setup stages add the Sentinel-specific roles required by
the skills.

Test with:

```text
What tables are available in the connected Log Analytics workspace?
```

**Checkpoint:** The connector is **Connected** and returns tables from the
customer's Sentinel workspace, not only the agent telemetry workspace.

## 7. Add `kql-search-mcp`

1. Open **Builder > Connectors > Add connector > MCP**.
2. Choose **Stdio**.
3. Set **MCP Server** to `kql-search-mcp`.
4. Set **Command** to `npx`.
5. Add two separate arguments in this order: `-y` and `kql-search-mcp`.
6. Add `GITHUB_TOKEN` with the fine-grained PAT from stage 4.
7. Optionally add `FAVORITE_REPOS` as a comma-separated list, for example:

   ```text
   <customer-org>/<customer-repo>,Azure/Azure-Sentinel,microsoft/Microsoft-365-Defender-Hunting-Queries
   ```

8. Select the agent managed identity when the wizard requests one.
9. Enable this minimum tool set used by the repository's KQL authoring skill:

   - `get_table_schema`
   - `search_github_examples_fallback`
   - `search_kql_repositories`
   - `validate_kql_query`
   - `find_column`
   - `generate_kql_query`
   - `search_tables`
   - `get_query_documentation`
   - `list_table_categories`
   - `get_tables_by_category`

Do not select all package tools by default. Azure SRE Agent permits at most 80
tools across native and MCP connectors, and a smaller set improves tool
selection accuracy. Package `1.0.5` has a known issue in
`search_favorite_repos`; the repository skill uses
`search_github_examples_fallback` instead.

Test with:

```text
Use get_table_schema to show the columns of SigninLogs, then validate a query that returns five recent records.
```

**Checkpoint:** The server is connected, both tool calls complete, and no token
value appears in chat or logs.

## 8. Add `ms-learn-mcp`

1. Open **Builder > Connectors > Add connector > MCP**.
2. Choose **Streamable HTTP**.
3. Set **MCP Server** to `ms-learn-mcp`.
4. Set the URL to `https://learn.microsoft.com/api/mcp`.
5. Select **No authentication**.
6. Select all three tools returned by the server.
7. Add the connector and verify its status is **Connected**.

Test with:

```text
Use Microsoft Learn to find the official Azure SRE Agent documentation for managed connectors and return the page title and URL.
```

## 9. Continue Repository Setup

Return to the root [README](../README.md#e-discover-the-required-ids) and
continue with **E. Discover the required IDs**, runtime configuration, Entra ID
API permissions, Azure RBAC, optional Key Vault integration, and Sentinel data
connector prerequisites.

Before production use, verify all of these conditions:

- Code Access references the customer-owned repository and is **Ready**.
- Outlook, Teams, Log Analytics, `kql-search-mcp`, and `ms-learn-mcp` are
  **Connected**.
- When repository writes are required, GitHub MCP is **Connected**, `main` is
   protected, and only the approved branch, file, commit, and PR tools are
   enabled.
- Only the documented minimum operations are enabled unless an approved use
  case requires more.
- Write operations use the intended approval and destination-locking policy.
- PATs are repository-scoped, short-lived, stored only in protected connector
  configuration, and owned by a documented rotation process.
- No credential has appeared in screenshots, chat, logs, or repository files.

## Verification Sources

The setup procedure was checked against the following Microsoft documentation
and package metadata. Preview portal labels may change; use the current
equivalent when a label differs.

- [Create and set up Azure SRE Agent](https://learn.microsoft.com/azure/sre-agent/create-agent)
- [Set up an Outlook connector](https://learn.microsoft.com/azure/sre-agent/outlook-connector)
- [Set up the Teams connector](https://learn.microsoft.com/azure/sre-agent/set-up-teams-connector)
- [Set up a Log Analytics connector](https://learn.microsoft.com/azure/sre-agent/setup-log-analytics-connector)
- [MCP connectors and tools](https://learn.microsoft.com/azure/sre-agent/mcp-connectors)
- [Set up a GitHub connector](https://learn.microsoft.com/azure/sre-agent/github-connector)
- [Connect source code](https://learn.microsoft.com/azure/sre-agent/connect-source-code)
- [`kql-search-mcp` package](https://www.npmjs.com/package/kql-search-mcp), verified at version `1.0.5`