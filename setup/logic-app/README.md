# Microsoft Sentinel Investigation Logic App ARM Templates

These templates deploy parameterized Logic App Consumption playbooks that send
Microsoft Sentinel incidents or account entities to authenticated Azure SRE
Agent HTTP triggers.

| Template | Sentinel trigger | Value sent to Azure SRE Agent |
|---|---|---|
| `investigate-incident-on-azure-sre-agent.json` | Incident creation | Sentinel `providerIncidentId` |
| `investigate-user-on-azure-sre-agent.json` | Account entity | User principal name built from `Name` and `UPNSuffix` |

Each template creates:

- A Microsoft Sentinel managed API connection that uses managed identity
  authentication.
- A Logic App Consumption workflow with a system-assigned managed identity.
- Optionally, an `SRE Agent Standard User` role assignment for the workflow
  identity on the resource group that contains the Azure SRE Agent.
- Optionally, a `Microsoft Sentinel Automation Contributor` role assignment on
  the playbook resource group for a tenant-specific Sentinel automation
  principal.

## Prerequisites

- The target subscription has the `Microsoft.Logic`, `Microsoft.Web`, and
  `Microsoft.Authorization` resource providers registered.
- Microsoft Sentinel is enabled on a Log Analytics workspace.
- The target Azure SRE Agent and the HTTP trigger corresponding to each selected
  template already exist.
- The deploying identity can create Logic Apps and API connections in the
  target resource group.
- When `assignSreAgentRole` is `true`, the deploying identity can create role
  assignments on the Azure SRE Agent resource group.
- Microsoft Sentinel has permission to run playbooks in the target resource
  group. This can be configured from the Sentinel workspace **Settings >
  Settings > Playbook permissions** page. Alternatively, supply the
  tenant-specific automation principal object ID and enable
  `assignSentinelAutomationRole`.

## Parameters

The required target-specific values are:

| Parameter | Description |
|---|---|
| `sreAgentTriggerUrl` | Full HTTP trigger URL exposed by the target Azure SRE Agent. |
| `sreAgentResourceGroupResourceId` | Resource ID of the resource group that contains the target Azure SRE Agent. |

`sreAgentAudience` defaults to the audience used by Azure SRE Agent. Role
definition GUIDs default to the corresponding built-in Azure roles and should
normally remain unchanged.

Both workflows preserve their source payload contract and send the extracted
value in the `user_email` JSON property expected by the corresponding SRE Agent
trigger. The incident workflow sends `providerIncidentId`; the user workflow
sends the account UPN.

## Deploy

Choose a template and create a target-specific parameter file from its matching
`.parameters.example.json` file. The incident playbook commands are:

```bash
az deployment group validate \
  --subscription <subscription-id> \
  --resource-group <playbook-resource-group> \
  --template-file setup/logic-app/investigate-incident-on-azure-sre-agent.json \
  --parameters @setup/logic-app/investigate-incident-on-azure-sre-agent.parameters.json

az deployment group create \
  --subscription <subscription-id> \
  --resource-group <playbook-resource-group> \
  --template-file setup/logic-app/investigate-incident-on-azure-sre-agent.json \
  --parameters @setup/logic-app/investigate-incident-on-azure-sre-agent.parameters.json
```

For the user playbook, use
`investigate-user-on-azure-sre-agent.json` and its matching parameter file in
the same commands. Each template creates a separate Microsoft Sentinel managed
API connection by default, derived from its workflow name.

The Logic App and managed API connection must use the same region. The Sentinel
workspace may be in a different region.

## Post-deployment check

1. Confirm that the Microsoft Sentinel connection reports `Connected` or
   `Ready` in the Logic App connections view.
2. Confirm that the workflow identity has `SRE Agent Standard User` on the SRE
   Agent resource group.
3. Add the incident playbook to the intended Microsoft Sentinel automation
  rule, or run either playbook manually against a matching test incident or
  account entity.
4. Verify that the HTTP action returns a successful status code and that the
  Azure SRE Agent starts the corresponding investigation.
