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
- An `SRE Agent Standard User` role assignment for the workflow identity on the
  deployment resource group.

## Prerequisites

- The target subscription has the `Microsoft.Logic`, `Microsoft.Web`, and
  `Microsoft.Authorization` resource providers registered.
- Microsoft Sentinel is enabled on a Log Analytics workspace.
- The target Azure SRE Agent and the HTTP trigger corresponding to each selected
  template already exist.
- Each template is deployed to the resource group that contains the target
  Azure SRE Agent. The template derives its region and role-assignment scope
  from that resource group.
- The deploying identity can create Logic Apps and API connections in the
  target resource group.
- The deploying identity can create role assignments on the Azure SRE Agent
  resource group.
- Microsoft Sentinel has permission to run playbooks in the target resource
  group. This can be configured from the Sentinel workspace **Settings >
  Settings > Playbook permissions** page.

## Parameters

Each template exposes exactly one parameter:

| Parameter | Description |
|---|---|
| `sreAgentTriggerUrl` | Full HTTP trigger URL exposed by the target Azure SRE Agent. |

The workflow name, deployment region, Sentinel connection name, Azure SRE Agent
audience, and built-in `SRE Agent Standard User` role definition are fixed
inside each template. They are intentionally not shown in the Azure custom
deployment form.

Both workflows preserve their source payload contract and send the extracted
value in the `user_email` JSON property expected by the corresponding SRE Agent
trigger. The incident workflow sends `providerIncidentId`; the user workflow
sends the account UPN.

## Deploy

Choose a template and create a target-specific parameter file from its matching
`.parameters.example.json` file. The file contains only the HTTP trigger URL.
Deploy it to the resource group that contains the Azure SRE Agent. The incident
playbook commands are:

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
API connection with a fixed name corresponding to its workflow.

The Logic App and managed API connection use the deployment resource group's
region. The Sentinel workspace may be in a different region.

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
