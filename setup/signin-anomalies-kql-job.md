# Sign-in anomaly KQL job setup

The `user-investigation` and `incident-investigation` skills query the optional
`Signinlogs_Anomalies_KQL_CL` table. The table contains new sign-in IP and device
observations from the last hour compared with a 90-day baseline. If the table is
absent, the skills fall back to raw sign-in data, but anomaly prioritization is
less precise.

This setup is based on the
[`Signinlogs_Anomalies_KQL_CL`](https://github.com/SCStelz/security-investigator/blob/35613cc4a07ac426ea915aa7211dc1e8a20b4096/docs/Signinlogs_Anomalies_KQL_CL.md)
procedure in `SCStelz/security-investigator`. See
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) for attribution and license.

## Prerequisites

- Microsoft Sentinel Data Lake is onboarded for the tenant.
- The Microsoft Entra ID connector populates both `SigninLogs` and
  `AADNonInteractiveUserSignInLogs`.
- The Sentinel Data Lake managed identity, normally named
  `msg-resources-<guid>`, has **Log Analytics Contributor** on the destination
  Log Analytics workspace.

The Data Lake managed identity is not the Azure SRE Agent UAMI. Its service
principal is created during Sentinel Data Lake onboarding. To find it and assign
the role from Azure Cloud Shell (Bash):

```bash
SUBSCRIPTION_ID='<subscription-id>'
WORKSPACE_RESOURCE_ID='<workspace-resource-id>'

az ad sp list --all \
   --query "[?starts_with(displayName, 'msg-resources-')].{displayName:displayName, objectId:id, appId:appId}" \
  -o table

az role assignment create \
  --subscription "$SUBSCRIPTION_ID" \
   --assignee-object-id '<data-lake-service-principal-object-id>' \
  --assignee-principal-type ServicePrincipal \
  --role 'Log Analytics Contributor' \
  --scope "$WORKSPACE_RESOURCE_ID"
```

If the first command returns no rows, onboard Sentinel Data Lake before
continuing. Do not grant this role to the Azure SRE Agent UAMI as a substitute.

## Create the job

1. Open the Microsoft Defender portal and confirm that Sentinel Data Lake is
   onboarded.
2. Go to **Data lake exploration > Jobs**.
3. Create a new KQL job and paste the complete query from
   [`signin-anomalies-kql-job.kql`](signin-anomalies-kql-job.kql).
4. Configure the job with:

   | Setting | Value |
   |---|---|
   | Name | `Signinlogs_Anomalies_Hourly` |
   | Schedule | Hourly, every 1 hour |
   | Destination | New Analytics-tier table |
   | Resulting destination table | `Signinlogs_Anomalies_KQL_CL` |

5. Save the job and run it once manually. The first successful run creates the
   destination table from the projected output schema.
6. Enable the hourly schedule.

The table name is case-sensitive: use `Signinlogs`, with a lowercase `l` in
`logs`. Do not create a separate custom log table or DCR with the same name; the
KQL job owns and populates the `_KQL_CL` destination.

The portal automatically adds `_KQL_CL` when it asks for a base destination
name. In that UI, enter `Signinlogs_Anomalies`. If the UI asks for the complete
destination table name, enter `Signinlogs_Anomalies_KQL_CL`. Confirm the preview
shows the exact resulting name before saving.

## Validate

Run this query after the first successful job execution:

```kql
Signinlogs_Anomalies_KQL_CL
| summarize Rows=count(), LastDetection=max(DetectedDateTime)
```

If the table is not resolved, confirm that the first job run succeeded and that
the Data Lake managed identity has **Log Analytics Contributor** on the workspace.
An empty table can be valid when no new IP or device observation occurred during
the most recent hourly window.

The first useful baseline requires historical sign-in data. The query compares
the latest hour with up to 90 days of `SigninLogs` and
`AADNonInteractiveUserSignInLogs` data.
