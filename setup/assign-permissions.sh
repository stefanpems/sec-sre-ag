#!/bin/bash
# ============================================================================
# Assign API permissions to the SRE Agent Managed Identity
# ============================================================================
# Run this script in Azure Cloud Shell (Bash) with an account that has
# Global Administrator or Privileged Role Administrator role in Entra ID.
#
# What it does:
#   Grants read-only Application permissions on Microsoft Graph and
#   WindowsDefenderATP APIs to the agent's UAMI, so that:
#   - az rest calls to graph.microsoft.com work (Entra ID data)
#   - az rest calls to api.securitycenter.microsoft.com work (MDE data)
#
# Usage:
#   chmod +x assign-permissions.sh
#   ./assign-permissions.sh <MANAGED_IDENTITY_OBJECT_ID> [SUBSCRIPTION_ID]
#
# Where:
#   MANAGED_IDENTITY_OBJECT_ID = Object ID (principal ID) of the managed
#                                identity used by the SRE Agent at runtime
#   SUBSCRIPTION_ID            = Subscription containing the SRE Agent. When
#                                omitted, the active Azure CLI subscription is
#                                used. The subscription selects the Entra tenant
#                                for every Microsoft Graph request.
#
# After running: wait up to 1 hour for Entra ID token cache to refresh,
# or force a new token in the agent's next session.
#
# For Azure RBAC roles (Sentinel Reader/Responder, Key Vault), use the
# companion script: assign-azure-roles.sh
# ============================================================================

set -euo pipefail

# --- Validate input ---
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <MANAGED_IDENTITY_OBJECT_ID> [SUBSCRIPTION_ID]"
  echo ""
  echo "  MANAGED_IDENTITY_OBJECT_ID  Object ID (principal ID) of the managed identity"
  echo "                              used by the SRE Agent at runtime"
  echo "  SUBSCRIPTION_ID             Subscription containing the SRE Agent"
  exit 1
fi

MANAGED_IDENTITY_OBJECT_ID="$1"
SUBSCRIPTION_ID="${2:-}"

if [[ -z "$SUBSCRIPTION_ID" ]]; then
  SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null) || {
    echo "ERROR: Could not read the active Azure CLI subscription."
    echo "       Run 'az login' or pass SUBSCRIPTION_ID explicitly."
    exit 1
  }
fi
SUBSCRIPTION_ID="${SUBSCRIPTION_ID//$'\r'/}"

TARGET_TENANT_ID=$(az account show \
  --subscription "$SUBSCRIPTION_ID" \
  --query tenantId -o tsv 2>/dev/null) || {
  echo "ERROR: Subscription '$SUBSCRIPTION_ID' is not available to the signed-in account."
  echo "       For cross-tenant setup, run 'az login --tenant <TARGET_TENANT_ID>'."
  exit 1
}
TARGET_TENANT_ID="${TARGET_TENANT_ID//$'\r'/}"
AZ_REST_CONTEXT=(--subscription "$SUBSCRIPTION_ID")

# --- Well-known Application IDs ---
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"   # Microsoft Graph
MDE_APP_ID="fc780465-2017-40d4-a0c5-307022471b92"     # WindowsDefenderATP

# --- Discover Service Principal Object IDs from Application IDs ---
echo "============================================"
echo " SRE Agent — Permission Assignment"
echo "============================================"
echo ""
echo "Managed identity Object ID: $MANAGED_IDENTITY_OBJECT_ID"
echo "Target subscription:         $SUBSCRIPTION_ID"
echo "Target tenant:               $TARGET_TENANT_ID"
echo ""
echo "Validating the managed identity and API service principals..."

MI_DETAILS=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MANAGED_IDENTITY_OBJECT_ID?\$select=displayName,appId,servicePrincipalType" \
  "${AZ_REST_CONTEXT[@]}" \
  --query "[displayName,appId,servicePrincipalType]" -o tsv 2>/dev/null) || {
  echo "ERROR: Object ID '$MANAGED_IDENTITY_OBJECT_ID' is not a service principal"
  echo "       in target tenant '$TARGET_TENANT_ID', or it is not readable."
  echo "       Use the Object ID/principal ID, not the client ID."
  exit 1
}
IFS=$'\t' read -r MI_DISPLAY_NAME MI_CLIENT_ID MI_PRINCIPAL_TYPE <<< "$MI_DETAILS"

if [[ "$MI_PRINCIPAL_TYPE" != "ManagedIdentity" ]]; then
  echo "ERROR: Object ID '$MANAGED_IDENTITY_OBJECT_ID' has servicePrincipalType"
  echo "       '$MI_PRINCIPAL_TYPE', not 'ManagedIdentity'."
  exit 1
fi
echo "  Managed identity:          $MI_DISPLAY_NAME"
echo "  Managed identity client ID: $MI_CLIENT_ID"

GRAPH_SP_OBJECT_ID=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId%20eq%20'$GRAPH_APP_ID'&\$select=id" \
  "${AZ_REST_CONTEXT[@]}" \
  --query "value[0].id" -o tsv 2>/dev/null) || {
  echo "ERROR: Could not find Microsoft Graph service principal."
  echo "       Ensure you are logged in to tenant '$TARGET_TENANT_ID'."
  exit 1
}
echo "  Microsoft Graph SP:      $GRAPH_SP_OBJECT_ID"

MDE_SP_OBJECT_ID=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId%20eq%20'$MDE_APP_ID'&\$select=id" \
  "${AZ_REST_CONTEXT[@]}" \
  --query "value[0].id" -o tsv 2>/dev/null) || {
  echo "ERROR: Could not find WindowsDefenderATP service principal."
  echo "       Ensure Microsoft Defender for Endpoint is provisioned in this tenant."
  exit 1
}
echo "  WindowsDefenderATP SP:   $MDE_SP_OBJECT_ID"
echo ""

# ============================================================================
# Permission definitions
# ============================================================================
# Each entry: "ResourceSPObjectID|AppRoleId|PermissionName"

PERMISSIONS=(
  # --- Microsoft Graph (read-only, except SecurityIncident.ReadWrite.All) ---
  "$GRAPH_SP_OBJECT_ID|df021288-bdef-4463-88db-98f22de89214|User.Read.All"
  "$GRAPH_SP_OBJECT_ID|7438b122-aefc-4978-80ed-43db9fcc7715|Device.Read.All"
  "$GRAPH_SP_OBJECT_ID|7ab1d382-f21e-4acd-a863-ba3e13f7da61|Directory.Read.All"
  "$GRAPH_SP_OBJECT_ID|483bed4a-2ad3-4361-a73b-c83ccdbdc53c|RoleManagement.Read.Directory"
  "$GRAPH_SP_OBJECT_ID|38d9df27-64da-44fd-b7c5-a6fbac20248f|UserAuthenticationMethod.Read.All"
  "$GRAPH_SP_OBJECT_ID|dc5007c0-2d7d-4c42-879c-2dab87571379|IdentityRiskyUser.Read.All"
  "$GRAPH_SP_OBJECT_ID|6e472fd1-ad78-48da-a0f0-97ab2c6b769e|IdentityRiskEvent.Read.All"
  "$GRAPH_SP_OBJECT_ID|b0afded3-3588-46d8-8b3d-9842eff778da|AuditLog.Read.All"
  "$GRAPH_SP_OBJECT_ID|230c1aed-a721-4c5d-9cb4-a90514e508ef|Reports.Read.All"
  "$GRAPH_SP_OBJECT_ID|34bf0e97-1971-4929-b999-9e2442d941d7|SecurityIncident.ReadWrite.All"

  # --- WindowsDefenderATP / MDE (read-only) ---
  "$MDE_SP_OBJECT_ID|ea8291d3-4b9a-44b5-bc3a-6cea3026dc79|Machine.Read.All"
  "$MDE_SP_OBJECT_ID|71fe6b80-7034-4028-9ed8-0f316df9c3ff|Alert.Read.All"
  "$MDE_SP_OBJECT_ID|8788f1a9-beca-4e26-ba58-10513f3b896f|File.Read.All"
  "$MDE_SP_OBJECT_ID|47bf842d-354b-49ef-b741-3a6dd815bc13|Ip.Read.All"
  "$MDE_SP_OBJECT_ID|721af526-ffa8-42d7-9b84-1a56244dd99d|Url.Read.All"
  "$MDE_SP_OBJECT_ID|528ca142-c849-4a5b-935e-10b8b9c38a84|Ti.Read.All"
  "$MDE_SP_OBJECT_ID|93489bf5-0fbc-4f2d-b901-33f2fe08ff05|AdvancedQuery.Read.All"
  "$MDE_SP_OBJECT_ID|41269fc5-d04d-4bfd-bce7-43a51cea049a|Vulnerability.Read.All"
)

# --- Fetch existing assignments (all resources) ---
echo "Checking existing permissions..."
EXISTING=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MANAGED_IDENTITY_OBJECT_ID/appRoleAssignments" \
  "${AZ_REST_CONTEXT[@]}" \
  --query "value[].join('|', [resourceId, appRoleId])" -o tsv 2>/dev/null || echo "")

ASSIGNED=0
SKIPPED=0
FAILED=0

# --- Assign permissions ---
echo ""
echo "--- Microsoft Graph permissions ---"
echo ""

CURRENT_RESOURCE=""

for ENTRY in "${PERMISSIONS[@]}"; do
  IFS='|' read -r RESOURCE_ID ROLE_ID ROLE_NAME <<< "$ENTRY"

  # Print section header on resource change
  if [[ "$RESOURCE_ID" != "$CURRENT_RESOURCE" ]]; then
    if [[ "$RESOURCE_ID" == "$MDE_SP_OBJECT_ID" ]]; then
      echo ""
      echo "--- WindowsDefenderATP (MDE) permissions ---"
      echo ""
    fi
    CURRENT_RESOURCE="$RESOURCE_ID"
  fi

  # Skip if already assigned
  if echo "$EXISTING" | grep -Fqx "$RESOURCE_ID|$ROLE_ID"; then
    echo "  SKIP  $ROLE_NAME (already assigned)"
    ((++SKIPPED))
    continue
  fi

  # Assign the permission
  BODY="{\"principalId\":\"$MANAGED_IDENTITY_OBJECT_ID\",\"resourceId\":\"$RESOURCE_ID\",\"appRoleId\":\"$ROLE_ID\"}"

  if az rest --method POST \
    --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MANAGED_IDENTITY_OBJECT_ID/appRoleAssignments" \
    "${AZ_REST_CONTEXT[@]}" \
    --body "$BODY" \
    --headers "Content-Type=application/json" \
    -o none 2>/dev/null; then
    echo "  OK    $ROLE_NAME"
    ((++ASSIGNED))
  else
    echo "  FAIL  $ROLE_NAME"
    ((++FAILED))
  fi
done

# --- Summary ---
echo ""
echo "============================================"
echo " Summary"
echo "============================================"
echo "  Assigned: $ASSIGNED"
echo "  Skipped:  $SKIPPED (already present)"
echo "  Failed:   $FAILED"
echo ""

if [[ $FAILED -gt 0 ]]; then
  echo "⚠️  Some assignments failed. Ensure you have"
  echo "   Global Administrator or Privileged Role Administrator role."
  exit 1
fi

VERIFY_ASSIGNMENTS=$(az rest --method GET \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MANAGED_IDENTITY_OBJECT_ID/appRoleAssignments" \
  "${AZ_REST_CONTEXT[@]}" \
  --query "value[].join('|', [resourceId, appRoleId])" -o tsv 2>/dev/null || echo "")

DEVICE_READ_ALL_ROLE_ID="7438b122-aefc-4978-80ed-43db9fcc7715"
if ! echo "$VERIFY_ASSIGNMENTS" | grep -Fqx "$GRAPH_SP_OBJECT_ID|$DEVICE_READ_ALL_ROLE_ID"; then
  echo "ERROR: Post-assignment verification did not find Microsoft Graph"
  echo "       Device.Read.All on managed identity '$MI_DISPLAY_NAME'."
  exit 1
fi

echo "  VERIFIED  Microsoft Graph Device.Read.All"
echo ""
echo "✅ Done. Token cache may take up to 1 hour to refresh."
echo "   After that, Graph API and MDE API calls from the agent"
echo "   will work without additional consent prompts."
echo "   Start a new agent session before testing Graph access."
echo ""
echo "Next step: run assign-azure-roles.sh to assign Azure RBAC roles"
echo "(Sentinel Reader/Responder, Key Vault Secrets User)."
