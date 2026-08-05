#!/bin/bash
# ============================================================================
# Discover Azure resource IDs required by the SRE Agent setup scripts
# ============================================================================
# Run this script in Azure Cloud Shell (Bash) with an account that can read
# managed identities, Log Analytics workspaces, Sentinel solutions, and vaults.
#
# Usage:
#   chmod +x discover-setup-ids.sh
#   ./discover-setup-ids.sh [SUBSCRIPTION_ID]
#
# The script is read-only. It does not change the active Azure CLI subscription
# and passes the selected subscription explicitly to every resource query.
# ============================================================================

set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [SUBSCRIPTION_ID]"
  exit 1
fi

if [[ $# -eq 1 ]]; then
  SUBSCRIPTION_ID="$1"
else
  SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null) || {
    echo "ERROR: Could not read the active Azure subscription. Run 'az login' first."
    exit 1
  }
  SUBSCRIPTION_ID="${SUBSCRIPTION_ID//$'\r'/}"
fi

SUBSCRIPTION_NAME=$(az account show \
  --subscription "$SUBSCRIPTION_ID" \
  --query name -o tsv 2>/dev/null) || {
  echo "ERROR: Subscription '$SUBSCRIPTION_ID' is not available to the current account."
  exit 1
}
SUBSCRIPTION_NAME="${SUBSCRIPTION_NAME//$'\r'/}"

TENANT_ID=$(az account show \
  --subscription "$SUBSCRIPTION_ID" \
  --query tenantId -o tsv)
TENANT_ID="${TENANT_ID//$'\r'/}"

mapfile -t IDENTITY_ROWS < <(az identity list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].join('|', [name, resourceGroup, clientId, principalId, id])" \
  -o tsv | tr -d '\r')

mapfile -t SENTINEL_SOLUTION_ROWS < <(az resource list \
  --subscription "$SUBSCRIPTION_ID" \
  --resource-type Microsoft.OperationsManagement/solutions \
  --query "[?starts_with(name, 'SecurityInsights(')].join('|', [name, resourceGroup])" \
  -o tsv | tr -d '\r')

SENTINEL_ROWS=()
for ROW in "${SENTINEL_SOLUTION_ROWS[@]}"; do
  IFS='|' read -r SOLUTION_NAME RESOURCE_GROUP <<< "$ROW"
  WORKSPACE_NAME="${SOLUTION_NAME#SecurityInsights(}"
  WORKSPACE_NAME="${WORKSPACE_NAME%)}"
  WORKSPACE_ID=$(az monitor log-analytics workspace show \
    --subscription "$SUBSCRIPTION_ID" \
    --resource-group "$RESOURCE_GROUP" \
    --workspace-name "$WORKSPACE_NAME" \
    --query id -o tsv)
  WORKSPACE_ID="${WORKSPACE_ID//$'\r'/}"
  SENTINEL_ROWS+=("$WORKSPACE_NAME|$RESOURCE_GROUP|$WORKSPACE_ID")
done

mapfile -t KEYVAULT_ROWS < <(az keyvault list \
  --subscription "$SUBSCRIPTION_ID" \
  --query "[].join('|', [name, resourceGroup, id])" \
  -o tsv | tr -d '\r')

echo "============================================"
echo " SRE Agent - Setup ID Discovery"
echo "============================================"
echo "Subscription: $SUBSCRIPTION_NAME"
echo "Subscription ID: $SUBSCRIPTION_ID"
echo "Tenant ID:       $TENANT_ID"
echo ""

echo "--- User-Assigned Managed Identities ---"
if [[ ${#IDENTITY_ROWS[@]} -eq 0 ]]; then
  echo "  None found."
else
  for ROW in "${IDENTITY_ROWS[@]}"; do
    IFS='|' read -r NAME RESOURCE_GROUP CLIENT_ID OBJECT_ID RESOURCE_ID <<< "$ROW"
    echo ""
    echo "  Name:           $NAME"
    echo "  Resource group: $RESOURCE_GROUP"
    echo "  Object ID:      $OBJECT_ID"
    echo "  Client ID:      $CLIENT_ID"
    echo "  Resource ID:    $RESOURCE_ID"
  done
fi
echo ""

echo "--- Microsoft Sentinel Workspaces ---"
if [[ ${#SENTINEL_ROWS[@]} -eq 0 ]]; then
  echo "  None found."
else
  for ROW in "${SENTINEL_ROWS[@]}"; do
    IFS='|' read -r NAME RESOURCE_GROUP RESOURCE_ID <<< "$ROW"
    echo ""
    echo "  Name:           $NAME"
    echo "  Resource group: $RESOURCE_GROUP"
    echo "  Resource ID:    $RESOURCE_ID"
  done
fi
echo ""

echo "--- Key Vaults (optional) ---"
if [[ ${#KEYVAULT_ROWS[@]} -eq 0 ]]; then
  echo "  None found."
else
  for ROW in "${KEYVAULT_ROWS[@]}"; do
    IFS='|' read -r NAME RESOURCE_GROUP RESOURCE_ID <<< "$ROW"
    echo ""
    echo "  Name:           $NAME"
    echo "  Resource group: $RESOURCE_GROUP"
    echo "  Resource ID:    $RESOURCE_ID"
  done
fi
echo ""

if [[ ${#IDENTITY_ROWS[@]} -eq 1 && ${#SENTINEL_ROWS[@]} -eq 1 ]]; then
  IFS='|' read -r UAMI_NAME UAMI_RESOURCE_GROUP UAMI_CLIENT_ID UAMI_OBJECT_ID UAMI_RESOURCE_ID <<< "${IDENTITY_ROWS[0]}"
  IFS='|' read -r WORKSPACE_NAME WORKSPACE_RESOURCE_GROUP WORKSPACE_RESOURCE_ID <<< "${SENTINEL_ROWS[0]}"

  echo "--- Ready-to-run commands ---"
  echo ""
  echo "./assign-permissions.sh '$UAMI_OBJECT_ID'"
  echo "./assign-azure-roles.sh '$UAMI_CLIENT_ID' '$WORKSPACE_RESOURCE_ID'"
  echo ""
  echo "To include Key Vault access, append the selected Key Vault Resource ID"
  echo "as the third argument to assign-azure-roles.sh."
else
  echo "Select one UAMI and one Sentinel workspace from the values above, then run:"
  echo ""
  echo "./assign-permissions.sh '<UAMI_OBJECT_ID>'"
  echo "./assign-azure-roles.sh '<UAMI_CLIENT_ID>' '<WORKSPACE_RESOURCE_ID>' ['<KEYVAULT_RESOURCE_ID>']"
fi
