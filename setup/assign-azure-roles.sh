#!/bin/bash
# ============================================================================
# Assign Azure RBAC roles to SRE Agent User-Assigned Managed Identity
# ============================================================================
# Run this script in Azure Cloud Shell (Bash) or any terminal logged into
# Azure CLI with an account that has Owner or User Access Administrator
# on the target subscription / resource group.
#
# What it does:
#   Assigns Azure RBAC roles so the agent can:
#   - Query Sentinel tables via Azure Monitor MCP  (Sentinel Reader)
#   - Post comments on incidents via ARM API        (Sentinel Responder)
#   - Retrieve API tokens from Key Vault            (Key Vault Secrets User)
#
# Usage:
#   chmod +x assign-azure-roles.sh
#   ./assign-azure-roles.sh <UAMI_CLIENT_ID> <WORKSPACE_RESOURCE_ID> [KEYVAULT_RESOURCE_ID]
#
# Where:
#   UAMI_CLIENT_ID        Client ID (appId) of the User-Assigned Managed Identity
#                         (Azure Portal → Managed Identities → <name> → Properties → Client ID)
#
#   WORKSPACE_RESOURCE_ID Full resource ID of the Log Analytics workspace, e.g.:
#                         /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>
#
#   KEYVAULT_RESOURCE_ID  (Optional) Full resource ID of the Key Vault, e.g.:
#                         /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>
#                         Only needed if you use IP enrichment (enrich_ips.py).
#
# The script is idempotent — it skips roles already assigned.
# Azure RBAC roles typically propagate within 5-10 minutes.
# ============================================================================

set -euo pipefail

# --- Validate input ---
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <UAMI_CLIENT_ID> <WORKSPACE_RESOURCE_ID> [KEYVAULT_RESOURCE_ID]"
  echo ""
  echo "  UAMI_CLIENT_ID         Client ID of the agent's UAMI"
  echo "  WORKSPACE_RESOURCE_ID  Full resource ID of the Log Analytics workspace"
  echo "  KEYVAULT_RESOURCE_ID   (Optional) Full resource ID of the Key Vault"
  exit 1
fi

UAMI_CLIENT_ID="$1"
WORKSPACE_SCOPE="$2"
KEYVAULT_SCOPE="${3:-}"

echo "============================================"
echo " SRE Agent — Azure RBAC Role Assignment"
echo "============================================"
echo ""
echo "UAMI Client ID:    $UAMI_CLIENT_ID"
echo "Workspace scope:   $WORKSPACE_SCOPE"
[[ -n "$KEYVAULT_SCOPE" ]] && echo "Key Vault scope:   $KEYVAULT_SCOPE"
echo ""

ASSIGNED=0
SKIPPED=0
FAILED=0

# --- Helper function ---
assign_role() {
  local ROLE="$1"
  local SCOPE="$2"

  if az role assignment list \
       --assignee "$UAMI_CLIENT_ID" \
       --role "$ROLE" \
       --scope "$SCOPE" \
       --query '[0].id' -o tsv 2>/dev/null | grep -q .; then
    echo "  SKIP  $ROLE (already assigned)"
    ((++SKIPPED))
  else
    if az role assignment create \
         --assignee "$UAMI_CLIENT_ID" \
         --role "$ROLE" \
         --scope "$SCOPE" \
         -o none 2>/dev/null; then
      echo "  OK    $ROLE"
      ((++ASSIGNED))
    else
      echo "  FAIL  $ROLE"
      ((++FAILED))
    fi
  fi
}

# --- Sentinel workspace roles ---
echo "--- Sentinel workspace ---"
echo ""

assign_role "Microsoft Sentinel Reader"    "$WORKSPACE_SCOPE"
assign_role "Microsoft Sentinel Responder" "$WORKSPACE_SCOPE"

# --- Key Vault role (optional) ---
if [[ -n "$KEYVAULT_SCOPE" ]]; then
  echo ""
  echo "--- Key Vault ---"
  echo ""
  assign_role "Key Vault Secrets User" "$KEYVAULT_SCOPE"
fi

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
  echo "   Owner or User Access Administrator role on the target scope."
  exit 1
fi

echo "✅ Done. RBAC roles typically propagate within 5-10 minutes."
echo "   After that, Sentinel queries and incident comments will work."
