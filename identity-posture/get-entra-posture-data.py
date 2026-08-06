#!/usr/bin/env python3
"""
Collect identity posture data from Entra ID via Microsoft Graph API.

This script supports TWO execution modes:

  1. COLLECT mode (default) — calls Graph API via `az rest` (requires az CLI in PATH).
     Use this when running standalone or in environments with az CLI installed.

  2. VALIDATE mode (--validate) — checks that previously-saved JSON files exist
     and are well-formed.  The agent uses this after collecting data via the
     RunAzCliReadCommands tool (which doesn't require az in PATH).

If the script detects that `az` is NOT in PATH during COLLECT mode, it will:
  - Check if data files already exist in --output-dir (from a previous run)
  - If YES → automatically switch to VALIDATE mode
  - If NO  → print the exact RunAzCliReadCommands calls the agent must make,
             with the filenames to save results to, then exit with code 2.

Usage
-----
    # Standalone collection (az CLI available):
    python3 get-entra-posture-data.py

    # Validate pre-collected files:
    python3 get-entra-posture-data.py --validate

    # Custom output directory:
    python3 get-entra-posture-data.py --output-dir ./reports/posture

    # Skip signInActivity (if Entra ID P1 not licensed):
    python3 get-entra-posture-data.py --skip-sign-in-activity

Prerequisites (COLLECT mode)
----------------------------
    - Azure CLI installed and logged in (az login)
    - Python 3.8+
    - Permissions: Directory.Read.All, AuditLog.Read.All (P1),
      RoleManagement.Read.Directory (P2), IdentityRiskyUser.Read.All (P2),
      UserAuthenticationMethod.Read.All, Reports.Read.All

Saved files
-----------
    users_<ts>.json, directory_roles_<ts>.json, pim_eligible_roles_<ts>.json,
    risky_users_<ts>.json, deleted_users_<ts>.json, mfa_registration_<ts>.json,
    collection_metadata_<ts>.json
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone


# ─── Constants ───────────────────────────────────────────────────────────────

GRAPH_STEPS: list[dict] = [
    {
        "name": "users",
        "label": "User Inventory",
        "prefix": "users",
        "uri_template": (
            "https://graph.microsoft.com/v1.0/users"
            "?$select={fields}&$top=999&$count=true"
        ),
        "fields_full": (
            "id,userPrincipalName,displayName,mail,accountEnabled,"
            "createdDateTime,department,jobTitle,userType,"
            "onPremisesSyncEnabled,onPremisesDistinguishedName,"
            "onPremisesDomainName,lastPasswordChangeDateTime,"
            "passwordPolicies,signInActivity"
        ),
        "fields_no_signin": (
            "id,userPrincipalName,displayName,mail,accountEnabled,"
            "createdDateTime,department,jobTitle,userType,"
            "onPremisesSyncEnabled,onPremisesDistinguishedName,"
            "onPremisesDomainName,lastPasswordChangeDateTime,"
            "passwordPolicies"
        ),
        "consistency_level": True,
        "critical": True,
    },
    {
        "name": "directory_roles",
        "label": "Directory Roles",
        "prefix": "directory_roles",
        "uri": (
            "https://graph.microsoft.com/v1.0/directoryRoles"
            "?$expand=members($select=id,userPrincipalName,displayName)"
        ),
    },
    {
        "name": "pim_eligible",
        "label": "PIM Eligible Roles",
        "prefix": "pim_eligible_roles",
        "uri": (
            "https://graph.microsoft.com/beta/roleManagement/directory/"
            "roleEligibilityScheduleInstances"
            "?$expand=principal($select=id,userPrincipalName,displayName),"
            "roleDefinition($select=displayName)"
        ),
    },
    {
        "name": "risky_users",
        "label": "Risky Users",
        "prefix": "risky_users",
        "uri": (
            "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
            "?$select=id,userPrincipalName,userDisplayName,riskLevel,"
            "riskState,riskDetail,riskLastUpdatedDateTime,isDeleted,"
            "isProcessing&$top=500"
        ),
    },
    {
        "name": "deleted_users",
        "label": "Deleted Users",
        "prefix": "deleted_users",
        "uri": (
            "https://graph.microsoft.com/v1.0/directory/deletedItems/"
            "microsoft.graph.user"
            "?$select=id,userPrincipalName,displayName,deletedDateTime,"
            "onPremisesSyncEnabled&$top=999"
        ),
    },
    {
        "name": "mfa_registration",
        "label": "MFA Registration",
        "prefix": "mfa_registration",
        "uri": (
            "https://graph.microsoft.com/v1.0/reports/authenticationMethods/"
            "userRegistrationDetails"
            "?$select=id,userPrincipalName,userDisplayName,isMfaRegistered,"
            "isMfaCapable,isPasswordlessCapable,isSsprRegistered,"
            "isSsprEnabled,isSsprCapable,methodsRegistered"
            "&$top=500"
        ),
    },
]


# ─── Helper: az availability ────────────────────────────────────────────────

def is_az_available() -> bool:
    """Return True if `az` CLI is in PATH and responds."""
    return shutil.which("az") is not None


# ─── Helper: paginated Graph call ───────────────────────────────────────────

def invoke_graph_paged(
    uri: str, label: str = "items", use_consistency_level: bool = False
) -> tuple[list[dict], str]:
    """Call Graph API with pagination.  Returns (results, status)."""
    all_results: list[dict] = []
    current_uri: str | None = uri
    page = 0

    while current_uri:
        page += 1
        cmd = ["az", "rest", "--method", "GET", "--uri", current_uri, "--output", "json"]
        if use_consistency_level:
            cmd.extend(["--headers", "ConsistencyLevel=eventual"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", timeout=120
            )
            if result.returncode != 0:
                err = result.stderr.strip()
                if "403" in err or "Forbidden" in err:
                    print(f"  ⚠ 403 Forbidden: {label}", file=sys.stderr)
                    return all_results, "403"
                print(f"  ⚠ Error (page {page}): {err[:200]}", file=sys.stderr)
                return all_results, "ERROR"

            data = json.loads(result.stdout)
            items = data.get("value", [])
            all_results.extend(items)
            print(f"  Page {page}: {len(items)} {label} (total: {len(all_results)})")
            current_uri = data.get("@odata.nextLink")

        except json.JSONDecodeError as e:
            print(f"  ⚠ JSON decode error (page {page}): {e}", file=sys.stderr)
            return all_results, "ERROR"
        except subprocess.TimeoutExpired:
            print(f"  ⚠ Timeout on page {page}", file=sys.stderr)
            return all_results, "TIMEOUT"
        except Exception as e:
            print(f"  ⚠ Exception (page {page}): {e}", file=sys.stderr)
            return all_results, "ERROR"

    status = "OK" if all_results else "EMPTY"
    return all_results, status


# ─── Helper: save JSON ──────────────────────────────────────────────────────

def save_json(output_dir: str, prefix: str, timestamp: str, data: list | dict) -> str:
    """Save data as JSON and return the file path."""
    filename = f"{prefix}_{timestamp}.json"
    path = os.path.join(output_dir, filename)
    payload = data if isinstance(data, dict) else {"value": data, "count": len(data)}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
    return path


# ─── Helper: find latest file ───────────────────────────────────────────────

def find_latest(output_dir: str, prefix: str) -> str | None:
    pattern = os.path.join(output_dir, f"{prefix}_*.json")
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


# ═══════════════════════════════════════════════════════════════════════════════
#  MODE: COLLECT (uses az rest)
# ═══════════════════════════════════════════════════════════════════════════════

def run_collect(output_dir: str, skip_sign_in: bool) -> list[dict]:
    """Collect all Graph API data via az rest.  Returns summary list."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    summary: list[dict] = []

    for i, step in enumerate(GRAPH_STEPS, 1):
        name = step["name"]
        label = step["label"]
        prefix = step["prefix"]
        print(f"\n=== [{i}/{len(GRAPH_STEPS)}] {label} ===")

        # Build URI
        if "uri_template" in step:
            fields = step["fields_no_signin"] if skip_sign_in else step["fields_full"]
            uri = step["uri_template"].replace("{fields}", fields)
        else:
            uri = step["uri"]

        cl = step.get("consistency_level", False)
        data, status = invoke_graph_paged(uri, label=label, use_consistency_level=cl)

        # Retry users without signInActivity if empty
        if name == "users" and len(data) == 0 and not skip_sign_in:
            print("  ⚠ Retrying without signInActivity …", file=sys.stderr)
            uri = step["uri_template"].replace("{fields}", step["fields_no_signin"])
            data, status = invoke_graph_paged(uri, label=label, use_consistency_level=cl)

        if data:
            path = save_json(output_dir, prefix, ts, data)
            print(f"  → Saved {len(data)} records → {os.path.basename(path)}")
            summary.append({"step": label, "count": len(data), "file": os.path.basename(path), "status": status})
        else:
            print(f"  → No data returned ({status})")
            summary.append({"step": label, "count": 0, "file": "N/A", "status": status})

    # Save metadata
    meta = {
        "CollectionTimestamp": ts,
        "CollectionDateUTC": datetime.now(timezone.utc).isoformat(),
        "SkipSignInActivity": skip_sign_in,
        "Mode": "collect",
        "Steps": summary,
    }
    save_json(output_dir, "collection_metadata", ts, meta)
    return summary


# ═══════════════════════════════════════════════════════════════════════════════
#  MODE: VALIDATE (reads existing files)
# ═══════════════════════════════════════════════════════════════════════════════

def run_validate(output_dir: str) -> list[dict]:
    """Validate pre-collected JSON files.  Returns summary list."""
    summary: list[dict] = []
    print(f"\nValidating files in: {output_dir}\n")

    for step in GRAPH_STEPS:
        prefix = step["prefix"]
        label = step["label"]
        path = find_latest(output_dir, prefix)

        if path is None:
            print(f"  [--] {label}: not found")
            summary.append({"step": label, "count": 0, "file": "N/A", "status": "MISSING"})
            continue

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            arr = data.get("value", data) if isinstance(data, dict) else data
            if not isinstance(arr, list):
                arr = [arr]
            count = len(arr)
            fname = os.path.basename(path)
            icon = "[OK]" if count > 0 else "[--]"
            print(f"  {icon} {label}: {count} records ({fname})")
            summary.append({"step": label, "count": count, "file": fname, "status": "OK" if count > 0 else "EMPTY"})
        except Exception as e:
            print(f"  [!!] {label}: error reading {path} — {e}")
            summary.append({"step": label, "count": 0, "file": os.path.basename(path), "status": "ERROR"})

    # Also check KQL enrichment files
    kql_prefixes = [
        ("kql_uac_flags", "KQL — UAC Flags"),
        ("kql_mdi_tags", "KQL — MDI Tags"),
        ("kql_identity_risk", "KQL — IdentityInfo Risk"),
        ("kql_builtin_accounts", "KQL — Built-In Accounts"),
        ("kql_stale_summary", "KQL — Stale Summary"),
        ("kql_stale_detail", "KQL — Stale Detail"),
        ("kql_cross_domain", "KQL — Cross-Domain"),
        ("kql_service_accounts", "KQL — Service Accounts"),
    ]
    print()
    for prefix, label in kql_prefixes:
        path = find_latest(output_dir, prefix)
        if path:
            print(f"  [OK] {label}: found ({os.path.basename(path)})")
        else:
            print(f"  [--] {label}: not collected yet")

    return summary


# ═══════════════════════════════════════════════════════════════════════════════
#  MODE: PRINT AGENT INSTRUCTIONS (az not available, no existing files)
# ═══════════════════════════════════════════════════════════════════════════════

def print_agent_instructions(output_dir: str, skip_sign_in: bool):
    """Print the exact RunAzCliReadCommands the agent should execute."""
    ts = "<TIMESTAMP>"
    print("\n" + "=" * 70)
    print("  az CLI is NOT available.  The agent must collect data via tools.")
    print("=" * 70)
    print(f"\nFor each step below, use RunAzCliReadCommands and save the")
    print(f"JSON output to {output_dir}/<filename>.\n")
    print(f"Replace {ts} with the current timestamp (YYYYMMDD_HHMMSS).\n")

    for i, step in enumerate(GRAPH_STEPS, 1):
        label = step["label"]
        prefix = step["prefix"]
        if "uri_template" in step:
            fields = step["fields_no_signin"] if skip_sign_in else step["fields_full"]
            uri = step["uri_template"].replace("{fields}", fields)
        else:
            uri = step["uri"]

        cl_flag = ' --headers "ConsistencyLevel=eventual"' if step.get("consistency_level") else ""
        print(f"--- Step {i}: {label} ---")
        print(f"File: {prefix}_{ts}.json")
        print(f'az rest --method GET --uri "{uri}"{cl_flag}')
        print()

    print("After collecting all data, run:")
    print(f"  python3 get-entra-posture-data.py --validate --output-dir {output_dir}")
    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Collect or validate identity posture data from Entra ID."
    )
    parser.add_argument(
        "--output-dir", default="./output/identity-posture",
        help="Directory for JSON output files (default: ./output/identity-posture)"
    )
    parser.add_argument(
        "--validate", action="store_true",
        help="Validate existing files instead of collecting new data"
    )
    parser.add_argument(
        "--skip-sign-in-activity", action="store_true",
        help="Skip signInActivity field (requires Entra ID P1)"
    )
    args = parser.parse_args()

    output_dir = args.output_dir

    # ── Validate mode ──
    if args.validate:
        summary = run_validate(output_dir)
        ok = sum(1 for s in summary if s["status"] in ("OK",))
        print(f"\n[VALIDATE] {ok}/{len(GRAPH_STEPS)} Graph API files present.")
        sys.exit(0)

    # ── Collect mode ──
    if is_az_available():
        print("[MODE] COLLECT — az CLI detected, collecting via Graph API …")
        summary = run_collect(output_dir, args.skip_sign_in_activity)
        print("\n=== Collection Summary ===")
        for s in summary:
            icon = {"OK": "[OK]", "EMPTY": "[--]"}.get(s["status"], "[!!]")
            print(f"  {icon} {s['step']}: {s['count']} records ({s['status']})")
        print(f"\n[DONE] Files saved to {output_dir}")
    else:
        # az not available — check if files already exist
        has_users = find_latest(output_dir, "users") is not None
        if has_users:
            print("[MODE] az CLI not found, but existing data detected. Switching to VALIDATE …")
            run_validate(output_dir)
            sys.exit(0)
        else:
            print_agent_instructions(output_dir, args.skip_sign_in_activity)
            sys.exit(2)


if __name__ == "__main__":
    main()
