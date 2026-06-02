---
name: identity-posture
description: >
  Audit identity security posture across the organization. Triggers on keywords like
  "identity posture", "identity security report", "account hygiene", "stale accounts",
  "privileged accounts", "password posture", "identity providers", "identity sprawl",
  "service accounts", "deleted accounts with roles", "honeytoken", "sensitive accounts",
  "MFA coverage", "risky users".
  Collects data from Microsoft Graph API (user inventory, roles, PIM, risk, MFA)
  and Log Analytics KQL (IdentityInfo UAC flags, MDI tags, IdentityLogonEvents, SigninLogs).
  Produces a posture assessment covering account inventory, privileged account audit,
  stale/deleted account hygiene, password posture, MFA coverage, risk distribution,
  MDI tag analysis, and department-level insights.
  Inline chat or markdown output.
threat_pulse_domains: [identity]
drill_down_prompt: 'Run identity posture report — account hygiene, privilege distribution, stale accounts'
---

# Identity Security Posture — Skill Instructions

## Purpose

Audit the **identity security posture** of the Entra ID tenant using a dual-source approach:

| Source | What it provides |
|--------|-----------------|
| **Microsoft Graph API** | User inventory, directory roles, PIM assignments, Identity Protection risk, MFA registration, deleted users |
| **Log Analytics KQL** | IdentityInfo (AD UAC flags, MDI tags, on-prem context), SigninLogs (stale detection) |

## Skill Files

| File | Purpose | When used |
|------|---------|-----------|
| [get-entra-posture-data.py](get-entra-posture-data.py) | Collect or validate Graph API data | Phase 0 |
| [get-entra-posture-data.md](get-entra-posture-data.md) | Graph API call reference (URIs, fields, errors) | Reference |
| [kql-enrichment-queries.md](kql-enrichment-queries.md) | All KQL queries with save-file instructions | Phase 1 |
| [analyze-identity-posture.py](analyze-identity-posture.py) | Analysis engine — reads JSON, computes score, generates report | Phase 2 |
| [generate_html_report.py](generate_html_report.py) | HTML report generator — reads JSON, computes all metrics, produces styled HTML | Phase 2 (on request) |
| [svg-widgets.yaml](svg-widgets.yaml) | SVG dashboard widget manifest | Optional post-report |
### File Resolution (codeRefs-first)

Before executing any skill file (scripts, data files, companion files), resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/identity-posture/<filename>
   → If found: use/execute directly from this path (companion files are co-located here)
2. tmp/identity-posture/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("identity-posture", "<filename>") from Builder
   → CreateFile("tmp/identity-posture/<filename>", <content>)
   → Repeat for ALL companion files referenced by the script
```

**Rules:**
- When a file is found in `codeRefs/`, execute it directly from there — do NOT copy it to `tmp/`.
- When materializing from Builder (step 3), materialize ALL companion files the script depends on, not just the script itself.
- This cascade applies to every file listed in the Skill Files table above.

### Pre-requisite: Environment Configuration (config.json)

Before executing any script resolved via the File Resolution cascade, the agent MUST ensure that `config.json` exists at the **workspace root** (the top-level directory of the agent workspace, NOT inside `codeRefs/` or skill-specific directories).

**Procedure:**

1. **Check:** Verify that `config.json` exists at the workspace root and contains a non-empty `sentinel_workspace_id` value. If it does, skip to step 3.

2. **If `config.json` is missing or incomplete**, create it:
   a. **Ask the user** for the tenant name using AskUserQuestion with header "Tenant" and question: "What is your tenant name? (e.g., contoso.onmicrosoft.com or contoso.it)?"
   b. **Extract from agent system prompt settings:**
      - `subscription_id` → from the `<azure_resource_access>` section (the subscription ID the agent has access to)
      - `sentinel_workspace_id` → from the `<log_analytics_access>` section (the workspace GUID after `workspace=`)
      - `workspace_name` → from the `<log_analytics_access>` section (the workspace name before the colon)
   c. **Discover** the workspace resource group by running:
      ```
      az monitor log-analytics workspace show --workspace-name <workspace_name> --subscription <subscription_id> --query resourceGroup -o tsv
      ```
   d. **Create** `config.json` at the workspace root with this structure:
      ```json
      {
        "tenant_name": "<tenant_name>",
        "sentinel_workspace_id": "<workspace_guid>",
        "subscription_id": "<subscription_id>",
        "azure_mcp": {
          "subscription_id": "<subscription_id>",
          "resource_group": "<discovered_resource_group>",
          "workspace_name": "<workspace_name>"
        },
        "api_tokens": {}
      }
      ```

3. **Proceed** with the skill workflow. All Python scripts find `config.json` by walking up from their own directory (max 6 levels), so the workspace root is the correct and expected location.

**Rules:**
- Do NOT write `config.json` inside `codeRefs/` or inside skill-specific directories.
- Do NOT hardcode any environment-specific values in this skill file — all values are derived at runtime from the agent's own settings and user input.
- The `api_tokens` object is left empty — API tokens are loaded from Key Vault or environment variables at runtime.

---

## ⚠️ CRITICAL RULES — READ FIRST

1. **DO NOT generate scripts on the fly.** All logic is in the companion `.py` and `.md` files. The agent only executes tools and launches existing scripts.

2. **DO NOT call `az` from the terminal.** The `az` CLI is not in PATH in the agent sandbox. Use the `RunAzCliReadCommands` tool for every Graph API call.

3. **ONE Graph API call at a time.** Parallel RunAzCliReadCommands calls can cause token issues and partial results. Execute them **sequentially**.

4. **Save every tool response as JSON.** Each Graph API response and each KQL result must be saved to `output/identity-posture/` with the prescribed filename before running the analysis script.

5. **Default to inline output. Do NOT ask** the user for output mode. Present results inline in chat. Only generate a markdown file, HTML report, or JSON export if the user explicitly requests it.

6. **Evidence-based only.** Report only what data shows. Use `✅ No [finding] detected` for zero results.

7. **Resolve scripts before execution.** Skill files may not exist on the filesystem. Always resolve them via the [File Resolution cascade](#file-resolution-coderefs-first) before running them (see Phase 2, Step 2.0).

### ⛔ PROHIBITED

| Action | Reason |
|--------|--------|
| Using `subprocess` or `az` in the terminal | `az` is not in PATH |
| Generating inline Python for analysis | Use `analyze-identity-posture.py` |
| Copy-pasting KQL from SKILL.md | Use [kql-enrichment-queries.md](kql-enrichment-queries.md) |
| Making 6 parallel Graph API calls | Token/throttling failures — do them sequentially |
| Guessing data or assuming results | Only report what data files contain |
| Running `python3 analyze-identity-posture.py` without resolving first | File may not exist on disk — see Step 2.0 |

---

## Execution Workflow

### Phase 0 — Graph API Data Collection

**Goal:** Collect 6 datasets from Microsoft Graph API and save them as JSON.

**Step 0.1 — Check for existing data:**
Look in `output/identity-posture/` for existing data files.

```
Cache Check Logic:

1. If NO data files exist → proceed to Step 0.2 (fresh collection)

2. If data files exist, calculate their age:
   → age = current_UTC_time − file_modification_timestamp
   → If age > 4 hours → IGNORE cache entirely, proceed to Step 0.2 (fresh collection)
   → If age ≤ 4 hours → proceed to step 3

3. Analyze the user's ORIGINAL prompt for implicit intent:

   REDO KEYWORDS (triggers fresh collection, any language):
     "ripeti", "aggiorna", "rifai", "repeat", "redo", "refresh",
     "update", "re-analyze", "start over", "da capo",
     "from scratch", "ricomincia", "nuovo", "nuova analisi"
   → If ANY redo keyword is detected → IGNORE cache, proceed to Step 0.2

   USE-CACHE KEYWORDS (triggers cache reuse, any language):
     "completa", "continua", "complete", "continue", "finish",
     "usa i dati", "use cached", "use existing", "prosegui",
     "riprendi", "resume", "genera report", "generate report",
     "genera il report", "crea report"
   → If ANY use-cache keyword is detected → LOAD cached data, skip to Phase 2

   NO IMPLICIT INTENT DETECTED:
   → ASK the user:
     Question: "Ho trovato dati di un'analisi precedente in output/identity-posture/,
                completata <TIME_AGO> fa (alle <HH:MM> UTC).
                Vuoi utilizzare questi dati o preferisci raccoglierli da zero?"
     Options:
       1. "Usa i dati esistenti" — Riprende dall'analisi precedente
       2. "Raccogli da zero" — Ignora la cache e ricomincia la raccolta dati

     → If user selects "Usa i dati esistenti" → LOAD cached data, skip to Phase 2
     → If user selects "Raccogli da zero" → proceed to Step 0.2
```

**Important rules:**
- **NEVER silently reuse cached data** — always either detect explicit intent from the prompt or ask the user.
- **NEVER ask the user if the prompt already contains an implicit answer** — detect keywords first.
- **Cache files from a DIFFERENT thread/session are still valid** — the 4-hour TTL is the only expiration criterion.

**Step 0.2 — Collect data (sequential, one at a time):**

For each step below, use `RunAzCliReadCommands` with the exact `az rest` command.
Then save the full JSON response (the `output` field from the tool result) to the specified file.
Use `RunInTerminal` with a short Python snippet to save the JSON:

```python
# Example: agent saves tool output to file
python3 -c "
import json, sys
data = json.loads(sys.stdin.read())
with open('output/identity-posture/users_YYYYMMDD_HHMMSS.json', 'w') as f:
    json.dump(data, f, indent=2)
" <<'EOF'
<paste the JSON output here>
EOF
```

Execute these **6 steps in order** (see [get-entra-posture-data.md](get-entra-posture-data.md) for full URI reference):

| # | Step | az rest command | Save as |
|---|------|----------------|---------|
| 1 | Users | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,mail,accountEnabled,createdDateTime,department,jobTitle,userType,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,lastPasswordChangeDateTime,passwordPolicies,signInActivity&$top=999&$count=true" --headers "ConsistencyLevel=eventual"` | `users_<ts>.json` |
| 2 | Directory Roles | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($select=id,userPrincipalName,displayName)"` | `directory_roles_<ts>.json` |
| 3 | PIM Eligible | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal($select=id,userPrincipalName,displayName),roleDefinition($select=displayName)"` | `pim_eligible_roles_<ts>.json` |
| 4 | Risky Users | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$select=id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime,isDeleted,isProcessing&$top=999"` | `risky_users_<ts>.json` |
| 5 | Deleted Users | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?$select=id,userPrincipalName,displayName,deletedDateTime,onPremisesSyncEnabled&$top=999"` | `deleted_users_<ts>.json` |
| 6 | MFA Registration | `az rest --method GET --uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=id,userPrincipalName,userDisplayName,isMfaRegistered,isMfaCapable,isPasswordlessCapable,isSsprRegistered,isSsprEnabled,isSsprCapable,methodsRegistered,defaultMfaMethod&$top=999"` | `mfa_registration_<ts>.json` |

**Error handling per step:**
- **403 Forbidden:** Log the error, skip the step, proceed to next. Note in summary.
- **Empty result on Step 1 with signInActivity:** Retry without `signInActivity` in `$select` (needs Entra ID P1).
- **Rate limiting (429):** Wait 30 seconds, retry once.
- **Step 1 returns 403:** STOP — fundamental permission missing. Report to user.

**Step 0.3 — Validate collected data:**

```bash
python3 get-entra-posture-data.py --validate --output-dir output/identity-posture/
```

This prints a summary of which files are present and valid.

---

### Phase 1 — KQL Enrichment

**Goal:** Run KQL queries against the Log Analytics workspace to enrich Graph data with on-prem AD context, sign-in activity, and MDI intelligence.

**Step 1.1 — Read the queries file:**

Read [kql-enrichment-queries.md](kql-enrichment-queries.md) for the exact KQL for each query.

**Step 1.2 — Execute queries and save results:**

For each query, use the `monitor-client_monitor_workspace_log_query` tool with:
- `resource-group`: from workspace config
- `workspace`: workspace GUID
- `table`: the primary table (e.g., `IdentityInfo`, `SigninLogs`)
- `query`: the exact KQL from the queries file

Then save the `results` array to the specified JSON file:

| Query | Primary Table | Save as |
|-------|--------------|---------|
| KQL-LA1: UAC Flags | IdentityInfo | `kql_uac_flags_<ts>.json` |
| KQL-LA2: MDI Tags | IdentityInfo | `kql_mdi_tags_<ts>.json` |
| KQL-LA3: Risk & Blast Radius | IdentityInfo | `kql_identity_risk_<ts>.json` |
| KQL-LA4: Built-In Accounts | IdentityInfo | `kql_builtin_accounts_<ts>.json` |
| KQL-LA5: Stale Detail | SigninLogs | `kql_stale_detail_<ts>.json` |
| KQL-LA5b: Stale Summary | SigninLogs | `kql_stale_summary_<ts>.json` |
| KQL-LA7: Service Accounts | IdentityInfo | `kql_service_accounts_<ts>.json` |
| KQL-LA8: Cross-Domain Summary | IdentityInfo | `kql_cross_domain_<ts>.json` |

**KQL queries CAN run in parallel** (no dependencies between them).

**Save pattern:** After each KQL tool call, save results with:
```bash
python3 -c "import json; json.dump({'results': <RESULTS>}, open('output/identity-posture/kql_<name>_<ts>.json','w'), indent=2)"
```

**If IdentityInfo table is not available:** Skip KQL-LA1 through LA4, LA7, LA8. Note the gap. KQL-LA5/LA5b (SigninLogs) should always work.

---

### Phase 2 — Analysis & Report

**Goal:** Compute all metrics, the Identity Posture Score, and generate the report.

**Step 2.0 — Resolve the analysis script to disk:**

Resolve `analyze-identity-posture.py` via the [File Resolution cascade](#file-resolution-coderefs-first):

1. Check `codeRefs/sec-sre-ag/identity-posture/analyze-identity-posture.py` → if found, use that path directly.
2. Else check `tmp/identity-posture/analyze-identity-posture.py` → if found, use that path.
3. Else: `read_skill_file(skill_name="identity-posture", file_path="analyze-identity-posture")` → get content, then save to `tmp/identity-posture/analyze-identity-posture.py` via `CreateFile`.

The same cascade applies for `get-entra-posture-data.py` if used for validation (Step 0.3).

> **Why the cascade?** `codeRefs/` contains the latest version-controlled scripts with companion files co-located.
> The `read_skill_file` tool returns file content via API but does not place files
> on the local filesystem. Attempting to run `python3 analyze-identity-posture.py` directly
> will fail with `No such file or directory` (exit code 2) unless resolved first.

**Step 2.1 — Output Modes:**

| Mode | When | What |
|------|------|------|
| **Inline** (default) | Always | Present all metrics, score, and findings directly in chat |
| **Markdown file** | Only if user explicitly requests | Save `.md` report via analyze-identity-posture.py |
| **HTML report** | Only if user explicitly requests | Materialize `generate_html_report.py` and execute (see below) |
| **JSON export** | Only if user explicitly requests | Save computed metrics as JSON |

> **Never ask** which mode — default to inline. If user says "generate HTML", "scarica MD", etc., then use the requested mode.

**Step 2.2 — Run the analysis script:**

```bash
python3 tmp/identity-posture/analyze-identity-posture.py \
    --input-dir  output/identity-posture/ \
    --output-dir reports/identity-posture/ \
    --format     both \
    --tenant     <tenant_short_name>
```

> **`--tenant` resolution:** The script reads `tenant_name` from `config.json` (auto-generated at the workspace root) as the default. If `config.json` is missing or `tenant_name` is empty, pass `--tenant <name>` explicitly or ask the user.

The script:
1. Finds the most recent file for each data type
2. Computes inventory, privilege, stale, password, MFA, risk metrics
3. Computes the Identity Posture Score (0–100, five dimensions)
4. Generates the full markdown report
5. Prints an inline summary to stdout

**Step 2.3 — HTML report (only if explicitly requested):**

Resolve `generate_html_report.py` via the [File Resolution cascade](#file-resolution-coderefs-first) (same as Step 2.0), then run:

```bash
python3 tmp/identity-posture/generate_html_report.py \
    output/identity-posture/ \
    --output-dir reports/identity-posture/ \
    --tenant <tenant_short_name>
```

**Step 2.4 — Present results:**
- Show all metrics, score card, and findings directly inline in chat (ALWAYS, never skip)
- If markdown was requested: provide a link to the `.md` report file
- If HTML was requested: provide a link to the `.html` report file
- Offer SVG dashboard generation if requested

---

## Identity Posture Score Formula

$$
\text{IdentityPostureScore} = \sum_{i=1}^{5} \text{DimensionScore}_i \quad (0\text{–}100)
$$

| Dimension | Max | 🟢 Low (0–5) | 🟡 Medium (6–12) | 🔴 High (13–20) |
|-----------|-----|-------------|------------------|-----------------|
| **Stale/Deleted** | 20 | <5% stale | 5–15% stale | >15% stale |
| **Privileged Exposure** | 20 | <5 permanent high-priv; PIM used | 5–15 permanent | >15 permanent; no PIM |
| **Password Posture** | 20 | <10% PwdNeverExpires | 10–40% | >40%; PasswordNotRequired present |
| **Risk & MFA** | 20 | <5% high risk; >95% MFA | 5–10% risk; 80–95% MFA | >10% high risk; <80% MFA |
| **Identity Sprawl** | 20 | Consistent AD/Entra | Minor gaps | Major hybrid mismatches |

| Score | Rating | Action |
|-------|--------|--------|
| 0–20 | ✅ Healthy | Routine monitoring |
| 21–45 | 🟡 Elevated | Review hygiene gaps |
| 46–70 | 🟠 Concerning | Multiple risk signals — investigate |
| 71–100 | 🔴 Critical | Immediate remediation required |

---

## Permission Requirements

The managed identity needs these Graph API permissions for full data collection:

| Permission | appRoleId | Steps | License |
|-----------|-----------|-------|---------|
| `Directory.Read.All` | `7ab1d382-f21e-4acd-a863-ba3e13f7da61` | 1 (Users), 2 (Roles), 5 (Deleted) | — |
| `AuditLog.Read.All` | `b0afded3-3588-46d8-8b3d-9842eff778da` | 1 (signInActivity) | Entra ID P1 |
| `RoleManagement.Read.Directory` | `483bed4a-2ad3-4361-a73b-c83ccdbdc53c` | 3 (PIM) | Entra ID P2 |
| `IdentityRiskyUser.Read.All` | `dc5007c0-2d7d-4c42-879c-2dab87571379` | 4 (Risky Users) | Entra ID P2 |
| `UserAuthenticationMethod.Read.All` | `38d9df27-64da-44fd-b7c5-a6fbac20248f` | 6 (MFA) | — |
| `Reports.Read.All` | `230c1aed-a721-4c5d-9cb4-a90514e508ef` | 6 (MFA) | — |

If a step returns 403, the skill proceeds with available data and notes the gap.

To grant missing permissions to a managed identity, use the companion script
or run `az rest --method POST` to assign appRoleAssignments to the service principal
(requires Global Admin or Privileged Role Administrator):

```bash
# 1. Find MI service principal object ID
MI_SP_ID=$(az ad sp show --id <mi-client-id> --query id -o tsv)

# 2. Find Microsoft Graph service principal object ID
GRAPH_SP_ID=$(az ad sp show --id 00000003-0000-0000-c000-000000000000 --query id -o tsv)

# 3. Assign each permission (example: Directory.Read.All)
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI_SP_ID/appRoleAssignments" \
  --body "{\"principalId\": \"$MI_SP_ID\", \"resourceId\": \"$GRAPH_SP_ID\", \"appRoleId\": \"7ab1d382-f21e-4acd-a863-ba3e13f7da61\"}"
```

> **Token caching:** After granting permissions, the MI token cache may retain the old token
> for up to 1 hour. If Graph API still returns 403, wait 30–60 minutes and retry.

---

## Known Pitfalls

### 1. `az` CLI Not in Terminal PATH
**Problem:** The agent sandbox does not have `az` in PATH.
**Solution:** Always use `RunAzCliReadCommands` tool, never `subprocess`/terminal `az`.

### 2. Parallel Graph API Calls Cause Failures
**Problem:** Running 6 RunAzCliReadCommands in parallel can cause token refresh issues, resulting in 403 or default-field responses.
**Solution:** Execute Graph API calls **one at a time, sequentially**. KQL queries CAN run in parallel (different auth path).

### 3. `$select` Returning Default Fields
**Problem:** Sometimes RunAzCliReadCommands ignores `$select` and returns default fields.
**Solution:** After Step 1, check if the response contains `accountEnabled` and `signInActivity`. If missing, retry once. If still missing, proceed with available data — the analyze script handles default-field users.

### 4. signInActivity Requires Entra ID P1
**Problem:** `signInActivity` needs P1 + `AuditLog.Read.All` + `ConsistencyLevel: eventual`.
**Solution:** If Step 1 returns empty or lacks signInActivity, retry without it. Use KQL-LA5 (SigninLogs) as fallback for stale detection.

### 5. `array_index_of(null)` Returns Null in KQL
**Problem:** When `UserAccountControl` is null, `array_index_of(null, "PasswordNeverExpires")` returns null (not -1), incorrectly matching.
**Solution:** All KQL queries in [kql-enrichment-queries.md](kql-enrichment-queries.md) use `| where isnotnull(UserAccountControl)` guard.

### 6. passwordPolicies vs UserAccountControl
**Problem:** Two different sources for "password never expires":
- Graph: `passwordPolicies` = "DisablePasswordExpiration" (Entra ID)
- IdentityInfo: `UserAccountControl` contains "PasswordNeverExpires" (AD UAC)
**Solution:** Report both separately. Hybrid accounts may have both.

### 7. MFA Registration ≠ MFA Enforcement
**Problem:** `isMfaRegistered == true` means method registered, not that MFA is enforced.
**Solution:** Note in report: "MFA registration ≠ enforcement. Review Conditional Access."

### 8. IdentityInfo May Not Be in Workspace
**Problem:** Requires Defender XDR connector streaming to Sentinel.
**Solution:** Check table existence. If not found, skip KQL-LA1–LA4, LA7–LA8 and note.

### 9. SigninLogs Retention
**Problem:** Default 30d retention. 90d stale detection needs extended retention.
**Solution:** Check actual data range. Note if <90d available.

### 10. Graph API Pagination
**Problem:** Max 999 per page; large tenants need `@odata.nextLink`.
**Solution:** After each RunAzCliReadCommands call, check for `@odata.nextLink` in the response. If present, follow it with another call and merge results.

### 11. Skill Files Not on Filesystem
**Problem:** `read_skill_file` returns file content via API but does NOT place files on the local filesystem. Running `python3 analyze-identity-posture.py` directly fails with `No such file or directory` (exit code 2).
**Solution:** Always resolve scripts via the [File Resolution cascade](#file-resolution-coderefs-first) (codeRefs → tmp → Builder) before execution. See Phase 2, Step 2.0.

### 12. `Tags` Column Is String, Not Dynamic (KQL SEM0218)
**Problem:** The `Tags` column in `IdentityInfo` is stored as `string`, not `dynamic`. Using `array_index_of(Tags, "Sensitive")` fails at KQL compile time with `SEM0218: array_index_of(): argument #1 must be a dynamic`. The `iff()` wrapper does NOT prevent compile-time type validation.
**Solution:** Always wrap with `todynamic()`: `array_index_of(todynamic(Tags), "Sensitive")`. The same defensive pattern should be applied to `UserAccountControl` inside `iff()` blocks. See KQL-LA4 in [kql-enrichment-queries.md](kql-enrichment-queries.md).

---

## Quality Checklist

Before delivering the report, verify:

- [ ] User inventory collected (Step 1 — critical)
- [ ] All 6 Graph steps attempted (403s noted)
- [ ] KQL enrichment queries run (table availability noted)
- [ ] All data saved to `output/identity-posture/` with correct filenames
- [ ] `get-entra-posture-data.py --validate` passes
- [ ] Analysis script resolved to disk (Step 2.0)
- [ ] `analyze-identity-posture.py` runs without errors
- [ ] Identity Posture Score computed (per-dimension breakdown shown)
- [ ] Zero-result findings use explicit absence pattern
- [ ] MFA coverage cross-referenced with privileged accounts
- [ ] Stale detection method documented (Graph signInActivity vs SigninLogs)
- [ ] Coverage gaps documented (missing permissions, unavailable tables)
- [ ] Recommendations prioritized and evidence-based

---

## SVG Dashboard (Optional)

After report generation, the user can request a visual SVG dashboard.
See [svg-widgets.yaml](svg-widgets.yaml) for the widget manifest.

---

## URL Registry — Canonical Links for Reports

**MANDATORY:** Copy URLs verbatim. Never construct or guess URLs.

| Label | URL |
|-------|-----|
| Graph Users | `https://learn.microsoft.com/en-us/graph/api/user-list` |
| Graph Roles | `https://learn.microsoft.com/en-us/graph/api/directoryrole-list` |
| Graph PIM | `https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityscheduleinstances` |
| Graph Risky | `https://learn.microsoft.com/en-us/graph/api/riskyuser-list` |
| IdentityInfo | `https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityinfo-table` |
| MDI Accounts | `https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/accounts` |
