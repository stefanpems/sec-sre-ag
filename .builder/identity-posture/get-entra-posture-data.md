# Entra Identity Posture — Graph API Reference

## Purpose

This document provides the exact Graph API calls for collecting identity posture data
from Entra ID. Use with `RunAzCliReadCommands` tool or `az rest` in terminal.

For **batch collection** of all data at once, use the companion script:
[get-entra-posture-data.py](get-entra-posture-data.py)

This document is the **individual call reference** — use when the agent needs
to make specific calls or re-run a single step.

---

## ⛔ Critical: Tool Selection

> **Priority 1:** Use `RunAzCliReadCommands` tool if available (handles auth via Managed Identity).
> **Priority 2:** Use `az rest` in terminal if `RunAzCliReadCommands` is not available.
> **NEVER** use `RunAzCliWriteCommands` — even for GET calls (see user-investigation skill for rationale).
> **NEVER** use `microsoft_graph_get` — the Graph MCP Server is not integrated with Azure SRE Agent (cannot currently be connected).

---

## Permission Requirements

| Step | Endpoint | Permission (Application) | License |
|------|----------|--------------------------|---------|
| 1 | `/users` | Directory.Read.All | — |
| 1 | `/users` + signInActivity | AuditLog.Read.All | Entra ID P1 |
| 2 | `/directoryRoles` | Directory.Read.All | — |
| 3 | `/roleManagement/directory/roleEligibilityScheduleInstances` | RoleManagement.Read.Directory | Entra ID P2 (PIM) |
| 4 | `/identityProtection/riskyUsers` | IdentityRiskyUser.Read.All | Entra ID P2 |
| 5 | `/directory/deletedItems` | Directory.Read.All | — |
| 6 | `/reports/authenticationMethods/userRegistrationDetails` | UserAuthenticationMethod.Read.All, Reports.Read.All | — |

---

## Decision Flow

```
Can I use RunAzCliReadCommands tool?
  ├─ YES → Use the calls below with RunAzCliReadCommands
  │         └─ If 403 on Step 1 → STOP all Graph calls, use KQL-only mode
  └─ NO
       └─ Can I use az rest in terminal?
            ├─ YES → Use the calls below with az rest
            │         └─ If 403 on Step 1 → STOP, use KQL-only mode
            └─ NO → Use KQL-only mode (IdentityInfo + SigninLogs from Log Analytics)
```

---

## Step 1: User Inventory (MUST be first — validates permissions)

**Graph endpoint:** `GET /v1.0/users`

**With signInActivity (requires Entra ID P1):**
```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,mail,accountEnabled,createdDateTime,department,jobTitle,userType,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,lastPasswordChangeDateTime,passwordPolicies,signInActivity&$top=999&$count=true" --headers "ConsistencyLevel=eventual"
```

**Without signInActivity (fallback if P1 not available):**
```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,displayName,mail,accountEnabled,createdDateTime,department,jobTitle,userType,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesDomainName,lastPasswordChangeDateTime,passwordPolicies&$top=999&$count=true" --headers "ConsistencyLevel=eventual"
```

**⚠️ Pagination:** Results are paginated (max 999 per page). Follow `@odata.nextLink` until null.

**Key fields extracted:**

| Field | Maps to Original | Usage |
|-------|-----------------|-------|
| `id` | AccountId | Unique account identifier |
| `userPrincipalName` | AccountUpn | User principal name |
| `displayName` | DisplayName | Display name |
| `accountEnabled` | AccountStatus | true=Enabled, false=Disabled |
| `createdDateTime` | CreatedDateTime | Account creation date |
| `department` | Department | Department |
| `userType` | Type (partial) | Member/Guest |
| `onPremisesSyncEnabled` | SourceProvider (partial) | true=hybrid (AD+AAD), null=cloud-only |
| `lastPasswordChangeDateTime` | LastPasswordChangeTime | Last password change |
| `passwordPolicies` | (enrichment) | "DisablePasswordExpiration" = PasswordNeverExpires |
| `signInActivity.lastSignInDateTime` | (stale detection) | Last interactive sign-in |
| `signInActivity.lastNonInteractiveSignInDateTime` | (stale detection) | Last non-interactive sign-in |

**If this returns 403:** STOP all Graph API calls. Proceed to KQL-only mode.

---

## Step 2: Directory Role Assignments (Permanent Roles)

**Graph endpoint:** `GET /v1.0/directoryRoles` with `$expand=members`

```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($select=id,userPrincipalName,displayName)"
```

**Post-processing:**
- Each role object has `displayName` (role name) and `members` (array of user objects)
- Filter for high-privilege roles (see `highPrivRoles` list in SKILL.md)
- Map: `role.displayName` → AssignedRoles equivalent
- All roles returned here are **permanent** (not PIM-eligible)

**High-privilege roles to flag:**
- Global Administrator
- Security Administrator
- Privileged Role Administrator
- Privileged Authentication Administrator
- Exchange Administrator
- SharePoint Administrator
- Application Administrator
- Cloud App Security Administrator
- Intune Administrator / Intune Service Administrator
- Compliance Administrator
- User Administrator
- Azure AD Joined Device Local Administrator

---

## Step 3: PIM Eligible Role Assignments

**Graph endpoint:** `GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances`

```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal($select=id,userPrincipalName,displayName),roleDefinition($select=displayName)"
```

**Post-processing:**
- Each instance has `principal` (user/group), `roleDefinition` (role name), `startDateTime`, `endDateTime`
- These are **PIM-eligible** roles — user must activate them to use
- Cross-reference with Step 2: accounts in Step 2 but NOT in Step 3 have permanent-only roles (higher risk)
- Accounts in Step 3 but NOT in Step 2 have PIM-only roles (lower risk)

**Key distinction:**
- **Permanent role** (Step 2 only) → always active → higher risk
- **PIM-eligible** (Step 3) → must be activated → lower risk
- **Both** → has permanent AND eligible roles → review if permanent is needed

---

## Step 4: Risky Users (Identity Protection)

**Graph endpoint:** `GET /v1.0/identityProtection/riskyUsers`

```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$select=id,userPrincipalName,userDisplayName,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime,isDeleted,isProcessing&$top=999"
```

**Key fields:**

| Field | Description |
|-------|-------------|
| `riskLevel` | none, low, medium, high, hidden |
| `riskState` | none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised |
| `riskDetail` | Reason code (e.g., aiConfirmedSigninSafe, adminDismissedAllRiskForUser) |
| `isDeleted` | Whether the user is deleted |
| `isProcessing` | Whether risk is being re-evaluated |

**Post-processing:**
- Filter `riskState == "atRisk"` for unresolved risky users
- Cross-reference with Step 2 roles: high-risk + high-privilege = **critical finding**
- Group by `riskLevel` for distribution reporting

---

## Step 5: Deleted Users (Recycle Bin)

**Graph endpoint:** `GET /v1.0/directory/deletedItems/microsoft.graph.user`

```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?$select=id,userPrincipalName,displayName,deletedDateTime,onPremisesSyncEnabled&$top=999"
```

**Post-processing:**
- Soft-deleted users remain in the Entra ID recycle bin for **30 days**
- These users may still have residual group memberships or role assignments
- Note: unlike the IdentityAccountInfo table (which shows deleted accounts with roles from ALL providers),
  Graph API only shows Entra ID deleted users. On-prem AD deleted accounts are not visible here.
- Count total deleted and note as data point for hygiene assessment

**Limitation:** Graph API cannot directly show which roles/groups a deleted user retains.
For full deleted-account-with-roles analysis, the IdentityAccountInfo table (via AH) is needed.
Report this as a coverage gap.

---

## Step 6: MFA Registration Details

**Graph endpoint:** `GET /v1.0/reports/authenticationMethods/userRegistrationDetails`

```
az rest --method GET --uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$select=id,userPrincipalName,userDisplayName,isMfaRegistered,isMfaCapable,isPasswordlessCapable,isSsprRegistered,isSsprEnabled,isSsprCapable,methodsRegistered,defaultMfaMethod&$top=999"
```

**Key fields:**

| Field | Description |
|-------|-------------|
| `isMfaRegistered` | User has registered at least one MFA method |
| `isMfaCapable` | User is capable of MFA (registered + enabled) |
| `isPasswordlessCapable` | User can sign in without a password |
| `methodsRegistered` | Array: microsoftAuthenticatorPush, fido2, phoneAuthentication, etc. |
| `defaultMfaMethod` | The default MFA method used |

**Post-processing:**
- Calculate MFA coverage: `countif(isMfaRegistered) / total users`
- Identify users with NO MFA registration → cross-reference with privileged roles
- Report passwordless-capable percentage as a maturity indicator
- Note: This data is NOT available from IdentityAccountInfo (which has empty `EnrolledMfas` in Preview)

---

## Error Handling

| Error | Meaning | Action |
|-------|---------|--------|
| 403 Forbidden | Insufficient permissions | Skip step, note in summary |
| 404 Not Found | Endpoint not available or resource not found | Skip step |
| 429 Too Many Requests | Rate limited | Wait and retry (az rest handles some retries) |
| Empty response | No data or wrong query | Verify $select fields, check permissions |
| Timeout | Large tenant, many users | Increase timeout, reduce $top |

---

## Data File Naming Convention

All output files follow the pattern: `<type>_<timestamp>.json`

| File | Content | Source Step |
|------|---------|------------|
| `users_YYYYMMDD_HHMMSS.json` | Full user inventory | Step 1 |
| `directory_roles_YYYYMMDD_HHMMSS.json` | Permanent role assignments | Step 2 |
| `pim_eligible_roles_YYYYMMDD_HHMMSS.json` | PIM eligible roles | Step 3 |
| `risky_users_YYYYMMDD_HHMMSS.json` | Identity Protection risky users | Step 4 |
| `deleted_users_YYYYMMDD_HHMMSS.json` | Soft-deleted users | Step 5 |
| `mfa_registration_YYYYMMDD_HHMMSS.json` | MFA registration details | Step 6 |
| `collection_metadata_YYYYMMDD_HHMMSS.json` | Collection summary/status | All |
