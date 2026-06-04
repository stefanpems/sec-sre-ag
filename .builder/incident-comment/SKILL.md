---
name: incident-comment
description: >
  Use this skill when asked to write, post, or add a comment to a Microsoft Sentinel
  incident. Accepts plain text, Markdown, or HTML content as input. Plain text is posted
  as-is; Markdown is converted to HTML optimized for the narrow Activities panel;
  HTML is adapted for single-column display. ALL input content is preserved in full —
  no summarization or truncation — unless the user explicitly requests it.
  Triggers on: "write comment", "add comment", "post comment", "scrivi commento",
  "aggiungi commento", "commenta incidente", "comment on incident",
  "post to incident", "annotate incident".
---

> ⚠️ **CRITICAL — ALWAYS PASS --subscription TO MCP MONITOR / AZ REST**
>
> When calling `monitor-client_monitor_workspace_log_query` or `RunAzCliReadCommands`,
> the `subscription` parameter is MANDATORY.

# Incident Comment — Post Content to Sentinel Incident

## Purpose

This skill posts content (plain text, Markdown, or HTML) as a comment on a Microsoft
Sentinel incident. The content is formatted for optimal display in the narrow
**Activities panel** (~400 px single column) of the Sentinel incident page.

**Key principles:**
- **ALL content must be passed through in full** — never summarize, truncate, or omit
  portions of the input unless the user explicitly requests a summary.
- Plain text → posted as-is.
- Markdown → converted to HTML with headers downscaled, tables scrollable, code blocks
  word-wrapped, and all elements adapted for narrow display.
- HTML → adapted: document wrappers stripped, multi-column grids converted to single
  column, fixed widths clamped, images responsive, headers downscaled, links opened
  in new tab.

## Limits

| Constraint | Value |
|---|---|
| Max characters per comment | 30,000 |
| Max comments per incident | 100 |
| Link format | `<a href="..." target="_blank">` |

## Skill Files

| File | Purpose |
|------|---------|
| [SKILL.md](SKILL.md) | This file — skill instructions |
| [format_comment.py](format_comment.py) | Content formatter — detects type, converts, outputs JSON body |

### File Resolution (codeRefs-first)

Before executing any skill file, resolve its location using this **mandatory cascade**:

```
1. codeRefs/sec-sre-ag/incident-comment/<filename>
   → If found: use/execute directly from this path
2. tmp/incident-comment/<filename>
   → If found: use from this path
3. Neither found:
   → read_skill_file("incident-comment", "<filename>") from Builder
   → CreateFile("tmp/incident-comment/<filename>", <content>)
```

**Rules:**
- When a file is found in `codeRefs/`, execute it directly — do NOT copy to `tmp/`.
- This cascade applies to every file listed in the Skill Files table above.

---

## Workflow

### Step 1: Identify the Incident

Determine the target incident from the user's prompt or conversation context.

**Incident ID formats:**

| Pattern | Source | How to resolve GUID |
|---------|--------|---------------------|
| Numeric (e.g., `12345`) | Defender XDR / Sentinel | Query SecurityIncident by `IncidentNumber` |
| GUID | Sentinel internal | Use directly as `IncidentName` |
| `INxx-xxxxx` | Defender XDR | Query SecurityIncident by `ProviderIncidentId` |

If the incident ID is **numeric** or **INxx-xxxxx** format and you need the GUID
(for the ARM/Sentinel API), resolve it:

```kql
SecurityIncident
| where IncidentNumber == <NUMERIC_ID> or ProviderIncidentId == "<ID>"
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| project IncidentNumber, IncidentName, Title, ProviderIncidentId
```

> **Note:** User-provided numeric IDs are typically the `ProviderIncidentId`
> (Defender XDR), not the Sentinel `IncidentNumber`. The KQL above searches both
> fields. Always set `hours` to at least **720** (30 days) to avoid missing older
> incidents.

Execute via `monitor-client_monitor_workspace_log_query` with:
- `workspace`: `951fd5ab-18a2-40c9-8b77-aca135d16fb9`
- `subscription`: `d6116047-3fe1-46f0-aa50-14dd661af84e`
- `resource-group`: `sentinel-us-rg`
- `table`: `SecurityIncident`
- `hours`: `720`

### Step 2: Identify the Content

The content to post can come from:

1. **Inline text in the user's prompt** — extract it.
2. **A file path** — the user points to a file (`.txt`, `.md`, `.html`, report output, etc.).
3. **Previous conversation output** — the user says "post this as a comment" referring to
   something you just generated (investigation report, analysis, etc.).

**Save the content to a temporary file** if it isn't already a file:

```bash
# Write content to a temp file
cat > tmp/incident-comment/input_content.<ext> << 'EOF'
<content here>
EOF
```

Use the appropriate extension: `.txt`, `.md`, or `.html`.

### Step 3: Format the Content

Resolve `format_comment.py` via the [File Resolution cascade](#file-resolution-coderefs-first), then run:

```bash
python3 <resolved_path>/format_comment.py <input_file> \
    --output-json tmp/incident-comment/comment_body.json \
    --api sentinel \
    [--type auto] \
    [--title "Optional Title"] \
    [--on-overflow reduce]
```

**CLI arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `input_file` | Yes | — | Path to the content file |
| `--output-json` | Yes | — | Where to write the JSON body |
| `--api` | No | `sentinel` | `sentinel` or `graph` — target API format |
| `--type` | No | `auto` | `auto`, `text`, `markdown`, `html` — content type |
| `--max-chars` | No | 30000 | Character limit |
| `--title` | No | None | Optional title banner prepended to comment |
| `--on-overflow` | No | `error` | `error` (exit 2), `reduce` (minify to fit — default for unattended), `split` (multiple files) |

**Exit codes:**
- `0` — success
- `1` — argument / runtime error
- `2` — content exceeds `--max-chars` (only when `--on-overflow error`)

**Overflow handling (content > 30,000 chars):**

If exit code is `2`, ask the user whether to **reduce** (minify to fit — recommended
default for unattended runs) or **split** into multiple comments. Then re-run with
the appropriate `--on-overflow` flag:

- `--on-overflow reduce` — strips HTML comments, collapses whitespace, removes inline
  styles, and truncates with a notice if still too long.
- `--on-overflow split` — splits at block-element boundaries and outputs numbered
  JSON files (`comment_body_1.json`, `comment_body_2.json`, …). Post each file as
  a separate comment.

For **unattended / autonomous** runs, default to `--on-overflow reduce`.

### Step 4: Post the Comment

#### Primary: ARM / Sentinel REST API (Python urllib)

The ARM/Sentinel API uses the UAMI token (obtained via `RunAzCliReadCommands`),
which carries Azure RBAC roles. This is the **reliable path** for posting comments.

> **Why not `--body @file`?** The `RunAzCliWriteCommands` tool environment does not
> mount the workspace filesystem — `@/path/to/file` sends the literal string instead
> of reading the file, and shell substitutions like `$(cat ...)` also fail. Use
> Python `urllib.request` in `RunInTerminal` instead.

**Steps:**

1. **Get an ARM token** via `RunAzCliReadCommands`:

   ```
   az account get-access-token --resource https://management.azure.com --query accessToken -o tsv --subscription d6116047-3fe1-46f0-aa50-14dd661af84e
   ```

2. **POST via Python** in `RunInTerminal`:

   ```python
   import json, urllib.request, ssl, uuid

   token = "<TOKEN_FROM_STEP_1>"

   with open("tmp/incident-comment/comment_body.json", "r") as f:
       body = json.load(f)

   payload = json.dumps(body).encode("utf-8")
   incident_guid = "<INCIDENT_GUID>"   # from Step 1 KQL
   comment_guid = str(uuid.uuid4())

   url = (
       f"https://management.azure.com/subscriptions/d6116047-3fe1-46f0-aa50-14dd661af84e"
       f"/resourceGroups/sentinel-us-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-us"
       f"/providers/Microsoft.SecurityInsights/incidents/{incident_guid}/comments/{comment_guid}"
       f"?api-version=2024-03-01"
   )

   req = urllib.request.Request(url, data=payload, method="PUT")
   req.add_header("Authorization", f"Bearer {token}")
   req.add_header("Content-Type", "application/json")

   with urllib.request.urlopen(req, context=ssl.create_default_context()) as resp:
       result = json.loads(resp.read().decode())
       print(f"SUCCESS — Comment ID: {result['name']}")
   ```

Where:
- `<INCIDENT_GUID>` is the `IncidentName` field (GUID) from SecurityIncident — resolved in Step 1.
- `<TOKEN_FROM_STEP_1>` is the ARM access token obtained in the first sub-step.

**Required permission:** `Microsoft Sentinel Responder` role on the workspace (**required**).

**Short-body fallback (< 1 KB):** For very short comments, you can use
`RunAzCliWriteCommands` with inline JSON body:

```
az rest --method PUT --url "<ARM_URL>" --body "{\"properties\":{\"message\":\"<SHORT_TEXT>\"}}" --subscription d6116047-3fe1-46f0-aa50-14dd661af84e
```

#### Why not Graph API?

The Graph API endpoint (`POST /security/incidents/{id}/comments`) requires the
`SecurityIncident.ReadWrite.All` **Application** permission. However, the agent's
`RunAzCliWriteCommands` tool uses a **delegated user token** for Graph API calls —
not the UAMI's application token. Delegated tokens do not carry Application-level
scopes, so the Graph API always returns **403 Forbidden**. The ARM/Sentinel API
path uses the UAMI token where RBAC roles apply correctly.

### Step 5: Confirm to User

After a successful POST/PUT:

1. Report: "Comment posted successfully on incident #<ID> (<Title>)."
2. Show a brief preview (first ~200 chars) of what was posted.
3. If the content was converted (MD→HTML or HTML adapted), note the conversion that
   was applied.

If the API call fails:
1. Report the error (status code, message).
2. If 403 → suggest the required permission assignment:
   - Graph API: `SecurityIncident.ReadWrite.All` application permission on the UAMI
   - ARM API: `Microsoft Sentinel Responder` role on the workspace
3. Offer to retry with the other API.

---

## Error Handling

| Issue | Solution |
|-------|----------|
| Incident not found | Verify ID format; try numeric, GUID, and ProviderIncidentId. Use `hours: 720` in KQL. |
| ARM API 403 | UAMI needs `Microsoft Sentinel Responder` RBAC role on the workspace (**required**). |
| Graph API 403 | **Expected** — Graph uses delegated tokens that lack Application scopes. Use ARM API instead. |
| `@file` / `$(cat)` in body | **Not supported** — tool environment doesn't mount workspace FS. Use Python urllib. |
| Content > 30,000 chars | Re-run with `--on-overflow reduce` (default for unattended) or `--on-overflow split`. |
| format_comment.py not found | Follow file resolution cascade (codeRefs → tmp → Builder) |
| Empty input | Reject with error message |
| Colors unreadable in light/dark mode | `format_comment.py` normalizes colors automatically for dual-theme compatibility. |

---

## Examples

### Example 1: Post plain text

**User:** "Add this comment to incident 12345: The user confirmed this was an authorized test."

```
Step 1: KQL → SecurityIncident | where IncidentNumber == 12345 or ProviderIncidentId == "12345"
        → Found: ProviderIncidentId=12345, IncidentName (GUID) = "abc-def-..."
Step 2: Content = "The user confirmed this was an authorized test." → save to tmp file
Step 3: python3 format_comment.py input.txt --output-json body.json --api sentinel
        → type=text, chars=49
Step 4: Get ARM token → Python urllib PUT .../incidents/abc-def-.../comments/<new-uuid>
        → body read from body.json, sent via urllib.request
Step 5: "Comment posted successfully on incident #12345 (Sentinel #NNN)."
```

### Example 2: Post Markdown investigation report

**User:** "Post the investigation report as a comment on the incident."

```
Step 1: Incident ID from conversation context (e.g., 98765)
        KQL → ProviderIncidentId == "98765" → GUID = "xyz-..."
Step 2: Content = previous investigation output (Markdown) → save to tmp file
Step 3: python3 format_comment.py report.md --output-json body.json --api sentinel
        → type=markdown, chars=4200 (converted to HTML)
Step 4: Get ARM token → Python urllib PUT .../incidents/xyz-.../comments/<new-uuid>
Step 5: "Comment posted on incident #98765. Content converted from Markdown to HTML."
```

### Example 3: Post HTML report

**User:** "Scrivi il report HTML come commento sull'incidente 54321."

```
Step 1: KQL → ProviderIncidentId == "54321" → GUID = "pqr-..."
Step 2: Content = HTML report file → use file path directly
Step 3: python3 format_comment.py report.html --output-json body.json --api sentinel
        → type=html, chars=8500 (adapted for single column)
Step 4: Get ARM token → Python urllib PUT .../incidents/pqr-.../comments/<new-uuid>
Step 5: "Commento pubblicato sull'incidente #54321. HTML adattato per la colonna singola."
```
