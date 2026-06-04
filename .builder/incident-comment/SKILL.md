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
| project IncidentNumber, IncidentName, Title
```

Execute via `monitor-client_monitor_workspace_log_query` with:
- `workspace`: `951fd5ab-18a2-40c9-8b77-aca135d16fb9`
- `subscription`: `d6116047-3fe1-46f0-aa50-14dd661af84e`
- `resource-group`: `sentinel-us-rg`
- `table`: `SecurityIncident`

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
    --api graph \
    [--type auto] \
    [--title "Optional Title"]
```

**CLI arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `input_file` | Yes | — | Path to the content file |
| `--output-json` | Yes | — | Where to write the JSON body |
| `--api` | No | `graph` | `graph` or `sentinel` — target API format |
| `--type` | No | `auto` | `auto`, `text`, `markdown`, `html` — content type |
| `--max-chars` | No | 30000 | Character limit |
| `--title` | No | None | Optional title banner prepended to comment |

**Exit codes:**
- `0` — success
- `1` — argument / runtime error
- `2` — content exceeds `--max-chars`

If exit code is `2`, inform the user that the content exceeds the 30,000 character limit
and ask whether to split into multiple comments or truncate.

### Step 4: Post the Comment

#### Primary: Microsoft Graph API

```bash
az rest --method POST \
    --url "https://graph.microsoft.com/v1.0/security/incidents/<INCIDENT_ID>/comments" \
    --headers "Content-Type=application/json" \
    --body @tmp/incident-comment/comment_body.json \
    --subscription d6116047-3fe1-46f0-aa50-14dd661af84e
```

Where `<INCIDENT_ID>` is the **numeric** incident ID (from Defender XDR / Sentinel
`IncidentNumber` field).

**Required permission:** `SecurityIncident.ReadWrite.All` (Application) on the UAMI.

Execute via `RunAzCliReadCommands` (yes — `az rest --method POST` works through this
tool; it is a REST call, not a resource mutation via ARM).

#### Fallback: ARM / Sentinel REST API

If the Graph API fails (403, 404, or permission error), use the ARM API:

```bash
az rest --method PUT \
    --url "https://management.azure.com/subscriptions/d6116047-3fe1-46f0-aa50-14dd661af84e/resourceGroups/sentinel-us-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-us/providers/Microsoft.SecurityInsights/incidents/<INCIDENT_GUID>/comments/<NEW_COMMENT_GUID>?api-version=2024-03-01" \
    --headers "Content-Type=application/json" \
    --body @tmp/incident-comment/comment_body.json \
    --subscription d6116047-3fe1-46f0-aa50-14dd661af84e
```

Where:
- `<INCIDENT_GUID>` is the `IncidentName` field (GUID) from SecurityIncident — resolved in Step 1.
- `<NEW_COMMENT_GUID>` is a freshly generated UUID (use `python3 -c "import uuid; print(uuid.uuid4())"` to generate one).

**Required permission:** `Microsoft Sentinel Responder` role on the workspace.

For the Sentinel API, re-run `format_comment.py` with `--api sentinel` to get the
correct JSON body format:

```bash
python3 <resolved_path>/format_comment.py <input_file> \
    --output-json tmp/incident-comment/comment_body_sentinel.json \
    --api sentinel
```

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
| Incident not found | Verify ID format; try numeric, GUID, and ProviderIncidentId |
| Graph API 403 | UAMI needs `SecurityIncident.ReadWrite.All` app permission |
| ARM API 403 | UAMI needs `Microsoft Sentinel Responder` role |
| Content > 30,000 chars | Ask user: split into multiple comments or truncate? |
| format_comment.py not found | Follow file resolution cascade (codeRefs → tmp → Builder) |
| Empty input | Reject with error message |

---

## Examples

### Example 1: Post plain text

**User:** "Add this comment to incident 12345: The user confirmed this was an authorized test."

```
Step 1: Incident ID = 12345 (numeric → use directly for Graph API)
Step 2: Content = "The user confirmed this was an authorized test." → save to tmp file
Step 3: python3 format_comment.py input.txt --output-json body.json --api graph
        → type=text, chars=49
Step 4: az rest --method POST --url .../incidents/12345/comments --body @body.json
Step 5: "Comment posted successfully on incident #12345."
```

### Example 2: Post Markdown investigation report

**User:** "Post the investigation report as a comment on the incident."

```
Step 1: Incident ID from conversation context (e.g., 98765)
Step 2: Content = previous investigation output (Markdown) → save to tmp file
Step 3: python3 format_comment.py report.md --output-json body.json --api graph
        → type=markdown, chars=4200 (converted to HTML)
Step 4: az rest --method POST --url .../incidents/98765/comments --body @body.json
Step 5: "Comment posted on incident #98765. Content converted from Markdown to HTML."
```

### Example 3: Post HTML report

**User:** "Scrivi il report HTML come commento sull'incidente 54321."

```
Step 1: Incident ID = 54321
Step 2: Content = HTML report file → use file path directly
Step 3: python3 format_comment.py report.html --output-json body.json --api graph
        → type=html, chars=8500 (adapted for single column)
Step 4: az rest --method POST --url .../incidents/54321/comments --body @body.json
Step 5: "Commento pubblicato sull'incidente #54321. HTML adattato per la colonna singola."
```
