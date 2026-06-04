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
    --output-readable tmp/incident-comment/comment_body_readable.txt \
    --api sentinel \
    [--type auto] \
    [--title "Optional Title"] \
    [--on-overflow reduce]
```

> **Always pass `--output-readable`** — it writes the JSON body split into lines
> of ≤1500 chars (ASCII-safe), so `ReadFile` can read the full body without
> truncation. Step 4 relies on this file.

**CLI arguments:**

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `input_file` | Yes | — | Path to the content file |
| `--output-json` | Yes | — | Where to write the JSON body (standard single-line JSON) |
| `--output-readable` | No | None | Where to write a ReadFile-friendly version (lines ≤1500 chars). **Always use this.** |
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

Use `RunAzCliWriteCommands` with `az rest` to PUT the comment via the ARM/Sentinel API.

> ⚠️ **IMPORTANT — This is the ONLY working method.**
>
> **Do NOT attempt Python `urllib` from `RunInTerminal`.** The sandbox network
> cannot make authenticated ARM calls — tokens obtained via `RunAzCliReadCommands`
> are IP-bound to the platform's network path, not the sandbox's. Python urllib
> always returns **401 AuthenticationFailed** regardless of token handling.
> This is a confirmed platform constraint (see `docs/known-issues.md` §1.5).
>
> **Do NOT attempt `--body @file`** with `RunAzCliWriteCommands` — the tool
> environment does not mount the workspace filesystem.

**Sub-steps:**

1. **Read the formatted body** — read `tmp/incident-comment/comment_body_readable.txt`
   using `ReadFile`. This file was written by `format_comment.py --output-readable`
   in Step 3, with lines wrapped at ≤1500 chars for ReadFile compatibility.
   **Concatenate all lines** (remove the line breaks that were added for wrapping)
   to reconstruct the full JSON body string.

2. **Generate a comment GUID** — run in `RunInTerminal`:
   ```bash
   python3 -c "import uuid; print(uuid.uuid4())"
   ```
   This can run **in parallel** with sub-step 1 (`ReadFile`).

3. **Post via `RunAzCliWriteCommands`:**

   ```
   az rest --method PUT --url "https://management.azure.com/subscriptions/<SUB_ID>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WS>/providers/Microsoft.SecurityInsights/incidents/<INCIDENT_GUID>/comments/<COMMENT_GUID>?api-version=2024-03-01" --body <JSON_BODY> --subscription <SUB_ID>
   ```

   Where:
   - `<SUB_ID>` = subscription ID
   - `<RG>` = workspace resource group (e.g., `sentinel-us-rg`)
   - `<WS>` = workspace name (e.g., `sentinel-us`)
   - `<INCIDENT_GUID>` = `IncidentName` from Step 1 KQL
   - `<COMMENT_GUID>` = UUID from sub-step 2
   - `<JSON_BODY>` = full JSON body from sub-step 1 (the concatenated content of
     `comment_body_readable.txt`)

**Required permission:** `Microsoft Sentinel Responder` role on the workspace.

### Step 5: Confirm to User

After a successful PUT:

1. Report: "Comment posted successfully on incident #<ID> (<Title>)."
2. Show a brief preview (first ~200 chars) of what was posted.
3. If the content was converted (MD→HTML or HTML adapted), note the conversion that
   was applied.

If the API call fails:
1. Report the error (status code, message).
2. If 403 → suggest: `Microsoft Sentinel Responder` role on the workspace for the UAMI.

---

## Error Handling

| Issue | Solution |
|-------|----------|
| Incident not found | Verify ID format; try numeric, GUID, and ProviderIncidentId. Use `hours: 720` in KQL. |
| ARM API 403 | UAMI needs `Microsoft Sentinel Responder` RBAC role on the workspace (**required**). |
| `@file` / `$(cat)` in body | **Not supported** — tool environment doesn't mount workspace FS. Pass body inline in the `az rest --body` parameter. |
| Python urllib 401 | **Do NOT use Python urllib.** The sandbox cannot make authenticated ARM calls. Use `RunAzCliWriteCommands` with `az rest`. See Step 4. |
| `az` not found in `RunInTerminal` | **Expected** — `az` CLI is not in PATH in the sandbox. Use `RunAzCliWriteCommands` tool instead. |
| Content > 30,000 chars | Re-run with `--on-overflow reduce` (default for unattended) or `--on-overflow split`. |
| format_comment.py not found | Follow file resolution cascade (codeRefs → tmp → Builder). |
| Empty input | Reject with error message. |
| Colors unreadable in light/dark mode | `format_comment.py` normalizes colors automatically for dual-theme compatibility. |
| ReadFile truncates body | Always use `--output-readable` in Step 3. Read the readable file, concatenate lines to reconstruct the full body. |

---

## Examples

### Example 1: Post plain text

**User:** "Add this comment to incident 12345: The user confirmed this was an authorized test."

```
Step 1: KQL → SecurityIncident | where IncidentNumber == 12345 or ProviderIncidentId == "12345"
        → Found: ProviderIncidentId=12345, IncidentName (GUID) = "abc-def-..."
Step 2: Content = "The user confirmed this was an authorized test." → save to tmp file
Step 3: python3 format_comment.py input.txt --output-json body.json
            --output-readable body_readable.txt --api sentinel
        → type=text, chars=49
Step 4: ReadFile body_readable.txt → concatenate lines → full JSON body
        Generate UUID → RunAzCliWriteCommands: az rest --method PUT --url ...  --body <JSON>
Step 5: "Comment posted successfully on incident #12345."
```

### Example 2: Post Markdown investigation report

**User:** "Post the investigation report as a comment on the incident."

```
Step 1: Incident ID from conversation context (e.g., 98765)
        KQL → ProviderIncidentId == "98765" → GUID = "xyz-..."
Step 2: Content = previous investigation output (Markdown) → save to tmp file
Step 3: python3 format_comment.py report.md --output-json body.json
            --output-readable body_readable.txt --api sentinel
        → type=markdown, chars=4200 (converted to HTML)
Step 4: ReadFile body_readable.txt → concatenate → az rest PUT via RunAzCliWriteCommands
Step 5: "Comment posted on incident #98765. Content converted from Markdown to HTML."
```

### Example 3: Post HTML report

**User:** "Scrivi il report HTML come commento sull'incidente 54321."

```
Step 1: KQL → ProviderIncidentId == "54321" → GUID = "pqr-..."
Step 2: Content = HTML report file → use file path directly
Step 3: python3 format_comment.py report.html --output-json body.json
            --output-readable body_readable.txt --api sentinel
        → type=html, chars=8500 (adapted for single column)
Step 4: ReadFile body_readable.txt → concatenate → az rest PUT via RunAzCliWriteCommands
Step 5: "Commento pubblicato sull'incidente #54321. HTML adattato per la colonna singola."
```
