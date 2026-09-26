# Technical Report (DOCX) — Optional Private Module

> Companion file of the `incident-investigation` skill. Read it ONLY when the user explicitly
> asks for a **technical report / rapporto tecnico / post-incident report in DOCX** or asks to
> **update** a report that was already issued.
>
> The renderer scripts, JSON schema, DOCX template and synthetic example are **not** in this
> public repository. They are in a **private repository connected to the agent** and are
> resolved under `codeRefs/`. Setup procedure: [docs/technical-report-docx-setup.md](../../docs/technical-report-docx-setup.md).

## Role Separation (MANDATORY)

| Who | What |
|-----|------|
| **Agent** | Analyzes the investigation evidence and produces **only a JSON file** that complies with the schema |
| **`render_rapporto.py`** | Converts the JSON into the DOCX, deterministically, starting from the official template |
| **`patch_rapporto.py`** | Applies targeted changes to an already issued DOCX |

- NEVER write, edit or unzip the `.docx` manually, and never generate OOXML.
- NEVER `ReadFile` the template, the generated DOCX, or the full schema/example into the context more than once per session. Use `jq`/`head` to extract only the fields you need.

## Step 1 — Resolve the Module (codeRefs only)

The module is a folder named `rapporto-tecnico-soc` that contains `render_rapporto.py`, located anywhere under `codeRefs/`. Do not hardcode the private repository name.

```bash
RENDER=$(find codeRefs -maxdepth 5 -type f -path '*/rapporto-tecnico-soc/render_rapporto.py' 2>/dev/null | head -1)
if [ -z "$RENDER" ]; then echo "MODULE_NOT_FOUND"; else MOD=$(dirname "$RENDER"); echo "MOD=$MOD"; fi
```

- `MODULE_NOT_FOUND` → tell the user: "The DOCX technical report module is not available in this environment (private repository not connected). See docs/technical-report-docx-setup.md." Then **stop**. Do NOT fall back to `read_skill_file`: the module is intentionally not in Builder, because Builder does not store binary files such as the template.

## Step 2 — Pre-flight Checks

```bash
TPL=$(ls "$MOD/template/Rapporto_Tecnico_TEMPLATE.docx" "$MOD/../template/Rapporto_Tecnico_TEMPLATE.docx" "$MOD/Rapporto_Tecnico_TEMPLATE.docx" 2>/dev/null | head -1)
[ -z "$TPL" ] && echo "TEMPLATE_NOT_FOUND"
python3 - "$TPL" <<'PY'
import sys
p = sys.argv[1] if len(sys.argv) > 1 else ""
if not p: sys.exit(0)
h = open(p, "rb").read(8)
if h.startswith(b"PK\x03\x04"): print("TEMPLATE_OK")
elif h.startswith(b"\xd0\xcf\x11\xe0"): print("TEMPLATE_ENCRYPTED")  # OLE container = IRM / sensitivity label with encryption (or legacy .doc)
else: print("TEMPLATE_INVALID")
PY
python3 -c "import docx, jsonschema" 2>/dev/null && echo "DEPS_OK" || pip install -q python-docx jsonschema
```

| Result | Action |
|--------|--------|
| `TEMPLATE_OK` + `DEPS_OK` | Proceed |
| `TEMPLATE_NOT_FOUND` / `TEMPLATE_INVALID` | Stop and report the path checked |
| `TEMPLATE_ENCRYPTED` | Stop: "The template in the private repository is protected (IRM / sensitivity label with encryption). Upload an unprotected copy." (python-docx fails with `Package not found`) |

## Step 3 — Build the JSON

1. Read `$MOD/SKILL.md` (private compilation rules — they take precedence over this file for field semantics).
2. Extract the required fields and formats from the schema, without dumping it:
   ```bash
   jq '{required, props: (.properties | map_values({required, type}))}' "$MOD/rapporto_tecnico.schema.json"
   ```
3. Use `$MOD/esempi/incidente_esempio.json` as the formatting reference (dates, timeline rows, ISP list).
4. Populate the fields from the investigation data (cache JSON `temp/investigation_<id>_*.json` or current session):

| JSON field | Source in the investigation |
|------------|-----------------------------|
| `evento.secops_incident_id` | Incident ID (portal ID) |
| `evento.data_ora_incidente` | Timestamp of the **first alert** (Q2, earliest `TimeGenerated`) — NOT the first attack event |
| `evento.data_ora_chiusura` | Incident `ClosedTime` (Q1), only if the incident is closed |
| `evento.ip_url_attaccati` | Targeted IPs / URLs / hosts from assets and evidences (Q3/Q4) |
| `evento.tipologia_attacco`, `summary.tipo_attacco` | Alert titles/categories + MITRE tactics |
| `summary.data_evento`, `summary.ora_evento` | Same instant as `evento.data_ora_incidente` |
| `summary.finestra_inizio` / `finestra_fine`, `connessioni_osservate` | KQL aggregates already collected in Phase 1/2 (do not run new heavy queries just for the report) |
| `timeline[]` | Chronological list of alerts and key events, one row per event |
| `conclusioni.e_incidente_sicurezza` | Incident `Classification`: TruePositive → `true`; FalsePositive / BenignPositive → `false`; Undetermined/empty → **ask** |
| `conclusioni.ha_causato_impatto` | Only if evidence proves it; otherwise **ask** |

5. **Always ask the user** (one AskUserQuestion per missing value, options only when the real values are known): `metadata.codice_documento`, `metadata.versione`, `metadata.classificazione`, `evento.soggetto_impattato`, `evento.tassonomia`, and ISP data (`analisi_attacco.isp`). Never infer them — a wrong security report has operational consequences.
6. Write the JSON to `tmp/incident-investigation/rt_<incidentId>.json` (CreateFile).

## Step 4 — Render

```bash
mkdir -p reports/incident-investigation
python3 "$MOD/render_rapporto.py" --dati tmp/incident-investigation/rt_<incidentId>.json \
  --out reports/incident-investigation/RT-<incidentId>.docx
```

- Expected output: `OK: generato <path>`.
- On a validation error, the script prints the exact JSON path: fix only that field and re-run (max 3 attempts, then report the error).
- Persist the DOCX with SaveFileToBlob and share the download link. For email/Teams delivery, follow the same patterns as the HTML report (attachment = workspace path of the `.docx`).

## Step 5 — Update an Already Issued Report (never regenerate)

The user must attach the issued DOCX to the thread (it lands in `tmp/ThreadFiles/<threadId>/`).

```bash
DOC=tmp/ThreadFiles/<threadId>/<file>.docx
python3 "$MOD/patch_rapporto.py" --doc "$DOC" --lista        # list editable anchors
python3 "$MOD/patch_rapporto.py" --doc "$DOC" --out reports/incident-investigation/<file>_v2.docx \
  --sezione <id> --testo "..."                               # or: --campo <id> --valore "..."
                                                             # or: --timeline-aggiungi "DD/MM/YYYY HH.MM GMT+01:00|Description"
                                                             # or: --conclusioni impatto=si|no incidente=si|no
```

- Always write to a new file with `--out` (the thread attachment is the original).
- Persist the new file with SaveFileToBlob and share the link.
