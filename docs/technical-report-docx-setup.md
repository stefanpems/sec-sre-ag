# Setup — DOCX Technical Report for `incident-investigation`

This procedure enables the optional **DOCX technical report** output of the
`incident-investigation` skill. The agent writes only a JSON file; a private Python
module renders the DOCX from an official Word template and can patch reports that
were already issued.

The module (scripts, JSON schema, template, synthetic example) usually contains
organization-specific content, so it is **not** in this public repository. It
lives in a **private GitHub repository connected to the agent**. The skill finds it
under `codeRefs/` at runtime.

## Why a private connected repository

| Option | Outcome |
|--------|---------|
| Supporting files in Builder | ❌ Builder stores text only (`deploy_skills.py` skips binary files), so the `.docx` template cannot be stored. Scripts would also have to go through the LLM context on every run. |
| Public repository | ❌ Exposes organization-specific content |
| **Private repository connected to the agent** | ✅ Files, including binaries, are on disk under `codeRefs/<repo>/`. No token cost, versioned with git. |

## Prerequisites

- An Azure SRE Agent with the `incident-investigation` skill already deployed.
- A private GitHub repository and credentials that can read it: a fine-grained PAT with
  **Contents: Read-only** + **Metadata: Read-only**, the OAuth connection, or a GitHub App
  installed on the repository.
- The module package: a folder named `rapporto-tecnico-soc/` that contains:

  ```
  rapporto-tecnico-soc/
  ├── SKILL.md                         private compilation rules (read by the agent)
  ├── rapporto_tecnico.schema.json     JSON Schema (source of truth for fields)
  ├── render_rapporto.py               JSON -> DOCX
  ├── patch_rapporto.py                DOCX -> DOCX (targeted update)
  ├── template/
  │   └── Rapporto_Tecnico_TEMPLATE.docx
  └── esempi/
      └── incidente_esempio.json       synthetic example
  ```

  The folder can be at any depth up to 4 levels under the repository root. The skill looks for
  `*/rapporto-tecnico-soc/render_rapporto.py`.

## Step 1 — Check the template locally (before uploading)

The template **must be a plain, unencrypted OOXML file**. A template protected by IRM or by a
sensitivity label with encryption is stored as an OLE container, and `python-docx` fails with
`Package not found`. Organizations with default or mandatory labeling may add the protection
silently when the file is saved.

```bash
python3 -c "import sys;h=open(sys.argv[1],'rb').read(4);print('OK' if h==b'PK\x03\x04' else 'ENCRYPTED/INVALID' if h==b'\xd0\xcf\x11\xe0' else 'INVALID')" \
  rapporto-tecnico-soc/template/Rapporto_Tecnico_TEMPLATE.docx
```

If the result is not `OK`, open the file in Word and apply a label **without encryption** (or remove
the protection). Save it again and re-check.

Optional smoke test (Python 3 + `pip install python-docx jsonschema`):

```bash
cd rapporto-tecnico-soc
python render_rapporto.py --dati esempi/incidente_esempio.json --out RT-test.docx   # -> OK: generato RT-test.docx
python patch_rapporto.py --doc RT-test.docx --lista
```

## Step 2 — Push the module to the private repository

```bash
git clone https://github.com/<owner>/<private-repo>.git && cd <private-repo>
cp -r /path/to/rapporto-tecnico-soc .
git add -A && git commit -m "Add rapporto-tecnico-soc module" && git push origin main
```

Check that the push reached GitHub and that the template on the remote is still a valid
zip. Uploading through the browser or a synced folder can re-apply protection:

```bash
git ls-remote origin main                      # must show a commit
curl -sL -H "Authorization: Bearer <token>" \
  -H "Accept: application/vnd.github.raw" \
  "https://api.github.com/repos/<owner>/<private-repo>/contents/<path>/template/Rapporto_Tecnico_TEMPLATE.docx" \
  | head -c 4 | xxd                            # must start with 504b 0304 (PK..)
```

## Step 3 — Connect the private repository to the agent

1. SRE Agent portal → your agent → **Settings / Code repositories** (GitHub connector).
2. Add `<owner>/<private-repo>` with the credentials from the prerequisites.
3. Open a **new** chat thread and ask the agent:

   > Check that codeRefs contains the rapporto-tecnico-soc module and that the template is a valid, unencrypted DOCX.

   The agent should report the module path (`codeRefs/<private-repo>/.../rapporto-tecnico-soc`)
   and `TEMPLATE_OK`.

> If the repository was connected **before** the first push, the clone in the agent may be empty.
> Push first, then start a new thread. The agent can also run `git fetch` + `git reset --hard FETCH_HEAD` in the clone.

## Step 4 — Deploy the updated skill

The skill changes are in `.builder/incident-investigation/`:

- `SKILL.md` has pointers: Skill Files table, USE-CACHE keywords, Output Modes row.
- `technical-report-docx.md` is a new companion file with the full workflow.

**Option A — script (recommended):**

```bash
cd .builder/deploy
python deploy_skills.py deploy --skills incident-investigation --dry-run
python deploy_skills.py deploy --skills incident-investigation
```

This also deploys every other change in `.builder/incident-investigation/` that is newer than
the version installed in Builder. Review the dry-run output first.

**Option B — portal:** Builder → Skills → `incident-investigation` → paste the new `SKILL.md`, then
add `technical-report-docx.md` as a supporting file with exactly that name.

## Step 5 — End-to-end test (synthetic data only)

In a new thread:

1. `Investigate incident <test-incident-id>` → complete the investigation → `done`
2. `Genera il rapporto tecnico DOCX per l'incidente <id>`

Expected behavior:

- The agent reads `technical-report-docx.md`, resolves the module, and runs the pre-flight checks.
- It asks for the fields it must not infer: document code, version, classification, impacted
  subject, taxonomy, ISP data.
- It writes `tmp/incident-investigation/rt_<id>.json`, runs `render_rapporto.py`, and returns a
  download link to `RT-<id>.docx`.

3. Attach the DOCX and ask: `Aggiorna il rapporto: incidente=si, aggiungi alla timeline "…"`.
   The agent should use `patch_rapporto.py --out …_v2.docx` and not regenerate the report.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `MODULE_NOT_FOUND` | Private repo not connected, empty clone, or folder not named `rapporto-tecnico-soc` | Step 2–3 |
| `TEMPLATE_ENCRYPTED` / `Package not found` | Template protected by IRM or a sensitivity label with encryption | Step 1, then push again |
| `ModuleNotFoundError: docx` | Sandbox missing deps | The skill runs `pip install python-docx jsonschema` automatically |
| Validation error with JSON path | Field does not match the schema (e.g. taxonomy pattern) | The agent fixes the field and re-runs (max 3 attempts) |
| Agent writes the DOCX manually or stops at the JSON | Old skill version in Builder | Step 4 |

## Updating the module

Push changes to the private repository. The agent picks them up on the next clone/sync, so there is
no Builder redeploy unless `technical-report-docx.md` or `SKILL.md` changes.
