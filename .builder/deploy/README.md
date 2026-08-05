# Deploy `.builder` skills to an Azure SRE Agent

`deploy_skills.py` recreates every skill under `.builder/<skill>/` in the target
agent's **Skill Builder**. Each skill folder's `SKILL.md` becomes the default
file and its YAML front-matter `description` becomes the skill description; every
other file in the folder is uploaded as a supporting (additional) file.

## Requirements
- Python 3.9+
- Azure CLI, signed in with an account that can reach the target subscription:
  `az login` (or `az login --tenant <TENANT>` if that subscription lives in a
  different Entra tenant than your default one).
- Role **SRE Agent Administrator** (or Author) on the target agent resource.
- `PyYAML` is optional (improves front-matter parsing); a built-in fallback is used otherwise.

> The tool always requests its access tokens **for the target subscription**
> (`az account get-access-token --subscription <SUB> ...`), so it automatically
> uses that subscription's home tenant. You do **not** need to `az account set`
> first — you only need to be logged in to that tenant at least once.

## Target configuration
Provide the target (CLI flags win over env vars over the config file):
- CLI flags: `--sub <SUB> --rg <RG> --agent <AGENT>` (`--tenant <TENANT>` optional)
- Env vars: `SRE_SUB`, `SRE_RG`, `SRE_AGENT` (`SRE_TENANT` optional)
- File: copy `deploy.config.example.json` → `deploy.config.json` (gitignored) and fill it in

`subscription`, `resourceGroup` and `agent` are required. `tenant` is **optional**
and informational only — it reminds you which tenant to `az login` into; the tool
derives the correct tenant from the subscription itself.

## Commands
```bash
# 1. Preview what will be sent (no network)
python deploy_skills.py deploy --dry-run

# 2. List skills already on the agent
python deploy_skills.py list

# 3. Create/update all skills, including supporting files (idempotent)
python deploy_skills.py deploy

# ...or a subset
python deploy_skills.py deploy --skills identity-posture,incident-comment

# 4. Dump the current server-side skills (shape reference)
python deploy_skills.py discover --out discovered

# 5. Delete named skills
python deploy_skills.py delete --skills threat-pulse
```

## How it works
Skills are created/updated with a single `PUT` to the per-agent **data plane** —
the same call the portal's Skill Builder makes:

```
PUT {agentEndpoint}/api/v2/extendedAgent/skills/{name}
{
  "name": "<name>",
  "type": "Skill",
  "properties": {
    "description": "<from SKILL.md front matter>",
    "tools": [],
    "skillContent": "<full SKILL.md>",
    "additionalFiles": [ { "filePath": "<relative path>", "content": "<text>" } ],
    "sourcePluginInstallation": null
  }
}
```

- **Endpoint**: `agentEndpoint` is read from
  `GET .../Microsoft.App/agents/<agent>?api-version=2025-05-01-preview` on ARM.
- **Auth**: `az account get-access-token --subscription <SUB> --resource <res>`
  for both the ARM endpoint lookup (`res=https://management.azure.com`) and the
  data-plane calls (`res=https://azuresre.dev`). Scoping to `<SUB>` selects the
  right tenant automatically.
- **Idempotent**: `PUT` replaces the whole skill, so re-running keeps the agent in
  sync with the local folders (including added/removed supporting files).
- **List / delete**: `GET` / `DELETE {agentEndpoint}/api/v2/extendedAgent/skills[/<name>]`.

No third-party Python packages are needed — only the standard library plus the
Azure CLI for tokens.

## Deploy to a different tenant / agent
The skill folders under `.builder/` are environment-agnostic, so the same repo
deploys anywhere. To target another agent (in the same or a different tenant):

1. **Sign in** to the tenant that owns the target subscription (once):
   ```bash
   az login --tenant <TARGET_TENANT_ID>
   ```
   (Plain `az login` is enough if that subscription is already in your default
   tenant.)
2. **Point the tool at the new agent** — either edit `deploy.config.json`:
   ```json
   { "subscription": "<SUB>", "resourceGroup": "<RG>", "agent": "<AGENT>" }
   ```
   or pass it inline (no config file needed):
   ```bash
   python deploy_skills.py deploy --sub <SUB> --rg <RG> --agent <AGENT>
   ```
3. **Preview, then deploy**:
   ```bash
   python deploy_skills.py deploy --sub <SUB> --rg <RG> --agent <AGENT> --dry-run
   python deploy_skills.py deploy --sub <SUB> --rg <RG> --agent <AGENT>
   python deploy_skills.py list   --sub <SUB> --rg <RG> --agent <AGENT>
   ```

Requirements on the new tenant: the signed-in account needs **SRE Agent
Administrator/Author** on that agent, and the agent must be in the **Running**
state. `SKILL.md` files and their supporting files carry no tenant-specific
values, so nothing else needs changing.
