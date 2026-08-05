# Deploy `.builder` skills to an Azure SRE Agent

`deploy_skills.py` recreates every skill under `.builder/<skill>/` in the target
agent's **Skill Builder**. Each skill folder's `SKILL.md` becomes the default
file and its YAML front-matter `description` becomes the skill description; every
other file in the folder is uploaded as a supporting (additional) file.

## Requirements
- Python 3.9+
- Azure CLI, logged in to the tenant that owns the target subscription: `az login --tenant <TENANT>`
- Role **SRE Agent Administrator** (or Author) on the target agent resource
- `PyYAML` is optional (improves front-matter parsing); a built-in fallback is used otherwise

## Target configuration
Provide the target four ways (CLI wins over env over config file):
- CLI flags: `--sub <SUB> --rg <RG> --agent <AGENT> --tenant <TENANT>`
- Env vars: `SRE_SUB`, `SRE_RG`, `SRE_AGENT`, `SRE_TENANT`
- File: copy `deploy.config.example.json` → `deploy.config.json` and fill it in

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
- **Auth**: `az account get-access-token --resource https://azuresre.dev` for the
  data-plane calls; `https://management.azure.com` for the endpoint lookup.
- **Idempotent**: `PUT` replaces the whole skill, so re-running keeps the agent in
  sync with the local folders (including added/removed supporting files).
- **List / delete**: `GET` / `DELETE {agentEndpoint}/api/v2/extendedAgent/skills[/<name>]`.

No third-party Python packages are needed — only the standard library plus the
Azure CLI for tokens.
