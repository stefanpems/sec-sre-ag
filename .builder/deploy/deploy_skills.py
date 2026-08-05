#!/usr/bin/env python3
"""
deploy_skills.py — Recreate the .builder/* skills in an Azure SRE Agent Skill Builder.

It reads every skill folder under `.builder/` (each contains a default `SKILL.md`
plus optional supporting files) and creates/updates the matching custom skill on a
target Azure SRE Agent resource via the ARM control-plane REST API
(Microsoft.App/agents/skills, api-version 2025-05-01-preview).

No third-party dependencies are required: authentication reuses the Azure CLI
(`az account get-access-token`) and HTTP calls use the standard library.

Typical workflow
----------------
1. Lock the exact skill JSON schema used by *your* tenant (recommended once):
       python deploy_skills.py discover --sub <SUB> --rg <RG> --agent <AGENT>

2. Preview the payloads that would be sent (no network):
       python deploy_skills.py build

3. Create/update all skills:
       python deploy_skills.py deploy --sub <SUB> --rg <RG> --agent <AGENT>

   or a subset:
       python deploy_skills.py deploy --sub <SUB> --rg <RG> --agent <AGENT> \
           --skills identity-posture,incident-comment

Configuration can also come from `.builder/deploy/deploy.config.json` (see
deploy.config.example.json) or environment variables SRE_SUB / SRE_RG / SRE_AGENT.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

API_VERSION = "2025-05-01-preview"
ARM_BASE = "https://management.azure.com"
ARM_RESOURCE = "https://management.azure.com"
DATAPLANE_RESOURCE = "https://azuresre.dev"

# Data-plane REST path used by the portal to read/write skills.
SKILLS_DATAPLANE_PATH = "/api/v2/extendedAgent/skills"

# Root that holds the skill folders (parent of this deploy/ dir).
BUILDER_ROOT = Path(__file__).resolve().parent.parent

# The default file that every skill must contain; it carries the YAML front matter.
DEFAULT_SKILL_FILE = "SKILL.md"

# Folders under BUILDER_ROOT that are NOT skills.
IGNORE_DIRS = {"deploy", ".git", "__pycache__"}


# --------------------------------------------------------------------------- #
# Skill discovery on the local file system
# --------------------------------------------------------------------------- #
@dataclass
class SkillFile:
    name: str          # path relative to the skill folder, forward slashes
    content: str


@dataclass
class Skill:
    folder: str
    name: str
    description: str
    files: list[SkillFile] = field(default_factory=list)

    @property
    def default_file(self) -> SkillFile | None:
        for f in self.files:
            if f.name == DEFAULT_SKILL_FILE:
                return f
        return None


def _parse_front_matter(text: str) -> dict[str, str]:
    """Extract `name` and `description` from the YAML front matter of a SKILL.md.

    Uses PyYAML when available, otherwise a minimal parser that understands plain
    scalars and folded/literal block scalars (`>` / `|`).
    """
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    # Find the closing '---' after the opening one.
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}
    fm = "\n".join(lines[1:end])

    try:
        import yaml  # type: ignore

        data = yaml.safe_load(fm) or {}
        return {str(k): _stringify(v) for k, v in data.items()}
    except Exception:
        pass

    # ---- Minimal fallback parser ---------------------------------------- #
    result: dict[str, str] = {}
    fm_lines = lines[1:end]
    idx = 0
    while idx < len(fm_lines):
        raw = fm_lines[idx]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or ":" not in raw or raw[0] in " \t":
            idx += 1
            continue
        key, _, val = raw.partition(":")
        key = key.strip()
        val = val.strip()
        if val in (">", "|", ">-", "|-", ">+", "|+"):
            # Block scalar: gather subsequent indented lines.
            block: list[str] = []
            idx += 1
            while idx < len(fm_lines) and (fm_lines[idx].startswith((" ", "\t")) or not fm_lines[idx].strip()):
                block.append(fm_lines[idx].strip())
                idx += 1
            result[key] = " ".join(b for b in block if b).strip()
            continue
        result[key] = val.strip().strip("'\"")
        idx += 1
    return result


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def load_local_skills(only: set[str] | None = None) -> list[Skill]:
    skills: list[Skill] = []
    for entry in sorted(BUILDER_ROOT.iterdir()):
        if not entry.is_dir() or entry.name in IGNORE_DIRS or entry.name.startswith("."):
            continue
        default_md = entry / DEFAULT_SKILL_FILE
        if not default_md.is_file():
            continue  # not a skill folder
        if only and entry.name not in only:
            continue

        files: list[SkillFile] = []
        for path in sorted(entry.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(entry).as_posix()
            try:
                content = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                print(f"  ! skipping binary/non-utf8 file: {rel}", file=sys.stderr)
                continue
            files.append(SkillFile(name=rel, content=content))

        fm = _parse_front_matter(default_md.read_text(encoding="utf-8"))
        name = fm.get("name") or entry.name
        description = fm.get("description") or ""
        skills.append(Skill(folder=entry.name, name=name, description=description, files=files))
    return skills


# --------------------------------------------------------------------------- #
# Auth + HTTP
# --------------------------------------------------------------------------- #
def get_token(resource: str) -> str:
    az = "az.cmd" if os.name == "nt" else "az"
    cmd = [az, "account", "get-access-token", "--resource", resource,
           "--query", "accessToken", "-o", "tsv"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        sys.exit("ERROR: Azure CLI (az) not found on PATH. Install it and run `az login`.")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"ERROR: failed to get token for {resource}.\n{exc.stderr.strip()}")
    token = out.stdout.strip()
    if not token:
        sys.exit(f"ERROR: empty token for {resource}. Run `az login` first.")
    return token


def http(method: str, url: str, token: str, body: dict | None = None) -> tuple[int, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw
        return exc.code, parsed
    except urllib.error.URLError as exc:
        return 0, str(exc)


# --------------------------------------------------------------------------- #
# ARM endpoint helpers
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    sub: str
    rg: str
    agent: str
    tenant: str | None = None

    def agent_url(self) -> str:
        return (f"{ARM_BASE}/subscriptions/{self.sub}/resourceGroups/{self.rg}"
                f"/providers/Microsoft.App/agents/{self.agent}")

    def agent_arm_url(self) -> str:
        return f"{self.agent_url()}?api-version={API_VERSION}"

    def skills_url(self) -> str:
        return f"{self.agent_url()}/skills?api-version={API_VERSION}"

    def skill_url(self, name: str) -> str:
        return f"{self.agent_url()}/skills/{name}?api-version={API_VERSION}"


def resolve_agent_endpoint(target: "Target") -> str:
    """Return the per-agent data-plane endpoint (properties.agentEndpoint)."""
    token = get_token(ARM_RESOURCE)
    status, body = http("GET", target.agent_arm_url(), token)
    if status != 200 or not isinstance(body, dict):
        sys.exit(f"ERROR: could not read agent (HTTP {status}): {json.dumps(body)[:300]}")
    endpoint = (body.get("properties") or {}).get("agentEndpoint")
    if not endpoint:
        sys.exit("ERROR: agent has no agentEndpoint property.")
    return endpoint.rstrip("/")


# --------------------------------------------------------------------------- #
# Data-plane skill write
# --------------------------------------------------------------------------- #
# Skills are created/updated with a single PUT to the per-agent data plane, using
# the exact body shape the portal sends:
#   PUT {agentEndpoint}/api/v2/extendedAgent/skills/{name}
#   {
#     "name": "<name>", "type": "Skill",
#     "properties": {
#       "description": "<desc>", "tools": [],
#       "skillContent": "<SKILL.md content>",
#       "additionalFiles": [ {"filePath": "<rel path>", "content": "<text>"} ],
#       "sourcePluginInstallation": null
#     }
#   }
# Auth: az CLI token for resource https://azuresre.dev.
SKILL_TYPE = "Skill"


def build_dataplane_body(skill: Skill) -> dict[str, Any]:
    default = skill.default_file
    skill_content = default.content if default else ""
    additional = [
        {"filePath": f.name, "content": f.content}
        for f in skill.files
        if f.name != DEFAULT_SKILL_FILE
    ]
    return {
        "name": skill.name,
        "type": SKILL_TYPE,
        "properties": {
            "description": skill.description,
            "tools": [],
            "skillContent": skill_content,
            "additionalFiles": additional,
            "sourcePluginInstallation": None,
        },
    }


def skill_dataplane_url(endpoint: str, name: str) -> str:
    return f"{endpoint}{SKILLS_DATAPLANE_PATH}/{name}"


def dataplane_list_skills(endpoint: str) -> list[dict]:
    token = get_token(DATAPLANE_RESOURCE)
    status, body = http("GET", endpoint + SKILLS_DATAPLANE_PATH, token)
    if status != 200 or not isinstance(body, dict):
        sys.exit(f"ERROR: list skills failed (HTTP {status}): {json.dumps(body)[:300]}")
    return body.get("value") or []


def dataplane_delete_skill(endpoint: str, name: str) -> tuple[int, Any]:
    token = get_token(DATAPLANE_RESOURCE)
    return http("DELETE", f"{endpoint}{SKILLS_DATAPLANE_PATH}/{name}", token)


def resolve_target(args) -> Target:
    cfg: dict[str, str] = {}
    cfg_path = Path(__file__).resolve().parent / "deploy.config.json"
    if cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  ! could not parse {cfg_path}: {exc}", file=sys.stderr)

    sub = args.sub or os.environ.get("SRE_SUB") or cfg.get("subscription")
    rg = args.rg or os.environ.get("SRE_RG") or cfg.get("resourceGroup")
    agent = args.agent or os.environ.get("SRE_AGENT") or cfg.get("agent")
    tenant = getattr(args, "tenant", None) or os.environ.get("SRE_TENANT") or cfg.get("tenant")

    missing = [n for n, v in (("--sub", sub), ("--rg", rg), ("--agent", agent)) if not v]
    if missing:
        sys.exit(f"ERROR: missing required target: {', '.join(missing)} "
                 f"(pass on CLI, set SRE_SUB/SRE_RG/SRE_AGENT, or fill deploy.config.json)")
    return Target(sub=sub, rg=rg, agent=agent, tenant=tenant)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_build(args) -> int:
    skills = load_local_skills(_only_set(args))
    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    for s in skills:
        body = build_dataplane_body(s)
        size = len(json.dumps(body, ensure_ascii=False).encode("utf-8"))
        extra = body["properties"]["additionalFiles"]
        files = ", ".join(f["filePath"] for f in extra) or "(none)"
        print(f"• {s.name:28s} SKILL.md + {len(extra)} file(s) ({size:,} B): {files}")
        if out_dir:
            (out_dir / f"{s.name}.body.json").write_text(
                json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    if out_dir:
        print(f"\nWrote request body JSON for {len(skills)} skills to {out_dir}")
    print(f"\n{len(skills)} skill(s) discovered locally.")
    return 0


def cmd_list(args) -> int:
    target = resolve_target(args)
    endpoint = resolve_agent_endpoint(target)
    items = dataplane_list_skills(endpoint)
    print(f"{len(items)} skill(s) on agent '{target.agent}':")
    for it in items:
        name = it.get("name", "?")
        props = it.get("properties", {}) if isinstance(it, dict) else {}
        desc = props.get("description", "") if isinstance(props, dict) else ""
        extra = props.get("additionalFiles") or []
        print(f"  - {name}: {str(desc)[:70]}  [+{len(extra)} file(s)]")
    return 0


def cmd_discover(args) -> int:
    target = resolve_target(args)
    endpoint = resolve_agent_endpoint(target)
    items = dataplane_list_skills(endpoint)
    if not items:
        print("No existing skills on this agent.")
        return 0
    out_dir = Path(args.out) if args.out else Path(__file__).resolve().parent / "discovered"
    out_dir.mkdir(parents=True, exist_ok=True)
    for it in items:
        name = it.get("name", "unknown")
        (out_dir / f"{name}.json").write_text(
            json.dumps(it, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Discovered {len(items)} skill(s). JSON written to {out_dir}\n")
    print("=== First skill (shape reference) ===")
    print(json.dumps(items[0], indent=2, ensure_ascii=False)[:4000])
    return 0


def cmd_deploy(args) -> int:
    target = resolve_target(args)
    skills = load_local_skills(_only_set(args))
    if not skills:
        print("No local skills matched.", file=sys.stderr)
        return 1

    if args.dry_run:
        for s in skills:
            body = build_dataplane_body(s)
            extra = len(body["properties"]["additionalFiles"])
            size = len(body["properties"]["skillContent"])
            print(f"[dry-run] PUT {s.name}: {size:,} B SKILL.md + {extra} file(s)")
        return 0

    endpoint = resolve_agent_endpoint(target)
    token = get_token(DATAPLANE_RESOURCE)
    ok, fail = 0, 0
    for s in skills:
        body = build_dataplane_body(s)
        extra = len(body["properties"]["additionalFiles"])
        status, resp = http("PUT", skill_dataplane_url(endpoint, s.name), token, body)
        if status in (200, 201, 202):
            print(f"  OK   {s.name} (+{extra} file(s))")
            ok += 1
        else:
            print(f"  FAIL {s.name} (HTTP {status}) {json.dumps(resp)[:300]}", file=sys.stderr)
            fail += 1
    print(f"\nDeployed: {ok} succeeded, {fail} failed.")
    return 1 if fail else 0


def cmd_delete(args) -> int:
    target = resolve_target(args)
    names = _only_set(args)
    if not names:
        sys.exit("ERROR: delete requires --skills <name[,name...]>")
    endpoint = resolve_agent_endpoint(target)
    for name in sorted(names):
        status, body = dataplane_delete_skill(endpoint, name)
        if status in (200, 202, 204):
            print(f"  DELETED {name} (HTTP {status})")
        else:
            print(f"  FAIL {name} (HTTP {status}) {json.dumps(body)[:300]}", file=sys.stderr)
    return 0


def _only_set(args) -> set[str] | None:
    raw = getattr(args, "skills", None)
    if not raw:
        return None
    return {x.strip() for x in raw.split(",") if x.strip()}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_target(p):
        p.add_argument("--sub", help="Azure subscription ID")
        p.add_argument("--rg", help="Resource group of the SRE Agent")
        p.add_argument("--agent", help="SRE Agent resource name")
        p.add_argument("--tenant", help="Entra tenant ID (GUID) of the subscription")
        p.add_argument("--skills", help="Comma-separated skill folder names to limit to")

    p_build = sub.add_parser("build", help="Build payloads locally (no network)")
    p_build.add_argument("--skills", help="Comma-separated skill folder names to limit to")
    p_build.add_argument("--out", help="Directory to write spec/envelope JSON into")
    p_build.set_defaults(func=cmd_build)

    p_list = sub.add_parser("list", help="List skills currently on the agent")
    add_target(p_list)
    p_list.set_defaults(func=cmd_list)

    p_disc = sub.add_parser("discover", help="Dump existing skills to confirm the JSON schema")
    add_target(p_disc)
    p_disc.add_argument("--out", help="Directory to write discovered specs into")
    p_disc.set_defaults(func=cmd_discover)

    p_dep = sub.add_parser("deploy", help="Create/update skills on the agent")
    add_target(p_dep)
    p_dep.add_argument("--dry-run", action="store_true", help="Show what would be sent")
    p_dep.set_defaults(func=cmd_deploy)

    p_del = sub.add_parser("delete", help="Delete named skills from the agent")
    add_target(p_del)
    p_del.set_defaults(func=cmd_delete)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
