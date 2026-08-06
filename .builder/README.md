# ⚠️ Reference Copies — NOT Authoritative

The files in this directory are **backup copies** of the SKILL.md files and LLM
instruction documents defined in the agent Builder.

**The authoritative version is in Builder** (SRE Agent portal → Builder → Skills).

When modifying a skill:
1. Make the change in Builder FIRST
2. Then update the copy here to keep it synchronized
3. Do NOT do the reverse (editing here and expecting the agent to read it from codeRefs)

The agent always reads skill files from Builder through the `read_skill_file` API.
Files in `codeRefs/` are used by the agent only as code and knowledge context,
NEVER as the skill source.
