# Shared Guardrails — Token & Result Safety

> Include this reference in every SKILL.md that executes KQL queries.

## Universal Rules

1. **Every KQL query MUST include `| take N`** unless it is a single-entity lookup or an aggregation (`summarize` with no `mv-expand`). Default cap: `| take 100`.

2. **Time window defaults:**
   - If the user does not specify a time range, use the skill's documented default.
   - If the user requests a time range exceeding the skill's maximum (see per-skill table), warn and wait for confirmation.
   - NEVER execute an unbounded query (`| where TimeGenerated > ago(0d)` or no time filter).

3. **Aggregation-first for large result sets:**
   - If a query returns >50 rows, present a summary/aggregation first.
   - Offer the full table only on explicit user request.

4. **`make_set()` limits:**
   - User lists: `make_set(..., 5)` (max 5 per aggregation group)
   - Endpoint/resource lists: `make_set(..., 10)` (max 10)
   - Never use `make_set()` without a limit parameter.

5. **Schema validation caching:**
   - Call `get_table_schema()` once per table per session.
   - Skip if the same table was already validated in the current thread.

## Per-Skill Time Window Limits

| Skill | Default | Max (warn before exceeding) |
|-------|---------|----------------------------|
| incident-listing | 24h | 30d |
| incident-statistics | 90d | 180d |
| threat-pulse | 7d | 30d (drill-downs) |
| mcp-usage-monitoring | 30d | 90d |
| user-investigation | 7d (standard) | 30d (comprehensive) |
| computer-investigation | 7d (standard) | 30d (comprehensive) |
| incident-investigation | 7d (standard) | 30d (comprehensive) |
| identity-posture | 90d | 90d (fixed) |
