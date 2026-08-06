#!/usr/bin/env python3
"""
MITRE ATT&CK Coverage Report — YAML-driven data gathering.

Reads query definitions from queries.yaml (multi-document),
executes them via 'az rest' (Sentinel API), 'az monitor' (KQL),
and optionally Microsoft Graph API (Custom Detections),
then writes a scratchpad file for report rendering by the LLM.

Architecture: queries.yaml → Python execution
→ scratchpad.md → LLM reads scratchpad and renders report.

Usage:
    python3 invoke_mitre_scan.py \\
        --workspace-id <GUID> \\
        --subscription-id <SUB_ID> \\
        --resource-group <RG> \\
        --workspace-name <WS_NAME> \\
        [--days 30] [--phase 0] [--config-path config.json] [--output-dir temp/]
"""

import argparse
import io
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# YAML PARSER (simple key:value + multiline pipe support)
# ═══════════════════════════════════════════════════════════════════

def _parse_yaml_text(text: str) -> dict:
    """Parse a single YAML document from text (simple key:value + multiline pipe)."""
    result = {}
    current_key = None
    multiline = io.StringIO()
    for line in text.splitlines(keepends=True):
        line_r = line.rstrip('\n\r')
        if current_key is None:
            if not line_r.strip() or line_r.strip().startswith('#'):
                continue
        if current_key is not None:
            if re.match(r'^\s{2,}', line_r):
                multiline.write(re.sub(r'^\s{2,}', '', line_r, count=1) + '\n')
                continue
            if not line_r.strip():
                multiline.write('\n')
                continue
            result[current_key] = multiline.getvalue().rstrip()
            current_key = None
            multiline = io.StringIO()
        m = re.match(r'^([a-zA-Z_]\w*):\s*\|\s*$', line_r)
        if m:
            current_key = m.group(1)
            multiline = io.StringIO()
            continue
        m = re.match(r'^([a-zA-Z_]\w*):\s*(.+)$', line_r)
        if m:
            result[m.group(1)] = m.group(2).strip()
    if current_key is not None:
        result[current_key] = multiline.getvalue().rstrip()
    return result


def import_all_queries(path: str) -> list[dict]:
    """Load multi-document YAML (--- separated) and return list of parsed dicts."""
    with open(path, encoding='utf-8') as f:
        content = f.read()
    docs = re.split(r'^---\s*$', content, flags=re.MULTILINE)
    results = []
    for doc in docs:
        doc = doc.strip()
        if not doc:
            continue
        parsed = _parse_yaml_text(doc)
        if parsed and parsed.get('id'):
            results.append(parsed)
    return results


# ═══════════════════════════════════════════════════════════════════
# SUBPROCESS HELPERS
# ═══════════════════════════════════════════════════════════════════

def run_az(args: list[str], timeout: int = 120) -> tuple[bool, str]:
    """Run an az CLI command and return (success, stdout_or_stderr)."""
    try:
        r = subprocess.run(
            ['az'] + args,
            capture_output=True, text=True, timeout=timeout, encoding='utf-8'
        )
        if r.returncode == 0:
            return True, r.stdout
        return False, r.stderr or r.stdout
    except subprocess.TimeoutExpired:
        return False, 'Command timed out'
    except FileNotFoundError:
        return False, 'Azure CLI (az) not found'


def az_json(args: list[str], timeout: int = 120):
    """Run az command and parse JSON output. Returns (data, error_str)."""
    ok, output = run_az(args + ['-o', 'json'], timeout=timeout)
    if not ok:
        return None, output
    try:
        return json.loads(output), None
    except json.JSONDecodeError as e:
        return None, f'JSON parse error: {e}'


# ═══════════════════════════════════════════════════════════════════
# KQL TABLE NAME EXTRACTION (from rule query text)
# ═══════════════════════════════════════════════════════════════════

_KQL_EXCLUDE = {
    'let','where','extend','project','summarize','join','union','on','by','and','or','not','in',
    'distinct','evaluate','lookup','find','search','invoke','getschema','consume','serialize',
    'fork','facet','as','set','alias','declare','pattern','restrict','render','print','datatable',
    'take','limit','top','sort','order','asc','desc','with','kind','isfuzzy','table','typeof',
    'mvexpand','mvapply','externaldata',
    'inner','outer','leftouter','rightouter','fullouter','anti','leftanti','rightanti','leftsemi','rightsemi',
    'contains','has','has_any','has_all','startswith','endswith','matches','between','like','notlike',
    'tostring','toint','tolong','todecimal','todouble','tobool','todynamic','toscalar','parse_json',
    'count','dcount','sum','avg','min','max','countif','dcountif','sumif','make_set','make_list',
    'make_bag','make_set_if','make_list_if','make_series','arg_max','arg_min','percentile','percentiles',
    'iff','case','coalesce','isnull','isnotnull','isempty','isnotempty','strlen','tolower','toupper',
    'trim','replace','split','strcat','strcat_delim','format_datetime','format_timespan','bin',
    'round','ceiling','floor','abs','log','exp','pow','sqrt','ago','now','datetime','timespan',
    'pack','bag_pack','array_length','array_index_of','set_difference','set_union','set_has_element',
    'set_intersect','materialize','range','gettype','column_ifexists','columnifexists','ingestion_time',
    'pack_array','bag_keys','bag_has_key','bag_merge','ipv4_is_private','ipv4_is_match',
    'hash_sha256','base64_decode_tostring','url_decode','parse','extract','extract_all',
    'row_number','prev','next','series_stats','series_decompose','geo_point_to_geohash','format_ipv4',
    'extractjson','parse_csv','parse_path','parse_url','parse_urlquery','parse_user_agent',
    'timegenerated','timestamp',
    'true','false','dynamic','external_table',
}


def get_kql_table_names(query: str) -> list[str]:
    if not query or not query.strip():
        return []
    tables: set[str] = set()
    # Normalize
    cleaned = re.sub(r'//[^\r\n]*', '', query)
    cleaned = re.sub(r'\r?\n', ' ', cleaned)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    # Collect let-variable names
    let_vars = {m.group(1).lower() for m in re.finditer(r'\blet\s+(\w+)\s*=', cleaned, re.I)}

    def valid(c: str) -> bool:
        return (len(c) >= 3 and c[0].isupper()
                and c.lower() not in _KQL_EXCLUDE
                and c.lower() not in let_vars)

    # 1. Function calls: table("SigninLogs")
    for m in re.finditer(r"""\w+\s*\(\s*['"]((?:[A-Z]\w{2,}(?:_CL)?))['"]\)""", cleaned):
        c = m.group(1)
        if valid(c):
            tables.add(c)
    # 2. First token of pipe segments
    for seg in cleaned.split('|'):
        seg = seg.strip()
        if not seg:
            continue
        m = re.match(r'^([A-Z]\w{2,}(?:_CL)?)\b', seg)
        if m and valid(m.group(1)):
            tables.add(m.group(1))
    # 3. Union operands
    for m in re.finditer(r'(?i:union)\s+(?:(?i:isfuzzy)\s*=\s*\w+\s+)?(.+?)(?:\||$)', cleaned):
        for tm in re.finditer(r'\b([A-Z]\w{2,}(?:_CL)?)\b', m.group(1)):
            if valid(tm.group(1)):
                tables.add(tm.group(1))
    # 4. Join operands
    for m in re.finditer(r'(?i:join)\b[^(]*\(\s*([A-Z]\w{2,}(?:_CL)?)\b', cleaned):
        if valid(m.group(1)):
            tables.add(m.group(1))
    # 5. Let assignments
    for m in re.finditer(r'(?i:let)\s+\w+\s*=\s*\(?\s*([A-Z]\w{2,}(?:_CL)?)\b', cleaned):
        if valid(m.group(1)):
            tables.add(m.group(1))
    return sorted(tables)


def _narrative(section_id: str, instructions: str, data_sources: str) -> str:
    return (f'<!-- LLM_NARRATIVE: {section_id} -->\n'
            f'<!-- Instructions: {instructions} -->\n'
            f'<!-- Data sources: {data_sources} -->\n'
            '<!-- /LLM_NARRATIVE -->')


def _prerendered_section(block: str, name: str) -> str:
    match = re.search(rf'^### {re.escape(name)}\s*$\n(.*?)(?=^### |\Z)', block,
                      flags=re.MULTILINE | re.DOTALL)
    return match.group(1).strip() if match else '<!-- NO_DATA -->'


def _score_assessment(score: float) -> str:
    if score >= 80:
        return '🟢 Strong'
    if score >= 60:
        return '🔵 Good'
    if score >= 40:
        return '🟡 Moderate'
    if score >= 20:
        return '🟠 Developing'
    return '🔴 Critical'


def build_report(context: dict) -> str:
    """Build a deterministic report skeleton from computed scan data."""
    meta = context['meta']
    score = context['score']
    inventory = context['inventory']
    attack_ref = context['attack_ref']
    tactic_order = context['tactic_order']
    tactic_display = context['tactic_display']
    tactic_rule_count = context['tactic_rule_count']
    technique_rule_count = context['technique_rule_count']
    tier1 = context['tier1_techniques']
    tier2 = context['tier2_techniques']
    untagged_rules = context['untagged_rules']
    ics_techs = context['ics_techs']
    technique_rule_names = context['technique_rule_names']
    parsed_scenarios = context['parsed_scenarios']
    prerendered = context['prerendered_block']

    top_recommendations = []
    scenario_candidates = [
        scenario for scenario in parsed_scenarios
        if scenario['Recommended'] > 0
        and not (scenario['State'] == 'CompletedByUser' and scenario['CompletionRate'] >= 50)
    ]
    scenario_candidates.sort(key=lambda scenario: scenario['CompletionRate'])
    if scenario_candidates:
        scenario = scenario_candidates[0]
        top_recommendations.append((
            '🔴' if scenario['CompletionRate'] < 15 else '🟠',
            f'Address {scenario["Scenario"]} coverage',
            f'{scenario["Active"]}/{scenario["Recommended"]} active detections ({scenario["CompletionRate"]}%)',
        ))
    actionable_zero = [
        tactic for tactic in tactic_order
        if tactic not in ('Reconnaissance', 'ResourceDevelopment')
        and tactic_rule_count.get(tactic, 0) == 0
    ]
    if actionable_zero:
        names = ', '.join(tactic_display[tactic] for tactic in actionable_zero[:3])
        top_recommendations.append(('🔴', f'Add detection coverage for {names}',
                                    f'{len(actionable_zero)} detectable tactic(s) have no enabled rules'))
    if untagged_rules:
        top_recommendations.append(('🟠', 'Apply MITRE tags to untagged rules',
                                    f'{len(untagged_rules)} rule(s) are excluded from coverage analysis'))
    low_coverage = []
    for tactic in tactic_order:
        tactic_data = attack_ref['tactics'].get(tactic, {})
        total = tactic_data.get('techniqueCount', 0)
        covered = sum(1 for tech in tactic_data.get('techniques', [])
                      if technique_rule_count.get(tech['id'], 0) > 0)
        percentage = 100.0 * covered / total if total else 0
        if 0 < percentage <= 15:
            low_coverage.append((percentage, tactic, covered, total))
    for percentage, tactic, covered, total in sorted(low_coverage):
        top_recommendations.append(('🟡', f'Deepen {tactic_display[tactic]} coverage',
                                    f'{covered}/{total} techniques covered ({percentage:.1f}%)'))
    if not top_recommendations:
        top_recommendations.append(('🟡', 'Validate detection efficacy with purple-team tests',
                                    'Confirm deployed detections fire against representative ATT&CK techniques'))
    fallback_recommendations = [
        ('🟡', 'Review data readiness and connector health',
         'Confirm every enabled rule has healthy, queryable source data'),
        ('🟡', 'Review SOC Optimization monthly',
         'Track new environment-relevant Content Hub recommendations'),
        ('🟡', 'Refresh ATT&CK mappings quarterly',
         'Keep rule tags and framework references current'),
    ]
    for fallback in fallback_recommendations:
        if len(top_recommendations) >= 3:
            break
        top_recommendations.append(fallback)
    top_recommendation_lines = [
        '| # | Priority | Recommendation | Impact |',
        '|---|----------|----------------|--------|',
    ]
    for index, (priority, recommendation, impact) in enumerate(top_recommendations[:3], 1):
        top_recommendation_lines.append(f'| {index} | {priority} | **{recommendation}** | {impact} |')

    lines = [
        '# MITRE ATT&CK Coverage Report', '',
        f'**Generated:** {meta["generated"]}',
        f'**Workspace:** {meta["workspace_name"]}',
        f'**Workspace ID:** {meta["workspace_id"]}',
        f'**ATT&CK Version:** Enterprise v{attack_ref["version"]} '
        f'({attack_ref["totalTechniques"]} techniques, {attack_ref["totalSubTechniques"]} sub-techniques)',
        f'**Alert/Incident Lookback:** {meta["days"]} days', '',
        '> This report analyzes detection coverage against the MITRE ATT&CK Enterprise framework based on rule MITRE tagging and operational alert data. Coverage percentages reflect enabled rules with MITRE tags — actual detection efficacy depends on data source availability, rule quality, and adversary behavior. All recommendations require human review and validation against organizational threat priorities before implementation.', '',
        '> *Why this report?* The built-in [Sentinel MITRE ATT&CK dashboard](https://security.microsoft.com/sentinel/mitre) ([docs](https://learn.microsoft.com/en-us/azure/sentinel/mitre-coverage?tabs=defender-portal)) only shows coverage for active Analytic Rules and Hunting Queries — it does **not** account for product-native platform alerts (MDE, MDI, MDCA, etc.), Custom Detection rules, or inherent Defender XDR coverage capabilities. This report fills that gap by combining rule-based coverage with platform alert evidence (Tier 1/2/3) and [SOC Optimization](https://security.microsoft.com/sentinel/precision) threat scenario alignment to provide a comprehensive view of actual detection posture.', '',
        '> *Custom Detections migration:* Microsoft is [unifying detection authoring](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/custom-detections-are-now-the-unified-experience-for-creating-detections-in-micr/4463875) around Custom Detections as the preferred rule type — offering unlimited real-time detections, lower ingestion costs, and seamless Defender XDR integration. This report already inventories Custom Detections alongside Analytic Rules to ensure coverage tracking remains accurate as the migration progresses.', '',
        '## 1. Executive Summary', '',
        f'### 🎯 MITRE Coverage Score: **{score["final"]}/100** — {_score_assessment(score["final"])}', '',
        '| Dimension | Score | Weight | Interpretation |',
        '|-----------|-------|--------|----------------|',
        f'| **Breadth** | {score["breadth"]}/100 | 25% | {score["weighted_credit"]}/{score["framework_total"]} readiness-weighted rule credit; {score["combined_total"]}/{score["framework_total"]} combined ({score["combined_pct"]}%) — blended 60/40 |',
        f'| **Balance** | {score["balance"]}/100 | 10% | {score["tactics_with_rules"]}/14 tactics have ≥1 enabled rule |',
        f'| **Operational** | {score["operational"]}/100 | 30% | {score["firing_mitre_rules"]}/{score["mitre_tagged_enabled"]} MITRE-tagged enabled rules produced alerts in {meta["days"]}d |',
        f'| **Tagging** | {score["tagging"]}/100 | 15% | {score["tagged_rules"]}/{score["total_rules"]} total rules have MITRE ATT&CK tags |',
        f'| **SOC Alignment** | {score["soc_alignment"]}/100 | 20% | {score["completed_soc"]}/{score["total_soc"]} SOC coverage scenarios met |', '',
        _narrative('exec_summary_context',
                   'Write 2-3 sentences interpreting score dimensions, Custom Detection skip status, breadth context, and phantom techniques.',
                   'SCORE.*, PHASE_1.AR_Summary, PHASE_1.CD_Summary, META.Days'), '',
        '### 📊 Detection Inventory', '',
        '| Metric | Count |', '|--------|-------|',
        f'| Total Analytic Rules | {inventory["ar_total"]} |',
        f'| Enabled AR (tagged / untagged) | {inventory["ar_enabled"]} ({inventory["ar_enabled"] - inventory["ar_no_mitre_enabled"]} / {inventory["ar_no_mitre_enabled"]}) |',
        f'| Disabled AR | {inventory["ar_disabled"]} |',
        f'| Custom Detections (total) | {inventory["cd_total"] if inventory["cd_status"] == "OK" else inventory["cd_status"]} |',
        f'| Enabled CD (tagged / untagged) | {inventory["cd_enabled"]} ({inventory["cd_enabled"] - inventory["cd_no_mitre_enabled"]} / {inventory["cd_no_mitre_enabled"]}) |',
        f'| Disabled CD | {inventory["cd_disabled"]} |',
        f'| **Combined Enabled Rules** | **{inventory["ar_enabled"] + inventory["cd_enabled"]}** |',
        f'| Rules with MITRE tags | {score["tagged_rules"]}/{score["total_rules"]} |',
        f'| Untagged rules | {len(untagged_rules)} |',
        f'| Techniques covered | {score["rule_covered"]}/{score["framework_total"]} |',
        f'| Tactics with ≥1 rule | {score["tactics_with_rules"]}/14 |',
        f'| Data readiness | {score["readiness_ready"]}/{score["readiness_total"]} ready ({score["readiness_pct"]}%) |', '',
        '### 🛡️ Platform Coverage', '',
        '| Layer | Techniques | Description |', '|-------|-----------|-------------|',
        f'| 🟢 **Tier 1: Alert-Proven** | {score["tier1"]} | Platform products triggered MITRE-attributed alerts in the last {meta["days"]}d |',
        f'| 🔵 **Tier 2: Deployed Capability** | {score["tier2"]} | Active products have CTID detect coverage but no alerts in the window |',
        f'| ⬜ **Tier 3: Catalog Capability** | {score["tier3"]} | CTID coverage with no active-product evidence |',
        f'| **Rule-Based** | {score["rule_covered"]} | Enabled analytic rules and Custom Detections |',
        f'| **Combined (Rule-Based + T1 + T2)** | **{score["combined_total"]}/{score["framework_total"]} ({score["combined_pct"]}%)** | Unique techniques covered by an active detection source |', '',
        f'> CTID Mapping v{score["ctid_version"]}. Platform coverage is supplementary; custom rules provide environment-specific detections.', '',
        '### 🎯 Top 3 Recommendations', '',
        *top_recommendation_lines, '',
        '## 2. Tactic Coverage Matrix', '',
        '> Compare with the built-in Sentinel MITRE ATT&CK dashboard, which shows Analytic Rule and Hunting Query coverage only. This matrix also includes Custom Detections; §5.1 adds platform coverage.', '',
        _prerendered_section(prerendered, 'TacticCoverageMatrix'), '',
        _narrative('tactic_matrix_analysis',
                   'Write 2-3 sentences on zero-coverage tactics, rule concentration, and combined platform uplift.',
                   'PRERENDERED.TacticCoverageMatrix, PRERENDERED.CombinedTacticCoverage, SCORE.RuleBasedPlusPlatform_Coverage'), '',
        '## 3. Technique Deep Dive', '',
    ]

    technique_block = _prerendered_section(prerendered, 'TechniqueTables')
    tactic_chunks = re.split(r'(?=^#### )', technique_block, flags=re.MULTILINE)
    tactic_ids = ['recon', 'resource_development', 'initial_access', 'execution', 'persistence',
                  'privilege_escalation', 'defense_evasion', 'credential_access', 'discovery',
                  'lateral_movement', 'collection', 'command_and_control', 'exfiltration', 'impact']
    chunks = [chunk.strip() for chunk in tactic_chunks if chunk.strip() and chunk.lstrip().startswith('#### ')]
    for index, chunk in enumerate(chunks):
        lines.extend([chunk, '', _narrative(
            f'technique_{tactic_ids[index]}',
            'Write 1-2 sentences about concentration, true gaps, and relevant operational or scenario cross-references.',
            f'PRERENDERED.TechniqueTables tactic {index + 1}, ThreatScenarios, DataReadiness'), ''])

    lines.extend([f'### Untagged Rules ({len(untagged_rules)} rules without MITRE tags)', '',
                  '| Rule Name | Rule ID | Enabled | Kind | Severity | Source |',
                  '|-----------|---------|---------|------|----------|--------|'])
    for rule in untagged_rules:
        lines.append(f'| {rule["Name"]} | {rule["RuleId"]} | {rule["Enabled"]} | {rule["Kind"]} | {rule["Severity"]} | {rule["Source"]} |')
    lines.extend(['', '> ⚠️ These rules have no MITRE ATT&CK tactics or techniques assigned and cannot contribute to coverage analysis.', ''])
    if ics_techs:
        lines.extend(['### ICS/OT Technique Coverage', '', '| Technique | Rules | Detections |', '|-----------|-------|------------|'])
        for tech_id in ics_techs:
            names = '; '.join(technique_rule_names.get(tech_id, [])[:3])
            lines.append(f'| {tech_id} | {technique_rule_count.get(tech_id, 0)} | {names} |')
        lines.extend(['', '> ICS/OT techniques use ATT&CK for ICS and are excluded from the Enterprise coverage score.', ''])

    detectable = set(tactic_order) - {'Reconnaissance', 'ResourceDevelopment'}
    zero_tactics = [t for t in tactic_order if tactic_rule_count.get(t, 0) == 0]
    lines.extend(['## 4. Coverage Gap Analysis', '',
                  '### Actionable Gaps (0% Coverage — Detectable Tactics)', '',
                  '| Tactic | Framework Techniques | True Gaps | Platform-Covered (T1+T2) |',
                  '|--------|----------------------|-----------|--------------------------|'])
    for tactic in zero_tactics:
        if tactic not in detectable:
            continue
        techniques = attack_ref['tactics'][tactic].get('techniques', [])
        platform_count = sum(1 for tech in techniques if tech['id'] in tier1 or tech['id'] in tier2)
        lines.append(f'| {tactic_display[tactic]} | {len(techniques)} | {len(techniques) - platform_count} | {platform_count} |')
    lines.extend(['', '### Inherent Blind Spots (0% Coverage — Pre-Compromise Tactics)', '',
                  '| Tactic | Framework Techniques | Note |', '|--------|----------------------|------|'])
    for tactic in zero_tactics:
        if tactic in detectable:
            continue
        count = attack_ref['tactics'][tactic].get('techniqueCount', 0)
        lines.append(f'| {tactic_display[tactic]} | {count} | Attacker activity occurs primarily outside the monitored environment; use compensating protect/respond controls. |')
    lines.extend(['', _narrative('gap_analysis_narrative',
                                 'Write 2-3 sentences on the highest-value true gaps and cross-reference the tactic matrix.',
                                 'TacticCoverage, PlatformTechniquesByTier, TechniqueTables'), '',
                  '### Threat Scenario Alignment', '',
                  '> SOC Optimization compares active analytics with scenario-specific recommended detections. Recommendation totals include templates for products that may not be deployed; prioritize the environment-relevant subset and use completion rate as the progress measure.', '',
                  _prerendered_section(prerendered, 'ThreatScenarios'), '',
                  _narrative('threat_scenario_narrative',
                             'Write 2-3 sentences on the top scenarios and identify compound gaps shared with the tactic matrix.',
                             'PRERENDERED.ThreatScenarios, PRERENDERED.TacticCoverageMatrix'), '',
                  '### AI-Suggested MITRE Tags', '',
                  context['tagging_block'], '',
                  '## 5. Operational MITRE Correlation', '',
                  '### 5.1 Platform-Native Detection Coverage', '',
                  _prerendered_section(prerendered, 'CombinedTacticCoverage'), '',
                  '### 5.2 Alert-Producing Rules by MITRE Tactic', '',
                  _prerendered_section(prerendered, 'AlertFiring'), '',
                  '### 5.3 Active vs Tagged Tactic Coverage', '',
                  _prerendered_section(prerendered, 'ActiveVsTagged'), '',
                  '### 5.4 Incidents by Tactic', '',
                  _prerendered_section(prerendered, 'IncidentsByTactic'), '',
                  '### 5.5 Data Readiness', '',
                  _prerendered_section(prerendered, 'DataReadiness'), '',
                  '> Data readiness validates table-level ingestion presence, not event-level completeness. Complete detection validation requires purple-team exercises mapped to ATT&CK techniques.', '',
                  '### 5.6 Connector Health', '',
                  _prerendered_section(prerendered, 'ConnectorHealth'), '',
                  _narrative('operational_correlation',
                             'Write 3-5 sentences correlating platform uplift, firing rules, silent rules, readiness, and connector health.',
                             'All PRERENDERED §5 blocks, SCORE.DataReadiness_*, PHASE_3'), '',
                  '## 6. Recommendations', '',
                  _narrative('recommendations',
                             'Write complete §6 with Quick Wins, Medium-Term Improvements, Ongoing Maintenance, and a Coverage Priority Matrix. Exclude inherent blind spots and reviewed scenarios.',
                             'All scratchpad sections, especially gaps, scenarios, tagging, silent rules, readiness, and connector health'), '',
                  '## Appendix', '', '### A. Query Reference', '',
                  '| Phase | Query | Type | Description | Status |',
                  '|-------|-------|------|-------------|--------|'])
    for query in context['query_reference']:
        lines.append(f'| {query["phase"]} | {query["id"]} | {query["type"]} | {query["description"]} | {query["status"]} |')
    lines.extend(['', f'**Generated:** {meta["generated"]} | **Execution Time:** {meta["execution_time"]}s | **Phases:** {meta["phases"]}', '',
                  '### B. MITRE Coverage Score Methodology', '',
                  'The MITRE Coverage Score is a composite metric (0–100) computed from 5 weighted dimensions. It is designed to reward **operationally validated** detection coverage — teams that purple-team their rules and confirm they fire score higher than teams that deploy rules without validating them.', '',
                  '#### Dimensions & Weights', '',
                  '| # | Dimension | Weight | What It Measures |', '|---|-----------|--------|------------------|',
                  '| 1 | **Breadth** | 25% | Readiness-weighted technique coverage across the ATT&CK framework |',
                  '| 2 | **Balance** | 10% | Kill chain phase distribution — are all 14 tactics represented? |',
                  '| 3 | **Operational** | 30% | % of MITRE-tagged rules that actually produced alerts in the lookback period |',
                  '| 4 | **Tagging** | 15% | % of all rules (enabled + disabled) with at least 1 MITRE tag |',
                  '| 5 | **SOC Alignment** | 20% | Completion rate of Microsoft SOC Optimization coverage recommendations |', '',
                  '**Why Operational is the heaviest weight (30%):** A rule that has never fired is unvalidated — it *might* detect an attack, or it might have a broken query, wrong data source, or logic error. Teams that run purple team exercises, atomic tests, or otherwise trigger their detections prove their rules work. This score rewards that effort directly.', '',
                  '#### Breadth: Readiness-Weighted Credit', '',
                  'Unlike a simple "technique has a rule = covered" binary, Breadth assigns **fractional credit** per technique based on the data readiness of its **best** covering rule:', '',
                  '| Rule\'s Best Status | Credit | Meaning |', '|--------------------|--------|---------|',
                  '| **Fired** (produced alerts) | 1.00 | Validated by real or simulated attack — highest confidence |',
                  '| **Ready** (data exists, 0 alerts) | 0.75 | Rule *can* fire — data pipeline is healthy, just has not been triggered |',
                  '| **Partial** (some tables missing) | 0.50 | Rule partially functional — may detect some variants but not all |',
                  '| **NoData** (zero ingestion) | 0.25 | Paper tiger — technique shows in the matrix but rule cannot fire |',
                  '| **TierBlocked** (table on wrong tier) | 0.00 | Structurally impossible — rule can never execute |', '',
                  '**How it works:** For each ATT&CK technique, the system checks every rule covering it and takes the **maximum** credit. If a technique has 1 firing rule and 10 NoData rules, it gets full 1.00 credit — the firing rule proves detection works. Both Analytic Rules (AR) and Custom Detection rules (CD) are assessed with the same readiness constraints.', '',
                  'The final Breadth score blends 60% readiness-weighted rule coverage + 40% combined coverage (rules + platform Tier 1 + Tier 2 detections).', '',
                  '#### Score Interpretation', '',
                  '| Score Range | Assessment | Typical Profile |', '|-------------|------------|-----------------|',
                  '| 80–100 | 🟢 **Strong** | Broad coverage, balanced tactics, operationally validated, well-tagged, SOC-aligned |',
                  '| 60–79 | 🔵 **Good** | Solid coverage with some gaps; may have clustering or unvalidated rules |',
                  '| 40–59 | 🟡 **Moderate** | Significant gaps in breadth or operational validation; improvement opportunities |',
                  '| 20–39 | 🟠 **Developing** | Limited coverage across the framework; many uncovered tactics |',
                  '| 0–19 | 🔴 **Critical** | Minimal detection coverage; urgent investment needed |', '',
                  '### C. Limitations', '',
                  '1. **Coverage ≠ detection:** Having a rule tagged with a technique does not guarantee detection — rule quality, data source availability, and adversary TTPs vary',
                  '2. **Operational dimension requires Phase 3:** If KQL queries fail, Operational score defaults to 0. This is a data gap, not necessarily poor operational coverage',
                  '3. **Custom Detection availability:** Graph API requires `CustomDetection.Read.All` admin consent. If unavailable, coverage metrics are AR-only',
                  '4. **Sub-technique granularity:** Coverage is measured at the parent technique level (e.g., T1078). Sub-technique-level coverage (T1078.001, T1078.004) would require deeper rule query text analysis',
                  '5. **ATT&CK framework currency:** The reference JSON reflects a point-in-time snapshot of ATT&CK Enterprise. Update when MITRE publishes new versions',
                  '6. **SOC Optimization scope:** Coverage recommendations are Microsoft\'s assessment based on deployed data sources and available Content Hub templates. They may not cover custom or third-party detection logic',
                  '7. **Paper tiger detection** depends on the lookback window — a rule that fires infrequently (quarterly) may appear as a paper tiger in a 30-day window', '',
                  f'**Report generated:** {meta["generated"]} | **Skill:** mitre-coverage-report v1 | **Mode:** file', ''])
    return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='MITRE ATT&CK Coverage Report — data gathering')
    parser.add_argument('--config-path', default=None)
    parser.add_argument('--output-dir', default=None)
    parser.add_argument('--workspace-id', default=None)
    parser.add_argument('--subscription-id', default=None)
    parser.add_argument('--resource-group', default=None)
    parser.add_argument('--workspace-name', default=None)
    parser.add_argument('--days', type=int, default=30, choices=[7, 14, 30, 60, 90])
    parser.add_argument('--phase', type=int, default=0, choices=[0, 1, 2, 3])
    parser.add_argument('--prefetch-dir', default=None, help='Directory with prefetched m1.json-m9.json files (Mode B)')
    parser.add_argument('--render-report', action='store_true', default=False,
                        help='Generate complete report skeleton with LLM narrative placeholders')
    parser.add_argument('--max-gap-rows', type=int, default=3,
                        help='Max uncovered (❌) technique rows per tactic in PRERENDERED tables (0=count only)')
    args = parser.parse_args()
    if args.max_gap_rows < 0:
        parser.error('--max-gap-rows must be 0 or greater')
    prefetch_dir = Path(args.prefetch_dir) if args.prefetch_dir else None

    script_dir = Path(__file__).resolve().parent
    # Walk up to find workspace root (contains config.json)
    workspace_root = script_dir
    config_found = False
    for _ in range(6):
        if (workspace_root / 'config.json').exists():
            config_found = True
            break
        workspace_root = workspace_root.parent

    standalone = not config_found and not args.config_path
    if standalone:
        output_dir = Path(args.output_dir) if args.output_dir else script_dir / 'output'
    else:
        config_path = Path(args.config_path) if args.config_path else workspace_root / 'config.json'
        output_dir = Path(args.output_dir) if args.output_dir else workspace_root / 'temp'

    query_file = script_dir / 'queries.yaml'
    reference_file = script_dir / 'mitre-attck-enterprise.json'

    if not query_file.exists():
        print(f'❌ Query file not found: {query_file}', file=sys.stderr)
        sys.exit(1)
    if not reference_file.exists():
        print(f'❌ ATT&CK reference file not found: {reference_file}', file=sys.stderr)
        sys.exit(1)

    days = args.days
    phase = args.phase

    # ─── Banner ──────────────────────────────────────────────────
    phase_label = 'All Phases' if phase == 0 else f'Phase {phase}'
    print()
    print('━' * 57)
    print(f'  MITRE ATT&CK Coverage Report — {phase_label} Data Gathering')
    print(f'  Engine: az rest + az monitor (KQL)')
    print(f'  Alert/Incident lookback: {days}d')
    print('━' * 57)
    print()

    # ─── Prerequisites ───────────────────────────────────────────
    if prefetch_dir:
        print(f'✅ Prefetch mode — reading data from {prefetch_dir}')
    else:
        acct, err = az_json(['account', 'show'])
        if acct is None:
            print(f'❌ Not logged in to Azure CLI. Run: az login --tenant ', file=sys.stderr)
            sys.exit(1)
        print(f'✅ Azure CLI authenticated — Tenant: {acct.get("tenantId", "?")}')

    # ─── Config Resolution ───────────────────────────────────────
    config = None
    if not standalone:
        cp = Path(args.config_path) if args.config_path else workspace_root / 'config.json'
        if cp.exists():
            with open(cp, encoding='utf-8') as f:
                config = json.load(f)
            print(f'✅ Config loaded — {cp}')

    workspace_id = args.workspace_id or (config or {}).get('sentinel_workspace_id')
    subscription_id = args.subscription_id
    if not subscription_id:
        subscription_id = (config or {}).get('subscription_id')
        if not subscription_id and config and 'azure_mcp' in config:
            subscription_id = config['azure_mcp'].get('subscription')
    resource_group = args.resource_group
    if not resource_group and config and 'azure_mcp' in config:
        resource_group = config['azure_mcp'].get('resource_group')
    workspace_name = args.workspace_name
    if not workspace_name and config and 'azure_mcp' in config:
        workspace_name = config['azure_mcp'].get('workspace_name')

    if not all([subscription_id, resource_group, workspace_name]):
        print('❌ Missing required: subscription_id, resource_group, workspace_name', file=sys.stderr)
        sys.exit(1)
    if not workspace_id:
        print('❌ Missing workspace_id (needed for KQL queries)', file=sys.stderr)
        sys.exit(1)

    print(f'✅ Workspace: {workspace_name} ({workspace_id})')
    print(f'✅ Subscription: {subscription_id} / RG: {resource_group}')

    # ─── Load ATT&CK Reference ──────────────────────────────────
    print('\n📚 Loading ATT&CK Enterprise reference...')
    with open(reference_file, encoding='utf-8') as f:
        attack_ref = json.load(f)
    print(f'   ✅ ATT&CK Enterprise v{attack_ref["version"]} — {attack_ref["totalTechniques"]} techniques, {attack_ref["totalSubTechniques"]} sub-techniques')

    # Build technique → tactic reverse lookup
    tech_to_tactics: dict[str, list[str]] = {}
    for tactic_name, tactic_data in attack_ref['tactics'].items():
        for tech in tactic_data['techniques']:
            tech_to_tactics.setdefault(tech['id'], []).append(tactic_name)

    # ─── Load CTID Platform Coverage ─────────────────────────────
    ctid_file = script_dir / 'm365-platform-coverage.json'
    ctid_ref = None
    if ctid_file.exists():
        with open(ctid_file, encoding='utf-8') as f:
            ctid_ref = json.load(f)
        print(f'   ✅ CTID M365 Platform Coverage — {ctid_ref["metadata"]["techniques_with_detect"]} detect techniques, {ctid_ref["metadata"]["total_capabilities"]} capabilities')
    else:
        print(f'   ⚠️  CTID reference not found — platform coverage analysis limited')

    # ─── Load Known KQL Tables ───────────────────────────────────
    known_tables_file = script_dir / 'known-kql-tables.json'
    known_tables: set[str] = set()
    if known_tables_file.exists():
        with open(known_tables_file, encoding='utf-8') as f:
            kt_json = json.load(f)
        for k in kt_json.get('tables', {}).keys():
            if not k.startswith('_'):
                known_tables.add(k.lower())
        print(f'   ✅ Known KQL tables reference: {len(known_tables)} tables loaded')

    # ═══════════════════════════════════════════════════════════════
    # LOAD & EXECUTE QUERIES
    # ═══════════════════════════════════════════════════════════════
    phases_to_run = [1, 2, 3] if phase == 0 else [phase]
    all_results: dict = {}
    all_queries: dict = {}
    total_start = time.time()

    # Load all queries from single file, group by phase
    all_query_defs = import_all_queries(str(query_file))
    queries_by_phase: dict[int, list[dict]] = {}
    for qd in all_query_defs:
        p_val = int(qd.get('phase', 0))
        queries_by_phase.setdefault(p_val, []).append(qd)

    if prefetch_dir:
        query_id_to_file = {
            'mitre-m1': 'm1.json', 'mitre-m2': 'm2.json', 'mitre-m3': 'm3.json',
            'mitre-m4': 'm4.json', 'mitre-m5': 'm5.json', 'mitre-m6': 'm6.json',
            'mitre-m7': 'm7.json', 'mitre-m8': 'm8.json', 'mitre-m9': 'm9.json',
        }
        for p in phases_to_run:
            phase_queries = queries_by_phase.get(p, [])
            if not phase_queries:
                continue
            print(f'\n📂 Phase {p} — {len(phase_queries)} queries (prefetch):')
            for parsed in phase_queries:
                q_id = parsed.get('id')
                if not q_id:
                    continue
                all_queries[q_id] = parsed
                q_name = parsed.get('name', q_id)
                fname = query_id_to_file.get(q_id)
                if fname:
                    fpath = prefetch_dir / fname
                    if fpath.exists():
                        file_size_kb = fpath.stat().st_size / 1024
                        max_kb = int(parsed.get('max_response_kb', 0))
                        if max_kb > 0 and file_size_kb > max_kb:
                            print(f'   ⚠️  {q_name}: prefetch file {fname} is {file_size_kb:.0f}KB (limit {max_kb}KB) — loading anyway')
                        with open(fpath, encoding='utf-8') as f:
                            data = json.load(f)
                        if isinstance(data, dict) and '_status' in data:
                            all_results[q_id] = data
                            print(f'   ⏭️  {q_name}: {data["_status"]}')
                        elif isinstance(data, list):
                            all_results[q_id] = data
                            print(f'   ✅ {q_name}: {len(data)} items (prefetch)')
                        else:
                            all_results[q_id] = data if isinstance(data, list) else [data]
                            print(f'   ✅ {q_name}: loaded (prefetch)')
                    else:
                        print(f'   ⚠️  {q_name}: prefetch file {fname} not found')
                        all_results[q_id] = {'_status': 'SKIPPED', '_error': f'prefetch file {fname} not found'}
                else:
                    print(f'   ⚠️  {q_name}: no prefetch mapping for {q_id}')
                    all_results[q_id] = {'_status': 'SKIPPED', '_error': 'no prefetch mapping'}
        total_query_time = round(time.time() - total_start, 1)
        print(f'\n✅ All prefetch data loaded — {total_query_time}s')
    else:
        for p in phases_to_run:
            phase_queries = queries_by_phase.get(p, [])
            if not phase_queries:
                print(f'⚠️  No queries defined for Phase {p} — skipping')
                continue
            print(f'\n📂 Phase {p} — {len(phase_queries)} queries:')

            for parsed in phase_queries:
                q_id = parsed.get('id')
                if not q_id:
                    continue
                all_queries[q_id] = parsed
                q_type = parsed.get('type', '')
                q_name = parsed.get('name', q_id)
                print(f'   🔄 {q_name}...', end='', flush=True)
                start = time.time()

                if q_type == 'rest':
                    url = parsed.get('url', '')
                    url = url.replace('{subscription_id}', subscription_id)
                    url = url.replace('{resource_group}', resource_group)
                    url = url.replace('{workspace_name}', workspace_name)
                    jmespath = parsed.get('jmespath')
                    az_args = ['rest', '--method', 'get', '--url', url]
                    if jmespath:
                        az_args += ['--query', jmespath]
                    data, err = az_json(az_args, timeout=120)
                    elapsed = round(time.time() - start, 1)
                    if data is not None:
                        if not isinstance(data, list):
                            data = [data]
                        result_size_kb = len(json.dumps(data).encode()) / 1024
                        max_kb = int(parsed.get('max_response_kb', 0))
                        if max_kb > 0 and result_size_kb > max_kb * 1.5:
                            print(f' ⚠️ response is {result_size_kb:.0f}KB (soft limit {max_kb}KB)', end='')
                        all_results[q_id] = data
                        print(f' ✅ {len(data)} items ({elapsed}s)')
                    else:
                        print(f' ❌ FAILED ({elapsed}s)')
                        all_results[q_id] = {'_status': 'FAILED', '_error': err}

                elif q_type == 'graph':
                    # Graph API via az rest (no PowerShell dependency)
                    endpoint = parsed.get('endpoint', '')
                    select_fields = parsed.get('select', '')
                    uri = f'https://graph.microsoft.com{endpoint}'
                    if select_fields:
                        uri += f'?$select={select_fields}'
                    az_args = ['rest', '--method', 'get', '--url', uri, '--resource', 'https://graph.microsoft.com']
                    data, err = az_json(az_args, timeout=120)
                    elapsed = round(time.time() - start, 1)
                    if data is not None:
                        values = data.get('value', []) if isinstance(data, dict) else data
                        if not isinstance(values, list):
                            values = [values]
                        result_size_kb = len(json.dumps(values).encode()) / 1024
                        max_kb = int(parsed.get('max_response_kb', 0))
                        if max_kb > 0 and result_size_kb > max_kb * 1.5:
                            print(f' ⚠️ response is {result_size_kb:.0f}KB (soft limit {max_kb}KB)', end='')
                        all_results[q_id] = values
                        print(f' ✅ {len(values)} rules ({elapsed}s)')
                    else:
                        print(f' ⏭️  SKIPPED ({elapsed}s) — {err}')
                        all_results[q_id] = {'_status': 'SKIPPED', '_error': err}

                elif q_type == 'kql':
                    raw_query = parsed.get('query', '').replace('{days}', str(days))
                    raw_timespan = parsed.get('timespan', f'P{days}D').replace('{days}', str(days))
                    single_line = re.sub(r'\s+', ' ', raw_query).strip()
                    az_args = [
                        'monitor', 'log-analytics', 'query',
                        '--workspace', workspace_id,
                        '--analytics-query', single_line,
                        '--timespan', raw_timespan,
                    ]
                    data, err = az_json(az_args, timeout=180)
                    elapsed = round(time.time() - start, 1)
                    if data is not None:
                        if not isinstance(data, list):
                            data = [data]
                        result_size_kb = len(json.dumps(data).encode()) / 1024
                        max_kb = int(parsed.get('max_response_kb', 0))
                        if max_kb > 0 and result_size_kb > max_kb * 1.5:
                            print(f' ⚠️ response is {result_size_kb:.0f}KB (soft limit {max_kb}KB)', end='')
                        all_results[q_id] = data
                        print(f' ✅ {len(data)} rows ({elapsed}s)')
                    else:
                        print(f' ❌ FAILED ({elapsed}s)')
                        all_results[q_id] = {'_status': 'FAILED', '_error': err}

                elif q_type == 'cli':
                    cmd = parsed.get('command', '')
                    cmd = cmd.replace('{subscription_id}', subscription_id)
                    cmd = cmd.replace('{resource_group}', resource_group)
                    cmd = cmd.replace('{workspace_name}', workspace_name)
                    # Split the command and run through subprocess
                    parts = cmd.split()
                    data, err = az_json(parts[1:], timeout=120)  # strip leading 'az'
                    elapsed = round(time.time() - start, 1)
                    if data is not None:
                        if not isinstance(data, list):
                            data = [data]
                        result_size_kb = len(json.dumps(data).encode()) / 1024
                        max_kb = int(parsed.get('max_response_kb', 0))
                        if max_kb > 0 and result_size_kb > max_kb * 1.5:
                            print(f' ⚠️ response is {result_size_kb:.0f}KB (soft limit {max_kb}KB)', end='')
                        all_results[q_id] = data
                        print(f' ✅ {len(data)} tables ({elapsed}s)')
                    else:
                        print(f' ❌ FAILED ({elapsed}s)')
                        all_results[q_id] = {'_status': 'FAILED', '_error': err}
                else:
                    print(f' ⏭️  Unknown type "{q_type}"')

        total_query_time = round(time.time() - total_start, 1)
        print(f'\n✅ All queries complete — {total_query_time}s total')

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1 POST-PROCESSING: Rule Inventory & MITRE Extraction
    # ═══════════════════════════════════════════════════════════════
    print('\n📊 Computing MITRE coverage metrics...')
    phase1 = io.StringIO()
    phase1.write('## PHASE_1 — Rule Inventory & MITRE Extraction\n')

    m1_data = all_results.get('mitre-m1', [])
    ar_total = ar_enabled = ar_disabled = 0
    ar_with_tactics = ar_with_techniques = ar_no_mitre = ar_no_mitre_enabled = 0

    tactic_rule_count: dict[str, int] = {}
    technique_rule_count: dict[str, int] = {}
    technique_rule_names: dict[str, list[str]] = {}
    technique_rule_ids: dict[str, list[str]] = {}
    all_rule_tactics: dict[str, list[str]] = {}
    all_rule_techniques: dict[str, list[str]] = {}
    untagged_rules: list[dict] = []

    tactic_order = [
        'Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution',
        'Persistence', 'PrivilegeEscalation', 'DefenseEvasion', 'CredentialAccess',
        'Discovery', 'LateralMovement', 'Collection', 'CommandAndControl',
        'Exfiltration', 'Impact'
    ]

    if isinstance(m1_data, list) and len(m1_data) > 0:
        ar_total = len(m1_data)
        for rule in m1_data:
            is_enabled = rule.get('enabled') in (True, 'true', 'True')
            if is_enabled:
                ar_enabled += 1
            else:
                ar_disabled += 1
            tactics = rule.get('tactics') or []
            techniques = rule.get('techniques') or []
            has_tactics = len(tactics) > 0
            has_techniques = len(techniques) > 0
            if has_tactics:
                ar_with_tactics += 1
            if has_techniques:
                ar_with_techniques += 1
            if not has_tactics and not has_techniques:
                ar_no_mitre += 1
                if is_enabled:
                    ar_no_mitre_enabled += 1
                untagged_rules.append({
                    'Name': rule.get('displayName', ''),
                    'RuleId': rule.get('ruleId', ''),
                    'Enabled': is_enabled,
                    'Kind': rule.get('kind', ''),
                    'Severity': rule.get('severity', ''),
                    'Source': 'AR',
                })
            if is_enabled:
                for t in tactics:
                    tactic_rule_count[t] = tactic_rule_count.get(t, 0) + 1
                for tech in techniques:
                    technique_rule_count[tech] = technique_rule_count.get(tech, 0) + 1
                    technique_rule_names.setdefault(tech, []).append(f'[AR] {rule.get("displayName", "")}')
                    technique_rule_ids.setdefault(tech, []).append(rule.get('ruleId', ''))
            rid = rule.get('ruleId', '')
            all_rule_tactics[rid] = tactics if has_tactics else []
            all_rule_techniques[rid] = techniques if has_techniques else []

    # ─── M2: Custom Detection Rules ──────────────────────────────
    m2_data = all_results.get('mitre-m2', [])
    cd_total = cd_enabled = cd_disabled = 0
    cd_with_mitre = cd_no_mitre = cd_no_mitre_enabled = 0
    cd_status = 'OK'

    if isinstance(m2_data, dict) and '_status' in m2_data:
        cd_status = m2_data['_status']
        print(f'   ℹ️  Custom Detections: {cd_status} — {m2_data.get("_error", "")}')
    elif isinstance(m2_data, list) and len(m2_data) > 0:
        cd_total = len(m2_data)
        for cd in m2_data:
            is_enabled = cd.get('isEnabled') in (True, 'true', 'True')
            if is_enabled:
                cd_enabled += 1
            else:
                cd_disabled += 1
            cd_mitre = (cd.get('detectionAction', {}).get('alertTemplate', {}).get('mitreTechniques') or [])
            cd_category = cd.get('detectionAction', {}).get('alertTemplate', {}).get('category', '')
            has_techniques = len(cd_mitre) > 0
            has_tactic = cd_category and cd_category in tactic_order
            has_mitre = has_techniques or has_tactic
            if has_mitre:
                cd_with_mitre += 1
                if is_enabled:
                    if has_techniques:
                        for tech in cd_mitre:
                            technique_rule_count[tech] = technique_rule_count.get(tech, 0) + 1
                            technique_rule_names.setdefault(tech, []).append(f'[CD] {cd.get("displayName", "")}')
                            technique_rule_ids.setdefault(tech, []).append(f'CD:{cd.get("id", "")}')
                    cd_tactics = []
                    if has_tactic:
                        cd_tactics = [cd_category]
                    else:
                        for tech in cd_mitre:
                            parent = re.match(r'^(T\d{4})', tech)
                            pid = parent.group(1) if parent else tech
                            cd_tactics.extend(tech_to_tactics.get(pid, []))
                        cd_tactics = list(set(cd_tactics))
                    for t in cd_tactics:
                        tactic_rule_count[t] = tactic_rule_count.get(t, 0) + 1
            else:
                cd_no_mitre += 1
                if is_enabled:
                    cd_no_mitre_enabled += 1
                untagged_rules.append({
                    'Name': cd.get('displayName', ''),
                    'RuleId': cd.get('id', ''),
                    'Enabled': is_enabled,
                    'Kind': 'CustomDetection',
                    'Severity': 'N/A',
                    'Source': 'CD',
                })

    # ─── Phase 1 scratchpad ──────────────────────────────────────
    phase1.write(f'\n### AR_Summary\nAR_Total: {ar_total}\nAR_Enabled: {ar_enabled}\nAR_Disabled: {ar_disabled}\n')
    phase1.write(f'AR_WithTactics: {ar_with_tactics}\nAR_WithTechniques: {ar_with_techniques}\n')
    phase1.write(f'AR_NoMitre: {ar_no_mitre}\nAR_NoMitre_Enabled: {ar_no_mitre_enabled}\n')
    phase1.write(f'\n### CD_Summary\nCD_Status: {cd_status}\nCD_Total: {cd_total}\n')
    phase1.write(f'CD_Enabled: {cd_enabled}\nCD_Disabled: {cd_disabled}\n')
    phase1.write(f'CD_WithMitre: {cd_with_mitre}\nCD_NoMitre: {cd_no_mitre}\nCD_NoMitre_Enabled: {cd_no_mitre_enabled}\n')

    # ─── Tactic Coverage Matrix ──────────────────────────────────
    phase1.write('\n### TacticCoverage\n<!-- Tactic | EnabledRules | FrameworkTechniques | CoveredTechniques | CoveragePct -->\n')
    total_framework_techs = 0
    total_covered_techs = 0
    total_enabled_rules = 0
    for tactic in tactic_order:
        rc = tactic_rule_count.get(tactic, 0)
        ti = attack_ref['tactics'].get(tactic, {})
        ft = ti.get('techniqueCount', 0)
        covered = 0
        for tech in ti.get('techniques', []):
            if technique_rule_count.get(tech['id'], 0) > 0:
                covered += 1
        pct = round(100.0 * covered / ft, 1) if ft > 0 else 0
        total_framework_techs += ft
        total_covered_techs += covered
        total_enabled_rules += rc
        phase1.write(f'{tactic} | {rc} | {ft} | {covered} | {pct}\n')
    overall_coverage = round(100.0 * total_covered_techs / total_framework_techs, 1) if total_framework_techs > 0 else 0
    phase1.write(f'TOTAL | {total_enabled_rules} | {total_framework_techs} | {total_covered_techs} | {overall_coverage}\n')

    # ─── Per-Technique Detail rows ───────────────────────────────
    tech_detail_rows = []
    for tactic in tactic_order:
        ti = attack_ref['tactics'].get(tactic, {})
        for tech in sorted(ti.get('techniques', []), key=lambda t: t['id']):
            rc = technique_rule_count.get(tech['id'], 0)
            rn = '; '.join(technique_rule_names.get(tech['id'], [])[:5])
            tech_detail_rows.append({
                'Tactic': tactic, 'TechId': tech['id'], 'TechName': tech['name'],
                'SubTechCount': tech.get('subTechniques', 0), 'EnabledRules': rc, 'RuleNames': rn,
            })

    # ─── Untagged Rules ──────────────────────────────────────────
    phase1.write('\n### UntaggedRules\n<!-- Name | RuleId | Enabled | Kind | Severity | Source -->\n')
    for r in untagged_rules:
        phase1.write(f'{r["Name"]} | {r["RuleId"]} | {r["Enabled"]} | {r["Kind"]} | {r["Severity"]} | {r["Source"]}\n')

    # ─── ICS Techniques ──────────────────────────────────────────
    ics_techs = sorted([k for k in technique_rule_count if re.match(r'^T0\d{3}', k)])
    phase1.write('\n### ICS_Techniques\n<!-- TechniqueID | EnabledRules | RuleNames -->\n')
    for ics_id in ics_techs:
        rc = technique_rule_count[ics_id]
        rn = '; '.join(technique_rule_names.get(ics_id, [])[:3])
        phase1.write(f'{ics_id} | {rc} | {rn}\n')

    phase1_block = phase1.getvalue().rstrip()
    print(f'   ✅ Phase 1 metrics complete — {ar_enabled} enabled AR, {cd_enabled} enabled CD, {overall_coverage}% technique coverage')

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2 POST-PROCESSING: SOC Optimization
    # ═══════════════════════════════════════════════════════════════
    phase2 = io.StringIO()
    phase2.write('## PHASE_2 — SOC Optimization Insights\n')
    m3_data = all_results.get('mitre-m3', [])
    soc_coverage_recs = []
    soc_mitre_tagging = []
    soc_status = 'OK'

    if isinstance(m3_data, dict) and '_status' in m3_data:
        soc_status = m3_data['_status']
    elif isinstance(m3_data, list):
        soc_coverage_recs = [r for r in m3_data if r.get('typeId', '').startswith('Precision_Coverage') and r.get('typeId') != 'Precision_Coverage_DetectionMitreTagging']
        soc_mitre_tagging = [r for r in m3_data if r.get('typeId') == 'Precision_Coverage_DetectionMitreTagging']

    phase2.write(f'\n### SOC_Summary\nSOC_Status: {soc_status}\nSOC_CoverageRecs: {len(soc_coverage_recs)}\nSOC_MitreTaggingRecs: {len(soc_mitre_tagging)}\n')

    # Deduplicate scenarios
    scenario_groups: dict[str, list] = {}
    for rec in soc_coverage_recs:
        sn = rec.get('useCaseName', '(unnamed)')
        scenario_groups.setdefault(sn, []).append(rec)
    deduped = []
    for sn, grp in scenario_groups.items():
        active = [r for r in grp if r.get('state') != 'CompletedBySystem']
        deduped.append(active[0] if active else grp[0])
    dedup_dropped = len(soc_coverage_recs) - len(deduped)
    if dedup_dropped > 0:
        print(f'   ℹ️  Deduplicated SOC scenarios: dropped {dedup_dropped} stale entries')

    phase2.write('\n### ThreatScenarios\n<!-- Scenario | State | ActiveDetections | RecommendedDetections | PlatformCovered | TemplateCovered | TemplateGap | CompletionRate | TacticSummary -->\n')
    parsed_scenarios: list[dict] = []

    for rec in sorted(deduped, key=lambda r: r.get('useCaseName') or ''):
        scenario = rec.get('useCaseName') or '(unnamed)'
        state = rec.get('state', '')
        active_count = rec_count = 0
        tactic_summary = ''
        platform_covered = template_covered = template_gap = 0
        suggestions = rec.get('suggestions') or []
        if suggestions:
            addl = suggestions[0].get('additionalProperties', {}) or {}
            active_count = int(addl.get('ActiveDetectionsCount', 0) or 0)
            rec_count = int(addl.get('RecommendedDetectionsCount', 0) or 0)
            # CoverageEntities
            ce_raw = addl.get('CoverageEntities')
            if ce_raw:
                if isinstance(ce_raw, str):
                    try: ce_raw = json.loads(ce_raw)
                    except: ce_raw = []
                if isinstance(ce_raw, list):
                    for ce in ce_raw:
                        ce_type = (ce.get('Identifier') or {}).get('Type', '')
                        ce_status = ce.get('Status', '')
                        if ce_type == 'FirstPartyProduct' and ce_status == 'Covered':
                            platform_covered += 1
                        elif ce_type == 'Template':
                            if ce_status == 'Covered':
                                template_covered += 1
                            elif ce_status == 'NotCovered':
                                template_gap += 1
            # Tactics
            tactics_raw = addl.get('Tactics')
            if tactics_raw:
                if isinstance(tactics_raw, str):
                    try: tactics_raw = json.loads(tactics_raw)
                    except: tactics_raw = []
                if isinstance(tactics_raw, list):
                    parts = []
                    for tp in tactics_raw:
                        if isinstance(tp, dict):
                            parts.append(f'{tp.get("Name", "")}:{tp.get("CurrentCount", 0)}/{tp.get("RecommendedCount", 0)}')
                    tactic_summary = ', '.join(parts)

        completion_rate = round(100.0 * active_count / rec_count, 1) if rec_count > 0 else 0
        parsed_scenarios.append({
            'Scenario': scenario, 'State': state, 'Active': active_count,
            'Recommended': rec_count, 'Platform': platform_covered,
            'Sentinel': template_covered, 'SentinelGap': template_gap,
            'CompletionRate': completion_rate, 'TacticSummary': tactic_summary,
        })
        phase2.write(f'{scenario} | {state} | {active_count} | {rec_count} | {platform_covered} | {template_covered} | {template_gap} | {completion_rate} | {tactic_summary}\n')

    # MITRE Tagging Suggestions
    phase2.write('\n### MitreTaggingSuggestions\n')
    if soc_mitre_tagging:
        tr = soc_mitre_tagging[0]
        phase2.write(f'State: {tr.get("state", "")}\nDescription: {tr.get("description", "")}\n')
        suggestions = tr.get('suggestions') or []
        if suggestions:
            addl = suggestions[0].get('additionalProperties', {}) or {}
            ar_tags = addl.get('AnalyticRulesRecommendedTags')
            if isinstance(ar_tags, str):
                try: ar_tags = json.loads(ar_tags)
                except: ar_tags = []
            if not isinstance(ar_tags, list):
                ar_tags = []
            ar_applied = ar_not_applied = ar_partial = ar_not_found = 0
            for tag in ar_tags:
                rule_id = tag.get('ResourceName', '')
                sug_tactics = tag.get('Tactics') or []
                sug_techniques = tag.get('Techniques') or []
                actual_tactics = all_rule_tactics.get(rule_id)
                if actual_tactics is None:
                    ar_not_found += 1
                else:
                    actual_techniques = all_rule_techniques.get(rule_id, [])
                    t_ok = all(t in actual_tactics for t in sug_tactics)
                    tech_ok = len(sug_techniques) == 0 or all(t in actual_techniques for t in sug_techniques)
                    if t_ok and tech_ok:
                        ar_applied += 1
                    elif t_ok or tech_ok:
                        ar_partial += 1
                    else:
                        ar_not_applied += 1
            phase2.write(f'AR_TagSuggestions: {len(ar_tags)}\nAR_TagsApplied: {ar_applied}\n')
            phase2.write(f'AR_TagsPartial: {ar_partial}\nAR_TagsNotApplied: {ar_not_applied}\nAR_TagsNotFound: {ar_not_found}\n')
            cd_tags = addl.get('CustomDetectionsRecommendedTags')
            if isinstance(cd_tags, str):
                try: cd_tags = json.loads(cd_tags)
                except: cd_tags = []
            if not isinstance(cd_tags, list):
                cd_tags = []
            phase2.write(f'CD_TagSuggestions: {len(cd_tags)}\n')
    else:
        phase2.write('(No MITRE tagging recommendations found)\n')

    phase2_block = phase2.getvalue().rstrip()
    print(f'   ✅ Phase 2 metrics complete — {len(deduped)} coverage scenarios ({dedup_dropped} stale dropped), {len(soc_mitre_tagging)} tagging recs')

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3 POST-PROCESSING
    # ═══════════════════════════════════════════════════════════════
    phase3 = io.StringIO()
    phase3.write('## PHASE_3 — Operational MITRE Correlation\n')

    # ─── M4: Alert Firing ────────────────────────────────────────
    m4_data = all_results.get('mitre-m4', [])
    phase3.write('\n### AlertFiring\n')
    firing_tactics: dict[str, int] = {}

    if isinstance(m4_data, list) and len(m4_data) > 0:
        phase3.write(f'AlertFiring_Count: {len(m4_data)}\n')
        phase3.write('<!-- Source | AlertName | RuleId | AlertCount | HighSev | MedSev | LowSev | InfoSev -->\n')
        for alert in m4_data:
            src = alert.get('Source', 'AR')
            phase3.write(f'{src} | {alert.get("AlertName","")} | {alert.get("RuleId","")} | {alert.get("AlertCount",0)} | {alert.get("HighSev",0)} | {alert.get("MediumSev",0)} | {alert.get("LowSev",0)} | {alert.get("InfoSev",0)}\n')
            # Firing tactics
            alert_tactics = []
            if src == 'AR' and alert.get('RuleId') in all_rule_tactics:
                alert_tactics = all_rule_tactics[alert['RuleId']]
            elif src == 'CD':
                raw = alert.get('Tactics', [])
                if isinstance(raw, str):
                    try: raw = json.loads(raw)
                    except: raw = []
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, list):
                            alert_tactics.extend([s for s in item if s and s != '[]'])
                        elif isinstance(item, str) and item and item != '[]':
                            alert_tactics.append(item)
                alert_tactics = list(set(alert_tactics))
            for t in alert_tactics:
                firing_tactics[t] = firing_tactics.get(t, 0) + int(alert.get('AlertCount', 0))
    else:
        phase3.write(f'AlertFiring_Count: 0\n(No SecurityAlert data in {days}d window)\n')

    # ─── M5: Incidents by Tactic ─────────────────────────────────
    m5_data = all_results.get('mitre-m5', [])
    phase3.write('\n### IncidentsByTactic\n')
    if isinstance(m5_data, list) and len(m5_data) > 0:
        phase3.write(f'IncidentTactic_Count: {len(m5_data)}\n')
    elif isinstance(m5_data, dict) and '_status' in m5_data:
        phase3.write(f'IncidentTactic_Status: {m5_data["_status"]}\n')
    else:
        phase3.write(f'IncidentTactic_Count: 0\n(No SecurityIncident data in {days}d window)\n')

    # ─── M6: Platform Alert Coverage + CTID ──────────────────────
    m6_data = all_results.get('mitre-m6', [])
    phase3.write('\n### PlatformAlertCoverage\n')
    platform_techniques: dict[str, dict] = {}
    active_products: dict[str, bool] = {}
    family_only_products: dict[str, bool] = {}

    prod_aliases = {}
    prod_families = {}
    prod_display_names = {}
    if ctid_ref:
        prod_aliases = ctid_ref.get('product_aliases', {})
        prod_families = ctid_ref.get('product_families', {})
        prod_display_names = ctid_ref.get('display_names', {})

    if isinstance(m6_data, list) and len(m6_data) > 0:
        phase3.write(f'PlatformAlert_TechniqueCount: {len(m6_data)}\n')
        for row in m6_data:
            tech = row.get('Technique', '')
            ac = int(row.get('AlertCount', 0))
            dt = int(row.get('DistinctAlertTypes', 0))
            products = row.get('Products', [])
            if isinstance(products, str):
                try: products = json.loads(products)
                except: products = [products]
            alert_names = row.get('AlertNames', [])
            if isinstance(alert_names, str):
                try: alert_names = json.loads(alert_names)
                except: alert_names = [alert_names]
            alert_details = []
            for entry in alert_names:
                parts = str(entry).split('|||', 1)
                if len(parts) == 2:
                    alert_details.append({'Product': parts[0], 'Name': parts[1]})
                else:
                    alert_details.append({'Product': None, 'Name': entry})
            platform_techniques[tech] = {'AlertCount': ac, 'DistinctAlertTypes': dt, 'Products': products, 'AlertDetails': alert_details}
            for p in products:
                np = prod_aliases.get(p, p)
                active_products[np] = True
        # Expand product families
        for child in list(active_products.keys()):
            if child in prod_families:
                parent = prod_families[child]
                if parent not in active_products:
                    active_products[parent] = True
                    family_only_products[parent] = True
        display_products = sorted([p for p in active_products if p not in family_only_products])
        phase3.write(f'\n### DeployedProducts\nActiveProducts_Count: {len(display_products)}\n')
        for prod in display_products:
            dn = prod_display_names.get(prod, prod)
            phase3.write(f'{dn} | techniques\n')

    # Supplementary product detection from SecurityAlert
    if not prefetch_dir:
        try:
            prod_query = f"SecurityAlert | where TimeGenerated > ago({days}d) | where ProviderName !in~ ('ASI Scheduled Alerts', 'ASI NRT Alerts') | where isnotempty(ProductName) | summarize AlertCount = count() by ProductName"
            data, err = az_json([
                'monitor', 'log-analytics', 'query',
                '--workspace', workspace_id,
                '--analytics-query', prod_query,
                '--timespan', f'P{days}D',
            ], timeout=60)
            if data and isinstance(data, list):
                for row in data:
                    rp = row.get('ProductName', '')
                    np = prod_aliases.get(rp, rp)
                    if np not in active_products:
                        active_products[np] = True
                for child in list(active_products.keys()):
                    if child in prod_families:
                        parent = prod_families[child]
                        if parent not in active_products:
                            active_products[parent] = True
                            family_only_products[parent] = True
                display_products = sorted([p for p in active_products if p not in family_only_products])
        except Exception:
            pass

    # ─── CTID Tier Classification ────────────────────────────────
    tier1_techniques: dict[str, dict] = {}
    tier2_techniques: dict[str, dict] = {}
    tier3_techniques: dict[str, dict] = {}

    if ctid_ref:
        cap_to_product = ctid_ref.get('capability_to_product', {})
        classified: set[str] = set()
        for tactic_name, tactic_data in attack_ref['tactics'].items():
            for tech in tactic_data.get('techniques', []):
                tid = tech['id']
                if tid in classified:
                    continue
                classified.add(tid)
                if tid in platform_techniques:
                    tier1_techniques[tid] = platform_techniques[tid]
                    continue
                detect_caps = ctid_ref.get('detect_coverage', {}).get(tid)
                if detect_caps and len(detect_caps) > 0:
                    has_active = False
                    for cap_id in detect_caps:
                        product = cap_to_product.get(cap_id)
                        if product and product in active_products:
                            has_active = True
                            break
                    if has_active:
                        prods = list(set(cap_to_product.get(c, '') for c in detect_caps if cap_to_product.get(c)))
                        tier2_techniques[tid] = {'Capabilities': detect_caps, 'Products': prods}
                    else:
                        tier3_techniques[tid] = {'Capabilities': detect_caps}

    phase3.write(f'\n### PlatformTechniquesByTier\n')
    phase3.write(f'Tier1_AlertProven: {len(tier1_techniques)}\nTier2_DeployedCapability: {len(tier2_techniques)}\nTier3_CatalogCapability: {len(tier3_techniques)}\n')
    if ctid_ref:
        phase3.write(f'CTID_Version: {ctid_ref.get("metadata", {}).get("ctid_version", "N/A")}\n')

    # ─── M7: Table Ingestion Volume ──────────────────────────────
    m7_data = all_results.get('mitre-m7', [])
    table_volumes: dict[str, float] = {}
    if isinstance(m7_data, list) and len(m7_data) > 0:
        for row in m7_data:
            table_volumes[row.get('DataType', '')] = float(row.get('AvgDailyMB', 0))

    # ─── M9: Table Tier Classification ───────────────────────────
    m9_data = all_results.get('mitre-m9', [])
    table_tiers: dict[str, str] = {}
    non_analytics_tables: dict[str, str] = {}
    if isinstance(m9_data, list) and len(m9_data) > 0:
        for row in m9_data:
            plan = row.get('plan', '')
            table_tiers[row.get('name', '')] = plan
            if plan == 'Basic':
                non_analytics_tables[row['name']] = 'Basic'
            elif plan == 'Auxiliary':
                non_analytics_tables[row['name']] = 'Data Lake'

    # ─── Data Readiness ──────────────────────────────────────────
    phase3.write('\n### DataReadiness\n')
    ready_count = partial_count = no_data_count = tier_blocked_count = no_query_count = 0
    rule_readiness: dict[str, str] = {}
    non_ready_rules: list[dict] = []
    missing_tables_summary: dict[str, int] = {}
    unverified_tables_summary: dict[str, int] = {}
    tier_blocked_tables_summary: dict[str, dict] = {}
    tier_blocked_rule_ids: dict[str, bool] = {}

    if isinstance(m1_data, list) and len(m1_data) > 0 and len(table_volumes) > 0:
        for rule in m1_data:
            is_enabled = rule.get('enabled') in (True, 'true', 'True')
            if not is_enabled:
                continue
            query_text = rule.get('query', '')
            if not query_text or not query_text.strip():
                no_query_count += 1
                continue
            tables = get_kql_table_names(query_text)
            if not tables:
                no_query_count += 1
                continue
            tables_with_data = []
            tables_no_data = []
            tables_unverified = []
            tables_tier_blocked = []
            table_volume_str = []
            for t in tables:
                if t in non_analytics_tables:
                    tables_tier_blocked.append(t)
                    tier_blocked_tables_summary.setdefault(t, {'Tier': non_analytics_tables[t], 'Count': 0})
                    tier_blocked_tables_summary[t]['Count'] += 1
                elif t in table_volumes:
                    tables_with_data.append(t)
                    table_volume_str.append(f'{t}={table_volumes[t]}MB')
                else:
                    is_known = t.lower() in known_tables
                    is_custom = t.endswith('_CL')
                    if is_known or is_custom or not known_tables:
                        tables_no_data.append(t)
                        missing_tables_summary[t] = missing_tables_summary.get(t, 0) + 1
                    else:
                        tables_unverified.append(t)
                        unverified_tables_summary[t] = unverified_tables_summary.get(t, 0) + 1

            if tables_tier_blocked:
                status = 'TierBlocked'
            elif not tables_no_data:
                status = 'Ready'
            elif tables_with_data:
                status = 'Partial'
            else:
                status = 'NoData'

            if status == 'Ready': ready_count += 1
            elif status == 'Partial': partial_count += 1
            elif status == 'NoData': no_data_count += 1
            elif status == 'TierBlocked':
                tier_blocked_count += 1
                tier_blocked_rule_ids[rule.get('ruleId', '')] = True
            rule_readiness[rule.get('ruleId', '')] = status

            if status != 'Ready':
                non_ready_rules.append({
                    'RuleName': rule.get('displayName', ''),
                    'Tables': ', '.join(tables),
                    'Status': status,
                    'MissingTables': ', '.join(tables_no_data) or '—',
                    'Volumes': ', '.join(table_volume_str) or '—',
                })

    # CD readiness
    if isinstance(m2_data, list) and len(m2_data) > 0 and len(table_volumes) > 0:
        for cd in m2_data:
            is_enabled = cd.get('isEnabled') in (True, 'true', 'True')
            if not is_enabled:
                continue
            qt = (cd.get('queryCondition', {}) or {}).get('queryText', '')
            if not qt:
                rule_readiness[f'CD:{cd.get("id", "")}'] = 'Ready'
                continue
            cd_tables = get_kql_table_names(qt)
            if not cd_tables:
                rule_readiness[f'CD:{cd.get("id", "")}'] = 'Ready'
                continue
            cd_wd = []
            cd_nd = []
            cd_tb = []
            for t in cd_tables:
                if t in non_analytics_tables:
                    cd_tb.append(t)
                elif t in table_volumes:
                    cd_wd.append(t)
                else:
                    is_known = t.lower() in known_tables
                    if is_known or t.endswith('_CL') or not known_tables:
                        cd_nd.append(t)
            if cd_tb:
                st = 'TierBlocked'
            elif not cd_nd:
                st = 'Ready'
            elif cd_wd:
                st = 'Partial'
            else:
                st = 'NoData'
            rule_readiness[f'CD:{cd.get("id", "")}'] = st

    total_checked = ready_count + partial_count + no_data_count + tier_blocked_count
    readiness_pct = round(100.0 * ready_count / total_checked, 1) if total_checked > 0 else 0
    phase3.write(f'\n### DataReadiness_Summary\nRules_Ready: {ready_count}\nRules_Partial: {partial_count}\n')
    phase3.write(f'Rules_NoData: {no_data_count}\nRules_TierBlocked: {tier_blocked_count}\nRules_NoQuery: {no_query_count}\n')
    phase3.write(f'Readiness_Pct: {readiness_pct}\n')

    # ─── M8: Connector Health ────────────────────────────────────
    m8_data = all_results.get('mitre-m8', [])
    connector_health: dict[str, dict] = {}
    if isinstance(m8_data, list) and len(m8_data) > 0:
        phase3.write('\n### ConnectorHealth\n')
        for row in m8_data:
            name = row.get('SentinelResourceName', '')
            connector_health[name] = {
                'LastStatus': row.get('LastStatus', ''),
                'HealthPct': float(row.get('HealthPct', 0)),
                'FailureCount': int(row.get('FailureCount', 0)),
                'SuccessCount': int(row.get('SuccessCount', 0)),
            }

    phase3_block = phase3.getvalue().rstrip()
    print(f'   ✅ Phase 3 metrics complete — {len(platform_techniques)} platform techniques (T1), {len(tier2_techniques)} deployed capability (T2)')

    # ═══════════════════════════════════════════════════════════════
    # COMPUTE COVERAGE SCORE
    # ═══════════════════════════════════════════════════════════════
    print('\n📈 Computing MITRE Coverage Score...')

    mitre_tagged_enabled = ar_enabled - ar_no_mitre_enabled + cd_enabled - cd_no_mitre_enabled
    firing_mitre_rule_ids: dict[str, bool] = {}
    if isinstance(m4_data, list):
        for alert in m4_data:
            src = alert.get('Source', 'AR')
            rid = alert.get('RuleId', '')
            if src == 'AR' and rid in all_rule_tactics and len(all_rule_tactics[rid]) > 0:
                firing_mitre_rule_ids[rid] = True
            elif src == 'CD':
                raw = alert.get('Tactics', [])
                if isinstance(raw, str):
                    try: raw = json.loads(raw)
                    except: raw = []
                has = False
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, list):
                            for s in item:
                                if s and s != '':
                                    has = True
                                    break
                        elif isinstance(item, str) and item and item != '[]':
                            has = True
                        if has:
                            break
                if has:
                    firing_mitre_rule_ids[rid] = True
    firing_mitre_rules = len(firing_mitre_rule_ids)

    # Readiness-weighted Breadth
    readiness_credit = {'Fired': 1.0, 'Ready': 0.75, 'Partial': 0.50, 'NoData': 0.25, 'TierBlocked': 0.0}
    readiness_priority = {'Fired': 5, 'Ready': 4, 'Partial': 3, 'NoData': 2, 'TierBlocked': 1, 'Unknown': 3}
    total_weighted_credit = 0.0
    phantom_techniques = []
    tech_credit_breakdown: dict[str, str] = {}
    for tech, rc in technique_rule_count.items():
        if rc <= 0:
            continue
        rids = technique_rule_ids.get(tech, [])
        best_status = 'TierBlocked'
        best_prio = 1
        for rid in rids:
            if rid in firing_mitre_rule_ids:
                best_status = 'Fired'
                best_prio = 5
                break
            rs = rule_readiness.get(rid, 'Unknown')
            rp = readiness_priority.get(rs, 3)
            if rp > best_prio:
                best_status = rs
                best_prio = rp
        credit = readiness_credit.get(best_status, 0.75)
        total_weighted_credit += credit
        tech_credit_breakdown[tech] = best_status
        if best_status == 'TierBlocked':
            phantom_techniques.append(tech)
    phantom_tech_count = len(phantom_techniques)

    rule_breadth = 100.0 * total_weighted_credit / total_framework_techs if total_framework_techs > 0 else 0
    # Combined coverage count
    total_combined_techs = 0
    for tactic in tactic_order:
        ti = attack_ref['tactics'].get(tactic, {})
        for tech in ti.get('techniques', []):
            tid = tech['id']
            has_cov = (technique_rule_count.get(tid, 0) > 0 or tid in tier1_techniques or tid in tier2_techniques)
            if has_cov:
                total_combined_techs += 1
    combined_breadth = 100.0 * total_combined_techs / total_framework_techs if total_framework_techs > 0 else 0
    breadth_score = round(0.6 * rule_breadth + 0.4 * combined_breadth, 1)

    tactics_with_rules = sum(1 for t in tactic_order if tactic_rule_count.get(t, 0) > 0)
    balance_score = round(100.0 * tactics_with_rules / len(tactic_order), 1)

    operational_score = min(100, round(100.0 * firing_mitre_rules / mitre_tagged_enabled, 1)) if mitre_tagged_enabled > 0 else 0

    total_rules = ar_total + cd_total
    tagged_rules = ar_with_tactics + cd_with_mitre
    tagging_score = round(100.0 * tagged_rules / total_rules, 1) if total_rules > 0 else 0

    completed_soc = sum(1 for r in soc_coverage_recs if r.get('state') in ('CompletedBySystem', 'Completed', 'CompletedByUser'))
    total_soc = len(soc_coverage_recs)
    soc_align_score = round(100.0 * completed_soc / total_soc, 1) if total_soc > 0 else 50

    weights = {'breadth': 0.25, 'balance': 0.10, 'operational': 0.30, 'tagging': 0.15, 'socAlign': 0.20}
    final_score = round(
        breadth_score * weights['breadth'] +
        balance_score * weights['balance'] +
        operational_score * weights['operational'] +
        tagging_score * weights['tagging'] +
        soc_align_score * weights['socAlign'],
    1)

    credit_stats = {'Fired': 0, 'Ready': 0, 'Partial': 0, 'NoData': 0, 'TierBlocked': 0, 'Unknown': 0}
    for s in tech_credit_breakdown.values():
        credit_stats[s] = credit_stats.get(s, 0) + 1

    print(f'   Breadth:      {breadth_score} (weight {weights["breadth"]})')
    print(f'   Balance:      {balance_score} (weight {weights["balance"]})')
    print(f'   Operational:  {operational_score} (weight {weights["operational"]})')
    print(f'   Tagging:      {tagging_score} (weight {weights["tagging"]})')
    print(f'   SOC Align:    {soc_align_score} (weight {weights["socAlign"]})')
    print(f'   {"━" * 20}')
    print(f'   MITRE Score:  {final_score} / 100')
    print(f'   Tier 1 (Alert-Proven):     {len(tier1_techniques)} techniques')
    print(f'   Tier 2 (Deployed Cap):     {len(tier2_techniques)} techniques')
    print(f'   Tier 3 (Catalog Cap):      {len(tier3_techniques)} techniques')

    overall_combined_pct = round(100.0 * total_combined_techs / total_framework_techs, 1) if total_framework_techs > 0 else 0

    # ═══════════════════════════════════════════════════════════════
    # BUILD PRERENDERED BLOCKS
    # ═══════════════════════════════════════════════════════════════
    print('\n📐 Building PRERENDERED blocks...')
    pre = io.StringIO()

    prod_abbrev = {
        'Microsoft Defender for Endpoint': 'MDE', 'Microsoft Defender XDR': 'MXDR',
        'Microsoft Defender for Identity': 'MDI', 'Microsoft Defender for Cloud Apps': 'MDCA',
        'Microsoft Defender for Office 365': 'MDO', 'Microsoft Entra ID Protection': 'AADIP',
        'Microsoft Defender for Cloud': 'MDC', 'Microsoft Purview DLP': 'DLP',
        'Microsoft Defender for IoT': 'MDIoT', 'Microsoft 365 Insider Risk Management': 'IRM',
        'Microsoft Application Protection': 'MAP',
    }
    tactic_display = {
        'Reconnaissance': 'Reconnaissance', 'ResourceDevelopment': 'Resource Development',
        'InitialAccess': 'Initial Access', 'Execution': 'Execution',
        'Persistence': 'Persistence', 'PrivilegeEscalation': 'Privilege Escalation',
        'DefenseEvasion': 'Defense Evasion', 'CredentialAccess': 'Credential Access',
        'Discovery': 'Discovery', 'LateralMovement': 'Lateral Movement',
        'Collection': 'Collection', 'CommandAndControl': 'Command and Control',
        'Exfiltration': 'Exfiltration', 'Impact': 'Impact',
    }

    def get_prod_abbrev(dn):
        return prod_abbrev.get(dn, dn)

    def format_platform_alerts(tech_id, max_alerts=5):
        if tech_id not in tier1_techniques:
            return ''
        details = [d for d in tier1_techniques[tech_id].get('AlertDetails', []) if d]
        if not details:
            return ''
        fmt = []
        for d in details[:max_alerts]:
            pn = d.get('Product')
            if pn:
                pn = prod_aliases.get(pn, pn)
                pn = prod_display_names.get(pn, pn)
                fmt.append(f'[{get_prod_abbrev(pn)}] {d["Name"]}')
            else:
                fmt.append(d['Name'])
        result = '; '.join(fmt)
        if len(details) > max_alerts:
            result += f'; +{len(details) - max_alerts} platform'
        return result

    # ─── PRERENDERED.TacticCoverageMatrix ────────────────────────
    pre.write('## PRERENDERED\n\n### TacticCoverageMatrix\n')
    pre.write('<!-- Pre-rendered §2 table. Copy VERBATIM. -->\n\n')
    pre.write('| # | Badge | Tactic | Enabled Rules | Framework Techniques | Covered Techniques | Coverage % |\n')
    pre.write('|---|-------|--------|---------------|---------------------|--------------------|------------|\n')
    row_num = 0
    for tactic in tactic_order:
        row_num += 1
        dn = tactic_display.get(tactic, tactic)
        rc = tactic_rule_count.get(tactic, 0)
        ti = attack_ref['tactics'].get(tactic, {})
        ft = ti.get('techniqueCount', 0)
        covered = sum(1 for t in ti.get('techniques', []) if technique_rule_count.get(t['id'], 0) > 0)
        pct = round(100.0 * covered / ft, 1) if ft > 0 else 0
        if pct == 0: badge = '🔴'
        elif pct <= 15: badge = '🟠'
        elif pct <= 30: badge = '🟡'
        elif pct <= 50: badge = '🔵'
        elif pct <= 75: badge = '🟢'
        else: badge = '✅'
        pre.write(f'| {row_num} | {badge} | {dn} | {rc} | {ft} | {covered} | {pct}% |\n')
    pre.write(f'| | | **TOTAL** | **{total_enabled_rules}** | **{total_framework_techs}** | **{total_covered_techs}** | **{overall_coverage}%** |\n')

    # ─── PRERENDERED.CombinedTacticCoverage ──────────────────────
    pre.write('\n### CombinedTacticCoverage\n')
    pre.write('| Tactic | Rule-Based | T1 | T2 | T3 | Combined | Framework | Coverage |\n')
    pre.write('|--------|--------|----|----|----|---------|-----------|--------|\n')
    pr_t1 = pr_t2 = pr_t3 = pr_rb = pr_comb = pr_fw = 0
    for tactic in tactic_order:
        ti = attack_ref['tactics'].get(tactic, {})
        dn = tactic_display.get(tactic, tactic)
        ft = ti.get('techniqueCount', 0)
        t1 = t2 = t3 = rb = comb = 0
        for tech in ti.get('techniques', []):
            tid = tech['id']
            if tid in tier1_techniques: t1 += 1
            elif tid in tier2_techniques: t2 += 1
            elif tid in tier3_techniques: t3 += 1
            if technique_rule_count.get(tid, 0) > 0: rb += 1
            if technique_rule_count.get(tid, 0) > 0 or tid in tier1_techniques or tid in tier2_techniques:
                comb += 1
        cpct = round(100.0 * comb / ft, 1) if ft > 0 else 0
        pre.write(f'| {dn} | {rb} | {t1} | {t2} | {t3} | {comb} | {ft} | {cpct}% |\n')
        pr_t1 += t1; pr_t2 += t2; pr_t3 += t3; pr_rb += rb; pr_comb += comb; pr_fw += ft
    pr_pct = round(100.0 * pr_comb / pr_fw, 1) if pr_fw > 0 else 0
    pre.write(f'| **TOTAL** | **{pr_rb}** | **{pr_t1}** | **{pr_t2}** | **{pr_t3}** | **{pr_comb}** | **{pr_fw}** | **{pr_pct}%** |\n')

    # ─── PRERENDERED.TechniqueTables ─────────────────────────────
    pre.write('\n### TechniqueTables\n<!-- Per-tactic technique tables. Copy VERBATIM. -->\n')
    for tactic in tactic_order:
        ti = attack_ref['tactics'].get(tactic, {})
        dn = tactic_display.get(tactic, tactic)
        ft = ti.get('techniqueCount', 0)
        cov = sum(1 for t in ti.get('techniques', []) if technique_rule_count.get(t['id'], 0) > 0)
        comb = sum(1 for t in ti.get('techniques', []) if technique_rule_count.get(t['id'], 0) > 0 or t['id'] in tier1_techniques or t['id'] in tier2_techniques)
        cpct_r = round(100.0 * cov / ft, 1) if ft > 0 else 0
        cpct_c = round(100.0 * comb / ft, 1) if ft > 0 else 0
        rows_data = []
        for tech in sorted(ti.get('techniques', []), key=lambda t: t['id']):
            tid = tech['id']
            rc = technique_rule_count.get(tid, 0)
            tier = None
            if tid in tier1_techniques: tier = 'T1'
            elif tid in tier2_techniques: tier = 'T2'
            elif tid in tier3_techniques: tier = 'T3'
            if rc > 0: badge = '✅'
            elif tier == 'T1': badge = '🟢'
            elif tier == 'T2': badge = '🔵'
            elif tier == 'T3': badge = '⬜'
            else: badge = '❌'
            sort_p = 1 if rc > 0 else (2 if tier == 'T1' else (3 if tier == 'T2' else (4 if tier == 'T3' else 5)))
            # Detections column
            dets = '—'
            max_d = 5
            if rc > 0:
                rn_list = technique_rule_names.get(tid, [])
                shown_r = rn_list[:max_d]
                remaining = max_d - len(shown_r)
                shown_p = []
                overflow_r = max(0, len(rn_list) - max_d)
                overflow_p = 0
                if tier == 'T1' and remaining > 0 and tid in tier1_techniques:
                    ad = [d for d in tier1_techniques[tid].get('AlertDetails', []) if d]
                    for d in ad[:remaining]:
                        pn = d.get('Product')
                        if pn:
                            pn = prod_aliases.get(pn, pn)
                            pn = prod_display_names.get(pn, pn)
                            shown_p.append(f'[{get_prod_abbrev(pn)}] {d["Name"]}')
                        else:
                            shown_p.append(d['Name'])
                    overflow_p = max(0, len(ad) - remaining)
                elif tier == 'T1' and remaining <= 0 and tid in tier1_techniques:
                    overflow_p = len([d for d in tier1_techniques[tid].get('AlertDetails', []) if d])
                dets = '; '.join(shown_r + shown_p)
                oparts = []
                if overflow_r > 0: oparts.append(f'{overflow_r} rules')
                if overflow_p > 0: oparts.append(f'{overflow_p} platform')
                if oparts:
                    dets += f'; +{", ".join(oparts)}'
            elif tier == 'T1':
                pa = format_platform_alerts(tid, max_d)
                if pa:
                    dets = pa
            # Platform column
            plat = '—'
            if tier == 'T1':
                rp = tier1_techniques[tid].get('Products', [])
                np = list(set(prod_display_names.get(prod_aliases.get(p, p), p) for p in rp))
                plat = f'Tier 1: {", ".join(get_prod_abbrev(p) for p in np)}'
            elif tier == 'T2':
                rp = tier2_techniques[tid].get('Products', [])
                np = list(set(prod_display_names.get(p, p) for p in rp))
                plat = f'Tier 2: {", ".join(get_prod_abbrev(p) for p in np)}'
            elif tier == 'T3':
                plat = '⬜ Tier 3'
            rows_data.append((sort_p, -rc, tid, badge, tech['name'], tech.get('subTechniques', 0), rc, dets, plat))

        rows_data.sort(key=lambda r: (r[0], r[1], r[2]))
        # Limit gap rows
        gap_rows = [r for r in rows_data if r[0] == 5]
        non_gap = [r for r in rows_data if r[0] < 5]
        truncated = 0
        if len(gap_rows) > args.max_gap_rows:
            truncated = len(gap_rows) - args.max_gap_rows
            gap_rows = gap_rows[:args.max_gap_rows]
        display_rows = non_gap + gap_rows

        if comb > cov:
            pre.write(f'\n#### {dn} ({cov}/{ft} rules — {cpct_r}% · {comb}/{ft} combined — {cpct_c}%)\n')
        else:
            pre.write(f'\n#### {dn} ({cov}/{ft} techniques — {cpct_r}%)\n')
        if display_rows:
            pre.write('\n| Technique | Sub-Techs | Rules | Detections | Platform |\n')
            pre.write('|-----------|-----------|-------|------------|----------|\n')
            for r in display_rows:
                pre.write(f'| {r[3]} {r[2]} {r[4]} | {r[5]} | {r[6]} | {r[7]} | {r[8]} |\n')
            if truncated:
                pre.write(f'\n...and {truncated} additional uncovered techniques.\n')

    # ─── PRERENDERED.IncidentsByTactic ────────────────────────────
    pre.write('\n### IncidentsByTactic\n')
    ext_tactic_display = {
        'PreAttack': 'Pre-Attack', 'InhibitResponseFunction': 'Inhibit Response Function',
        'ImpairProcessControl': 'Impair Process Control',
    }
    tactic_order_idx = {t: i for i, t in enumerate(tactic_order)}
    if isinstance(m5_data, list) and len(m5_data) > 0:
        pre.write('\n| Tactic | Incidents | High | Medium | Low | Info | TP | FP | BP |\n')
        pre.write('|--------|-----------|------|--------|-----|------|----|----|\n')
        sorted_m5 = sorted(m5_data, key=lambda r: tactic_order_idx.get(r.get('Tactic', ''), 999))
        s_inc = s_h = s_m = s_l = s_i = s_tp = s_fp = s_bp = 0
        for row in sorted_m5:
            rt = row.get('Tactic', '')
            dt = tactic_display.get(rt, ext_tactic_display.get(rt, rt))
            inc = int(row.get('IncidentCount', 0))
            h = int(row.get('HighSev', 0)); m_ = int(row.get('MediumSev', 0))
            l_ = int(row.get('LowSev', 0)); i_ = int(row.get('InfoSev', 0))
            tp = int(row.get('TP', 0)); fp = int(row.get('FP', 0)); bp = int(row.get('BP', 0))
            vb = '🔴 ' if inc >= 100 else ('🟠 ' if inc >= 25 else '')
            pre.write(f'| {vb}{dt} | {inc} | {h} | {m_} | {l_} | {i_} | {tp} | {fp} | {bp} |\n')
            s_inc += inc; s_h += h; s_m += m_; s_l += l_; s_i += i_; s_tp += tp; s_fp += fp; s_bp += bp
        pre.write(f'| **TOTAL** | **{s_inc}** | **{s_h}** | **{s_m}** | **{s_l}** | **{s_i}** | **{s_tp}** | **{s_fp}** | **{s_bp}** |\n')
    else:
        pre.write('<!-- NO_DATA -->\n')

    # ─── PRERENDERED.ActiveVsTagged ──────────────────────────────
    pre.write('\n### ActiveVsTagged\n')
    firing_rule_ids: set[str] = set()
    firing_cd_names: set[str] = set()
    if isinstance(m4_data, list):
        for alert in m4_data:
            src = alert.get('Source', 'AR')
            if src == 'AR' and alert.get('RuleId', '') != 'CustomDetection':
                firing_rule_ids.add(alert['RuleId'])
            elif src == 'CD':
                firing_cd_names.add(alert.get('AlertName', ''))

    tactic_firing_rc: dict[str, int] = {}
    tactic_silent_rc: dict[str, int] = {}
    silent_rules_list: list[dict] = []

    if isinstance(m1_data, list):
        for rule in m1_data:
            is_en = rule.get('enabled') in (True, 'true', 'True')
            tactics = rule.get('tactics') or []
            if not is_en or not tactics:
                continue
            is_firing = rule.get('ruleId', '') in firing_rule_ids
            for t in tactics:
                if is_firing:
                    tactic_firing_rc[t] = tactic_firing_rc.get(t, 0) + 1
                else:
                    tactic_silent_rc[t] = tactic_silent_rc.get(t, 0) + 1
            if not is_firing:
                techs = rule.get('techniques') or []
                silent_rules_list.append({
                    'Name': rule.get('displayName', ''), 'Source': 'AR',
                    'Tactics': ', '.join(tactic_display.get(t, t) for t in tactics),
                    'Techniques': ', '.join(techs) if techs else '—',
                })

    if isinstance(m2_data, list):
        for cd in m2_data:
            is_en = cd.get('isEnabled') in (True, 'true', 'True')
            cd_mt = (cd.get('detectionAction', {}).get('alertTemplate', {}).get('mitreTechniques') or [])
            cd_cat = cd.get('detectionAction', {}).get('alertTemplate', {}).get('category', '')
            has_t = cd_cat and cd_cat in tactic_order
            has_tech = len(cd_mt) > 0
            if not is_en or (not has_t and not has_tech):
                continue
            cd_tacs = []
            if has_t:
                cd_tacs = [cd_cat]
            else:
                for tech in cd_mt:
                    pm = re.match(r'^(T\d{4})', tech)
                    pid = pm.group(1) if pm else tech
                    cd_tacs.extend(tech_to_tactics.get(pid, []))
                cd_tacs = list(set(cd_tacs))
            is_firing = cd.get('displayName', '') in firing_cd_names
            for t in cd_tacs:
                if is_firing:
                    tactic_firing_rc[t] = tactic_firing_rc.get(t, 0) + 1
                else:
                    tactic_silent_rc[t] = tactic_silent_rc.get(t, 0) + 1
            if not is_firing:
                silent_rules_list.append({
                    'Name': cd.get('displayName', ''), 'Source': 'CD',
                    'Tactics': ', '.join(tactic_display.get(t, t) for t in cd_tacs),
                    'Techniques': ', '.join(cd_mt) if cd_mt else '—',
                })

    pre.write('\n| Tactic | Tagged Rules | Firing | Silent | Active (Alerts) | Status |\n')
    pre.write('|--------|-------------|--------|--------|-----------------|--------|\n')
    paper_tiger_count = 0
    for tactic in tactic_order:
        tagged = tactic_rule_count.get(tactic, 0)
        fa = firing_tactics.get(tactic, 0)
        fr = tactic_firing_rc.get(tactic, 0)
        sr = tactic_silent_rc.get(tactic, 0)
        dn = tactic_display.get(tactic, tactic)
        if tagged == 0:
            sb = '🔴 No coverage'
        elif fa == 0:
            paper_tiger_count += 1
            sb = '⚠️ All silent'
        elif sr >= fr and sr >= 3:
            sb = '🟡 Mostly silent'
        else:
            sb = '✅ Validated'
        pre.write(f'| {dn} | {tagged} | {fr} | {sr} | {fa} | {sb} |\n')

    # Silent rules detail
    if silent_rules_list:
        pre.write(f'\n#### SilentRules\n<!-- {len(silent_rules_list)} enabled MITRE-tagged rules with 0 alerts -->\n')
        pre.write('\n| Rule | Source | Tactics | Techniques |\n|------|--------|---------|------------|\n')
        for sr in sorted(silent_rules_list, key=lambda r: (r['Tactics'], r['Name']))[:40]:
            pre.write(f'| {sr["Name"]} | {sr["Source"]} | {sr["Tactics"]} | {sr["Techniques"]} |\n')
        if len(silent_rules_list) > 40:
            pre.write(f'\n...and {len(silent_rules_list) - 40} additional silent rules.\n')

    # ─── PRERENDERED.ThreatScenarios ─────────────────────────────
    pre.write('\n### ThreatScenarios\n')
    main_scenarios = []
    reviewed_scenarios = []
    for s in parsed_scenarios:
        gap = s['Recommended'] - s['Active']
        rate = s['CompletionRate']
        if rate < 15: badge = '🔴'
        elif rate < 35: badge = '🟠'
        elif rate < 60: badge = '🟡'
        else: badge = '✅'
        state_display = s['State']
        is_reviewed = False
        if s['State'] == 'CompletedByUser':
            if rate >= 50:
                is_reviewed = True
            else:
                state_display = f'⚠️ Premature ({rate}%)'
        # Key tactic gaps
        key_gaps = '—'
        if s['TacticSummary']:
            underserved = []
            for entry in s['TacticSummary'].split(', '):
                m = re.match(r'^(\w+):(\d+)/(\d+)$', entry)
                if m:
                    tn, tc, tr_ = m.group(1), int(m.group(2)), int(m.group(3))
                    if tr_ > 0 and tc / tr_ < 0.5:
                        underserved.append((tactic_display.get(tn, tn), tc / tr_))
            if underserved:
                underserved.sort(key=lambda x: x[1])
                key_gaps = ', '.join(u[0] for u in underserved[:3])
        row_data = {'Badge': badge, 'Scenario': s['Scenario'], 'Active': s['Active'],
                    'Rec': s['Recommended'], 'Gap': gap, 'Platform': s['Platform'],
                    'Sentinel': s['Sentinel'], 'SentinelGap': s['SentinelGap'],
                    'State': state_display, 'KeyGaps': key_gaps, 'Rate': rate}
        if is_reviewed:
            reviewed_scenarios.append(row_data)
        else:
            main_scenarios.append(row_data)

    if main_scenarios or reviewed_scenarios:
        pre.write('\n#### Active Gaps\n\n| Priority | Scenario | Active | Rec. | Rate | Gap | Platform | Sentinel | Sentinel Gap | State | Key Tactic Gaps |\n')
        pre.write('|----------|----------|--------|------|------|-----|----------|----------|--------------|-------|-----------------|\n')
        for r in sorted(main_scenarios, key=lambda x: x['Gap'], reverse=True):
            pre.write(f'| {r["Badge"]} | {r["Scenario"]} | {r["Active"]} | {r["Rec"]} | {r["Rate"]}% | {r["Gap"]} | {r["Platform"]} | {r["Sentinel"]} | {r["SentinelGap"]} | {r["State"]} | {r["KeyGaps"]} |\n')
        if reviewed_scenarios:
            pre.write('\n#### Reviewed & Addressed Scenarios\n\n| Scenario | Active/Rec. | Rate | Gap | Note |\n')
            pre.write('|----------|-------------|------|-----|------|\n')
            for r in sorted(reviewed_scenarios, key=lambda x: x['Rate'], reverse=True):
                note = 'Reviewed — near-complete' if r['Rate'] >= 80 else ('Reviewed — remaining gap likely platform-covered' if r['Rate'] >= 65 else 'Reviewed — partial coverage accepted')
                pre.write(f'| {r["Scenario"]} | {r["Active"]}/{r["Rec"]} | {r["Rate"]}% | {r["Gap"]} | {note} |\n')

    # ─── PRERENDERED.DataReadiness ───────────────────────────────
    pre.write('\n### DataReadiness\n')
    if total_checked > 0:
        pre.write('\n| Status | Rules | Description |\n|--------|-------|-------------|\n')
        pre.write(f'| ✅ Ready | {ready_count} | All referenced tables have active ingestion |\n')
        pre.write(f'| ⚠️ Partial | {partial_count} | Some tables have data, others do not |\n')
        pre.write(f'| 🔴 No Data | {no_data_count} | Primary table(s) have zero ingestion |\n')
        pre.write(f'| 🚫 Tier Blocked | {tier_blocked_count} | Table on Basic/Data Lake tier |\n')
        pre.write(f'| **Data Readiness** | **{readiness_pct}%** | Ready / total checked |\n')
        if non_ready_rules:
            pre.write('\n#### Rules with Missing Data Sources\n\n| Rule Name | Tables | Status | Missing Tables | Available Volumes |\n')
            pre.write('|-----------|--------|--------|----------------|-------------------|\n')
            for nr in non_ready_rules:
                sb = {'NoData': '🔴 NoData', 'TierBlocked': '🚫 TierBlocked', 'Partial': '⚠️ Partial'}.get(nr['Status'], nr['Status'])
                pre.write(f'| {nr["RuleName"]} | {nr["Tables"]} | {sb} | {nr["MissingTables"]} | {nr["Volumes"]} |\n')
        if missing_tables_summary:
            pre.write('\n#### Missing Tables — Impact Summary\n\n| Table | Rules Affected |\n|-------|----------------|\n')
            for t, c in sorted(missing_tables_summary.items(), key=lambda x: -x[1]):
                pre.write(f'| {t} | {c} |\n')
        if tier_blocked_tables_summary:
            pre.write('\n#### Phantom Coverage — Tier-Blocked Tables\n\n| Table | Tier | Rules Affected |\n|-------|------|----------------|\n')
            for t, v in sorted(tier_blocked_tables_summary.items(), key=lambda x: -x[1]['Count']):
                pre.write(f'| {t} | {v["Tier"]} | {v["Count"]} |\n')

    # ─── PRERENDERED.ConnectorHealth ─────────────────────────────
    pre.write('\n### ConnectorHealth\n')
    if connector_health:
        pr_healthy = pr_degraded = pr_failing = 0
        unhealthy = []
        for name, v in connector_health.items():
            if v['LastStatus'] == 'Failure':
                pr_failing += 1
                unhealthy.append(v | {'Name': name})
            elif v['HealthPct'] < 90:
                pr_degraded += 1
                unhealthy.append(v | {'Name': name})
            else:
                pr_healthy += 1
        pre.write('\n| Status | Connectors | Description |\n|--------|------------|-------------|\n')
        pre.write(f'| ✅ Healthy | {pr_healthy} | >90% success rate |\n')
        pre.write(f'| ⚠️ Degraded | {pr_degraded} | <90% success rate |\n')
        pre.write(f'| 🔴 Failing | {pr_failing} | Last fetch failed |\n')
        if unhealthy:
            pre.write('\n#### Connectors with Health Issues\n\n| Connector | Last Status | Success | Failure | Health % |\n')
            pre.write('|-----------|-------------|---------|---------|----------|\n')
            for uh in sorted(unhealthy, key=lambda x: x['HealthPct']):
                pre.write(f'| {uh["Name"]} | {uh["LastStatus"]} | {uh["SuccessCount"]} | {uh["FailureCount"]} | {uh["HealthPct"]}% |\n')

    # ─── PRERENDERED.AlertFiring ─────────────────────────────────
    pre.write('\n### AlertFiring\n')
    if isinstance(m4_data, list) and len(m4_data) > 0:
        pr_alert_rows = []
        pr_ar = pr_cd = pr_unmatched = 0
        for alert in m4_data:
            src = alert.get('Source', 'AR')
            if src == 'AR': pr_ar += 1
            elif src == 'CD': pr_cd += 1
            rid = alert.get('RuleId', '')
            # Tactics
            if src == 'AR' and rid in all_rule_tactics and all_rule_tactics[rid]:
                dt = ', '.join(re.sub(r'([a-z])([A-Z])', r'\1 \2', t) for t in all_rule_tactics[rid])
            else:
                dt = '—'
            # Techniques
            if src == 'AR' and rid in all_rule_techniques and all_rule_techniques[rid]:
                dtech = ', '.join(all_rule_techniques[rid])
            else:
                dtech = '—'
            if src == 'AR' and dt == '—' and dtech == '—':
                pr_unmatched += 1
            sev_parts = []
            if int(alert.get('HighSev', 0)) > 0: sev_parts.append(f'H:{alert["HighSev"]}')
            if int(alert.get('MediumSev', 0)) > 0: sev_parts.append(f'M:{alert["MediumSev"]}')
            if int(alert.get('LowSev', 0)) > 0: sev_parts.append(f'L:{alert["LowSev"]}')
            if int(alert.get('InfoSev', 0)) > 0: sev_parts.append(f'I:{alert["InfoSev"]}')
            pr_alert_rows.append({
                'Badge': f'[{src}]', 'Name': alert.get('AlertName', ''),
                'Tactics': dt, 'Techniques': dtech,
                'Count': int(alert.get('AlertCount', 0)),
                'Severity': ' '.join(sev_parts) or '—',
            })
        m4_cap = 50
        title = f'Top {m4_cap}' if len(pr_alert_rows) >= m4_cap else str(len(pr_alert_rows))
        pre.write(f'\nSectionTitle: {title} Alert-Producing Rules\n')
        pre.write('\n| Alert | Tactics | Techniques | Alerts | Severity |\n|-------|---------|------------|--------|----------|\n')
        for row in sorted(pr_alert_rows, key=lambda r: -r['Count']):
            vb = '🔴 ' if row['Count'] >= 100 else ('🟠 ' if row['Count'] >= 20 else '')
            pre.write(f'| {vb}{row["Badge"]} {row["Name"]} | {row["Tactics"]} | {row["Techniques"]} | {row["Count"]} | {row["Severity"]} |\n')

    prerendered_block = pre.getvalue().rstrip()
    print('   ✅ PRERENDERED blocks complete')

    # ═══════════════════════════════════════════════════════════════
    # TRIM REDUNDANT SCRATCHPAD SECTIONS
    # ═══════════════════════════════════════════════════════════════
    def remove_section(block: str, section_name: str) -> str:
        lines = block.split('\n')
        result = []
        skipping = False
        for line in lines:
            if line.rstrip() == f'### {section_name}':
                skipping = True
                continue
            if skipping and re.match(r'^#{2,3} ', line):
                skipping = False
            if not skipping:
                result.append(line)
        return '\n'.join(result)

    for sect in ['ThreatScenarios']:
        phase2_block = remove_section(phase2_block, sect)
    for sect in ['IncidentsByTactic', 'PlatformTacticCoverage', 'DataReadiness_Summary',
                 'MissingTables', 'TierBlockedTables', 'ConnectorHealth_Summary',
                 'AlertFiring_MitreCorrelation', 'ActiveTacticCoverage',
                 'PlatformAlertCoverage', 'Tier1_AlertProven', 'Tier2_DeployedCapability',
                 'Tier3_CatalogCapability', 'DeployedProducts_Supplementary',
                 'TechniqueDetail', 'UnverifiedTables']:
        phase3_block = remove_section(phase3_block, sect)

    # ═══════════════════════════════════════════════════════════════
    # WRITE SCRATCHPAD
    # ═══════════════════════════════════════════════════════════════
    print('\n📝 Writing scratchpad...')
    ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    scratchpad_path = output_dir / f'mitre_scratch_{ts}.md'
    output_dir.mkdir(parents=True, exist_ok=True)

    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    scratchpad = f"""# SCRATCHPAD — MITRE ATT&CK Coverage Report
<!-- Auto-generated by invoke_mitre_scan.py. DO NOT edit manually. -->

## META
Workspace: {workspace_name}
WorkspaceId: {workspace_id}
Days: {days}
Generated: {now_iso}
ATT&CK_Version: {attack_ref['version']}
ATT&CK_Techniques: {attack_ref['totalTechniques']}
ATT&CK_SubTechniques: {attack_ref['totalSubTechniques']}
QueryCount: {len(all_queries)}
ExecutionTime: {total_query_time}s
Phases: {','.join(str(p) for p in phases_to_run)}

## SCORE
MITRE_Score: {final_score}
Breadth: {breadth_score}
Breadth_RuleOnly: {round(rule_breadth, 1)}
Breadth_Combined: {round(combined_breadth, 1)}
Breadth_Blend: 60/40
Balance: {balance_score}
Operational: {operational_score}
Tagging: {tagging_score}
SOC_Alignment: {soc_align_score}
Weights: breadth={weights['breadth']},balance={weights['balance']},operational={weights['operational']},tagging={weights['tagging']},socAlign={weights['socAlign']}
Platform_Tier1: {len(tier1_techniques)}
Platform_Tier2: {len(tier2_techniques)}
Platform_Tier3: {len(tier3_techniques)}
Platform_ActiveProducts: {len(display_products) if 'display_products' in dir() else 0}
DataReadiness_Pct: {readiness_pct}
DataReadiness_Ready: {ready_count}
DataReadiness_Partial: {partial_count}
DataReadiness_NoData: {no_data_count}
DataReadiness_TierBlocked: {tier_blocked_count}
PhantomTechniques: {phantom_tech_count}
PhantomTechniqueList: {','.join(sorted(phantom_techniques))}
TechCredit_Fired: {credit_stats['Fired']}
TechCredit_Ready: {credit_stats['Ready']}
TechCredit_Partial: {credit_stats['Partial']}
TechCredit_NoData: {credit_stats['NoData']}
TechCredit_TierBlocked: {credit_stats['TierBlocked']}
TechCredit_Unknown: {credit_stats['Unknown']}
TotalWeightedCredit: {round(total_weighted_credit, 2)}
RuleBasedPlusPlatform_Coverage: {total_combined_techs} / {total_framework_techs} ({overall_combined_pct}%)
CTID_Version: {ctid_ref.get('metadata', {}).get('ctid_version', 'N/A') if ctid_ref else 'N/A'}

{phase1_block}

{phase2_block}

{phase3_block}

{prerendered_block}
"""

    with open(scratchpad_path, 'w', encoding='utf-8') as f:
        f.write(scratchpad)

    file_size = round(scratchpad_path.stat().st_size / 1024, 1)

    report_path = None
    if args.render_report:
        report_root = workspace_root if config_found else script_dir.parent
        report_dir = report_root / 'reports' / 'mitre-coverage-report'
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f'MITRE_Coverage_Report_{ts}.md'

        tagging_block = _prerendered_section(phase2_block, 'MitreTaggingSuggestions')
        if tagging_block == '<!-- NO_DATA -->':
            tagging_block = '(No MITRE tagging recommendations found)'

        query_reference = []
        for query_id, query in all_queries.items():
            result = all_results.get(query_id, {})
            status = result.get('_status', 'OK') if isinstance(result, dict) else 'OK'
            query_reference.append({
                'phase': query.get('phase', ''),
                'id': query_id.replace('mitre-', '').upper(),
                'type': query.get('type', '').upper(),
                'description': query.get('name', ''),
                'status': status,
            })

        report_context = {
            'meta': {
                'generated': now_iso, 'workspace_name': workspace_name,
                'workspace_id': workspace_id, 'days': days,
                'execution_time': total_query_time,
                'phases': ','.join(str(p) for p in phases_to_run),
            },
            'score': {
                'final': final_score, 'breadth': breadth_score, 'balance': balance_score,
                'operational': operational_score, 'tagging': tagging_score,
                'soc_alignment': soc_align_score, 'weighted_credit': round(total_weighted_credit, 2),
                'framework_total': total_framework_techs, 'combined_total': total_combined_techs,
                'combined_pct': overall_combined_pct, 'tactics_with_rules': tactics_with_rules,
                'firing_mitre_rules': firing_mitre_rules, 'mitre_tagged_enabled': mitre_tagged_enabled,
                'tagged_rules': tagged_rules, 'total_rules': total_rules,
                'completed_soc': completed_soc, 'total_soc': total_soc,
                'tier1': len(tier1_techniques), 'tier2': len(tier2_techniques),
                'tier3': len(tier3_techniques), 'rule_covered': total_covered_techs,
                'ctid_version': ctid_ref.get('metadata', {}).get('ctid_version', 'N/A') if ctid_ref else 'N/A',
                'readiness_ready': ready_count, 'readiness_total': total_checked,
                'readiness_pct': readiness_pct,
            },
            'inventory': {
                'ar_total': ar_total, 'ar_enabled': ar_enabled, 'ar_disabled': ar_disabled,
                'ar_no_mitre_enabled': ar_no_mitre_enabled, 'cd_status': cd_status,
                'cd_total': cd_total, 'cd_enabled': cd_enabled, 'cd_disabled': cd_disabled,
                'cd_no_mitre_enabled': cd_no_mitre_enabled,
            },
            'attack_ref': attack_ref, 'tactic_order': tactic_order,
            'tactic_display': tactic_display, 'tactic_rule_count': tactic_rule_count,
            'technique_rule_count': technique_rule_count,
            'technique_rule_names': technique_rule_names,
            'tier1_techniques': tier1_techniques, 'tier2_techniques': tier2_techniques,
            'untagged_rules': untagged_rules, 'ics_techs': ics_techs,
            'parsed_scenarios': parsed_scenarios, 'prerendered_block': prerendered_block,
            'tagging_block': tagging_block, 'query_reference': query_reference,
        }
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(build_report(report_context))

    print()
    print('━' * 57)
    print('  ✅ Scratchpad written successfully')
    print('━' * 57)
    print(f'  📄 Path: {scratchpad_path}')
    if report_path:
        print(f'  📄 Report: {report_path}')
    print(f'  📏 Size: {file_size} KB')
    print(f'  ⏱️  Total time: {total_query_time}s')
    print(f'  📊 MITRE Score: {final_score} / 100')
    print(f'  🎯 Technique Coverage: {total_covered_techs} / {total_framework_techs} ({overall_coverage}%)')
    print(f'  🛡️  Combined (Rule+Platform): {total_combined_techs} / {total_framework_techs} ({overall_combined_pct}%)')
    print()


if __name__ == '__main__':
    main()
