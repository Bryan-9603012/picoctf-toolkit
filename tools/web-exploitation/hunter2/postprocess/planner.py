# postprocess/planner.py
"""
AI Planner for Intelligent Chaining

Based on application map and finding analysis:
- Plans optimal attack chains
- Suggests next steps based on current findings
- Ranks paths by exploitability
- Adapts to discovered context
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum


class AttackPhase(Enum):
    """Phases of an attack chain"""
    RECON = "recon"
    ACCESS = "access"
    ESCALATION = "escalation"
    EXFILTRATION = "exfiltration"
    PERSISTENCE = "persistence"


@dataclass
class AttackStep:
    """Single step in attack chain"""
    phase: AttackPhase
    action: str
    target_route: str
    expected_result: str
    preconditions: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    difficulty: str = "medium"  # easy, medium, hard


@dataclass
class AttackPlan:
    """Complete attack plan"""
    target: str
    steps: List[AttackStep] = field(default_factory=list)
    estimated_difficulty: str = "medium"
    success_probability: float = 0.0
    findings_required: List[str] = field(default_factory=list)


PRIMITIVE_ACTIONS = {
    "recon": [
        "directory_discovery",
        "port_scan",
        "tech_fingerprint",
        "route_mapping",
    ],
    "access": [
        "credential_theft",
        "session_hijack",
        "auth_bypass",
        "path_traversal",
        "injection",
    ],
    "escalation": [
        "privilege_escalation",
        "lateral_movement",
        "sensitive_data_access",
        "configuration_access",
    ],
    "exfiltration": [
        "data_dump",
        "credentials_export",
        "source_code_access",
        "database_dump",
    ],
    "persistence": [
        "backdoor_plant",
        "schedule_task",
        "registry_modify",
    ],
}


PREREQUISITE_MAP = {
    "credential_theft": ["directory_discovery"],
    "session_hijack": ["directory_discovery"],
    "auth_bypass": ["route_mapping"],
    "path_traversal": ["directory_discovery"],
    "privilege_escalation": ["credential_theft", "sensitive_data_access"],
    "lateral_movement": ["credential_theft"],
    "sensitive_data_access": ["directory_discovery", "route_mapping"],
    "configuration_access": ["directory_discovery"],
    "data_dump": ["sensitive_data_access"],
    "credentials_export": ["credential_theft"],
    "source_code_access": ["sensitive_data_access"],
}


def analyze_finding_for_planning(finding: Any) -> Dict[str, Any]:
    """Extract planning-relevant info from finding"""
    return {
        "rule_id": getattr(finding, 'rule_id', ''),
        "url": getattr(finding, 'url', ''),
        "severity": getattr(finding, 'severity', 'medium'),
        "exploitability": getattr(finding, 'exploitability', 'medium'),
        "extracted_data": getattr(finding, 'extracted_data', {}),
    }


def suggest_next_steps(
    current_findings: List[Any],
    app_map: Dict[str, Any],
) -> List[str]:
    """Suggest next actions based on current findings"""
    suggestions = []
    finding_types = {f.rule_id for f in current_findings}
    
    has_credential = any(
        'credential' in f.rule_id or 'token' in f.rule_id or 'password' in f.rule_id
        for f in current_findings
    )
    has_admin = any('admin' in f.url for f in current_findings)
    has_debug = any('debug' in f.url or 'actuator' in f.url for f in current_findings)
    has_git = any('.git' in f.url for f in current_findings)
    has_config = any('config' in f.url or '.env' in f.url for f in current_findings)
    
    if not has_git:
        suggestions.append("git_directory_discovery")
    
    if not has_config:
        suggestions.append("config_file_discovery")
    
    if has_credential and not has_admin:
        suggestions.append("admin_panel_access")
    
    if has_debug:
        suggestions.append("heapdump_analysis")
    
    if has_credential:
        suggestions.append("privilege_escalation")
    
    suggestions.append("api_endpoint_discovery")
    
    return suggestions


def build_attack_plan(
    target: str,
    findings: List[Any],
    app_map: Dict[str, Any],
) -> AttackPlan:
    """Build attack plan from findings and app map"""
    
    plan = AttackPlan(target=target)
    
    finding_info = [analyze_finding_for_planning(f) for f in findings]
    
    phases_to_steps = {
        AttackPhase.RECON: [],
        AttackPhase.ACCESS: [],
        AttackPhase.ESCALATION: [],
        AttackPhase.EXFILTRATION: [],
        AttackPhase.PERSISTENCE: [],
    }
    
    phases_to_steps[AttackPhase.RECON].extend([
        AttackStep(
            phase=AttackPhase.RECON,
            action="directory_discovery",
            target_route="/.git",
            expected_result="Git repository exposed",
            difficulty="easy",
        ),
        AttackStep(
            phase=AttackPhase.RECON,
            action="config_discovery",
            target_route="/.env",
            expected_result="Environment variables exposed",
            difficulty="easy",
        ),
    ])
    
    for info in finding_info:
        if 'heapdump' in info['rule_id'] or 'actuator' in info['rule_id']:
            phases_to_steps[AttackPhase.ACCESS].append(
                AttackStep(
                    phase=AttackPhase.ACCESS,
                    action="sensitive_data_access",
                    target_route=info['url'],
                    expected_result="Memory/heap data exposed",
                    preconditions=["debug_endpoint_access"],
                    difficulty="easy",
                )
            )
        
        if 'git' in info['rule_id']:
            phases_to_steps[AttackPhase.RECON].append(
                AttackStep(
                    phase=AttackPhase.RECON,
                    action="source_code_access",
                    target_route=info['url'],
                    expected_result="Source code exposed",
                    difficulty="easy",
                )
            )
        
        if info['extracted_data']:
            phases_to_steps[AttackPhase.EXFILTRATION].append(
                AttackStep(
                    phase=AttackPhase.EXFILTRATION,
                    action="credentials_export",
                    target_route=info['url'],
                    expected_result="Credentials extracted",
                    preconditions=["credential_access"],
                    difficulty="easy",
                )
            )
    
    for phase, steps in phases_to_steps.items():
        plan.steps.extend(steps)
    
    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    
    plan.success_probability = min(0.95, 0.3 + (critical_count * 0.15) + (high_count * 0.1))
    
    if critical_count >= 3:
        plan.estimated_difficulty = "easy"
    elif critical_count >= 1:
        plan.estimated_difficulty = "medium"
    else:
        plan.estimated_difficulty = "hard"
    
    plan.findings_required = [f.rule_id for f in findings]
    
    return plan


def rank_paths_by_exploitability(
    paths: List[List[str]],
    findings: List[Any],
) -> List[tuple]:
    """Rank attack paths by exploitability score"""
    
    path_scores = []
    
    for path in paths:
        score = 0
        
        for step in path:
            for f in findings:
                if step in f.url:
                    if f.severity == "critical":
                        score += 10
                    elif f.severity == "high":
                        score += 7
                    elif f.severity == "medium":
                        score += 4
        
        path_scores.append((path, score))
    
    path_scores.sort(key=lambda x: x[1], reverse=True)
    
    return path_scores


def adapt_plan_based_on_finding(
    plan: AttackPlan,
    new_finding: Any,
) -> AttackPlan:
    """Adapt attack plan based on new finding"""
    
    finding_info = analyze_finding_for_planning(new_finding)
    
    if finding_info['severity'] == "critical":
        new_step = AttackStep(
            phase=AttackPhase.ACCESS,
            action="exploit_critical_finding",
            target_route=finding_info['url'],
            expected_result="Critical finding exploited",
            difficulty="easy",
            preconditions=[finding_info['rule_id']],
        )
        plan.steps.insert(0, new_step)
        plan.success_probability = min(0.99, plan.success_probability + 0.1)
    
    return plan


def generate_reconnaissance_plan(
    target: str,
    app_map: Dict[str, Any],
) -> AttackPlan:
    """Generate initial reconnaissance plan"""
    
    plan = AttackPlan(target=target)
    
    routes = app_map.get('routes', [])
    sensitive = app_map.get('sensitive_routes', [])
    debug = app_map.get('debug_endpoints', [])
    
    if sensitive:
        plan.steps.append(
            AttackStep(
                phase=AttackPhase.RECON,
                action="sensitive_route_discovery",
                target_route=sensitive[0],
                expected_result="Sensitive route identified",
                difficulty="easy",
            )
        )
    
    if debug:
        plan.steps.append(
            AttackStep(
                phase=AttackPhase.RECON,
                action="debug_endpoint_discovery",
                target_route=debug[0],
                expected_result="Debug endpoint identified",
                difficulty="easy",
            )
        )
    
    plan.steps.extend([
        AttackStep(
            phase=AttackPhase.RECON,
            action="git_discovery",
            target_route="/.git",
            expected_result="Git directory found",
            difficulty="easy",
        ),
        AttackStep(
            phase=AttackPhase.RECON,
            action="config_discovery",
            target_route="/.env",
            expected_result="Config file found",
            difficulty="easy",
        ),
        AttackStep(
            phase=AttackPhase.RECON,
            action="route_mapping",
            target_route="/api",
            expected_result="API routes mapped",
            difficulty="medium",
        ),
    ])
    
    plan.estimated_difficulty = "medium"
    plan.success_probability = 0.4
    
    return plan


def print_plan_summary(plan: AttackPlan) -> None:
    """Print human-readable plan summary"""
    print(f"\n{'=' * 50}")
    print(f"Attack Plan: {plan.target}")
    print(f"{'=' * 50}")
    
    print(f"\nDifficulty: {plan.estimated_difficulty}")
    print(f"Success Probability: {plan.success_probability:.0%}")
    print(f"Total Steps: {len(plan.steps)}")
    
    current_phase = None
    for step in plan.steps:
        if step.phase != current_phase:
            current_phase = step.phase
            print(f"\n--- {step.phase.value.upper()} ---")
        
        print(f"  [{step.difficulty}] {step.action}")
        print(f"    -> {step.target_route}")
        print(f"    Expected: {step.expected_result}")
    
    print(f"\n{'=' * 50}")