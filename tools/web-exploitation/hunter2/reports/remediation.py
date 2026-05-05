# reports/remediation.py
"""
Remediation Layer - Structured remediation guidance for findings
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class RemediationStep:
    """Single remediation step"""
    step: str
    priority: str  # "immediate", "short", "long"
    effort: str  # "low", "medium", "high"
    description: str


@dataclass
class Remediation:
    """Complete remediation guidance for a finding"""
    summary: str
    steps: List[RemediationStep]
    references: List[str]
    additional_resources: List[str]


# Remediation templates by category
REMEDIATION_TEMPLATES = {
    "heapdump": Remediation(
        summary="Disable heapdump/debug endpoints in production",
        steps=[
            RemediationStep(
                step="Remove heapdump dependency or disable via configuration",
                priority="immediate",
                effort="low",
                description="Set spring-boot: actuator: enabled: false or management.endpoints.enabled: false"
            ),
            RemediationStep(
                step="Add authentication to remaining actuator endpoints",
                priority="short",
                effort="medium",
                description="Require auth for /actuator/* endpoints or disable sensitive endpoints"
            ),
            RemediationStep(
                step="Review environment for other debug endpoints",
                priority="short",
                effort="low",
                description="Search for /debug, /heap, /dump endpoints across all services"
            ),
        ],
        references=[
            "https://docs.spring.io/spring-boot/actuator.html",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        additional_resources=[
            "Disable actuator in production: spring-boot-actuator.disable",
        ]
    ),
    
    "git": Remediation(
        summary="Block access to .git directory via web server",
        steps=[
            RemediationStep(
                step="Configure web server to deny /.git access",
                priority="immediate",
                effort="low",
                description="Add rewrite rule to block /.git/* and return 403"
            ),
            RemediationStep(
                step="Remove .git from web root deployment",
                priority="immediate",
                effort="low",
                description="Exclude .git from deployment package"
            ),
            RemediationStep(
                step="Review for other VCS metadata exposure",
                priority="short",
                effort="low",
                description="Check for .svn, .hg, .bzr directories"
            ),
        ],
        references=[
            "https://cwe.mitre.org/data/definitions/552.html",
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Security_Misconfiguration",
        ],
        additional_resources=[]
    ),
    
    "actuator": Remediation(
        summary="Secure or disable Spring Boot Actuator endpoints",
        steps=[
            RemediationStep(
                step="Disable sensitive actuator endpoints in production",
                priority="immediate",
                effort="low",
                description="Set management.endpoints.web.exposure.exclude=env,heapdump,threaddump"
            ),
            RemediationStep(
                step="Add authentication to actuator endpoints",
                priority="short",
                effort="medium",
                description="Require Spring Security for /actuator/*"
            ),
            RemediationStep(
                step="Restrict by IP/network",
                priority="short",
                effort="medium",
                description="Add firewall or network ACL rules to limit access"
            ),
        ],
        references=[
            "https://docs.spring.io/spring-boot/actuator.html#production-ready-endpoints",
            "https://cwe.mitre.org/data/definitions/552.html",
        ],
        additional_resources=[]
    ),
    
    "env": Remediation(
        summary="Protect environment and configuration files",
        steps=[
            RemediationStep(
                step="Remove .env and config files from web root",
                priority="immediate",
                effort="low",
                description="Move secrets to environment variables or secret manager"
            ),
            RemediationStep(
                step="Block access to config file patterns",
                priority="immediate",
                effort="low",
                description="Add rewrite rules for .env, config.json, *.yml"
            ),
            RemediationStep(
                step="Rotate exposed credentials",
                priority="immediate",
                effort="high",
                description="If secrets were exposed, immediately rotate all affected credentials"
            ),
            RemediationStep(
                step="Implement secret management solution",
                priority="long",
                effort="high",
                description="Deploy HashiCorp Vault, AWS Secrets Manager, or similar"
            ),
        ],
        references=[
            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "https://cwe.mitre.org/data/definitions/200.html",
        ],
        additional_resources=[]
    ),
    
    "backup": Remediation(
        summary="Remove or protect backup files",
        steps=[
            RemediationStep(
                step="Remove backup files from web root immediately",
                priority="immediate",
                effort="low",
                description="Delete all .zip, .tar, .sql backup files from public directory"
            ),
            RemediationStep(
                step="Block backup file download attempts",
                priority="immediate",
                effort="low",
                description="Add web server rules to deny *.zip, *.sql, *.tar patterns"
            ),
            RemediationStep(
                step="Review deployment process for backup creation",
                priority="short",
                effort="medium",
                description="Ensure backups are stored in secure, non-web-accessible location"
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/",
            "https://cwe.mitre.org/data/definitions/552.html",
        ],
        additional_resources=[]
    ),
    
    "default": Remediation(
        summary="Review and secure the exposed endpoint",
        steps=[
            RemediationStep(
                step="Assess exposure scope and data sensitivity",
                priority="immediate",
                effort="medium",
                description="Determine what data was accessible and its sensitivity"
            ),
            RemediationStep(
                step="Implement appropriate access controls",
                priority="short",
                effort="medium",
                description="Add authentication, IP restrictions, or disable the endpoint"
            ),
            RemediationStep(
                step="Document and monitor the fix",
                priority="short",
                effort="low",
                description="Add to security monitoring and regression tests"
            ),
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        additional_resources=[]
    ),
}


def get_remediation(rule_id: str, category: str = "") -> Remediation:
    """
    Get remediation guidance for a finding.
    Falls back to default template if specific one not found.
    """
    # Try rule_id-based match first
    rule_lower = rule_id.lower()
    for key, template in REMEDIATION_TEMPLATES.items():
        if key in rule_lower:
            return template
    
    # Try category-based match
    if category:
        cat_lower = category.lower()
        for key, template in REMEDIATION_TEMPLATES.items():
            if key in cat_lower:
                return template
    
    # Return default template
    return REMEDIATION_TEMPLATES["default"]


def enrich_finding_with_remediation(finding: Any) -> Dict[str, Any]:
    """Add structured remediation to a finding"""
    remediation = get_remediation(getattr(finding, "rule_id", ""), getattr(finding, "category", ""))
    
    return {
        "remediation_summary": remediation.summary,
        "remediation_steps": [
            {
                "step": step.step,
                "priority": step.priority,
                "effort": step.effort,
                "description": step.description,
            }
            for step in remediation.steps
        ],
        "remediation_references": remediation.references,
        "remediation_additional_resources": remediation.additional_resources,
    }