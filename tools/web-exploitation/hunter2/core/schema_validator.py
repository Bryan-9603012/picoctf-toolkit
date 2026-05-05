# core/schema_validator.py
"""
Schema Conformance Validator

Validates that data objects conform to defined schemas:
- FINDING_SCHEMA.md
- ARTIFACT_SCHEMA.md
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ValidationError:
    field: str
    expected: str
    actual: str
    severity: str = "error"


@dataclass
class ValidationResult:
    valid: bool
    errors: List[ValidationError]
    warnings: List[str]
    
    def add_error(self, field: str, expected: str, actual: str):
        self.errors.append(ValidationError(field, expected, actual))
        self.valid = False
    
    def add_warning(self, msg: str):
        self.warnings.append(msg)


class FindingSchemaValidator:
    """Validates Finding objects against FINDING_SCHEMA.md"""
    
    REQUIRED_FIELDS = {
        "id": str,
        "rule_id": str,
        "title": str,
        "category": str,
        "severity": str,
        "confidence": str,
        "verification_state": str,
        "url": str,
    }
    
    ENUM_VALUES = {
        "severity": ["info", "low", "medium", "high", "critical"],
        "confidence": ["low", "medium", "high"],
        "verification_state": ["observed", "suspected", "verified", "exploited"],
    }
    
    OPTIONAL_FIELDS = [
        "name", "affected_asset", "cwe", "owasp", "evidence",
        "matches", "tags", "preconditions", "remediation", "references",
        "safe_check", "verify_check", "evidence_type", "exploitability",
        "extracted_data", "chain", "related_artifacts", "clues",
        "risk_score", "variables", "scan_id", "discovered_at", "verified_at",
        "source_rule_pack", "remediation_draft", "reproduction_steps", "exploit_chain",
    ]
    
    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult(valid=True, errors=[], warnings=[])
        
        # Check required fields
        for field, expected_type in self.REQUIRED_FIELDS.items():
            if field not in finding:
                result.add_error(field, f"required {expected_type.__name__}", "missing")
            elif not isinstance(finding[field], expected_type):
                result.add_error(field, expected_type.__name__, type(finding[field]).__name__)
        
        # Check enum values
        for field, allowed_values in self.ENUM_VALUES.items():
            if field in finding and finding[field] not in allowed_values:
                result.add_error(field, f"one of {allowed_values}", finding[field])
        
        # Check severity order
        if "severity" in finding:
            severity_order = ["info", "low", "medium", "high", "critical"]
            if finding["severity"] not in severity_order:
                result.add_warning(f"Unrecognized severity: {finding['severity']}")
        
        return result


class ArtifactSchemaValidator:
    """Validates Artifact objects against ARTIFACT_SCHEMA.md"""
    
    MINIMAL_REQUIRED_FIELDS = {
        "artifact_id": str,
        "scan_id": str,
        "finding_id": str,
        "type": str,
        "timestamp": str,
        "hash": str,
    }
    
    ARTIFACT_TYPES = [
        "http_request", "http_response", "http_exchange",
        "match_snapshot", "extracted_data", "reproduction_step",
    ]
    
    def validate(self, artifact: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult(valid=True, errors=[], warnings=[])
        
        # Check minimal required fields
        for field, expected_type in self.MINIMAL_REQUIRED_FIELDS.items():
            if field not in artifact:
                result.add_error(field, f"required {expected_type.__name__}", "missing")
            elif not isinstance(artifact[field], expected_type):
                result.add_error(field, expected_type.__name__, type(artifact[field]).__name__)
        
        # Check artifact type
        if "type" in artifact and artifact["type"] not in self.ARTIFACT_TYPES:
            result.add_warning(f"Unrecognized artifact type: {artifact['type']}")
        
        # For http_exchange type, check required subfields
        if artifact.get("type") == "http_exchange":
            self._validate_http_exchange(artifact, result)
        
        return result
    
    def _validate_http_exchange(self, artifact: Dict[str, Any], result: ValidationResult):
        """Validate http_exchange structure"""
        required_request_fields = ["method", "path", "url"]
        required_response_fields = ["status"]
        
        if "request" not in artifact:
            result.add_error("request", "object", "missing")
        else:
            for field in required_request_fields:
                if field not in artifact["request"]:
                    result.add_error(f"request.{field}", "string", "missing")
        
        if "response" not in artifact:
            result.add_error("response", "object", "missing")
        else:
            for field in required_response_fields:
                if field not in artifact["response"]:
                    result.add_error(f"response.{field}", "int", "missing")


class ScanConfigValidator:
    """Validates Config against POLICY_MATRIX.md"""
    
    VALID_POLICIES = ["safe", "balanced", "aggressive"]
    VALID_ENVIRONMENTS = ["dev", "staging", "prod", "unknown"]
    VALID_POLICY_FIELDS = [
        "fuzzing_enabled", "fuzz_payload_limit", "chaining_enabled", "max_chaining_depth",
        "allow_post", "allow_parameter_pollution", "allow_header_injection",
        "verification_depth", "max_verifications", "auto_trigger_exploit_runner",
    ]
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        result = ValidationResult(valid=True, errors=[], warnings=[])
        
        # Check policy
        if "policy" in config and config["policy"] not in self.VALID_POLICIES:
            result.add_error("policy", f"one of {self.VALID_POLICIES}", config["policy"])
        
        # Check environment
        if "environment" in config and config["environment"] not in self.VALID_ENVIRONMENTS:
            result.add_error("environment", f"one of {self.VALID_ENVIRONMENTS}", config["environment"])
        
        # Check scan_id format
        if "scan_id" in config:
            scan_id = config["scan_id"]
            if not scan_id.startswith("scan-"):
                result.add_error("scan_id", "scan-YYYYMMDD-HHMMSS", scan_id)
        
        return result


def validate_finding(finding: Dict[str, Any]) -> Tuple[bool, List[ValidationError]]:
    """Validate a finding against schema"""
    validator = FindingSchemaValidator()
    result = validator.validate(finding)
    return result.valid, result.errors


def validate_artifact(artifact: Dict[str, Any]) -> Tuple[bool, List[ValidationError]]:
    """Validate an artifact against schema"""
    validator = ArtifactSchemaValidator()
    result = validator.validate(artifact)
    return result.valid, result.errors


def validate_scan_config(config: Dict[str, Any]) -> Tuple[bool, List[ValidationError]]:
    """Validate scan config against policy"""
    validator = ScanConfigValidator()
    result = validator.validate(config)
    return result.valid, result.errors


def validate_finding_list(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate a list of findings, return summary"""
    validator = FindingSchemaValidator()
    
    total = len(findings)
    valid = 0
    errors_by_field = {}
    
    for i, finding in enumerate(findings):
        result = validator.validate(finding)
        if result.valid:
            valid += 1
        else:
            for error in result.errors:
                field_key = f"finding[{i}].{error.field}"
                errors_by_field[field_key] = error
    
    return {
        "total": total,
        "valid": valid,
        "invalid": total - valid,
        "errors": errors_by_field,
    }


def validate_artifact_list(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate a list of artifacts, return summary"""
    validator = ArtifactSchemaValidator()
    
    total = len(artifacts)
    valid = 0
    errors_by_field = {}
    
    for i, artifact in enumerate(artifacts):
        result = validator.validate(artifact)
        if result.valid:
            valid += 1
        else:
            for error in result.errors:
                field_key = f"artifact[{i}].{error.field}"
                errors_by_field[field_key] = error
    
    return {
        "total": total,
        "valid": valid,
        "invalid": total - valid,
        "errors": errors_by_field,
    }