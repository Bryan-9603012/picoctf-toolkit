# core/artifact_manager.py
"""
Artifact Runtime Manager

Enforces ARTIFACT_SCHEMA.md at runtime:
- Required fields validation
- Typed artifact creation
- Artifact ID generation
- Finding/artifact linkage
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import uuid


class ArtifactRecord(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e


ARTIFACT_TYPES = [
    "http_request", "http_response", "http_exchange",
    "match_snapshot", "extracted_data", "reproduction_step",
]


def generate_artifact_id(scan_id: str, finding_id: str, sequence: int) -> str:
    """Generate artifact_id: art-{scan_id}-{finding_id}-{seq}"""
    return f"art-{scan_id}-{finding_id}-{sequence:04d}"


def generate_hash(content: str) -> str:
    """Generate SHA256 hash of content"""
    return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"


class ArtifactBuilder:
    """Builder for creating validated artifacts"""

    def __init__(self, scan_id: str = "", finding_id: str = "", artifact_type: str = "http_exchange", sequence: int = 0, **kwargs):
        self._explicit_artifact_id = kwargs.pop("_explicit_artifact_id", "")
        self._explicit_timestamp = kwargs.pop("_explicit_timestamp", "")

        self.scan_id_value = scan_id
        self.finding_id_value = finding_id
        self.artifact_type_value = artifact_type
        self.sequence = sequence

        self.method = kwargs.get("method")
        self.path = kwargs.get("path")
        self.url = kwargs.get("url")
        self.request_headers = kwargs.get("request_headers", {})
        self.request_body = kwargs.get("request_body")
        self.response_status = kwargs.get("response_status")
        self.response_headers = kwargs.get("response_headers", {})
        self.response_body_snippet = kwargs.get("response_body_snippet")
        self.content_length = kwargs.get("content_length", 0)
        self.matched_patterns = kwargs.get("matched_patterns", [])
        self.elapsed_ms = kwargs.get("elapsed_ms")
        self.scope_reason = kwargs.get("scope_reason", "in-scope")
        self.rule_id = kwargs.get("rule_id")
        self.data_type = kwargs.get("data_type")
        self.classification = kwargs.get("classification")
        self.value_preview = kwargs.get("value_preview")
        self.step_number = kwargs.get("step_number")
        self.step_description = kwargs.get("step_description")
        self.success = kwargs.get("success", False)
        self.impact = kwargs.get("impact")

    def artifact_id(self, value: str):
        self._explicit_artifact_id = value
        return self

    def scan_id(self, value: str):
        self.scan_id_value = value
        return self

    def finding_id(self, value: str):
        self.finding_id_value = value
        return self

    def artifact_type(self, value: str):
        self.artifact_type_value = value
        return self

    def timestamp(self, value: str):
        self._explicit_timestamp = value
        return self

    def content(self, value: str):
        self.response_body_snippet = value
        self.value_preview = value[:120]
        return self

    def build(self) -> Dict[str, Any]:
        artifact_id = self._explicit_artifact_id or generate_artifact_id(self.scan_id_value or "scan", self.finding_id_value or "finding", self.sequence)

        if self.artifact_type_value not in ARTIFACT_TYPES:
            raise ValueError(f"Invalid artifact type: {self.artifact_type_value}")

        artifact = {
            "artifact_id": artifact_id,
            "scan_id": self.scan_id_value,
            "finding_id": self.finding_id_value,
            "type": self.artifact_type_value,
            "timestamp": self._explicit_timestamp or (datetime.utcnow().isoformat() + "Z"),
            "hash": "",
        }

        if self.artifact_type_value == "http_exchange":
            artifact["request"] = {
                "method": self.method or "GET",
                "path": self.path or "",
                "url": self.url or "",
                "headers": self.request_headers,
                "body": self.request_body,
            }
            artifact["response"] = {
                "status": self.response_status or 0,
                "headers": self.response_headers,
                "body_snippet": (self.response_body_snippet or "")[:2048],
                "content_length": self.content_length,
            }
            artifact["matched_patterns"] = self.matched_patterns
            artifact["metadata"] = {
                "elapsed_ms": self.elapsed_ms,
                "scope_reason": self.scope_reason,
                "rule_id": self.rule_id,
            }
            content = f"{self.method}:{self.path}:{self.response_status}"
            artifact["hash"] = generate_hash(content)
        elif self.artifact_type_value == "http_request":
            artifact["request"] = {
                "method": self.method or "GET",
                "path": self.path or "",
                "url": self.url or "",
                "headers": self.request_headers,
                "body": self.request_body,
            }
            artifact["hash"] = generate_hash(f"{self.method}:{self.path}")
        elif self.artifact_type_value == "http_response":
            artifact["response"] = {
                "status": self.response_status or 0,
                "headers": self.response_headers,
                "body_snippet": (self.response_body_snippet or "")[:2048],
                "content_length": self.content_length,
            }
            artifact["hash"] = generate_hash(f"{self.response_status}")
        elif self.artifact_type_value == "extracted_data":
            artifact["data_type"] = self.data_type or "unknown"
            artifact["classification"] = self.classification or ""
            artifact["value_preview"] = self.value_preview or ""
            artifact["source_url"] = self.url or ""
            artifact["hash"] = generate_hash(f"{self.data_type}:{self.value_preview}")
        elif self.artifact_type_value == "reproduction_step":
            artifact["step_number"] = self.step_number or 1
            artifact["description"] = self.step_description or ""
            artifact["success"] = self.success
            artifact["impact"] = self.impact or ""
            artifact["hash"] = generate_hash(f"{self.step_number}:{self.success}")
        elif self.artifact_type_value == "match_snapshot":
            artifact["matched_patterns"] = self.matched_patterns
            artifact["hash"] = generate_hash(":".join(self.matched_patterns))

        return ArtifactRecord(artifact)


class ArtifactStore:
    """In-memory artifact store with validation"""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._artifacts: List[Dict[str, Any]] = []
        self._finding_artifacts: Dict[str, List[str]] = {}  # finding_id -> [artifact_ids]
        self._sequence: int = 0
    
    def add_artifact(self, artifact: Dict[str, Any]) -> str:
        """Add artifact with validation"""
        # Check required fields
        required = ["artifact_id", "scan_id", "finding_id", "type", "timestamp", "hash"]
        for field in required:
            if field not in artifact:
                raise ValueError(f"Artifact missing required field: {field}")
        
        # Validate scan_id matches
        if artifact["scan_id"] != self.scan_id:
            raise ValueError(f"Artifact scan_id mismatch: {artifact['scan_id']} != {self.scan_id}")
        
        # Validate artifact type
        if artifact["type"] not in ARTIFACT_TYPES:
            raise ValueError(f"Invalid artifact type: {artifact['type']}")
        
        # Add to store
        self._artifacts.append(artifact)
        
        # Track finding-artifact linkage
        finding_id = artifact["finding_id"]
        if finding_id not in self._finding_artifacts:
            self._finding_artifacts[finding_id] = []
        self._finding_artifacts[finding_id].append(artifact["artifact_id"])
        
        return artifact["artifact_id"]
    
    def create_http_exchange(
        self,
        finding_id: str,
        method: str,
        url: str,
        status: int,
        response_body: str,
        headers: Dict[str, str],
        matched_patterns: List[str] = None,
        rule_id: str = None,
    ) -> str:
        """Convenience method to create http_exchange artifact"""
        builder = ArtifactBuilder(
            scan_id=self.scan_id,
            finding_id=finding_id,
            artifact_type="http_exchange",
            sequence=self._sequence,
            method=method,
            url=url,
            path=url.split("/", 3)[-1] if "/" in url else "/",
            response_status=status,
            response_body_snippet=response_body[:500],
            response_headers=headers,
            content_length=len(response_body),
            matched_patterns=matched_patterns or [],
            rule_id=rule_id,
        )
        
        artifact = builder.build()
        self._sequence += 1
        return self.add_artifact(artifact)
    
    def create_extracted_data(
        self,
        finding_id: str,
        data_type: str,
        classification: str,
        value_preview: str,
        source_url: str,
    ) -> str:
        """Convenience method to create extracted_data artifact"""
        builder = ArtifactBuilder(
            scan_id=self.scan_id,
            finding_id=finding_id,
            artifact_type="extracted_data",
            sequence=self._sequence,
            url=source_url,
            data_type=data_type,
            classification=classification,
            value_preview=value_preview,
        )
        
        artifact = builder.build()
        self._sequence += 1
        return self.add_artifact(artifact)
    
    def get_artifacts_by_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        """Get all artifacts for a finding"""
        return [a for a in self._artifacts if a["finding_id"] == finding_id]
    
    def get_artifact_by_id(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        """Get artifact by ID"""
        for a in self._artifacts:
            if a["artifact_id"] == artifact_id:
                return a
        return None
    
    def get_all_artifacts(self) -> List[Dict[str, Any]]:
        """Get all artifacts"""
        return self._artifacts
    
    def get_artifact_ids_for_finding(self, finding_id: str) -> List[str]:
        """Get artifact IDs for a finding"""
        return self._finding_artifacts.get(finding_id, [])
    
    def export_index(self) -> Dict[str, Any]:
        """Export artifact index"""
        return {
            "scan_id": self.scan_id,
            "total_artifacts": len(self._artifacts),
            "artifacts": [
                {
                    "artifact_id": a["artifact_id"],
                    "type": a["type"],
                    "finding_id": a["finding_id"],
                    "hash": a["hash"],
                }
                for a in self._artifacts
            ],
        }


def create_artifact_from_finding(
    finding_id: str,
    scan_id: str,
    evidence: Any,
    rule_id: str,
) -> Dict[str, Any]:
    """Create artifact from finding evidence"""
    store = ArtifactStore(scan_id)
    
    return store.create_http_exchange(
        finding_id=finding_id,
        method=evidence.method,
        url=evidence.url,
        status=evidence.status,
        response_body=evidence.response_body or "",
        headers=evidence.headers,
        matched_patterns=evidence.matched_pattern,
        rule_id=rule_id,
    )