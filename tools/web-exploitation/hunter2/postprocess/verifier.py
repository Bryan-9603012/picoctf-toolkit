# postprocess/verifier.py
"""
Finding State Transition Controller

Fixed Model:
- Rule Engine: can only produce observed (initial state)
- Verifier: can go observed → suspected → verified
- Exploit Runner: can go verified → exploited
- Manual Override: can go any → any with reason/actor/timestamp

Explicit Transition Table:
+----------+-------------+---------------+------------------+
| from     | to          | allowed       | controller       |
+----------+-------------+---------------+------------------+
| observed | suspected   | yes           | verifier         |
| suspected| verified    | yes           | verifier         |
| verified | exploited   | yes           | exploit_runner   |
| any      | any         | yes (audit)   | manual_override  |
+----------+-------------+---------------+------------------+
All other transitions: DENIED
"""

from __future__ import annotations
from typing import Optional, List, Dict, Any
from datetime import datetime
from dataclasses import dataclass, field, asdict


@dataclass
class StateTransition:
    """Audit log for each state transition"""
    finding_id: str
    from_state: str
    to_state: str
    actor_type: str  # rule_engine, verifier, exploit_runner, manual
    reason: str = ""
    actor_name: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    scan_id: Optional[str] = None
    source_module: Optional[str] = None
    artifact_ids: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result


class VerificationError(Exception):
    """Raised when an invalid state transition is attempted"""
    pass


# Explicit transition table
ALLOWED_TRANSITIONS = {
    "observed": {"suspected": "verifier"},
    "suspected": {"verified": "verifier"},
    "verified": {"exploited": "exploit_runner"},
}

FORBIDDEN_TRANSITIONS = [
    "observed → verified",
    "observed → exploited",
    "suspected → exploited",
    "suspected → observed",  # Can't go backwards
    "verified → suspected",
    "verified → observed",
    "exploited → verified",
    "exploited → suspected",
    "exploited → observed",
]


class FindingVerifier:
    """
    Controls finding state transitions based on fixed model.
    All transitions are logged for audit.
    """
    
    def __init__(self, scan_id: Optional[str] = None, source_module: str = "verifier"):
        self.scan_id = scan_id
        self.source_module = source_module
        self.transition_log: List[StateTransition] = []
        self.current_states: Dict[str, str] = {}
    
    def _check_transition_allowed(
        self,
        from_state: str,
        to_state: str,
        actor_type: str,
    ) -> bool:
        """Check if transition is explicitly allowed"""
        if from_state == to_state:
            return False  # No transition needed
        
        # Manual override allows any transition
        if actor_type == "manual":
            return True
        
        # Check explicit table
        allowed_controllers = ALLOWED_TRANSITIONS.get(from_state, {})
        return allowed_controllers.get(to_state) == actor_type
    
    def _validate_transition(
        self,
        from_state: str,
        to_state: str,
        actor_type: str,
    ) -> None:
        """Validate transition or raise VerificationError"""
        # Check if allowed
        if not self._check_transition_allowed(from_state, to_state, actor_type):
            raise VerificationError(
                f"Transition {from_state} → {to_state} by {actor_type} is not allowed. "
                f"Allowed transitions: {ALLOWED_TRANSITIONS.get(from_state, {})}"
            )
        
        # Explicitly check for forbidden transitions
        transition = f"{from_state} → {to_state}"
        if transition in FORBIDDEN_TRANSITIONS:
            raise VerificationError(
                f"Transition {transition} is explicitly forbidden. "
                f"Must follow: observed → suspected → verified → exploited"
            )
    
    def set_initial_state(
        self,
        finding_id: str,
        actor_name: str = "rule_engine",
    ) -> str:
        """
        Rule Engine: Set initial state to 'observed'.
        Only actor that can create new findings.
        """
        # Rule engine always starts with observed
        self._log_transition(
            finding_id=finding_id,
            from_state="",
            to_state="observed",
            actor_type="rule_engine",
            actor_name=actor_name,
            reason="Initial state from rule engine",
            source_module="rule_engine",
        )
        self.current_states[finding_id] = "observed"
        return "observed"
    
    def transition_to_suspected(
        self,
        finding_id: str,
        current_state: str,
        actor_name: str = "verifier",
        reason: str = "",
        artifact_ids: Optional[List[str]] = None,
    ) -> str:
        """
        Verifier: Upgrade from observed to suspected.
        Requires context indicators (headers, content patterns, tech indicators).
        """
        self._validate_transition(current_state, "suspected", "verifier")
        
        self._log_transition(
            finding_id=finding_id,
            from_state=current_state,
            to_state="suspected",
            actor_type="verifier",
            actor_name=actor_name,
            reason=reason or "Context indicators present (headers/patterns/tech)",
            source_module=self.source_module,
            artifact_ids=artifact_ids or [],
        )
        self.current_states[finding_id] = "suspected"
        return "suspected"
    
    def transition_to_verified(
        self,
        finding_id: str,
        current_state: str,
        actor_name: str = "verifier",
        reason: str = "",
        artifact_ids: Optional[List[str]] = None,
    ) -> str:
        """
        Verifier: Upgrade from suspected to verified.
        Requires extracted sensitive data (credentials, tokens, PII, config).
        """
        self._validate_transition(current_state, "verified", "verifier")
        
        self._log_transition(
            finding_id=finding_id,
            from_state=current_state,
            to_state="verified",
            actor_type="verifier",
            actor_name=actor_name,
            reason=reason or "Sensitive data extracted (credentials/tokens/PII/config)",
            source_module=self.source_module,
            artifact_ids=artifact_ids or [],
        )
        self.current_states[finding_id] = "verified"
        return "verified"
    
    def transition_to_exploited(
        self,
        finding_id: str,
        current_state: str,
        actor_name: str = "exploit_runner",
        reason: str = "",
        artifact_ids: Optional[List[str]] = None,
    ) -> str:
        """
        Exploit Runner: Upgrade from verified to exploited.
        Requires proof of privilege escalation or data exfiltration.
        """
        self._validate_transition(current_state, "exploited", "exploit_runner")
        
        self._log_transition(
            finding_id=finding_id,
            from_state=current_state,
            to_state="exploited",
            actor_type="exploit_runner",
            actor_name=actor_name,
            reason=reason or "Privilege escalation or data exfiltration confirmed",
            source_module=self.source_module,
            artifact_ids=artifact_ids or [],
        )
        self.current_states[finding_id] = "exploited"
        return "exploited"
    
    def manual_override(
        self,
        finding_id: str,
        current_state: str,
        new_state: str,
        actor_name: str,
        reason: str,
    ) -> str:
        """
        Manual Override: Allow any state transition with audit trail.
        Must include actor name and reason.
        """
        if not reason:
            raise VerificationError("Manual override requires a reason")
        
        if not actor_name:
            raise VerificationError("Manual override requires actor name")
        
        self._log_transition(
            finding_id=finding_id,
            from_state=current_state,
            to_state=new_state,
            actor_type="manual",
            actor_name=actor_name,
            reason=reason,
            source_module="manual_override",
        )
        
        self.current_states[finding_id] = new_state
        return new_state
    
    def _log_transition(
        self,
        finding_id: str,
        from_state: str,
        to_state: str,
        actor_type: str,
        actor_name: Optional[str],
        reason: str,
        source_module: Optional[str] = None,
        artifact_ids: Optional[List[str]] = None,
    ) -> None:
        """Log state transition for audit trail"""
        self.transition_log.append(StateTransition(
            finding_id=finding_id,
            from_state=from_state,
            to_state=to_state,
            actor_type=actor_type,
            actor_name=actor_name,
            reason=reason,
            timestamp=datetime.utcnow(),
            scan_id=self.scan_id,
            source_module=source_module or self.source_module,
            artifact_ids=artifact_ids or [],
        ))
    
    def get_state(self, finding_id: str) -> Optional[str]:
        """Return latest known state for a finding id."""
        return self.current_states.get(finding_id)

    def get_transition_log(self) -> List[StateTransition]:
        """Return full transition log for audit"""
        return self.transition_log
    
    def get_transition_log_as_dicts(self) -> List[Dict[str, Any]]:
        """Return transition log as dicts for serialization"""
        return [t.to_dict() for t in self.transition_log]


def transition_finding_state(
    finding,
    to_state: str,
    actor_type: str,
    actor_name: str,
    reason: str,
    artifact_ids: Optional[List[str]] = None,
    scan_id: Optional[str] = None,
) -> str:
    """
    Centralized API for finding state transitions.
    
    This is the ONLY interface that should be used to change finding states.
    Ensures:
    - Permission checks
    - State machine validation
    - Audit logging
    - No skip-level transitions
    """
    verifier = FindingVerifier(scan_id=scan_id)
    current_state = getattr(finding, "verification_state", "observed") or "observed"
    
    if actor_type == "rule_engine":
        return verifier.set_initial_state(finding.id, actor_name)
    elif actor_type == "verifier":
        if to_state == "suspected":
            return verifier.transition_to_suspected(
                finding.id, current_state, actor_name, reason, artifact_ids
            )
        elif to_state == "verified":
            return verifier.transition_to_verified(
                finding.id, current_state, actor_name, reason, artifact_ids
            )
    elif actor_type == "exploit_runner":
        if to_state == "exploited":
            return verifier.transition_to_exploited(
                finding.id, current_state, actor_name, reason, artifact_ids
            )
    elif actor_type == "manual":
        return verifier.manual_override(
            finding.id, current_state, to_state, actor_name, reason
        )
    
    raise VerificationError(f"Unknown actor_type: {actor_type}")