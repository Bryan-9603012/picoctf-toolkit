from dataclasses import dataclass, field


CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_NOISE = "NOISE"


@dataclass
class DecodeResult:
    method: str
    status: str
    output: str = ""
    score: int = 0
    flags: list[str] = field(default_factory=list)
    reason: str = ""
    error: str = ""
    chain: list[str] = field(default_factory=list)
    confidence: str = CONFIDENCE_NOISE
