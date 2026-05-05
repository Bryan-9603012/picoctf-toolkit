# Finding Lifecycle & State Machine

## Verification State Definitions

| State | Definition | Trigger Conditions |
|-------|------------|---------------------|
| `observed` | 看到可疑跡象，但未證明其有效性 | HTTP response matches rule pattern, 但缺少進一步證據 |
| `suspected` | 高機率成立，但未充分證明 | 有 matched pattern + 特定 header/content 符合預期，但未取得敏感資料 |
| `verified` | 有可重現證據證明存在 | 成功取得 sensitive data (credentials, tokens, config) 或達成 auth bypass |
| `exploited` | 完成更高影響利用或取得明確敏感結果 | 已成功跨權限 / 取得 admin access / 下載敏感檔案 |

## Confidence Levels (Independent of Verification State)

| Level | Definition | When to Use |
|-------|------------|-------------|
| `low` | 對 finding 正確性把握較低 | Pattern 匹配模糊、多種可能解釋、需人工確認 |
| `medium` | 有一定證據支持，但非 100% 確定 | 有明確 pattern match + 合理脈絡，但非關鍵敏感資料 |
| `high` | 高把握確定 finding 正確 | 已取得敏感資料、已成功利用、證據明確無歧義 |

## State Transition Rules

```
observed (default)
    │
    ├─ [matched pattern + suspicious content] ──► suspected
    │
    ├─ [obtained sensitive data] ──► verified
    │
    └─ [completed privilege escalation / admin access] ──► exploited
```

### State Transition Constraints - Fixed Model

| From | To | Allowed | Controller |
|------|-----|---------|------------|
| observed | suspected | yes | verifier |
| suspected | verified | yes | verifier |
| verified | exploited | yes | exploit_runner |
| any | any | yes (with audit) | manual_override |

**All other transitions are DENIED.**

Forbidden transitions:
- observed → verified
- observed → exploited
- suspected → exploited
- Any backward transitions

Must follow: observed → suspected → verified → exploited

## Who Controls State Transitions

| Actor | Responsibility |
|-------|----------------|
| **Rule Engine** | Sets initial state to `observed` based on match |
| **Verifier** | Upgrades `observed` → `suspected` → `verified` based on evidence |
| **Exploit Runner** | Upgrades `verified` → `exploited` when exploitation succeeds |
| **Manual Override** | Allows human to adjust state (for edge cases) |

### State Upgrade Conditions by Actor

```python
# Rule Engine: Initial State Assignment
def assign_initial_state(rule_match, evidence):
    if evidence.matched_pattern and evidence.status_200:
        return "observed"
    return "unknown"

# Verifier: State Upgrade Logic  
def upgrade_to_suspected(finding, evidence):
    if evidence.has_context_indicators:
        return "suspected"

def upgrade_to_verified(finding, evidence):
    if evidence.extracted_sensitive_data:
        return "verified"

# Exploit Runner: Exploited State
def upgrade_to_exploited(finding, evidence):
    if evidence.privilege_escalation or evidence.data_exfiltration:
        return "exploited"
```

## Confidence vs Verification Matrix

| Verification | Confidence | Meaning |
|--------------|------------|---------|
| observed | low | 看到跡象，但不確定是什麼 |
| observed | medium | 看到跡象，初步判斷有意義 |
| suspected | low | 高度懷疑，但缺少關鍵證據 |
| suspected | medium | 高度懷疑，有一定證據支持 |
| verified | medium | 已驗證存在，但影響範圍待確認 |
| verified | high | 已驗證且影響範圍明確 |
| exploited | high | 已成功利用，確定取得成果 |

## Evidence Requirements by State

- **observed**: HTTP status + matched pattern in response body
- **suspected**: observed + additional context (header hints, content patterns, tech indicators)
- **verified**: suspected + extracted sensitive data (credentials, tokens, PII, config)
- **exploited**: verified + successful privilege escalation or data exfiltration

## Finding State Machine Implementation

Each rule should define:
1. `initial_state`: defaults to "observed"
2. `state_conditions`: mapping of conditions that trigger state transitions
3. `evidence_required`: minimum evidence needed for each state

Example rule metadata:
```yaml
info:
  verification:
    initial: observed
    transitions:
      suspected:
        - body_contains: "password"
        - header_present: X-Api-Key
      verified:
        - extracted_data_type: credentials
        - status_200_with_sensitive
      exploited:
        - privilege_escalation: true
        - data_exfiltration: true
    evidence_required:
      observed: [status_code, matched_pattern]
      suspected: [observed + context_indicators]
      verified: [suspected + sensitive_data]
      exploited: [verified + proof_of_impact]
```