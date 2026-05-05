# Hunter-2 Project Decisions

## Architecture Decisions

### 1. Verification State Machine
- **Decision**: Progressive state machine (observed → suspected → verified → exploited)
- **Rationale**: Prevents skipping states, ensures proper evidence gathering at each level
- **No alternatives considered** - This is industry standard for verification workflows

### 2. Policy Matrix Design
- **Decision**: Three policies (safe/balanced/aggressive) with behavior derivation
- **Rationale**: Simple for users, sufficient for most use cases
- **Alternative considered**: Custom policy engine - deferred to future version

### 3. Finding Correlation Approach
- **Decision**: Graph-based correlation with keyword detection
- **Rationale**: Lightweight, works without ML, predictable
- **Alternative considered**: ML-based correlation - deferred for v2

### 4. Exploitability Scoring
- **Decision**: Weighted formula with separate bonuses
- **Rationale**: Transparent, adjustable, explainable
- **Alternative considered**: CVSS-like scoring - rejected for complexity

### 5. Baseline/Delta Design
- **Decision**: JSON-based baseline with key-based comparison
- **Rationale**: Simple, portable, CI-friendly
- **Alternative considered**: Database-backed baseline - rejected for portability

## Technical Decisions

### 6. Module Naming
- **Decision**: postprocess/* for post-scanning modules
- **Rationale**: Clear separation from scanning phase
- **Modules**: correlation, exploitability, metrics, planner, source_aware, baseline, suppression

### 7. Test Strategy
- **Decision**: Unit tests + integration tests + stability/quality tests
- **Rationale**: Comprehensive coverage without end-to-end test infrastructure

### 8. CLI Design
- **Decision**: Single CLI with sub-options (no subcommands)
- **Rationale**: Simpler for users, consistent with scanners like nmap/nikto

## Product Decisions

### 9. Version Numbering
- **Decision**: Semantic versioning (v1.0.0 = major.feature.bugfix)
- **Rationale**: Industry standard, clear expectation setting

### 10. Report Formats
- **Decision**: JSON (machine), Markdown (human), HTML (dashboard)
- **Rationale**: Cover all major use cases without over-complicating

### 11. Default Policy
- **Decision**: "balanced" as default
- **Rationale**: Safe middle-ground between safe and aggressive

## Deferred Decisions

- SARIF export format (v1.1)
- Database-backed baselines (v1.2)
- ML-based correlation (v2)
- Custom policy engine (v2)
- Windows support (future)

## Unresolved

- Source-aware mode accuracy metrics - need real-world data
- Planner effectiveness benchmarking - need user feedback
- FP rate baseline - need production data

---

**Last Updated**: 2026-04-11
**Version**: v1.0.0