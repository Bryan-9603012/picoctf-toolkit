# Hunter-2 Enterprise Upgrade Worklog

## Date: 2026-04-11

### Changes Made

#### 1. Core Models (`core/models.py`)
- Added new Enums: `VerificationState`, `ScanPolicy`, `TargetEnvironment`
- Enhanced `Evidence` class with: `request_body`, `response_body`, `response_headers`, `matched_pattern`, `timestamp`
- Enhanced `Finding` class with enterprise fields:
  - `id`, `title`, `affected_asset`
  - `verification_state` (observed/suspected/verified/exploited)
  - `cwe`, `owasp` for vulnerability classification
  - `preconditions`, `safe_check`, `verify_check`, `evidence_type`
  - `exploitability`, `reproduction_steps`, `exploit_chain`
  - `scan_id`, `discovered_at`, `verified_at`
  - `source_rule_pack`, `remediation_draft`
- Added new classes: `Target`, `ScanConfig`

#### 2. Rule Schema (`scanning/rule_engine/schema.py`)
- Created `RuleMetadata` class with full enterprise metadata support
- Added methods for: `cwe`, `owasp`, `exploitability`, `preconditions`, `safe_check`, `verify_check`, `evidence_type`
- Added `create_finding_from_rule()` helper function

#### 3. Config (`config/config.py`, `config/defaults.py`)
- Added enterprise config fields:
  - `policy` (safe/balanced/aggressive)
  - `environment` (dev/staging/prod/unknown)
  - `exclude_patterns`
  - `fail_on_severity`, `fail_verified_only`, `fail_exploited_only`
  - `baseline_scan_id`, `suppressions`

#### 4. CLI (`hunter/cli.py`)
- Added new arguments:
  - `--policy` (safe/balanced/aggressive)
  - `--env` (dev/staging/prod/unknown)
  - `--exclude` pattern
  - `--fail-on` severity (CI integration)
  - `--fail-verified-only`, `--fail-exploited-only`
- Updated policy handling in `apply_speed_profile()`
- Added exit code logic for CI integration

#### 5. Reports (`reports/markdown.py`)
- Added verification state statistics section
- Added verification state display per finding
- Added CWE/OWASP classification display
- Added confidence level display
- Added `_verification_state_zh()` helper

#### 6. Rule Example (`rules/packs/web-misconfig/git-exposure.yaml`)
- Updated with full enterprise metadata:
  - `confidence`, `description`, `references`
  - `cwe`, `owasp`, `exploitability`
  - `preconditions`, `evidence_type`
  - `safe_check`, `verify_check`

### Next Steps
1. Test the enterprise features with a scan
2. Add SARIF export format
3. Consider baseline comparison feature
4. Add suppression file support

---

## Date: 2026-04-11 (Phase 2: Schema Documentation)

### Documentation Added

#### 1. Finding Lifecycle (`docs/FINDING_LIFECYCLE.md`)
- Defined verification states: observed, suspected, verified, exploited
- Defined confidence levels: low, medium, high
- Created state transition rules with clear conditions
- Defined evidence requirements by state
- Created confidence vs verification matrix

#### 2. Artifact Schema (`docs/ARTIFACT_SCHEMA.md`)
- Defined artifact types: http-exchange, file, screenshot, code-snippet, credential, exploit-replay
- Specified required fields: artifact_id, finding_id, type, created_at, hash
- Defined HTTP exchange structure with request/response details
- Created storage directory structure and index format
- Documented replay capability and audit trail requirements

#### 3. Policy Matrix (`docs/POLICY_MATRIX.md`)
- Created comparison matrix for safe/balanced/aggressive policies
- Detailed behavior differences:
  - Fuzzing: payload count, target types, mutation
  - Chaining: multi-step, auth bypass attempts, chain depth
  - Verification: credential extraction, sensitive data checks
  - State-changing: POST/PUT/DELETE handling
  - Request budget: max requests, QPS, threads, timeout, retries
- Provided policy-specific behavior YAML examples
- Documented environment-specific defaults

#### 4. Golden Report Sample (`docs/GOLDEN_REPORT_SAMPLE.md`)
- Created comprehensive sample report format
- Added Scan Metadata section (scan_id, target, environment, policy, timestamps, duration)
- Demonstrated proper finding structure with all enterprise fields
- Showed evidence summary, reproduction steps, remediation
- Added Finding Traceability table (finding_id, rule_id, artifact_ids, verification, confidence)
- Included risk summary table by verification state
- Served as template for future report validation

#### 5. Finding Schema (`docs/FINDING_SCHEMA.md`) - NEW
- Defined complete Finding JSON schema
- Documented all top-level fields with types and required status
- Created enumeration values table (severity, verification_state, confidence)
- Defined Evidence Schema with all fields
- Added complete JSON example
- Established field naming conventions
- Added naming unification rules (proof → evidence, data → extracted_data, etc.)

### Next Steps
1. Test the enterprise features with a scan
2. Add SARIF export format
3. Consider baseline comparison feature
4. Add suppression file support

---

## Date: 2026-04-11 (Phase 2: Schema Documentation - Revised)

### Documentation Updated

#### 1. Finding Lifecycle (`docs/FINDING_LIFECYCLE.md`) - REVISED
- Added "Who Controls State Transitions" section:
  - Rule Engine: sets initial state to observed
  - Verifier: upgrades observed → suspected → verified
  - Exploit Runner: upgrades verified → exploited
  - Manual Override: allows human adjustment
- Added State Transition Constraints table:
  - observed → suspected: allowed
  - observed → verified: NOT allowed (must go through suspected)
  - observed → exploited: NOT allowed (cannot skip states)
  - suspected → verified: allowed
  - suspected → exploited: NOT allowed
  - verified → exploited: allowed
- Clarified that Confidence is independent of verification state
- Added Python code examples for state transition logic

#### 2. Artifact Schema (`docs/ARTIFACT_SCHEMA.md`) - REVISED
- Added "Minimal Required Fields" section:
  - artifact_id, finding_id, scan_id, type, timestamp, hash
- Renamed artifact types for consistency:
  - http_request, http_response, http_exchange
  - match_snapshot, extracted_data, reproduction_step
- Expanded HTTP Exchange structure with all required fields
- Added Extracted Data Structure example
- Added Reproduction Step Structure example

#### 3. Policy Matrix (`docs/POLICY_MATRIX.md`) - REVISED
- Converted to table format for better readability
- Added all missing fields:
  - concurrency (QPS, threads, timeout, retries, max_requests)
  - allowed_methods, replay_depth, exploit_attempts
- Added implementation code example in ScanConfig
- Added Custom Policy Extension example

#### 4. Finding Schema (`docs/FINDING_SCHEMA.md`) - NEW
- Complete Finding JSON schema definition
- All fields with types and required status
- Enumeration values table
- Evidence Schema definition
- Complete JSON example
- Field naming conventions
- Naming unification rules table

#### 5. Golden Report Sample (`docs/GOLDEN_REPORT_SAMPLE.md`) - REVISED
- Added Scan Metadata section at top
- Added Finding Traceability table at bottom
- More comprehensive structure for regression testing

---

## Date: 2026-04-11 (Phase 3: Implementation)

### Implementation Added

#### 1. Finding Verifier (`postprocess/verifier.py`) - NEW
- Implemented fixed state transition model:
  - Rule Engine: only produces observed (initial state)
  - Verifier: observed → suspected → verified (progressive)
  - Exploit Runner: verified → exploited
  - Manual Override: any → any with audit trail
- Added VerificationError exception for invalid transitions
- Added StateTransition dataclass for audit logging
- Added `_has_context_indicators()` for suspected state
- Added `_has_sensitive_data()` for verified state
- Added `_has_exploitation_evidence()` for exploited state
- Implemented `auto_verify_finding()` main entry point

#### 2. Config Enhancement (`config/config.py`)
- Added policy behavior derived fields:
  - `fuzzing_enabled`, `fuzz_payload_limit`
  - `chaining_enabled`, `max_chaining_depth`
  - `allow_post`, `allow_parameter_pollution`, `allow_header_injection`
  - `verification_depth`, `max_verifications`, `auto_escalate_to_exploited`
- Added `scan_id` for session tracking

#### 3. Policy Application (`config/defaults.py`)
- Added `generate_scan_id()` function
- Added `apply_policy_settings()` function that maps policy to behavior:
  - **safe**: fuzzing off, chaining off, deny POST, low verification, max 50 requests
  - **balanced**: fuzzing on, chaining 2 steps, restricted POST, medium verification, 150 max
  - **aggressive**: fuzzing unlimited, chaining unlimited, allow POST, high verification, unlimited

### Next Steps
1. Integrate verifier into main scan pipeline
2. Test state transitions with real findings
3. Add SARIF export format
4. Implement baseline comparison feature
5. Run test suite: `python -m pytest tests/ -v`
6. Do end-to-end sample run to verify full pipeline

---

## Date: 2026-04-11 (Phase 4: Schema Conformance & Runtime Enforcement)

### Implementation Added

#### 1. Schema Validator (`core/schema_validator.py`) - NEW
- FindingSchemaValidator: validates against FINDING_SCHEMA.md
  - Required fields check
  - Enum value validation (severity, confidence, verification_state)
  - Warning for unrecognized values
- ArtifactSchemaValidator: validates against ARTIFACT_SCHEMA.md
  - Minimal required fields: artifact_id, scan_id, finding_id, type, timestamp, hash
  - Type-specific validation for http_exchange
- ScanConfigValidator: validates against POLICY_MATRIX.md
  - Policy and environment enum validation
  - scan_id format validation
- Helper functions: validate_finding(), validate_artifact(), validate_scan_config()
- Batch validators: validate_finding_list(), validate_artifact_list()

#### 2. Artifact Manager (`core/artifact_manager.py`) - NEW
- generate_artifact_id(): creates art-{scan_id}-{finding_id}-{seq}
- generate_hash(): SHA256 hash generation
- ArtifactBuilder: builder pattern for typed artifact creation
  - Supports all 6 artifact types
  - Validates required fields
  - Generates hash from content
- ArtifactStore: in-memory artifact storage with validation
  - add_artifact(): with schema validation
  - create_http_exchange(): convenience method
  - create_extracted_data(): convenience method
  - get_artifacts_by_finding(): finding-artifact linkage
  - export_index(): for artifact index output

#### 3. Report Snapshot Tests (`tests/test_report_snapshots.py`) - NEW
- TestFindingSnapshot: validates finding structure
  - Required fields check
  - Enum value validation
  - Manual override display
  - Traceability fields (scan_id, discovered_at, verified_at)
- TestReportJsonSnapshot: validates report.json structure
  - Target, scan metadata, findings array
  - Metadata summary with severity/verification counts
- TestMarkdownReportSections: validates markdown output
  - Executive Summary
  - Finding details with verification_state, confidence, CWE/OWASP
  - Risk summary with verification breakdown
- TestArtifactLinkage: validates finding-artifact relationship
- TestEndToEndConfig: validates config propagation

### Tests Added
- test_schema_validator.py: Not created (run via schema_validator.py directly)
- test_report_snapshots.py: Report structure validation tests
- test_artifact_manager.py: Artifact runtime (via module test above)

### Runtime Verification Results
```
Finding valid: True, errors: 0
Artifact valid: True, errors: 0
Config valid: True, errors: 0
Created artifact: art-scan-20260411-001-finding-001-0000
Total artifacts: 1
```

---

## Date: 2026-04-11 (Phase 5: Baseline, Delta & Suppression)

### Implementation Added

#### 1. Baseline Comparison (`postprocess/baseline.py`) - NEW
- `BaselineStore`: manages baseline scans
- `compare_with_baseline()`: compares current findings with baseline
- `BaselineResult`: structured output with new/resolved/persistent/changed
- CLI integration: `--baseline`, `--new-only` flags

#### 2. Delta Reports (`reports/delta.py`) - NEW
- `generate_delta_report()`: creates delta between two scans
- `DeltaReport` output with trend summary

#### 3. Suppression Workflow (`postprocess/suppression.py`) - NEW
- `SuppressionStore`: CRUD for suppressions
- `is_suppressed()` matching logic with severity filter
- `apply_suppressions()`: filters findings

#### 4. Test Suite
- `tests/test_delta_reports.py`: Delta report tests
- `tests/test_suppressions.py`: Suppression tests

#### 5. Documentation
- `docs/SUPPRESSION_SCHEMA.md`: Suppression schema

### Exit Code & Triage Policy Deepening
- Added `--fail-on-new <severity>`: Only fail on NEW findings (requires --baseline)
- Added `--fail-on-changed <severity>`: Only fail on severity CHANGED findings (requires --baseline)
- Added `--fail-on-delta-only`: Fail if any delta exists (new/changed/resolved)
- Added `--ignore-expired-suppressions`: Ignore expired suppressions (default: false)
- Enhanced exit code logic with proper baseline/delta integration

### HTML Report Enhancement
- Added verification status breakdown section
- Added baseline comparison block (new/resolved/changed)
- Added suppressed count display
- Added per-finding verification state badge
- Added scan metadata integration

### C.智能增強
- Finding correlation logic (postprocess/correlation.py)
- Exploitability scoring (postprocess/exploitability.py)
- Tests: test_correlation.py, test_exploitability.py

### Release & Packaging
- pyproject.toml: version 1.0.0, metadata, classifiers
- RELEASE_NOTES.md: complete release notes
- INSTALL.md: installation guide
- config/samples.yaml: sample configurations
- demo.sh: demo workflow script

### Metrics & Benchmarking
- postprocess/metrics.py - NEW
  - Scan metrics computation
  - Baseline delta metrics
  - Verification rate
  - Correlation uplift
  - Exploitability distribution
- --metrics CLI flag
- tests/test_metrics.py

### Source-Aware / AI Planner
- postprocess/source_aware.py - NEW
  - Route categorization
  - Auth mechanism detection
  - Application map building
  - Route inference
  - Security summary
- postprocess/planner.py - NEW
  - Attack phase enum
  - Attack step/plan dataclasses
  - Suggest next steps
  - Build attack plan
  - Path ranking
  - Plan adaptation

### Stability & Quality Testing
- tests/test_stability.py - NEW
  - Empty input handling
  - Missing field handling
  - Invalid config handling
  - Large dataset performance
  - Feature conflict handling
  - Graceful degradation
  - Report consistency
- tests/test_quality.py - NEW
  - False positive handling
  - Duplicate detection
  - Correlation accuracy
  - Exploitability scoring quality
  - Planner quality checks

### Productization
- README.md updated for v1.0.0 enterprise focus
- CLI help with --version flag and examples
- docs/README.md documentation index
- Bug fix: planner.py typo (" injection" → "injection")

---

## Project Complete - v1.0.0

**Status**: Production Ready

**Core Features**: Finding Lifecycle, Policy Matrix, Baseline/Delta, Suppression, CI Integration, Correlation, Exploitability Scoring, Metrics, Source-aware Mode, AI Planner

**Test Coverage**: 14 test files covering state transitions, policy, reports, delta, suppressions, integration, regression, correlation, exploitability, metrics, stability, quality

**Documentation**: 6 schema docs + CLI usage + install guide + release notes

**Package**: v1.0.0 with pyproject.toml, RELEASE_NOTES.md, INSTALL.md, demo.sh, sample configs

## Date: 2026-04-16 (picoCTF Web Coverage Upgrade)

### Changes Made
- Added `scanning/passive/client_insights.py` for client-side clue extraction and low-risk web probes
- Added passive detection for HTML comments, hidden inputs, bookmarklets, inline JS auth logic, encoded JS clues, suspicious cookies, and missing session expiry
- Added same-origin script fetching for deeper client-side analysis
- Added low-risk SSTI probing on discovered forms in balanced/aggressive policy
- Improved config compatibility (`baseline`, `suppressions`) and rule loader path handling
- Hardened dedupe, JSON report serialization, suppression matching, verifier state tracking, and artifact builder ergonomics
- Added `tests/test_client_insights.py`

### Validation
- Passed targeted regression subset: `tests/test_client_insights.py`, `tests/test_ctf.py`, `tests/test_integration.py`
