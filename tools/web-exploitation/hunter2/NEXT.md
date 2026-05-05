# Hunter-2 Next Steps

## Version Status
- [x] v1 (Stable Rule Scanner): Complete
- [x] v1.1 (Enterprise Skeleton): Complete
- [x] v1.2 (Schema Conformance): Complete
- [x] v1.3 (Integration): Complete
- [x] v2 (Verification Scanner): Complete
- [x] v3 (Smart Enhancement): Complete

## Release v1.0.0 Done
- [x] pyproject.toml version 1.0.0
- [x] RELEASE_NOTES.md
- [x] INSTALL.md  
- [x] config/samples.yaml
- [x] demo.sh
- [x] Metrics module (postprocess/metrics.py)
- [x] --metrics CLI flag
- [x] Source-aware mode (postprocess/source_aware.py)
- [x] AI Planner (postprocess/planner.py)

## Documentation Status
- [x] FINDING_LIFECYCLE.md - State machine and transition rules
- [x] ARTIFACT_SCHEMA.md - Artifact types and structure
- [x] POLICY_MATRIX.md - Policy behavior matrix
- [x] FINDING_SCHEMA.md - Complete JSON schema
- [x] GOLDEN_REPORT_SAMPLE.md - Report template
- [x] SUPPRESSION_SCHEMA.md - Suppression workflow

## Tests Coverage
- [x] test_state_transitions.py
- [x] test_policy_application.py
- [x] test_report_snapshots.py
- [x] test_delta_reports.py
- [x] test_suppressions.py
- [x] test_integration.py
- [x] test_regression.py
- [x] test_correlation.py
- [x] test_exploitability.py
- [x] test_metrics.py
- [x] test_stability.py
- [x] test_quality.py

## Stability & Quality Done
- [x] Edge case handling tests
- [x] Performance tests with large datasets
- [x] Feature conflict handling
- [x] Graceful degradation tests
- [x] Report consistency tests
- [x] FP handling tests
- [x] Duplicate detection tests
- [x] Correlation accuracy tests
- [x] Exploitability scoring quality tests
- [x] Planner quality tests

## Productization Done
- [x] README updated (v1.0.0, enterprise focus)
- [x] CLI help with examples and version flag
- [x] docs/README.md for documentation index
- [x] Installer fix (typo in planner)

## Pending after 2026-04-16 coverage upgrade
- Improve full-suite stability for legacy modules (correlation, exploitability, policy, fingerprint, suppressions)
- Add stronger request tampering workflow probes
- Add explicit session persistence replay checks
- Add richer encoded artifact decoding for WebDecode-like challenges
