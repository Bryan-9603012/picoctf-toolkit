# tests/test_rule_schema.py
import pytest
from scanning.rule_engine.schema import (
    get_rule_id,
    get_rule_info,
    get_rule_tags,
    get_rule_remediation,
    get_method_and_paths,
)


SIMPLE_RULE = {
    "id": "test-simple",
    "info": {
        "name": "Test Rule",
        "severity": "high",
        "category": "test",
        "remediation": "Fix it",
    },
    "tags": ["tag1", "tag2"],
    "request": {
        "method": "GET",
        "paths": ["/test", "/test2"],
    },
}

CHAIN_RULE = {
    "id": "test-chain",
    "info": {
        "name": "Chain Rule",
        "severity": "critical",
        "category": "chain",
    },
    "tags": ["chain"],
    "steps": [
        {
            "id": "step1",
            "request": {"method": "GET", "path": "/first"},
            "match": {"status": 200},
        },
        {
            "id": "step2",
            "when": {"previous_status": 200},
            "request": {"method": "POST", "path": "/second"},
            "match": {"status": 201},
        },
    ],
}


def test_get_rule_id():
    assert get_rule_id(SIMPLE_RULE) == "test-simple"
    assert get_rule_id({"_file": "custom.yaml"}) == "custom.yaml"
    assert get_rule_id({}) == "rule"


def test_get_rule_info():
    info = get_rule_info(SIMPLE_RULE)
    assert info["name"] == "Test Rule"
    assert info["severity"] == "high"
    assert info["remediation"] == "Fix it"


def test_get_rule_tags():
    tags = get_rule_tags(SIMPLE_RULE)
    assert "tag1" in tags
    assert "tag2" in tags


def test_get_rule_remediation():
    assert get_rule_remediation(SIMPLE_RULE) == "Fix it"
    assert get_rule_remediation({"info": {}}) == ""


def test_get_method_and_paths_simple():
    method, paths = get_method_and_paths(SIMPLE_RULE)
    assert method == "GET"
    assert "/test" in paths
    assert "/test2" in paths


def test_get_method_and_paths_chain():
    method, paths = get_method_and_paths(CHAIN_RULE)
    assert method == "GET"
    assert paths == []
