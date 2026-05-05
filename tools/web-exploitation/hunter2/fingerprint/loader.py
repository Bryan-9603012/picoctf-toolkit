# fingerprint/loader.py
from __future__ import annotations

import os
from typing import Dict, Tuple

import yaml


def load_fingerprint_dbs(fingerprints_dir: str) -> Tuple[Dict, Dict]:
    tech_path = os.path.join(fingerprints_dir, "tech.yaml")
    waf_path = os.path.join(fingerprints_dir, "waf.yaml")

    tech_db = {}
    waf_db = {}

    try:
        with open(tech_path, "r", encoding="utf-8") as f:
            tech_db = yaml.safe_load(f) or {}
    except Exception:
        tech_db = {}

    try:
        with open(waf_path, "r", encoding="utf-8") as f:
            waf_db = yaml.safe_load(f) or {}
    except Exception:
        waf_db = {}

    return tech_db, waf_db