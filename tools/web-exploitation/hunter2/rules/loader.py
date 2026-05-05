# rules/loader.py
from __future__ import annotations

import os
from typing import Dict, List, Optional

import yaml


class AttrDict(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(name) from e


def _load_yaml(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"Invalid YAML (not dict): {path}")
    obj["_file"] = os.path.basename(path)
    obj["_path"] = path
    return AttrDict(obj)


def list_packs(rules_dir: str) -> List[str]:
    packs_dir = os.path.join(rules_dir, "packs")
    if not os.path.isdir(packs_dir):
        return []
    return sorted([d for d in os.listdir(packs_dir) if os.path.isdir(os.path.join(packs_dir, d))])


def list_rules_in_pack(rules_dir: str, pack: str) -> List[str]:
    pack_dir = os.path.join(rules_dir, "packs", pack)
    if not os.path.isdir(pack_dir):
        return []
    return sorted([fn for fn in os.listdir(pack_dir) if fn.endswith((".yml", ".yaml"))])


def _auto_packs(tech: List[str], waf: List[str]) -> List[str]:
    packs = ["web-misconfig", "ctf"]
    if "spring" in [t.lower() for t in tech or []]:
        packs.append("spring")
    return sorted(set(packs))


def load_rules(
    rules_dir: str,
    *,
    pack: Optional[str] = None,
    tech: Optional[List[str]] = None,
    waf: Optional[List[str]] = None,
) -> List[Dict]:
    if not os.path.isdir(rules_dir):
        raise FileNotFoundError(f"Rules dir not found: {rules_dir}")

    if pack == "auto":
        packs = _auto_packs(tech or [], waf or [])
        pack = ",".join(packs)

    rules: List[Dict] = []
    if pack:
        packs = [p.strip() for p in str(pack).split(",") if p.strip()]
        for pk in packs:
            pack_dir = os.path.join(rules_dir, "packs", pk)
            if not os.path.isdir(pack_dir):
                alt_pack_dir = os.path.join(rules_dir, pk)
                if os.path.isdir(alt_pack_dir):
                    pack_dir = alt_pack_dir
                else:
                    raise FileNotFoundError(f"Pack not found: {pack_dir}")
            for fn in sorted(os.listdir(pack_dir)):
                if fn.endswith((".yml", ".yaml")):
                    rules.append(_load_yaml(os.path.join(pack_dir, fn)))
        return rules

    # legacy: rules/*.yml
    for fn in sorted(os.listdir(rules_dir)):
        if fn.endswith((".yml", ".yaml")):
            rules.append(_load_yaml(os.path.join(rules_dir, fn)))
    return rules