"""Loads the plant, zones, threats and requirements models (YAML in model/)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "model"
CAPTURES = ROOT / "captures"
IMG = ROOT / "docs" / "img"

FR = ["IAC", "UC", "SI", "DC", "RDF", "TRE", "RA"]
FR_NAMES = {
    "IAC": "Identification and authentication control",
    "UC": "Use control",
    "SI": "System integrity",
    "DC": "Data confidentiality",
    "RDF": "Restricted data flow",
    "TRE": "Timely response to events",
    "RA": "Resource availability",
}


def _load(name: str) -> dict:
    return yaml.safe_load((MODEL / name).read_text(encoding="utf-8"))


@lru_cache
def plant() -> dict:
    return _load("plant.yaml")


@lru_cache
def zones() -> dict:
    return _load("zones.yaml")


def threats() -> dict:
    return _load("threats.yaml")


def requirements() -> dict:
    return _load("requirements.yaml")


def assets() -> dict[str, dict]:
    return {a["id"]: a for a in plant()["assets"]}


def ip_to_asset() -> dict[str, str]:
    return {a["ip"]: a["id"] for a in plant()["assets"]}


def asset_zone() -> dict[str, str]:
    return {a: z for z, d in zones()["zones"].items() for a in d["assets"]}
