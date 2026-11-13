"""
Compliance matrix (exercise 07): requirement -> control -> evidence -> status.

The evidence for each control is a set of pytest tests. The matrix is built from a
real test run (JUnit XML), so a control only counts as met when its tests pass on
this machine. That is the idea of "compliance as code": the audit trail is the CI.

  run_tests()     runs pytest and returns {test id: passed?}
  matrix(results) one row per 62443-3-3 SR with its controls and status
  csf(results)    the same controls seen through NIST CSF 2.0 functions
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

import matplotlib.pyplot as plt
import pandas as pd

from .model import FR, ROOT, requirements

CSF_FUNCTIONS = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover"}


def run_tests(extra: list[str] | None = None) -> dict[str, bool]:
    with tempfile.NamedTemporaryFile(suffix=".xml") as f:
        subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={f.name}",
                        *(extra or []), "tests"], cwd=ROOT, capture_output=True, text=True)
        tree = ET.parse(f.name)
    out = {}
    for tc in tree.iter("testcase"):
        mod = tc.get("classname", "").replace(".", "/") + ".py"
        tid = f"{mod}::{tc.get('name')}"
        failed = any(child.tag in ("failure", "error", "skipped") for child in tc)
        out[tid] = not failed
    return out


def control_status(results: dict[str, bool]) -> pd.DataFrame:
    rows = []
    for c in requirements()["controls"]:
        ev = c["evidence"]
        if c["status"] == "planned":
            st = "planned"
        elif ev and all(results.get(e, False) for e in ev):
            st = "met"
        else:
            st = "evidence failing"
        rows.append({"control": c["id"], "name": c["name"], "exercise": c["exercise"], "status": st,
                     "evidence": f"{sum(results.get(e, False) for e in ev)}/{len(ev)} tests" if ev else "none",
                     "62443-3-3": ", ".join(c["satisfies"]), "NIST CSF 2.0": ", ".join(c["csf"]),
                     "ATT&CK mitigations": ", ".join(c["mitigations"])})
    return pd.DataFrame(rows)


def _ctl(cid: str) -> dict:
    return next(c for c in requirements()["controls"] if c["id"] == cid)


def matrix(results: dict[str, bool]) -> pd.DataFrame:
    cs = control_status(results).set_index("control")
    rows = []
    for r in requirements()["requirements"]:
        ctl = [c["id"] for c in requirements()["controls"] if r["id"] in c["satisfies"]]
        met = [c for c in ctl if cs.loc[c, "status"] == "met"]
        full = [c for c in met if r["id"] not in _ctl(c).get("partial", [])]
        st = [cs.loc[c, "status"] for c in ctl]
        status = "met" if full else "partial" if met else "planned" if "planned" in st else "gap"
        rows.append({"SR": r["id"], "FR": r["fr"], "requirement": r["title"],
                     "controls": ", ".join(ctl) or "none", "status": status})
    return pd.DataFrame(rows)


def csf(results: dict[str, bool]) -> pd.DataFrame:
    cs = control_status(results)
    rows = []
    for _, c in cs.iterrows():
        for sub in c["NIST CSF 2.0"].split(", "):
            rows.append({"function": CSF_FUNCTIONS[sub.split(".")[0]], "subcategory": sub,
                         "control": c["control"], "status": c["status"]})
    return pd.DataFrame(rows).sort_values(["function", "subcategory"])


COL = {"met": "#27ae60", "partial": "#2980b9", "planned": "#f39c12", "gap": "#c0392b", "evidence failing": "#c0392b"}


def chart(m: pd.DataFrame):
    order = FR
    t = m.groupby(["FR", "status"]).size().unstack(fill_value=0).reindex(order).fillna(0)
    fig, ax = plt.subplots(figsize=(8, 3.4))
    left = None
    for st in ("met", "partial", "planned", "gap"):
        if st in t:
            ax.barh(t.index, t[st], left=left, color=COL[st], label=st)
            left = t[st] if left is None else left + t[st]
    ax.invert_yaxis(); ax.set_xlabel("system requirements (IEC 62443-3-3) in this lab")
    ax.set_title("Coverage per foundational requirement")
    ax.legend(frameon=False, ncol=4, loc="lower right")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    return fig
