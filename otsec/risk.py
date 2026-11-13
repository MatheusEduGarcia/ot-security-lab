"""
Risk assessment (exercise 03), following the flow of IEC 62443-3-2:
threats per zone, inherent risk, countermeasures, residual risk, and the gap
between the target security level (SL-T) and what the controls achieve (SL-A).

Risk = likelihood x consequence (1..25). Bands: low < 6, medium < 12, high < 20, critical >= 20.
"""
from __future__ import annotations

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .model import FR, requirements, threats, zones

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


def band(score: int) -> str:
    return "critical" if score >= 20 else "high" if score >= 12 else "medium" if score >= 6 else "low"


def controls(status: str | None = None) -> pd.DataFrame:
    c = pd.DataFrame(requirements()["controls"])
    return c if status is None else c[c.status == status]


def assess(only_implemented: bool = True) -> pd.DataFrame:
    done = set(controls("implemented").id) if only_implemented else set(controls().id)
    rows = []
    for t in threats()["threats"]:
        reduction = sum(v for k, v in t["controls"].items() if k in done)
        res_l = max(1, t["likelihood"] - reduction)
        inherent, residual = t["likelihood"] * t["consequence"], res_l * t["consequence"]
        rows.append({"id": t["id"], "technique": t["technique"], "name": t["name"], "zone": t["zone"],
                     "L": t["likelihood"], "C": t["consequence"], "inherent": inherent, "inherent_band": band(inherent),
                     "controls": ", ".join(k for k in t["controls"] if k in done) or "none implemented",
                     "missing": ", ".join(k for k in t["controls"] if k not in done),
                     "L_res": res_l, "residual": residual, "residual_band": band(residual)})
    return pd.DataFrame(rows)


def sl_achieved() -> dict[str, int]:
    """Simplified: per FR, the highest credit of any implemented control (1 if none)."""
    sl = {fr: 1 for fr in FR}
    for c in requirements()["controls"]:
        if c["status"] == "implemented":
            for fr, lvl in c.get("credit", {}).items():
                sl[fr] = max(sl[fr], lvl)
    return sl


def sl_gaps() -> pd.DataFrame:
    a = sl_achieved()
    rows = []
    for zid, d in zones()["zones"].items():
        for fr, t in zip(FR, d["sl_t"]):
            rows.append({"zone": zid, "FR": fr, "SL_T": t, "SL_A": a[fr], "gap": max(0, t - a[fr])})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------- figures
COL = {"low": "#27ae60", "medium": "#f1c40f", "high": "#e67e22", "critical": "#c0392b"}


def heatmaps(df: pd.DataFrame):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
    grid = np.array([[l * c for c in range(1, 6)] for l in range(1, 6)])
    cmap = plt.matplotlib.colors.ListedColormap([COL["low"], COL["medium"], COL["high"], COL["critical"]])
    norm = plt.matplotlib.colors.BoundaryNorm([0, 6, 12, 20, 26], 4)
    for ax, (lcol, title) in zip(axes, (("L", "Inherent risk"), ("L_res", "Residual risk (implemented controls)"))):
        ax.imshow(grid, origin="lower", cmap=cmap, norm=norm, alpha=0.35, extent=(0.5, 5.5, 0.5, 5.5))
        cells: dict = {}
        for r in df.itertuples():
            cells.setdefault((r.C, getattr(r, lcol)), []).append(r.id)
        for (c, l), ids in cells.items():
            ax.text(c, l, "\n".join(ids), ha="center", va="center", fontsize=8, fontweight="bold")
        ax.set_xticks(range(1, 6)); ax.set_yticks(range(1, 6))
        ax.set_xlabel("consequence"); ax.set_title(title)
    axes[0].set_ylabel("likelihood")
    fig.tight_layout()
    return fig


def sl_radar(zone: str):
    g = sl_gaps()
    g = g[g.zone == zone]
    ang = np.linspace(0, 2 * np.pi, len(FR), endpoint=False).tolist()
    close = lambda v: list(v) + [list(v)[0]]
    fig = plt.figure(figsize=(4.6, 4.6))
    ax = fig.add_subplot(polar=True)
    ax.plot(close(ang), close(g.SL_T), color="#c0392b", lw=2, label="SL-T (target)")
    ax.fill(close(ang), close(g.SL_A), color="#2980b9", alpha=0.3, label="SL-A (achieved)")
    ax.set_xticks(ang, FR); ax.set_yticks([1, 2, 3, 4]); ax.set_ylim(0, 4)
    ax.set_title(f"zone {zone}", pad=14)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.25), ncol=2, fontsize=8, frameon=False)
    return fig
