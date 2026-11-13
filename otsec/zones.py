"""
Zones and conduits (exercise 02), in the sense of IEC 62443-3-2.

  check_model()         design rules on the model itself
  conduit_for(flow)     which conduit, if any, allows an observed flow
  compliance(flows)     every observed flow classified as allowed / violation, with the reason
  dot()                 Graphviz drawing of zones, assets and conduits (optionally with violations)
"""
from __future__ import annotations

import pandas as pd

from .model import FR, asset_zone, assets, zones

PURDUE = {1: "Level 1 · control", 2: "Level 2 · supervision", 3: "Level 3 · site operations",
          3.5: "Level 3.5 · DMZ", 4: "Level 4 · enterprise"}
ZCOLOR = {"cell": "#c0392b", "supervision": "#e67e22", "site_ops": "#2980b9", "dmz": "#8e44ad", "enterprise": "#7f8c8d"}


def check_model() -> list[str]:
    """Design rules. Empty list means the design is consistent."""
    z, problems = zones(), []
    placed = [a for d in z["zones"].values() for a in d["assets"]]
    for a in assets():
        n = placed.count(a)
        if n != 1:
            problems.append(f"asset {a} is in {n} zones (must be exactly one)")
    for d in z["zones"].values():
        if len(d["sl_t"]) != len(FR):
            problems.append(f"zone {d['name']} must have one SL-T per FR")
    level = {k: v["purdue"] for k, v in z["zones"].items()}
    for c in z["conduits"]:
        a, b = level[c["from"]], level[c["to"]]
        if {a, b} & {4} and 3.5 not in (a, b):
            problems.append(f"{c['id']}: enterprise must only reach the plant through the DMZ")
        if abs(a - b) > 1 and 3.5 not in (a, b):
            problems.append(f"{c['id']}: skips a Purdue level ({a} to {b})")
        for side, key in (("src", "from"), ("dst", "to")):
            for x in c[side]:
                if asset_zone().get(x) != c[key]:
                    problems.append(f"{c['id']}: {x} is not in zone {c[key]}")
    return problems


def conduit_for(src: str, dst: str, port: int) -> str | None:
    for c in zones()["conduits"]:
        if src in c["src"] and dst in c["dst"] and port == c["port"]:
            return c["id"]
    return None


def compliance(flows: pd.DataFrame) -> pd.DataFrame:
    zone = asset_zone()
    rows = []
    for f in flows.itertuples():
        zs, zd = zone.get(f.src_id), zone.get(f.dst_id)
        c = conduit_for(f.src_id, f.dst_id, f.dport)
        if zs is None:
            verdict, why = "VIOLATION", "source is not in the asset inventory"
        elif zs == zd:
            verdict, why = "inside zone", "same zone, governed by host controls"
        elif c:
            verdict, why = "allowed", f"conduit {c}"
        else:
            same_pair = [k for k in zones()["conduits"] if k["src"].count(f.src_id) and k["dst"].count(f.dst_id)]
            if same_pair:
                why = f"right peers but wrong port {f.dport} (conduit {same_pair[0]['id']} allows {same_pair[0]['port']})"
            elif {zs, zd} & {"enterprise"} and "dmz" not in (zs, zd):
                why = "enterprise reaches the plant without passing through the DMZ"
            else:
                why = f"no conduit from {zs} to {zd} for this pair"
            verdict = "VIOLATION"
        rows.append({"src": f.src_id, "dst": f.dst_id, "port": f.dport, "service": f.service,
                     "from_zone": zs or "?", "to_zone": zd or "?", "verdict": verdict, "reason": why,
                     "packets": f.packets})
    return pd.DataFrame(rows)


def dot(violations: pd.DataFrame | None = None) -> str:
    z = zones()
    L = ['digraph Z { rankdir=BT; compound=true; nodesep=0.3; ranksep=0.6; fontname="Helvetica";',
         'node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=10 fillcolor=white];',
         'edge [fontname="Helvetica" fontsize=8];']
    for zid, d in sorted(z["zones"].items(), key=lambda kv: kv[1]["purdue"]):
        slt = " ".join(f"{fr}{v}" for fr, v in zip(FR, d["sl_t"]))
        L.append(f'subgraph cluster_{zid} {{ label="{d["name"]}\\n{PURDUE[d["purdue"]]}\\nSL-T {slt}"; '
                 f'style="rounded,filled"; fillcolor="{ZCOLOR[zid]}22"; color="{ZCOLOR[zid]}"; fontsize=10;')
        for a in d["assets"]:
            x = assets()[a]
            L.append(f'"{a}" [label="{a}\\n{x["kind"]} · {x["ip"]}" color="{ZCOLOR[zid]}"];')
        L.append("}")
    for c in z["conduits"]:
        L.append(f'"{c["src"][0]}" -> "{c["dst"][0]}" [label="{c["id"]} · {c["port"]}" color="#27ae60" penwidth=2];')
    if violations is not None:
        for v in violations[violations.verdict == "VIOLATION"].itertuples():
            src = v.src if not v.src.startswith("UNKNOWN") else "rogue"
            if src == "rogue":
                L.append('"rogue" [label="UNKNOWN\\nrogue device" fillcolor="#2c3e50" fontcolor=white];')
            L.append(f'"{src}" -> "{v.dst}" [label="{v.port}" color="#c0392b" style=dashed penwidth=1.5 fontcolor="#c0392b"];')
    L.append("}")
    return "\n".join(L)
