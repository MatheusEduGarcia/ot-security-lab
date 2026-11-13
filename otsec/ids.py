"""
A small allowlist IDS for Modbus/TCP (exercise 06).

OT traffic is boring on purpose: the same hosts poll the same registers with the
same function codes all day. That makes "learn normal, alert on anything new" very
effective, which is how commercial OT IDS products work at their core.

Baseline (learned from a normal day):
  * talkers       which (client, server, port) pairs exist
  * functions     which Modbus function codes each pair uses
  * read window   which register addresses each pair reads
  * writes        which registers each pair writes, and the value range seen
  * rate          the highest request rate per client, per second

Rules, each tied to the MITRE ATT&CK for ICS technique it usually reveals:
  R1 scan              one source opens connections to many hosts          T0846
  R2 new talker        a pair never seen in the baseline                   T0886 / T0846
  R3 new function      function code never used by this pair               T0888 / T0816 / T0855
  R4 read outside map  reads beyond the registers this pair normally reads T0861
  R5 unauthorized write a write from a pair that never writes              T0855 / T0836
  R6 value out of range a write with a value outside the learned range     T0836
  R7 rate              requests per second far above the baseline          T0814
"""
from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from .inventory import FC_NAME, WRITE_FC

FC_TECH = {43: "T0888", 8: "T0816", 6: "T0855", 16: "T0855", 5: "T0855", 15: "T0855"}


@dataclass
class Baseline:
    talkers: set = field(default_factory=set)
    functions: dict = field(default_factory=dict)
    read_window: dict = field(default_factory=dict)
    writes: dict = field(default_factory=dict)
    rate: dict = field(default_factory=dict)

    @classmethod
    def learn(cls, df: pd.DataFrame, margin: float = 0.2) -> "Baseline":
        b = cls()
        req = df[(df.get("is_request") == True) & df.fc.notna()]  # noqa: E712
        b.talkers = set(map(tuple, df[df.dport == 502][["src", "dst"]].drop_duplicates().values))
        for (s, d), g in req.groupby(["src", "dst"]):
            b.functions[(s, d)] = set(g.fc.astype(int))
            reads = g[g.fc.isin([3, 4])]
            if len(reads):
                b.read_window[(s, d)] = (int(reads.addr.min()), int((reads.addr + reads.qty_or_value).max()))
            w = g[g.fc.isin(list(WRITE_FC))]
            if len(w):
                lo, hi = w.value.min(), w.value.max()
                pad = max(1.0, (hi - lo) * margin, abs(hi) * margin)
                b.writes[(s, d)] = (set(w.addr.astype(int)), lo - pad, hi + pad)
        per_sec = req.assign(sec=req.time.astype(int)).groupby(["src", "sec"]).size()
        b.rate = (per_sec.groupby(level=0).max() * 3).to_dict()
        return b

    def describe(self) -> pd.DataFrame:
        rows = []
        for k in sorted(self.functions):
            w = self.writes.get(k)
            rows.append({"client": k[0], "server": k[1],
                         "functions": ", ".join(FC_NAME.get(f, str(f)) for f in sorted(self.functions[k])),
                         "read registers": "%d to %d" % self.read_window[k] if k in self.read_window else "",
                         "writes": f"regs {sorted(w[0])}, values {w[1]:.0f} to {w[2]:.0f}" if w else "never",
                         "max req/s (x3)": self.rate.get(k[0])})
        return pd.DataFrame(rows)


def detect(df: pd.DataFrame, b: Baseline, scan_hosts: int = 5) -> pd.DataFrame:
    alerts = []

    def alert(i, r, rule, tech, detail):
        alerts.append({"index": i, "time": r.time, "rule": rule, "technique": tech, "src": r.src, "dst": r.dst, "detail": detail})

    syn = df[(df.dport == 502) & (df.tcp_flags == "S")]
    for src, g in syn.groupby("src"):
        g = g.sort_values("time")
        quiet_until = -1.0
        for i, r in g.iterrows():
            window = g[(g.time >= r.time - 10) & (g.time <= r.time)]
            if window.dst.nunique() >= scan_hosts and r.time > quiet_until:
                alert(i, r, "R1 scan", "T0846", f"{window.dst.nunique()} hosts probed on 502 in 10 s")
                alerts[-1]["dst"] = "many"
                quiet_until = r.time + 60  # one alert per scan, not one per probe
    req = df[(df.get("is_request") == True) & df.fc.notna()]  # noqa: E712
    seen_pairs = set()
    for i, r in req.iterrows():
        k, fc = (r.src, r.dst), int(r.fc)
        if k not in b.talkers:
            if k not in seen_pairs:
                alert(i, r, "R2 new talker", "T0886", f"{r.src} never talked Modbus to {r.dst}")
            seen_pairs.add(k)
        if fc not in b.functions.get(k, set()):
            tech = FC_TECH.get(fc, "T0888" if fc not in (3, 4) else "T0861")
            alert(i, r, "R3 new function", tech, f"FC {fc} ({FC_NAME.get(fc, '?')}) not in baseline for this pair")
        if fc in (3, 4) and k in b.read_window:
            lo, hi = b.read_window[k]
            if r.addr < lo or r.addr + r.qty_or_value > hi:
                alert(i, r, "R4 read outside map", "T0861", f"reads {int(r.addr)}..{int(r.addr + r.qty_or_value)}, normal is {lo}..{hi}")
        elif fc in (3, 4) and k not in b.functions:
            if r.addr + r.qty_or_value > 20:
                alert(i, r, "R4 read outside map", "T0861", f"unknown client reads {int(r.addr)}..{int(r.addr + r.qty_or_value)}")
        if fc in WRITE_FC:
            if k not in b.writes:
                alert(i, r, "R5 unauthorized write", "T0855", f"write to register {int(r.addr)} from a pair that never writes")
            else:
                regs, lo, hi = b.writes[k]
                if int(r.addr) not in regs or not (lo <= r.value <= hi):
                    alert(i, r, "R6 value out of range", "T0836", f"reg {int(r.addr)} = {int(r.value)}, normal {lo:.0f}..{hi:.0f}")
            if k not in b.writes and pd.notna(r.get("value")):
                alert(i, r, "R6 value out of range", "T0836", f"reg {int(r.addr)} = {int(r.value)} by an unauthorized client")
    per_sec = req.assign(sec=req.time.astype(int)).groupby(["src", "sec"])
    for (src, _sec), g in per_sec:
        limit = b.rate.get(src, 20)
        if len(g) > limit:
            r = g.iloc[int(limit)]
            alert(r.name, r, "R7 rate", "T0814", f"{len(g)} requests in one second (limit {limit})")
    return pd.DataFrame(alerts, columns=["index", "time", "rule", "technique", "src", "dst", "detail"])


def summarize(alerts: pd.DataFrame) -> pd.DataFrame:
    if alerts.empty:
        return alerts
    return (alerts.groupby(["rule", "technique", "src", "dst"])
            .agg(first=("time", "min"), count=("time", "size"), example=("detail", "first")).reset_index()
            .sort_values("first"))


def score(alerts: pd.DataFrame, labels: pd.DataFrame, df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Per technique in the ground truth: was it detected, and by which rules? Plus false positives."""
    lab = labels.set_index("index").label
    a = alerts.assign(truth=alerts["index"].map(lab))
    rows = []
    for tech in sorted({l.split(":")[1] for l in lab if l.startswith("attack:")}):
        hit = a[a.truth == f"attack:{tech}"]
        rows.append({"technique": tech, "attack packets": int((lab == f"attack:{tech}").sum()),
                     "detected": not hit.empty, "rules": ", ".join(sorted(hit.rule.unique())),
                     "time to detect (s)": round(hit.time.min() - df.loc[lab[lab == f"attack:{tech}"].index, "time"].min(), 3)
                     if not hit.empty else None})
    fp = a[a.truth == "normal"]
    return pd.DataFrame(rows), {"alerts": len(a), "false_positives": len(fp)}
