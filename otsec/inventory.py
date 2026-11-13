"""
Passive asset inventory from a capture (exercise 01).

Passive means we only listen: no scan, no packet sent to the plant. This is the
safe way to inventory an OT network, because active scans can crash old PLCs.

  packets(pcap)        -> one row per TCP packet, with Modbus and MQTT decoded
  inventory(df)        -> one row per device seen: IP, MAC, services offered, peers
  flows(df)            -> who talks to whom, on which port, how much
  mqtt_secrets(df)     -> credentials and topics readable in clear-text MQTT
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

import pandas as pd
from scapy.all import IP, TCP, Ether, Raw, rdpcap

from .model import asset_zone, assets, ip_to_asset

SERVICE = {502: "modbus", 1883: "mqtt", 8883: "mqtts", 4840: "opcua", 3389: "rdp", 443: "https"}
FC_NAME = {1: "read coils", 2: "read discrete inputs", 3: "read holding registers", 4: "read input registers",
           5: "write single coil", 6: "write single register", 8: "diagnostics", 15: "write multiple coils",
           16: "write multiple registers", 43: "read device identification"}
WRITE_FC = {5, 6, 15, 16}


def _modbus(payload: bytes, is_request: bool) -> dict:
    if len(payload) < 8:
        return {}
    _tid, _pid, _ln, _uid, fc = struct.unpack(">HHHBB", payload[:8])
    d = {"fc": fc}
    if is_request and fc in (1, 2, 3, 4, 5, 6, 15, 16) and len(payload) >= 12:
        d["addr"], d["qty_or_value"] = struct.unpack(">HH", payload[8:12])
        if fc == 16 and len(payload) >= 15:
            d["value"] = struct.unpack(">H", payload[13:15])[0]
        if fc == 6:
            d["value"] = d["qty_or_value"]
    return d


def _mqtt(payload: bytes) -> dict:
    if not payload:
        return {}
    kind = payload[0] >> 4
    i, mult, n = 1, 1, 0
    while i < len(payload):
        b = payload[i]; n += (b & 127) * mult; mult *= 128; i += 1
        if not b & 128:
            break
    body = payload[i:]
    rd = lambda o: (body[o + 2:o + 2 + struct.unpack(">H", body[o:o + 2])[0]].decode(errors="replace"),
                    o + 2 + struct.unpack(">H", body[o:o + 2])[0])
    try:
        if kind == 1:  # CONNECT
            _, o = rd(0); o += 4
            cid, o = rd(o); user, o = rd(o); pw, o = rd(o)
            return {"mqtt": "CONNECT", "client_id": cid, "user": user, "password": pw}
        if kind == 3:  # PUBLISH
            topic, o = rd(0)
            return {"mqtt": "PUBLISH", "topic": topic, "message": body[o:].decode(errors="replace")}
    except (struct.error, IndexError):
        pass
    return {}


def packets(path) -> pd.DataFrame:
    rows = []
    for p in rdpcap(str(path)):
        if IP not in p or TCP not in p:
            continue
        tcp = p[TCP]
        pay = bytes(p[Raw].load) if Raw in p else b""
        r = {"time": float(p.time), "src": p[IP].src, "dst": p[IP].dst, "src_mac": p[Ether].src if Ether in p else None,
             "sport": tcp.sport, "dport": tcp.dport, "tcp_flags": str(tcp.flags), "size": len(p), "payload_len": len(pay)}
        if 502 in (tcp.sport, tcp.dport) and pay:
            r["is_request"] = tcp.dport == 502
            r.update(_modbus(pay, r["is_request"]))
        if 1883 in (tcp.sport, tcp.dport) and pay:
            r.update(_mqtt(pay))
        rows.append(r)
    df = pd.DataFrame(rows)
    df["ts"] = pd.to_datetime(df.time, unit="s", utc=True)
    names = ip_to_asset()
    df["src_id"] = df.src.map(names).fillna("UNKNOWN " + df.src)
    df["dst_id"] = df.dst.map(names).fillna("UNKNOWN " + df.dst)
    return df


def inventory(df: pd.DataFrame) -> pd.DataFrame:
    """One row per device actually seen on the wire, compared with the documented asset list."""
    known = assets()
    zone = asset_zone()
    offered = (df[df.sport.isin(SERVICE.keys()) & (df.payload_len > 0)]
               .groupby("src").sport.apply(lambda s: sorted({SERVICE[p] for p in s})))
    rows = []
    for ip in sorted(set(df.src) | set(df[df.tcp_flags.str.contains("SA")].src)):
        mine = df[df.src == ip]
        aid = ip_to_asset().get(ip)
        peers = sorted(set(df[df.src == ip].dst_id) | set(df[df.dst == ip].src_id))
        rows.append({
            "ip": ip, "mac": mine.src_mac.iloc[0], "asset": aid or "NOT IN INVENTORY",
            "kind": known[aid]["kind"] if aid else "?", "zone": zone.get(aid, "?"),
            "services_seen": ", ".join(offered.get(ip, [])),
            "talks_to": len(peers), "packets_sent": len(mine),
        })
    return pd.DataFrame(rows)


def flows(df: pd.DataFrame) -> pd.DataFrame:
    """Client to server flows (direction from the side that opened or requests)."""
    req = df[df.dport.isin(SERVICE.keys())]
    g = req.groupby(["src_id", "dst_id", "dport"]).agg(packets=("size", "size"), bytes=("size", "sum")).reset_index()
    g["service"] = g.dport.map(SERVICE)
    zone = asset_zone()
    g["src_zone"] = g.src_id.map(zone).fillna("?")
    g["dst_zone"] = g.dst_id.map(zone).fillna("?")
    return g.sort_values(["src_zone", "src_id", "dst_id"]).reset_index(drop=True)


def mqtt_secrets(df: pd.DataFrame) -> pd.DataFrame:
    if "mqtt" not in df:
        return pd.DataFrame()
    m = df[df.mqtt.notna()]
    cols = [c for c in ("ts", "src_id", "mqtt", "user", "password", "topic", "message") if c in m]
    return m[cols].drop_duplicates(subset=[c for c in ("src_id", "mqtt", "user", "topic") if c in m])


def modbus_summary(df: pd.DataFrame) -> pd.DataFrame:
    m = df[(df.get("is_request") == True) & df.fc.notna()].copy()  # noqa: E712
    m["function"] = m.fc.astype(int).map(FC_NAME).fillna("other")
    m["write"] = m.fc.astype(int).isin(WRITE_FC)
    return m.groupby(["src_id", "dst_id", "function", "write"]).size().rename("requests").reset_index()


def when(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")
