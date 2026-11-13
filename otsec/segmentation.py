"""
Network segmentation (exercise 04): the conduit list becomes a default-deny
firewall, and the firewall is tested for real.

The lab runs every zone on its own loopback subnet (127.0.<zone>.0/24), so a single
Linux machine is enough. The rules are plain iptables on the loopback interface,
in a dedicated chain (OTLAB) that is removed afterwards. Needs root (or sudo).

  policy()            iptables rules generated from model/zones.yaml
  apply() / remove()  install and remove the chain
  Listeners           real TCP servers on every asset service (ip, port)
  reach(src, dst, p)  does a TCP connect from src to dst:p succeed?
"""
from __future__ import annotations

import os
import socket
import subprocess
import threading

from .model import assets, zones

CHAIN = "OTLAB"


def subnet(zone: str) -> str:
    ip = assets()[zones()["zones"][zone]["assets"][0]]["ip"]
    return ".".join(ip.split(".")[:3]) + ".0/24"


def policy() -> list[list[str]]:
    z = zones()
    rules = [["-A", CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]]
    for zid in z["zones"]:  # traffic inside a zone is left to host controls
        rules.append(["-A", CHAIN, "-s", subnet(zid), "-d", subnet(zid), "-j", "ACCEPT"])
    for c in z["conduits"]:  # one rule per allowed (source host, destination host, port)
        for s in c["src"]:
            for d in c["dst"]:
                rules.append(["-A", CHAIN, "-s", assets()[s]["ip"], "-d", assets()[d]["ip"], "-p", "tcp",
                              "--dport", str(c["port"]), "-m", "comment", "--comment", c["id"], "-j", "ACCEPT"])
    for zs in z["zones"]:  # default deny between lab zones
        for zd in z["zones"]:
            if zs != zd:
                rules.append(["-A", CHAIN, "-s", subnet(zs), "-d", subnet(zd), "-p", "tcp",
                              "-j", "REJECT", "--reject-with", "tcp-reset"])
    return rules


def as_text() -> str:
    return "\n".join("iptables " + " ".join(r) for r in policy())


def _ipt(*args, check=True):
    cmd = ["iptables", *args] if os.geteuid() == 0 else ["sudo", "-n", "iptables", *args]
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def available() -> bool:
    try:
        return _ipt("-L", "-n", check=False).returncode == 0
    except FileNotFoundError:
        return False


def apply():
    remove()
    _ipt("-N", CHAIN)
    for r in policy():
        _ipt(*r)
    _ipt("-I", "OUTPUT", "-o", "lo", "-j", CHAIN)


def remove():
    _ipt("-D", "OUTPUT", "-o", "lo", "-j", CHAIN, check=False)
    _ipt("-F", CHAIN, check=False)
    _ipt("-X", CHAIN, check=False)


def counters() -> str:
    return _ipt("-L", CHAIN, "-n", "-v", check=False).stdout


class Listeners:
    """Accepts and closes TCP connections on every (ip, port) the model says exists."""

    def __init__(self):
        self.socks = []
        for a in assets().values():
            for svc in a["services"]:
                port = int(svc.split("/")[1])
                s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((a["ip"], port)); s.listen(64); s.settimeout(0.2)
                self.socks.append(s)
        self.stop = threading.Event()
        self.t = threading.Thread(target=self._loop, daemon=True); self.t.start()

    def _loop(self):
        while not self.stop.is_set():
            for s in self.socks:
                try:
                    c, _ = s.accept(); c.close()
                except (TimeoutError, OSError):
                    pass

    def close(self):
        self.stop.set(); self.t.join()
        for s in self.socks:
            s.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def reach(src_ip: str, dst_ip: str, port: int, timeout: float = 0.5) -> bool:
    c = socket.socket(); c.settimeout(timeout)
    try:
        c.bind((src_ip, 0)); c.connect((dst_ip, port)); return True
    except OSError:
        return False
    finally:
        c.close()


def test_paths() -> list[dict]:
    """The paths worth testing: every conduit, the as-found violations and the attacker's paths."""
    A = {k: v["ip"] for k, v in assets().items()}
    paths = [{"name": f"{c['id']} {s} to {d}", "src": A[s], "dst": A[d], "port": c["port"], "expected": True}
             for c in zones()["conduits"] for s in c["src"][:1] for d in c["dst"][:1]]
    paths += [
        {"name": "office-1 RDP to hmi-1", "src": A["office-1"], "dst": A["hmi-1"], "port": 3389, "expected": False},
        {"name": "erp-1 MQTT to broker-1", "src": A["erp-1"], "dst": A["broker-1"], "port": 1883, "expected": False},
        {"name": "hist-1 Modbus to plc-1", "src": A["hist-1"], "dst": A["plc-1"], "port": 502, "expected": False},
        {"name": "rogue Modbus to plc-1", "src": "127.0.40.66", "dst": A["plc-1"], "port": 502, "expected": False},
        {"name": "rogue Modbus to plc-2", "src": "127.0.40.66", "dst": A["plc-2"], "port": 502, "expected": False},
        {"name": "dmz-broker back into broker-1", "src": A["dmz-broker"], "dst": A["broker-1"], "port": 8883, "expected": False},
    ]
    return paths
