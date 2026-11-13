"""
Synthetic network captures of the plant, written as real pcap files.

Three captures are produced, all reproducible from a seed:

  baseline_day1.pcap  ten minutes of normal operation, "as found" on a flat network.
                      It already contains a few flows that break the zone design
                      (an office PC on RDP to the HMI, the historian polling a PLC
                      directly, MQTT in clear text). Exercise 02 finds them.
  baseline_day2.pcap  another normal day with a different seed. Used to measure
                      false positives of the IDS in exercise 06.
  attack.pcap         a normal day plus an attack from a rogue laptop, staged after
                      MITRE ATT&CK for ICS. Every attack packet is labelled in
                      attack_labels.csv with its technique, so detection can be scored.

Nothing here touches a real network: packets are built in memory and written to disk.

Run:  python -m otsec.traffic
"""
from __future__ import annotations

import csv
import hashlib
import random
import struct

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from .model import CAPTURES, assets

MODBUS = 502
ROGUE = {"ip": "127.0.40.66", "mac": "02:66:66:66:66:66"}
T0 = 1794556800.0  # 2026-11-13 08:00 UTC


def _mac(asset_id: str) -> str:
    h = int(hashlib.sha1(asset_id.encode()).hexdigest()[:6], 16)
    return "02:00:5e:%02x:%02x:%02x" % (h >> 16, (h >> 8) & 0xFF, h & 0xFF)


class Capture:
    def __init__(self, seed: int):
        self.rnd = random.Random(seed)
        self.pkts: list = []
        self.labels: list[str] = []
        self.tid = 0
        self.ports: dict = {}
        self.seq: dict = {}

    # ----------------------------------------------------------- low level
    def _ep(self, who: str) -> tuple[str, str]:
        if who == "rogue":
            return ROGUE["ip"], ROGUE["mac"]
        a = assets()[who]
        return a["ip"], _mac(who)

    def _sport(self, src: str, dst: str, dport: int) -> int:
        key = (src, dst, dport)
        if key not in self.ports:
            self.ports[key] = self.rnd.randint(40000, 60000)
        return self.ports[key]

    def _pkt(self, t, src, dst, sport, dport, flags, payload=b"", label="normal"):
        sip, smac = self._ep(src)
        dip, dmac = self._ep(dst)
        k = (sip, sport, dip, dport)
        seq = self.seq.get(k, self.rnd.randint(1, 2**31))
        p = Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags=flags, seq=seq)
        if payload:
            p = p / Raw(payload)
        self.seq[k] = seq + max(len(payload), 1)
        p.time = T0 + t
        self.pkts.append(p)
        self.labels.append(label)

    def session(self, t, src, dst, dport, label="normal"):
        sp = self._sport(self._ep(src)[0], self._ep(dst)[0], dport)
        self._pkt(t, src, dst, sp, dport, "S", label=label)
        self._pkt(t + 0.0004, dst, src, dport, sp, "SA", label=label)
        self._pkt(t + 0.0008, src, dst, sp, dport, "A", label=label)

    def exchange(self, t, src, dst, dport, req: bytes, resp: bytes, label="normal"):
        sp = self._sport(self._ep(src)[0], self._ep(dst)[0], dport)
        self._pkt(t, src, dst, sp, dport, "PA", req, label)
        if resp:
            self._pkt(t + 0.003 + self.rnd.random() * 0.004, dst, src, dport, sp, "PA", resp, label)

    # ----------------------------------------------------------- Modbus/TCP
    def modbus(self, t, src, dst, pdu_req: bytes, pdu_resp: bytes, label="normal"):
        self.tid = (self.tid + 1) % 65536
        mbap = lambda pdu: struct.pack(">HHHB", self.tid, 0, len(pdu) + 1, 1) + pdu
        self.exchange(t, src, dst, MODBUS, mbap(pdu_req), mbap(pdu_resp) if pdu_resp else b"", label)

    def read_holding(self, t, src, dst, start=0, qty=10, label="normal"):
        values = [self.rnd.randint(0, 500) for _ in range(qty)]
        resp = struct.pack(">BB", 3, 2 * qty) + b"".join(struct.pack(">H", v) for v in values)
        self.modbus(t, src, dst, struct.pack(">BHH", 3, start, qty), resp, label)

    def write_single(self, t, src, dst, addr, value, label="normal"):
        pdu = struct.pack(">BHH", 6, addr, value)
        self.modbus(t, src, dst, pdu, pdu, label)

    def write_multiple(self, t, src, dst, addr, values, label="normal"):
        body = b"".join(struct.pack(">H", v) for v in values)
        req = struct.pack(">BHHB", 16, addr, len(values), len(body)) + body
        self.modbus(t, src, dst, req, struct.pack(">BHH", 16, addr, len(values)), label)

    # ----------------------------------------------------------- MQTT 3.1.1, clear text on purpose
    @staticmethod
    def _rl(n: int) -> bytes:
        out = b""
        while True:
            d, n = n % 128, n // 128
            out += bytes([d | (0x80 if n else 0)])
            if not n:
                return out

    def mqtt_connect(self, t, src, dst, user, password, label="normal"):
        s = lambda x: struct.pack(">H", len(x)) + x.encode()
        var = s("MQTT") + bytes([4, 0xC2]) + struct.pack(">H", 60)
        pay = s(f"{src}-client") + s(user) + s(password)
        pkt = bytes([0x10]) + self._rl(len(var + pay)) + var + pay
        self.exchange(t, src, dst, 1883, pkt, bytes([0x20, 2, 0, 0]), label)

    def mqtt_publish(self, t, src, dst, topic, payload, label="normal"):
        body = struct.pack(">H", len(topic)) + topic.encode() + payload.encode()
        self.exchange(t, src, dst, 1883, bytes([0x30]) + self._rl(len(body)) + body, b"", label)

    def opaque(self, t, src, dst, port, n=180, label="normal"):
        """Encrypted or binary traffic (TLS, OPC UA SecureChannel, RDP): only sizes are visible."""
        self.exchange(t, src, dst, port, self.rnd.randbytes(n), self.rnd.randbytes(n // 2), label)


def normal_day(c: Capture, minutes: int = 10):
    r = c.rnd
    for dst in ("plc-1", "plc-2"):
        c.session(0.1, "hmi-1", dst, MODBUS); c.session(0.2, "scada-1", dst, MODBUS)
    c.session(0.3, "hist-1", "scada-1", 4840); c.session(0.4, "scada-1", "broker-1", 1883)
    c.mqtt_connect(0.5, "scada-1", "broker-1", "scada", "Acme2024!")
    for s in range(minutes * 60):
        t = s + r.random() * 0.05
        for dst in ("plc-1", "plc-2"):
            c.read_holding(t, "hmi-1", dst, 0, 10)
            if s % 2 == 0:
                c.read_holding(t + 0.2, "scada-1", dst, 0, 20)
        if s % 5 == 0:
            c.opaque(t + 0.3, "hist-1", "scada-1", 4840, 240)
            c.mqtt_publish(t + 0.4, "scada-1", "broker-1", "acme/sao-paulo/packaging/line-1/filler-01/speed",
                           '{"value": %.1f}' % r.uniform(440, 500))
        if s % 10 == 0:
            c.opaque(t + 0.5, "erp-1", "dmz-broker", 8883, 300)
            c.opaque(t + 0.6, "broker-1", "dmz-broker", 8883, 400)
        if s % 30 == 0:  # shadow IT: the historian also reads PLC-1 directly (breaks conduit C3)
            c.read_holding(t + 0.7, "hist-1", "plc-1", 0, 10)
        if s % 60 == 0:  # remote support: office PC on RDP to the HMI (crosses IT straight into L2)
            c.opaque(t + 0.8, "office-1", "hmi-1", 3389, 900)
        if s % 45 == 0:  # an ERP report reading the UNS broker directly, in clear text
            c.mqtt_publish(t + 0.9, "erp-1", "broker-1", "acme/erp/report", '{"ok": true}')
    for k, t in enumerate((120.0, 300.0, 480.0)):  # three authorized setpoint changes from the EWS
        c.session(t - 0.5, "ews-1", "plc-1", MODBUS)
        c.write_multiple(t, "ews-1", "plc-1", 100, [r.randint(440, 480)])


def attack(c: Capture):
    lab = lambda tech: f"attack:{tech}"
    t = 200.0
    for host in range(1, 31):  # T0846 Remote System Discovery: SYN sweep of the cell subnet
        ip = f"127.0.10.{host}"
        if ip in ("127.0.10.11", "127.0.10.12"):
            dst = "plc-1" if host == 11 else "plc-2"
            c.session(t, "rogue", dst, MODBUS, lab("T0846"))
        else:
            p = Ether(src=ROGUE["mac"]) / IP(src=ROGUE["ip"], dst=ip) / TCP(sport=c.rnd.randint(40000, 60000), dport=MODBUS, flags="S")
            p.time = T0 + t; c.pkts.append(p); c.labels.append(lab("T0846"))
        t += 0.02
    t = 210.0
    for dst in ("plc-1", "plc-2"):  # T0888 Remote System Information Discovery: read device identification
        c.modbus(t, "rogue", dst, bytes([0x2B, 0x0E, 0x01, 0x00]),
                 bytes([0x2B, 0x0E, 0x01, 0x01, 0, 0, 3, 0, 4]) + b"ACME" + bytes([1, 6]) + b"PLC-X1" + bytes([2, 5]) + b"v2.31",
                 lab("T0888"))
        t += 0.5
    t = 220.0
    for start in range(0, 1000, 100):  # T0861 Point & Tag Identification: sweep the register map
        c.read_holding(t, "rogue", "plc-1", start, 100, lab("T0861")); t += 0.1
    c.write_single(240.0, "rogue", "plc-1", 100, 9999, lab("T0836"))  # T0836 Modify Parameter (setpoint)
    c.modbus(250.0, "rogue", "plc-2", struct.pack(">BHH", 8, 1, 0), struct.pack(">BHH", 8, 1, 0), lab("T0816"))  # restart
    t = 260.0
    for _ in range(1500):  # T0814 Denial of Service: request flood
        c.read_holding(t, "rogue", "plc-1", 0, 125, lab("T0814")); t += 0.001


def build_all(minutes: int = 10):
    CAPTURES.mkdir(exist_ok=True)
    out = {}
    for name, seed, evil in (("baseline_day1", 1, False), ("baseline_day2", 2, False), ("attack", 3, True)):
        c = Capture(seed)
        normal_day(c, minutes)
        if evil:
            attack(c)
        order = sorted(range(len(c.pkts)), key=lambda i: float(c.pkts[i].time))
        pkts = [c.pkts[i] for i in order]
        labels = [c.labels[i] for i in order]
        wrpcap(str(CAPTURES / f"{name}.pcap"), pkts)
        if evil:
            with open(CAPTURES / "attack_labels.csv", "w", newline="") as f:
                w = csv.writer(f); w.writerow(["index", "label"])
                w.writerows(enumerate(labels))
        out[name] = len(pkts)
    return out


if __name__ == "__main__":
    print(build_all())
