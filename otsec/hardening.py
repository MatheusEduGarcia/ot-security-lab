"""
Protocol hardening (exercise 05): MQTT and OPC UA, before and after.

  pki()                    a private CA plus certificates for the broker, the OPC UA
                           server and two OPC UA clients (one trusted, one not)
  Mosquitto(secure=...)    runs a real mosquitto: insecure (anonymous, port 1883)
                           or hardened (TLS 8883, accounts, per-topic ACL)
  sniff_credentials(...)   listens on loopback and shows what an observer can read
  password_issues(pw)      a small password policy check
  opcua_server(...)        asyncua server that only accepts Basic256Sha256 SignAndEncrypt,
                           trusted client certificates and a user login

Everything is generated at runtime under configs/runtime (git-ignored). No key is committed.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .model import ROOT, assets

RUNTIME = ROOT / "configs" / "runtime"
BROKER_IP = assets()["broker-1"]["ip"]
SCADA_IP = assets()["scada-1"]["ip"]

# Accounts on the hardened broker. In a real plant these come from a vault, never from git.
# The lab generates them so nothing secret is committed.
ACCOUNTS = ("scada", "historian", "dashboard")

ACL = """# one account per client, least privilege
user scada
topic write acme/sao-paulo/packaging/#

user historian
topic read acme/#

user dashboard
topic read acme/sao-paulo/packaging/+/+/state
"""


# ------------------------------------------------------------------ PKI
def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write(path: Path, key, cert):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.with_suffix(".key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                           serialization.PrivateFormat.TraditionalOpenSSL,
                                                           serialization.NoEncryption()))
    path.with_name(path.name + "_key.pem").write_bytes(path.with_suffix(".key").read_bytes())  # asyncua wants .pem
    path.with_suffix(".pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    path.with_suffix(".der").write_bytes(cert.public_bytes(serialization.Encoding.DER))


def _cert(cn, key, issuer_cert, issuer_key, *, ca=False, ips=(), uri=None, server=True, days=365):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME OT Lab"),
                                  x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(issuer_cert.subject if issuer_cert else x509.Name([
             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME OT Lab"), x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
    else:
        san = [x509.IPAddress(ipaddress.ip_address(i)) for i in ips] + [x509.DNSName(cn)]
        if uri:
            san.append(x509.UniformResourceIdentifier(uri))
        b = (b.add_extension(x509.SubjectAlternativeName(san), critical=False)
              .add_extension(x509.KeyUsage(True, True, True, True, False, False, False, False, False), critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                             critical=False))
    return b.sign(issuer_key or key, hashes.SHA256())


def pki(force: bool = False) -> Path:
    d = RUNTIME / "pki"
    if (d / "ca.pem").exists() and not force:
        return d
    shutil.rmtree(d, ignore_errors=True)
    ca_key = _key(); ca = _cert("ACME OT Lab CA", ca_key, None, None, ca=True, days=3650)
    _write(d / "ca", ca_key, ca)
    d.chmod(0o755)
    for name, ips, uri in (("broker-1", [BROKER_IP], None),
                           ("scada-opcua", [SCADA_IP], "urn:acme:scada-1:opcua"),
                           ("historian-client", [], "urn:acme:hist-1:client"),
                           ("untrusted-client", [], "urn:acme:unknown:client")):
        k = _key()
        signer = (ca, ca_key) if name != "untrusted-client" else (None, None)  # self-signed, not from our CA
        _write(d / name, k, _cert(name, k, *signer, ips=ips, uri=uri))
    for f in [d, *d.iterdir()]:
        f.chmod(0o755 if f.is_dir() else 0o644)  # lab only: lets the broker user read its key
    return d


def passwords() -> dict[str, str]:
    """Strong random passwords generated once per lab run (stored only under configs/runtime)."""
    import secrets
    f = RUNTIME / "passwords.txt"
    if f.exists():
        return dict(line.split(":", 1) for line in f.read_text().split())
    RUNTIME.mkdir(parents=True, exist_ok=True)
    def strong(u):
        while True:
            pw = secrets.token_urlsafe(18)
            if not password_issues(pw, u):
                return pw
    pw = {u: strong(u) for u in ACCOUNTS}
    f.write_text("\n".join(f"{u}:{p}" for u, p in pw.items()))
    return pw


COMMON = ["password", "123456", "admin", "acme", "scada", "plc", "welcome", "qwerty"]


def password_issues(pw: str, user: str = "") -> list[str]:
    issues = []
    if len(pw) < 12:
        issues.append("shorter than 12 characters")
    if sum(any(f(c) for c in pw) for f in (str.islower, str.isupper, str.isdigit, lambda c: not c.isalnum())) < 3:
        issues.append("fewer than 3 character classes")
    low = pw.lower()
    if user and user.lower() in low:
        issues.append("contains the user name")
    if any(w in low for w in COMMON):
        issues.append("contains a common word")
    if any(str(y) in pw for y in range(2015, 2031)):
        issues.append("contains a year")
    return issues


# ------------------------------------------------------------------ MQTT broker
class Mosquitto:
    def __init__(self, secure: bool):
        self.secure = secure
        RUNTIME.mkdir(parents=True, exist_ok=True)
        # Distro AppArmor profiles (Ubuntu) only let mosquitto read under /etc/mosquitto,
        # so when we can write there (root) the broker's files go there, removed on exit.
        etc = Path("/etc/mosquitto")
        base = etc if etc.is_dir() and os.access(etc, os.W_OK) else RUNTIME
        self.dir = Path(tempfile.mkdtemp(prefix="otlab-", dir=base))
        if secure:
            src = pki()
            p = self.dir
            for f in ("ca.pem", "broker-1.pem", "broker-1.key"):
                shutil.copy(src / f, p / f)
            pwf = self.dir / "passwd"
            for i, (u, pw) in enumerate(passwords().items()):
                subprocess.run(["mosquitto_passwd", "-b"] + (["-c"] if i == 0 else []) + [str(pwf), u, pw], check=True)
            (self.dir / "acl").write_text(ACL)
            conf = f"""listener 8883 {BROKER_IP}
allow_anonymous false
password_file {pwf}
acl_file {self.dir / 'acl'}
cafile {p / 'ca.pem'}
certfile {p / 'broker-1.pem'}
keyfile {p / 'broker-1.key'}
tls_version tlsv1.2
"""
            self.port = 8883
        else:
            conf = f"listener 1883 {BROKER_IP}\nallow_anonymous true\n"
            self.port = 1883
        (self.dir / "mosquitto.conf").write_text(conf)
        self.dir.chmod(0o755)  # mosquitto drops root privileges to its own user
        for f in self.dir.iterdir():
            f.chmod(0o644)

    def __enter__(self):
        self.proc = subprocess.Popen(["mosquitto", "-c", str(self.dir / "mosquitto.conf")],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(0.6)
        if self.proc.poll() is not None:
            raise RuntimeError(self.proc.stdout.read().decode())
        return self

    def __exit__(self, *exc):
        self.proc.terminate(); self.proc.wait(5)
        shutil.rmtree(self.dir, ignore_errors=True)


def mqtt_client(user=None, password=None, tls=False, ca=True):
    import paho.mqtt.client as mqtt
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if user:
        c.username_pw_set(user, password)
    if tls:
        import ssl
        if ca:
            c.tls_set(ca_certs=str(pki() / "ca.pem"))
        else:
            c.tls_set(cert_reqs=ssl.CERT_REQUIRED)  # system CAs only: our private CA is unknown
    return c


def mqtt_try_connect(port, **kw) -> str:
    """Returns 'connected' or the reason it failed."""
    c = mqtt_client(**kw)
    result = {}
    c.on_connect = lambda cl, u, f, rc, p=None: result.setdefault("rc", str(rc))
    try:
        c.connect(BROKER_IP, port, keepalive=5)
    except Exception as e:  # noqa: BLE001  TLS errors surface here
        return f"refused: {type(e).__name__}: {str(e)[:70]}"
    c.loop_start()
    for _ in range(30):
        if "rc" in result:
            break
        time.sleep(0.05)
    c.loop_stop(); c.disconnect()
    rc = result.get("rc", "no CONNACK")
    return "connected" if rc == "Success" else f"refused: {rc}"


def mqtt_pubsub(port, publisher: dict, subscriber: dict, topic: str, tls=False) -> bool:
    """Does a message published by `publisher` on `topic` reach `subscriber` (subscribed to #)?"""
    got = threading.Event()
    s = mqtt_client(tls=tls, **subscriber)
    s.on_message = lambda *a: got.set()
    s.connect(BROKER_IP, port); s.subscribe("#"); s.loop_start(); time.sleep(0.3)
    p = mqtt_client(tls=tls, **publisher)
    p.connect(BROKER_IP, port); p.loop_start()
    p.publish(topic, '{"value": "RUNNING"}', qos=1); time.sleep(0.5)
    p.loop_stop(); p.disconnect(); s.loop_stop(); s.disconnect()
    return got.is_set()


def sniff_credentials(port: int, action, seconds: float = 2.0) -> dict:
    """Captures loopback traffic to `port` while `action()` runs, and reports what is readable."""
    from scapy.all import TCP, AsyncSniffer, Raw
    sn = AsyncSniffer(iface="lo", lfilter=lambda p: TCP in p and port in (p[TCP].sport, p[TCP].dport), store=True)
    sn.start(); time.sleep(0.3)
    action()
    time.sleep(seconds); pk = sn.stop()
    blob = b"".join(bytes(p[Raw].load) for p in pk if Raw in p)
    return {"packets": len(pk), "bytes": len(blob), "blob": blob}


# ------------------------------------------------------------------ OPC UA
def opcua_server(secure: bool = True):
    """Returns an un-started asyncua Server bound to scada-1:4840."""
    from asyncua import Server, ua
    from asyncua.crypto.permission_rules import SimpleRoleRuleset
    from asyncua.server.user_managers import UserManager
    from asyncua.server.users import User, UserRole

    pw = passwords()

    class Users(UserManager):
        def get_user(self, iserver, username=None, password=None, certificate=None):
            if username == "historian" and password == pw["historian"]:
                return User(role=UserRole.User)
            return None

    srv = Server(user_manager=Users() if secure else None)
    srv.set_endpoint(f"opc.tcp://{SCADA_IP}:4840/acme/scada")
    srv.set_server_name("ACME SCADA OPC UA")
    if secure:
        srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt], permission_ruleset=SimpleRoleRuleset())
        srv.set_security_IDs(["Username"])
    else:
        srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    return srv


async def opcua_start(srv, secure: bool = True):
    from asyncua.crypto.truststore import TrustStore
    from asyncua.crypto.validator import CertificateValidator, CertificateValidatorOptions
    p = pki()
    await srv.init()
    srv.set_application_uri("urn:acme:scada-1:opcua")
    await srv.load_certificate(str(p / "scada-opcua.der"))
    await srv.load_private_key(str(p / "scada-opcua_key.pem"))
    if secure:
        trust = TrustStore([p / "trusted"], [])
        (p / "trusted").mkdir(exist_ok=True)
        shutil.copy(p / "ca.der", p / "trusted" / "ca.der")
        await trust.load()
        srv.set_certificate_validator(CertificateValidator(
            CertificateValidatorOptions.TRUSTED_VALIDATION | CertificateValidatorOptions.PEER_CLIENT, trust))
    ns = await srv.register_namespace("urn:acme:plant")
    obj = await srv.nodes.objects.add_object(ns, "Filler01")
    speed = await obj.add_variable(ns, "Speed", 468.0)
    await srv.start()
    return speed


async def opcua_try(user=None, password=None, cert="historian-client", secure=True) -> str:
    from asyncua import Client
    p = pki()
    c = Client(f"opc.tcp://{SCADA_IP}:4840/acme/scada", timeout=3)
    c.application_uri = f"urn:acme:{'hist-1' if cert == 'historian-client' else 'unknown'}:client"
    try:
        if secure:
            await c.set_security_string(f"Basic256Sha256,SignAndEncrypt,{p / (cert + '.der')},{p / (cert + '_key.pem')},{p / 'scada-opcua.der'}")
        if user:
            c.set_user(user); c.set_password(password)
        async with c:
            node = await c.nodes.objects.get_child(["2:Filler01", "2:Speed"])
            return f"connected, Speed = {await node.read_value()}"
    except Exception as e:  # noqa: BLE001
        return f"refused: {type(e).__name__}: {str(e)[:80]}"
