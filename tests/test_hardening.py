import asyncio
import logging

import pytest

from otsec import hardening as h

from .conftest import needs_mosquitto, needs_root

logging.getLogger("asyncua").setLevel(logging.CRITICAL)
SPEED = "acme/sao-paulo/packaging/line-1/filler-01/state"


@pytest.fixture(scope="module")
def secure_broker():
    with h.Mosquitto(secure=True) as b:
        yield b


@needs_mosquitto
def test_mqtt_anonymous_rejected(secure_broker):
    assert h.mqtt_try_connect(8883, tls=True).startswith("refused")
    pw = h.passwords()
    assert h.mqtt_try_connect(8883, user="scada", password="wrong", tls=True).startswith("refused")
    assert h.mqtt_try_connect(8883, user="scada", password=pw["scada"], tls=True) == "connected"


@needs_mosquitto
def test_mqtt_tls_required(secure_broker):
    pw = h.passwords()
    assert h.mqtt_try_connect(8883, user="scada", password=pw["scada"]).startswith("refused")
    assert "CERTIFICATE_VERIFY_FAILED" in h.mqtt_try_connect(8883, user="scada", password=pw["scada"], tls=True, ca=False)


@needs_mosquitto
@needs_root
def test_credentials_not_visible_on_the_wire(secure_broker):
    pw = h.passwords()
    r = h.sniff_credentials(8883, lambda: h.mqtt_try_connect(8883, user="scada", password=pw["scada"], tls=True))
    assert r["packets"] > 0 and pw["scada"].encode() not in r["blob"]


@needs_mosquitto
def test_mqtt_acl(secure_broker):
    pw = h.passwords()
    scada, hist = {"user": "scada", "password": pw["scada"]}, {"user": "historian", "password": pw["historian"]}
    assert h.mqtt_pubsub(8883, scada, hist, SPEED, tls=True)
    assert not h.mqtt_pubsub(8883, scada, hist, "acme/curitiba/packaging/line-3/filler-01/state", tls=True)
    assert not h.mqtt_pubsub(8883, hist, hist, SPEED, tls=True)


def test_password_policy():
    assert h.password_issues("Acme2024!", "scada")
    assert all(not h.password_issues(p, u) for u, p in h.passwords().items())


async def _opcua():
    pw = h.passwords()
    srv = h.opcua_server(secure=True)
    await h.opcua_start(srv, secure=True)
    try:
        return {
            "none": await h.opcua_try(secure=False),
            "untrusted": await h.opcua_try("historian", pw["historian"], cert="untrusted-client"),
            "no_user": await h.opcua_try(None, None),
            "ok": await h.opcua_try("historian", pw["historian"]),
        }
    finally:
        await srv.stop()


@pytest.fixture(scope="module")
def opcua():
    return asyncio.run(_opcua())


def test_opcua_rejects_insecure(opcua):
    assert opcua["none"].startswith("refused")
    assert "BadCertificateUntrusted" in opcua["untrusted"]
    assert opcua["no_user"].startswith("refused")


def test_opcua_secure_session(opcua):
    assert opcua["ok"].startswith("connected")
