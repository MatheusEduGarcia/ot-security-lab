import pytest

from otsec import segmentation as s
from otsec.model import zones

from .conftest import needs_root


def test_policy_matches_conduits():
    rules = s.policy()
    allow = [r for r in rules if "ACCEPT" in r and "--dport" in r]
    expected = sum(len(c["src"]) * len(c["dst"]) for c in zones()["conduits"])
    assert len(allow) == expected
    assert rules[-1][-3:] == ["REJECT", "--reject-with", "tcp-reset"]


@pytest.fixture(scope="module")
def enforced():
    with s.Listeners():
        before = {p["name"]: s.reach(p["src"], p["dst"], p["port"]) for p in s.test_paths()}
        s.apply()
        try:
            after = {p["name"]: s.reach(p["src"], p["dst"], p["port"]) for p in s.test_paths()}
        finally:
            s.remove()
    return before, after


@needs_root
def test_live_enforcement(enforced):
    before, after = enforced
    assert all(before.values()), "flat network: everything reachable before the firewall"
    for p in s.test_paths():
        assert after[p["name"]] == p["expected"], p["name"]


@needs_root
def test_enterprise_blocked_from_plant(enforced):
    _, after = enforced
    assert not after["office-1 RDP to hmi-1"] and not after["erp-1 MQTT to broker-1"]
    assert after["C6 erp-1 to dmz-broker"]
