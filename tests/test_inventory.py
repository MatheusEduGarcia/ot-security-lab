import pytest

from otsec import inventory as inv
from otsec.model import CAPTURES, assets


@pytest.fixture(scope="module")
def day1():
    return inv.packets(CAPTURES / "baseline_day1.pcap")


def test_inventory_matches_documented_assets(day1):
    seen = set(inv.inventory(day1).asset)
    assert seen == set(assets())


def test_rogue_device_is_flagged():
    i = inv.inventory(inv.packets(CAPTURES / "attack.pcap"))
    rogue = i[i.asset == "NOT IN INVENTORY"]
    assert list(rogue.ip) == ["127.0.40.66"]


def test_clear_text_mqtt_exposes_credentials(day1):
    s = inv.mqtt_secrets(day1)
    assert "Acme2024!" in set(s.password.dropna())
