from otsec import inventory as inv
from otsec import zones as z
from otsec.model import CAPTURES


def test_model_is_consistent():
    assert z.check_model() == []


def test_as_found_violations():
    c = z.compliance(inv.flows(inv.packets(CAPTURES / "baseline_day1.pcap")))
    v = set(map(tuple, c[c.verdict == "VIOLATION"][["src", "dst", "port"]].values))
    assert v == {("erp-1", "broker-1", 1883), ("office-1", "hmi-1", 3389),
                 ("hist-1", "plc-1", 502), ("scada-1", "broker-1", 1883)}
