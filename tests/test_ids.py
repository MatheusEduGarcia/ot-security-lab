import pandas as pd
import pytest

from otsec import ids
from otsec import inventory as inv
from otsec.model import CAPTURES


@pytest.fixture(scope="module")
def baseline():
    return ids.Baseline.learn(inv.packets(CAPTURES / "baseline_day1.pcap"))


def test_no_false_positives_on_normal_day(baseline):
    assert ids.detect(inv.packets(CAPTURES / "baseline_day2.pcap"), baseline).empty


def test_detects_every_technique(baseline):
    df = inv.packets(CAPTURES / "attack.pcap")
    alerts = ids.detect(df, baseline)
    table, totals = ids.score(alerts, pd.read_csv(CAPTURES / "attack_labels.csv"), df)
    assert table.detected.all()
    assert totals["false_positives"] == 0
