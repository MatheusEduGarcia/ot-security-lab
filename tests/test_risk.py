from otsec import risk


def test_controls_lower_risk():
    d = risk.assess()
    assert (d.residual <= d.inherent).all()
    assert not (d.residual_band == "critical").any()


def test_gaps_are_reported_honestly():
    d = risk.assess()
    assert d.set_index("id").loc["TH12", "residual_band"] == "high"  # removable media: no control implemented
