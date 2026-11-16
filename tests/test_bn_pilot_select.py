from src.bn_pilot_select import PILOT_TARGETS, select_pilot_cohort
from src.common.config import load_config


def test_pilot_select_counts_and_train_only():
    cfg = load_config("configs/local.yaml")
    pilot = select_pilot_cohort(cfg)
    assert len(pilot) == sum(PILOT_TARGETS.values())
    assert set(pilot.groupby("pilot_category").size().to_dict().keys()) == set(PILOT_TARGETS.keys())
    for cat, need in PILOT_TARGETS.items():
        assert int((pilot["pilot_category"] == cat).sum()) == need
