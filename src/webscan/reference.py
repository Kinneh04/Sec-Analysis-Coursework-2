"""Build artifacts/v3.2/feature_reference.json: per-feature training-pool statistics used to explain verdicts.

Aggregate statistics only (medians, non-zero rates, class counts); no sample is stored. Needs the local V3.2
training artifacts, so it is run once by the maintainer and the small JSON is committed:

  .venv\\Scripts\\python.exe -m src.webscan.reference
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pandas as pd

OUT = Path("artifacts/v3.2/feature_reference.json")


def _class_counts(mask: pd.Series, y: pd.Series) -> dict[str, int]:
    return {"benign": int(((y == 0) & mask).sum()), "malicious": int(((y == 1) & mask).sum())}


def build() -> dict:
    from src.v3.data import load_pool
    from src.v3.pe_features_v3 import SECTION_BUCKETS, stable_bucket
    from src.v3.retrain import train_cohorts_for_tag
    from src.webscan.scanner import bundle

    warnings.filterwarnings("ignore")
    pool = load_pool("configs/local.yaml", include_v1_train=True, cohorts=train_cohorts_for_tag("v3.2"))
    cols = list(bundle()["pe_v3"]["cols"])
    y = pool["label"]
    b, m = pool.loc[y == 0, cols], pool.loc[y == 1, cols]
    stats = {}
    for c in cols:
        stats[c] = [round(float(b[c].median()), 6), round(float(m[c].median()), 6),
                    round(float((b[c] != 0).mean()), 4), round(float((m[c] != 0).mean()), 4)]

    def sec(name: str) -> tuple[str, str]:
        k = stable_bucket(name, SECTION_BUCKETS)
        return f"pe3_secname_vsize_{k:02d}", f"pe3_secname_size_{k:02d}"

    nv, nr = sec(".ndata")      # NSIS: uninitialised .ndata section (virtual size > 0, nothing on disk)
    uv, ur = sec("UPX0")        # UPX: UPX0 has no raw data either
    classes = {
        "nsis": {**_class_counts((pool[nv] > 0) & (pool[nr] == 0), y),
                 "how": "section hashing to the .ndata bucket with virtual size > 0 and raw size 0 (approximate)"},
        "upx": {**_class_counts((pool[uv] > 0) & (pool[ur] == 0), y),
                "how": "section hashing to the UPX0 bucket with virtual size > 0 and raw size 0 (approximate)"},
        "dotnet": {**_class_counts(pool["pe3_dir_14_present"] > 0, y), "how": ".NET (CLR) data directory present"},
        "signature_block": {**_class_counts(pool["pe3_dir_04_present"] > 0, y),
                            "how": "Authenticode certificate table present (validity not checked in training data)"},
        "high_entropy_overlay": {**_class_counts(pool["pe3_overlay_entropy"] > 7.2, y), "how": "overlay entropy > 7.2 bits/byte"},
    }
    return {"model_tag": "v3.2", "n": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
            "columns": ["benign_median", "malicious_median", "benign_nonzero", "malicious_nonzero"],
            "features": stats, "classes": classes}


if __name__ == "__main__":
    ref = build()
    OUT.write_text(json.dumps(ref, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB): n={ref['n']}")
    for k, v in ref["classes"].items():
        print(f"  {k:22} benign={v['benign']:5} malicious={v['malicious']:5}")
