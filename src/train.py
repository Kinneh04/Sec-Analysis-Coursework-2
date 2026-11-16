from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.common.config import artifacts, load_config
from src.metrics import tpr_at_fpr


def _cols(prefixes: tuple[str, ...], df: pd.DataFrame) -> list[str]:
    skip = {
        "pe_status",
        "pe_extractor",
        "bn_status",
        "bn_extractor",
        "bn_source",
        "bn_arch",
        "bn_error",
        "extractor_version",
        "analyzer_version",
        "analysis_duration_seconds",
    }
    cols = [c for c in df.columns if c.startswith(prefixes) and c not in skip]
    return [c for c in cols if pd.api.types.is_numeric_dtype(df[c])]


def _make_model(name: str, seed: int):
    if name == "logistic_regression":
        return Pipeline(
            [
                ("imp", SimpleImputer(strategy="median")),
                ("sc", StandardScaler()),
                ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)),
            ]
        )
    if name == "random_forest":
        return Pipeline(
            [
                ("imp", SimpleImputer(strategy="median")),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=200,
                        class_weight="balanced_subsample",
                        random_state=seed,
                        n_jobs=-1,
                    ),
                ),
            ]
        )
    if name == "lightgbm":
        return Pipeline(
            [
                ("imp", SimpleImputer(strategy="median")),
                (
                    "clf",
                    LGBMClassifier(
                        n_estimators=300,
                        learning_rate=0.05,
                        class_weight="balanced",
                        random_state=seed,
                        verbosity=-1,
                    ),
                ),
            ]
        )
    raise ValueError(name)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/local.yaml")
    ap.add_argument("--split-prefix", default="", help="e.g. pe_all_ for full PE cohort")
    ap.add_argument("--output-suffix", default="", help="Appended to run_id / manifest (e.g. _full)")
    args = ap.parse_args()
    cfg = load_config(args.config)
    art = artifacts(cfg)
    seed = int(cfg["models"]["random_seed"])
    pfx = args.split_prefix
    out_suffix = args.output_suffix
    train = pd.read_parquet(art / "splits" / f"{pfx}train.parquet")
    val = pd.read_parquet(art / "splits" / f"{pfx}val.parquet")

    y_train = train["label"].map({"benign": 0, "malicious": 1}).to_numpy()
    y_val = val["label"].map({"benign": 0, "malicious": 1}).to_numpy()

    feature_sets = {
        "pe": _cols(("pe_",), train),
        "bn": _cols(("bn_", "cfg_", "mlil_", "legacy_hlil_regex_", "quality_"), train),
    }
    feature_sets["pe_bn"] = feature_sets["pe"] + feature_sets["bn"]
    if pfx == "pe_all_":
        active_sets = ["pe"]
    else:
        active_sets = list(cfg["models"]["feature_sets"])

    models_dir = art / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    manifest_name = f"train_manifest{out_suffix}.json" if out_suffix else "train_manifest.json"
    manifest = []

    for fs in active_sets:
        cols = feature_sets[fs]
        for algo in cfg["models"]["algorithms"]:
            run_id = f"{algo}__{fs}{out_suffix}"
            pipe = _make_model(algo, seed)
            pipe.fit(train[cols], y_train)
            val_scores = pipe.predict_proba(val[cols])[:, 1]
            thr_info = tpr_at_fpr(y_val, val_scores, float(cfg["evaluation"]["primary_fpr"]))
            bundle = {"pipeline": pipe, "features": cols, "threshold": thr_info["threshold"], "run_id": run_id}
            out = models_dir / f"{run_id}.pkl"
            with out.open("wb") as f:
                pickle.dump(bundle, f)
            manifest.append(
                {
                    "run_id": run_id,
                    "algorithm": algo,
                    "feature_set": fs,
                    "n_features": len(cols),
                    "val_tpr_at_primary_fpr": thr_info["tpr"],
                    "val_fpr": thr_info["fpr"],
                    "threshold": thr_info["threshold"],
                }
            )
            print(run_id, thr_info)

    (models_dir / manifest_name).write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
