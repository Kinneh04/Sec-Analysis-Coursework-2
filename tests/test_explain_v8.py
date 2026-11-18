"""Explanation layer for the V8 blend (src/webscan/explain.py, src/webscan/reference.py).

No Binary Ninja, network, malware or research export needed. Tests that need thrember, the EMBER2024 model or the built
reference file skip when they are absent. The hashing check against a real PE uses SA2_TEST_PE (any benign PE file) or,
on Windows, the running python.exe.
"""

from __future__ import annotations

import json
import math
import os
import pickle
import re
import sys
from pathlib import Path

import numpy as np
import pytest

from src.webscan import explain

ROOT = Path(__file__).resolve().parents[1]
FMTS = {"bool", "flag", "bytes", "logbytes", "absbytes", "entropy", "absentropy", "absnum", "pct", "ratio", "hex", "byte", "arch",
        "subsystem", "em_machine", "em_subsystem", "time", "duration", "num"}
CANDIDATE = ROOT / "artifacts/v8/models/candidate.pkl"
REF = ROOT / explain.REFERENCE

try:
    import thrember  # noqa: F401
    HAS_THREMBER = True
except Exception:
    HAS_THREMBER = False


def sig(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def ember_names() -> list[str]:
    from src.v8.ember_map import ember_feature_names

    return ember_feature_names()


def bn_names() -> list[str]:
    if CANDIDATE.is_file():
        with CANDIDATE.open("rb") as fh:
            return list(pickle.load(fh)["cols"])
    return sorted(explain.BN)


def _pe_samples() -> list[Path]:
    out = []
    env = os.environ.get("SA2_TEST_PE")
    if env:
        out += [Path(p) for p in env.split(os.pathsep) if p]
    if sys.platform == "win32":
        out.append(Path(sys.executable))
    return [p for p in out if p.is_file() and p.read_bytes()[:2] == b"MZ"]


# ------------------------------------------------------------------ catalogue

def test_bn_catalogue_matches_model_columns():
    cols = bn_names()
    assert len(cols) == 114
    assert set(cols) == set(explain.BN)


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
@pytest.mark.parametrize("ctx", [None, "empty", "dll"])
def test_every_feature_has_plain_title_group_and_format(ctx):
    c = {"None": {}, "empty": explain.build_context([], {}, []),
         "dll": explain.build_context([".text", ".rdata", "UPX0"], {"kernel32.dll": ["VirtualAlloc", "ord_5"]}, ["DllMain"])}[str(ctx)]
    names = ember_names() + bn_names()
    assert len(names) == 2568 + 114
    for n in names:
        g, title, fmt = explain.describe(n, c)
        assert g in explain.GROUPS, n
        assert fmt in FMTS, (n, fmt)
        assert title and title != n and "em_" not in title and "cap6_" not in title and "hl6_" not in title, (n, title)
        for v in (0.0, 1.0, -3.0, 1234.5, float("nan")):
            assert isinstance(explain.fmt_value(v, fmt), str)


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
def test_group_assignment_is_sensible():
    d = lambda n: explain.describe(n, {})[0]  # noqa: E731
    assert d("em_general_size") == "size"
    assert d("em_histogram_byte_41") == d("em_byteentropy_e14_b3") == "entropy"
    assert d("em_strings_regex_05_btc_wallet") == "strings"
    assert d("em_header_coff_machine") == "headers"
    assert d("em_imports_function_hash_0512") == d("em_imports_library_hash_042") == "imports"
    assert d("em_exports_export_hash_007") == d("em_exports_has_exports_128") == "exports"
    assert d("em_section_overlay_entropy") == "overlay"
    assert d("em_datadirectories_resource_size") == "resources"
    assert d("em_datadirectories_security_size") == d("em_authenticode_num_certs") == "signature"
    assert d("em_richheader_n_pairs") == "rich"
    assert d("em_pefilewarnings_warn_32") == d("em_pefilewarnings_n_warnings") == "warnings"
    assert d("cap6_r_injection") == d("hl6_resolved_net") == "code"
    assert {"size", "entropy", "overlay", "headers", "directories", "sections", "imports", "exports", "strings", "resources"} <= set(explain.GROUPS)


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
def test_thrember_quirks_are_stated():
    t = lambda n: explain.describe(n, {})[1]  # noqa: E731
    names = ember_names()
    email = next(n for n in names if n.endswith("_email_addr"))
    reg = next(n for n in names if n.endswith("_registry_key"))
    assert "MAC" in t(email) and "typo" in t(reg)
    assert "128" in t("em_exports_has_exports_128")
    assert "always 0" in t("em_section_min_entropy")
    assert explain.fmt_value(128.0, "flag") == "yes"
    assert explain.describe("em_header_coff_machine", {})[2] == "em_machine"
    assert explain.fmt_value(32.0, "em_machine") == "x64" and explain.fmt_value(1.0, "em_machine") == "x86 (32-bit)"
    assert explain.fmt_value(2.0, "em_subsystem") == "Windows GUI"
    warn = explain.describe("em_pefilewarnings_warn_00", {})[1]
    assert warn.startswith("pefile warning: AddressOfEntryPoint")


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
def test_machine_and_subsystem_tables_match_thrember():
    from thrember.features import HeaderFileInfo

    h = HeaderFileInfo()
    assert len(explain.EM_MACHINES) == len(h._machine_types)
    assert explain.EM_MACHINES[h._machine_types.index("IMAGE_FILE_MACHINE_AMD64")] == "x64"
    assert explain.EM_MACHINES[h._machine_types.index("IMAGE_FILE_MACHINE_ARM64")] == "ARM64"
    assert len(explain.EM_SUBSYSTEMS) == len(h._subsystem_types)
    assert explain.EM_SUBSYSTEMS[h._subsystem_types.index("IMAGE_SUBSYSTEM_WINDOWS_CUI")] == "console"


# ------------------------------------------------------------------ hashing

@pytest.mark.parametrize("kind", sorted(explain.HASH_DIMS))
def test_hash_slots_reproduce_feature_hasher(kind):
    from sklearn.feature_extraction import FeatureHasher

    toks = ["kernel32.dll:VirtualAlloc", ".text", "upx0", "", "ws2_32.dll:WS2_32.dll:ordinal23", "DllMain", "16777216", ".text"]
    want = FeatureHasher(explain.HASH_DIMS[kind], input_type="string",
                         alternate_sign=explain.HASH_SIGNED[kind]).transform([toks]).toarray()[0]
    got = np.zeros(explain.HASH_DIMS[kind])
    for slot, sign in explain.hash_slots(toks, kind):
        got[slot] += sign
    assert np.array_equal(got, want)


def test_hashed_titles_stay_true():
    ctx = explain.build_context([".text", ".rdata"], {"kernel32.dll": ["VirtualAlloc"]}, [])
    em = ctx["em"]
    assert em["resolution"] == "approximate"
    (slot, _), = explain.hash_slots(["kernel32.dll:VirtualAlloc"], "fn")
    g, title, fmt = explain.describe(f"em_imports_function_hash_{slot:04d}", ctx, 1.0)
    assert title == "Imports VirtualAlloc (kernel32.dll)" and g == "imports"
    empty = next(s for s in range(1024) if s not in em["fn"])
    title0 = explain.describe(f"em_imports_function_hash_{empty:04d}", ctx, 0.0)[1]
    assert "none in this file" in title0
    # set in the vector but nothing of this file maps there: never claim absence
    title1 = explain.describe(f"em_imports_function_hash_{empty:04d}", ctx, 2.0)[1]
    assert "not resolved" in title1
    (s_text, _), = explain.hash_slots([".text"], "sec")
    assert explain.describe(f"em_section_size_hash_{s_text:02d}", ctx, -4096.0)[1:] == ("Size on disk of section .text", "absbytes")
    assert explain.fmt_value(-4096.0, "absbytes") == "4.0 KB"
    (s_rd, _), = explain.hash_slots([".rdata"], "sec")
    (s_up, _), = explain.hash_slots(["upx0"], "sec")
    assert s_rd == s_up  # a real collision: the title must not pretend the slot is .rdata alone when both are present
    both = explain.build_context([".rdata", "UPX0"], {}, [])
    t = explain.describe(f"em_section_vsize_hash_{s_rd:02d}", both, 100.0)[1]
    assert "signed sum" in t and ".rdata" in t and "upx0" in t


def _vector_and_ctx(path: Path):
    from thrember import PEFeatureExtractor

    raw = path.read_bytes()
    vec = np.asarray(PEFeatureExtractor().feature_vector(raw), dtype=np.float64)
    return raw, vec, explain.build_context([], {}, [], raw=raw)


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
@pytest.mark.skipif(not _pe_samples(), reason="no benign PE sample (set SA2_TEST_PE)")
def test_hash_resolution_matches_thrember_vector():
    import pefile

    names = ember_names()
    idx = {n: i for i, n in enumerate(names)}
    for path in _pe_samples():
        raw, vec, ctx = _vector_and_ctx(path)
        em = ctx["em"]
        assert em["resolution"] == "exact"
        pred = {k: np.zeros(n) for k, n in explain.HASH_DIMS.items()}
        for kind in ("lib", "fn", "exp", "props", "entry"):
            for slot, members in em[kind].items():
                pred[kind][slot] += sum(s for _, s in members)
        pe = pefile.PE(data=raw)
        sizes = {"size": np.zeros(50), "vsize": np.zeros(50), "entropy": np.zeros(50)}
        for s in pe.sections:
            nm = s.Name.strip(b"\x00").decode(errors="ignore").lower()
            (slot, sign), = explain.hash_slots([nm], "sec")
            sizes["size"][slot] += sign * s.SizeOfRawData
            sizes["vsize"][slot] += sign * s.Misc_VirtualSize
            sizes["entropy"][slot] += sign * s.get_entropy()
        rich = np.zeros(32)
        vals = list(pe.RICH_HEADER.values) if pe.RICH_HEADER is not None else []
        for i in range(0, len(vals) - 1, 2):
            (slot, sign), = explain.hash_slots([str(vals[i])], "rich")
            rich[slot] += sign * vals[i + 1]
        pe.close()

        def got(prefix: str, n: int, w: int) -> np.ndarray:
            return np.array([vec[idx[f"{prefix}{i:0{w}d}"]] for i in range(n)])

        assert np.array_equal(got("em_imports_library_hash_", 256, 3), pred["lib"])
        assert np.array_equal(got("em_imports_function_hash_", 1024, 4), pred["fn"])
        assert np.array_equal(got("em_exports_export_hash_", 128, 3), pred["exp"])
        assert np.array_equal(got("em_section_props_hash_", 50, 2), pred["props"])
        assert np.array_equal(got("em_section_entry_name_hash_", 10, 1), pred["entry"])
        assert np.array_equal(got("em_section_size_hash_", 50, 2), sizes["size"].astype(np.float32))
        assert np.array_equal(got("em_section_vsize_hash_", 50, 2), sizes["vsize"].astype(np.float32))
        assert np.allclose(got("em_section_entropy_hash_", 50, 2), sizes["entropy"], atol=1e-5)
        assert np.array_equal(got("em_richheader_pair_hash_", 32, 2), rich.astype(np.float32))
        assert vec[idx["em_imports_n_functions"]] == sum(len(v) for v in em["fn"].values())


# ------------------------------------------------------------------ reasons

def _contrib(rng: np.random.Generator) -> list[tuple[str, float, float]]:
    names = ["em_general_size", "em_section_overlay_entropy", "em_header_coff_machine", "em_imports_function_hash_0007",
             "em_authenticode_num_certs", "cap6_r_injection", "hl6_n_resolved", "cap6_fn_xor_loop"]
    out = [(n, float(rng.normal()), float(rng.normal(scale=0.4))) for n in names]
    out.append(("cap6_syscall", float("nan"), 0.05))
    return out


@pytest.mark.parametrize("seed", range(5))
def test_reasons_waterfall_sums_to_final_score(seed):
    rng = np.random.default_rng(seed)
    contrib = _contrib(rng)
    base = float(rng.normal())
    r = explain.reasons(contrib, base, explain.build_context([], {}, []), top_k=20)
    total = base + sum(c for _, _, c in contrib)
    assert r["final_probability"] == pytest.approx(sig(total), abs=1e-6)
    assert sum(g["contribution"] for g in r["groups"]) + base == pytest.approx(total, abs=1e-3)
    assert all(g["group"] in explain.GROUPS for g in r["groups"])
    assert r["bn_contribution"] == pytest.approx(sum(c for n, _, c in contrib if n.startswith(("cap6_", "hl6_"))), abs=1e-3)
    nan_row = next(t for t in r["top"] if t["feature"] == "cap6_syscall")
    assert nan_row["value"] == "not available" and nan_row["raw_value"] is None and nan_row["source"] == "binary_ninja"
    for t in r["top"]:
        assert set(t) >= {"feature", "group", "title", "value", "raw_value", "contribution", "direction", "strength", "typical"}


def test_strength_cut_offs():
    assert explain.strength(explain.STRONG) == "strong"
    assert explain.strength(-explain.MODERATE) == "moderate"
    assert explain.strength(explain.MODERATE / 2) == "minor"


@pytest.mark.skipif(not (ROOT / "artifacts/ember2024/models/artifacts/ember2024/models/EMBER2024_PE.model").is_file()
                    or not CANDIDATE.is_file() or not HAS_THREMBER, reason="EMBER2024 model, candidate.pkl or thrember absent")
def test_reasons_on_real_contributions_sum_to_probability():
    from src.v8 import deploy

    b = deploy.load_bundle(verify=False, download=False)
    v = np.zeros(2568, dtype=np.float32)
    v[2] = 1
    v[0] = 50_000
    for bn in (None, {c: 1.0 for c in b["cols"]}):
        s = deploy.score_vector(b, v, bn)
        r = explain.reasons(s["contrib"], s["contrib_base"], explain.build_context([], {}, []), top_k=12)
        assert r["final_probability"] == pytest.approx(s["probability"], abs=1e-5)
        assert sum(g["contribution"] for g in r["groups"]) + s["contrib_base"] == pytest.approx(math.log(s["probability"] / (1 - s["probability"])), abs=1e-3)
        assert (r["bn_contribution"] is None) == (bn is None)


# ------------------------------------------------------------------ assessment

def _report(*, path: str, blend_flag: bool, r1_flag: bool, p: float = 0.6, r1p: float = 0.7) -> dict:
    thr = 0.31491
    return {"verdict": "malicious" if blend_flag else "benign", "probability": p,
            "engines": [{"name": "v8_blend", "recommended": True, "threshold": thr, "probability": p, "flagged": blend_flag,
                         "bn_score": 0.4 if path == "blend" else None},
                        {"name": "ember2024", "recommended": False, "threshold": thr, "probability": r1p, "flagged": r1_flag}],
            "decision_path": {"path": path, "reason": "ok" if path == "blend" else "bn_disabled",
                              "note": None if path == "blend" else "Binary Ninja is disabled (SA2_BN=0)"},
            "explanation": {"groups": [{"group": "code", "label": explain.GROUPS["code"][0], "contribution": 0.8}],
                            "top": [{"title": "Functions matching the process injection rule", "value": "2", "contribution": 0.5}]}}


SIGS = [{"id": "unsigned", "severity": "info", "title": "Not digitally signed", "evidence": "x"}]


def test_assessment_blend_path_agreeing_engines():
    a = explain.assessment(_report(path="blend", blend_flag=True, r1_flag=True), SIGS)
    assert a["decision_path"] == "blend" and not a["engines_disagree"]
    assert "Binary Ninja code features were available" in a["summary"]
    assert "disagree" not in a["summary"]
    assert "does not change the model verdict" in a["note"]


def test_assessment_r1_fallback():
    a = explain.assessment(_report(path="r1_fallback", blend_flag=False, r1_flag=False, p=0.01, r1p=0.01), SIGS)
    assert "EMBER2024's own verdict" in a["summary"] and "SA2_BN=0" in a["summary"]
    assert a["label"] == "No significant concern"


def test_assessment_engine_disagreement_without_blend_numbers_is_not_attributed():
    up = explain.assessment(_report(path="blend", blend_flag=True, r1_flag=False, p=0.4, r1p=0.2), SIGS)
    assert up["engines_disagree"] and "The two engines disagree" in up["summary"]
    assert up["label"] == "Flagged by the blend only - review" and up["disagreement"]["kind"] == "unknown"
    assert "cannot say whether" in up["summary"]
    down = explain.assessment(_report(path="blend", blend_flag=False, r1_flag=True, p=0.2, r1p=0.5), SIGS)
    assert down["engines_disagree"] and down["label"] == "Cleared by the blend only - review"
    assert any("EMBER2024 on its own does" in x for x in down["points_against"])


THR_F, T_BLEND_F, W_F = 0.31491410519549656, -0.91947, 0.3  # frozen values (offset logit(thr) - t_blend = +0.142)


def _blend_report(r1_margin: float, bn_term: float, t_blend: float = T_BLEND_F) -> dict:
    """Covered-file report whose v8_blend numbers are consistent: m = r1_margin + bn_term + (logit(thr) - t_blend)."""
    shift = math.log(THR_F / (1 - THR_F))
    m = r1_margin + bn_term + shift - t_blend
    sig = lambda x: 1 / (1 + math.exp(-x))  # noqa: E731
    p, r1p = sig(m + shift), sig(r1_margin + shift)
    rep = _report(path="blend", blend_flag=m >= 0, r1_flag=r1_margin >= 0, p=p, r1p=r1p)
    rep["engines"][0].update(coverage="covered", r1_logit=r1_margin + shift, bn_logit=bn_term / W_F, w=W_F, t_blend=t_blend,
                             display_shift=shift, blend_margin=m, bn_score=sig(bn_term / W_F))
    return rep


@pytest.mark.parametrize("r1m,bt,t_blend,kind,label", [
    # blend flags, EMBER2024 does not
    (-0.5, 0.6, T_BLEND_F, "bn", "Flagged by code analysis only - review"),
    (-0.1, -0.02, T_BLEND_F, "offset", "Flagged by the blend threshold offset - borderline, review"),
    (-0.1, 0.0, T_BLEND_F, "offset", "Flagged by the blend threshold offset - borderline, review"),
    (-0.2, 0.1, T_BLEND_F, "both", "Flagged by code analysis plus threshold offset - review"),
    (-0.05, 0.1, T_BLEND_F, "either", "Flagged by code analysis only - review"),
    # EMBER2024 flags, blend does not (the frozen offset is positive, so offset/both need a negative test offset)
    (0.1, -0.5, T_BLEND_F, "bn", "Cleared by code analysis - review"),
    (0.1, 0.05, -0.77724 + 0.3, "offset", "Cleared by the blend threshold offset - borderline, review"),
    (0.2, -0.15, -0.77724 + 0.1, "both", "Cleared by code analysis plus threshold offset - review"),
])
def test_disagreement_attribution(r1m, bt, t_blend, kind, label):
    rep = _blend_report(r1m, bt, t_blend)
    d = explain.disagreement(rep)
    assert d["kind"] == kind and d["label"] == label
    assert d["r1_margin"] == pytest.approx(r1m) and d["bn_term"] == pytest.approx(bt, abs=1e-12)
    assert f"{r1m:+.3f}" in d["text"] and f"{bt:+.3f}" in d["text"] and f"{d['offset']:+.3f}" in d["text"]
    assert d["text"].count(". ") <= 2  # one or two sentences
    a = explain.assessment(rep, SIGS)
    assert a["engines_disagree"] and a["label"] == label and d["text"] in a["summary"]
    if kind == "offset":
        assert "code analysis" not in a["label"] and "threshold offset alone was enough" in d["text"]
        assert "Binary Ninja features pulled" not in a["summary"]
    if t_blend == T_BLEND_F:
        assert d["offset"] == pytest.approx(0.14223, abs=1e-4)


def test_disagreement_none_when_engines_agree():
    assert explain.disagreement(_blend_report(0.5, 0.2)) is None
    assert explain.assessment(_blend_report(0.5, 0.2), SIGS)["disagreement"] is None


def test_glossary_contribution_says_logit_of_final_score():
    assert "logit (log-odds) of the final score" in explain.GLOSSARY_EXTRA["Contribution (log-odds)"]


def test_assessment_never_changes_verdict_and_handles_legacy_reports():
    legacy = {"verdict": "malicious", "probability": 0.97,
              "engines": [{"name": "pe_v3", "recommended": True, "threshold": 0.9603, "flagged": True}],
              "explanation": {"groups": [], "top": []}}
    a = explain.assessment(legacy, SIGS)
    assert "pe_v3" in a["summary"] and legacy["verdict"] == "malicious"
    assert explain.assessment({"probability": None}, [])["label"] == "Not scored"


def test_signature_signal_does_not_claim_the_model_ignores_signatures():
    s = explain._sig_signal({"status": "Valid", "signer": "Contoso"})
    assert "does not use signatures" not in s["meaning"] and "validity" in s["meaning"]


# ------------------------------------------------------------------ reference file

@pytest.mark.skipif(not REF.is_file(), reason="artifacts/v8/feature_reference.json not built (python -m src.webscan.reference)")
def test_reference_schema():
    text = REF.read_text(encoding="utf-8")
    ref = json.loads(text)
    assert ref["model_tag"] == "v8"
    assert ref["n"] == {"benign": 3506, "malicious": 2358}
    nbn = {k: v["benign"] + v["malicious"] for k, v in ref["n_bn"].items()}
    assert nbn["cap6"] == 1256 and nbn["both"] <= min(nbn["cap6"], nbn["hl6"])  # 1256 = candidate.pkl train_bn_rows
    assert ref["columns"] == ["benign_median", "malicious_median", "benign_nonzero", "malicious_nonzero"]
    assert set(ref["r1_operating_points"]) == {"fpr_0.01", "fpr_0.02", "fpr_0.05"}
    assert ref["r1_operating_points"]["fpr_0.01"] == pytest.approx(0.31491410519549656, abs=1e-15)
    ops = ref["r1_operating_points"]
    assert ops["fpr_0.05"] < ops["fpr_0.02"] < ops["fpr_0.01"]
    assert set(ref["classes"]) == {"nsis", "upx", "dotnet", "signature_block", "high_entropy_overlay"}
    for c in ref["classes"].values():
        assert all(isinstance(c[k], int) for k in ("benign", "malicious", "benign_flagged_r1", "malicious_flagged_r1"))
    feats = ref["features"]
    assert set(bn_names()) <= set(feats)
    assert all(len(v) == 4 for v in feats.values())
    if HAS_THREMBER:
        assert set(ember_names()) <= set(feats)
    assert not re.search(r"[0-9a-f]{64}", text), "reference must not contain file hashes"
    assert len(text) < 200_000


# ------------------------------------------------------------------ wording checked against the extractors

def test_bn_titles_do_not_claim_library_identification_or_observed_runtime_behaviour():
    t = lambda n: explain.BN[n][0]  # noqa: E731
    assert "sub_*" in t("hl6_frac_library_named") and "identified as library" not in t("hl6_frac_library_named")
    assert "sub_*" in t("hl6_n_sub") and "library" not in t("hl6_n_sub")
    for n in ("cap6_n_dyn_names", "cap6_n_dyn_sensitive"):
        assert "GetProcAddress" in t(n) and "inferred, not observed" in t(n)
    for n, (title, _) in explain.BN.items():
        assert "identified as library" not in title, n
        assert "resolved at run time" not in title and "resolving an API at run time" not in title, n


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
def test_byteentropy_title_is_a_joint_share_with_overlapping_windows():
    from thrember.features import ByteEntropyHistogram

    h = ByteEntropyHistogram()
    assert (h.window, h.step) == (2048, 1024)  # the title's "2 KB windows, 1 KB step"
    title = explain.describe("em_byteentropy_e14_b3", {})[1]
    assert title.startswith("Share of all sampled bytes that are 0x30-0x3F") and "overlapping 2 KB windows, 1 KB step" in title
    assert "lying in" not in title


def _entry_ctx(where):
    slot = explain._by_slot([""], "entry")
    return {"em": {"have": {"entry"}, "entry": slot, "entry_where": where}}, next(iter(slot))


@pytest.mark.skipif(not HAS_THREMBER, reason="thrember not installed")
def test_entry_section_title_when_entry_point_is_outside_every_section():
    ctx, slot = _entry_ctx("outside")
    title = explain.describe(f"em_section_entry_name_hash_{slot}", ctx, 1.0)[1]
    assert title.startswith("Entry point lies outside every section") and "(unnamed)" not in title
    ctx, slot = _entry_ctx("inside")
    assert explain.describe(f"em_section_entry_name_hash_{slot}", ctx, 1.0)[1] == "Execution starts in an unnamed section"


@pytest.mark.skipif(not (_pe_samples() and HAS_THREMBER), reason="no benign PE sample (set SA2_TEST_PE)")
def test_entry_where_from_a_real_pe_with_the_entry_point_moved_outside():
    import pefile

    raw = _pe_samples()[0].read_bytes()
    assert explain._em_tokens_exact(raw)["_entry_where"] == "inside"
    pe = pefile.PE(data=raw, fast_load=True)
    off = pe.OPTIONAL_HEADER.get_field_absolute_offset("AddressOfEntryPoint")
    pe.close()
    moved = raw[:off] + (0x7FFFFFF0).to_bytes(4, "little") + raw[off + 4:]  # in memory only; never written or run
    toks = explain._em_tokens_exact(moved)
    assert toks["_entry_where"] == "first_exec" and toks["entry"][0] == ".text"
    ctx = explain.build_context([], {}, [], raw=moved)
    slot = next(iter(ctx["em"]["entry"]))
    title = explain.describe(f"em_section_entry_name_hash_{slot}", ctx, 1.0)[1]
    assert title.startswith("Entry point lies outside every section; first executable section .text")
