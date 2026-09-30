"""Tests for the common benchmarking framework, adapters, unified runner and analysis (Member 4).

RSA is not implemented in src/ yet (Member 2). The RSA plug-in path is tested with a
stand-in module built from `cryptography` inside this file only.
"""
import math
import statistics
import sys
import types
from functools import partial

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import benchmarks.adapters as adapters_pkg
from benchmarks import analyze, benchmark_all
from benchmarks.adapters import AESAdapter, HybridAdapter, RSAAdapter, SHA256Adapter, build_adapters
from benchmarks.adapters.rsa_adapter import oaep_limit, split_keypair
from benchmarks.framework import (HYBRID, KEYGEN, MIN_TRIALS, RAW_FIELDS, SIZE_SWEEP, SMALL_PAYLOAD,
                                  SUMMARY_FIELDS, AlgorithmAdapter, Operation, RunSettings, Unit,
                                  check_schema, correctness_label, describe, read_csv, run_configuration,
                                  t_critical, throughput_mbps, units_for, write_csv)
from datasets.generate_test_data import SIZES, make_bytes

FAST = RunSettings(trials=3, warmup=1, cpu_window=0.002, smoke=True)
META = {"scenario": SMALL_PAYLOAD, "file_type": "BIN", "size_label": "64B"}
MISSING = ("src._no_such_rsa_module",)


# --------------------------------------------------------------- statistics
@pytest.mark.parametrize("df, expected", [(1, 12.706), (2, 4.303), (9, 2.262), (19, 2.093), (29, 2.045),
                                          (40, 2.021), (60, 2.000), (120, 1.980), (10_000, 1.960)])
def test_t_critical(df, expected):
    assert t_critical(df) == pytest.approx(expected, abs=1e-3)


@pytest.mark.parametrize("bad", [0, -1, 1.5, True])
def test_t_critical_rejects_bad_df(bad):
    with pytest.raises(ValueError):
        t_critical(bad)


def test_describe_matches_statistics_module():
    values = [1.02, 0.98, 1.10, 0.95, 1.01, 1.04, 0.99, 1.07, 0.97, 1.03]
    size = 10 * 1024**2
    st = describe(values, size)
    sd = statistics.stdev(values)                        # sample SD, n - 1
    mean = statistics.mean(values)
    assert st.n == 10
    assert st.mean == pytest.approx(mean)
    assert (st.min, st.max) == (min(values), max(values))
    assert st.sd == pytest.approx(sd)
    assert st.sd != pytest.approx(statistics.pstdev(values))
    assert st.cv_pct == pytest.approx(sd / mean * 100)
    assert st.ci95 == pytest.approx(2.262 * sd / math.sqrt(10))
    assert st.throughput_mbps == pytest.approx(10 / (mean / 1000))


def test_describe_edge_cases():
    one = describe([2.0], 1024**2)
    assert (one.sd, one.ci95, one.cv_pct) == (0.0, 0.0, 0.0)
    assert describe([1.0, 2.0]).throughput_mbps is None           # no payload -> no throughput
    with pytest.raises(ValueError):
        describe([])


def test_throughput_and_correctness_label():
    assert throughput_mbps(1024**2, 0.5) == pytest.approx(2.0)
    assert throughput_mbps(0, 1.0) is None
    assert correctness_label(10, 10) == "PASS 10/10"
    assert correctness_label(8, 10) == "FAIL 2/10"


def test_minimum_trials_enforced():
    with pytest.raises(ValueError):
        RunSettings(trials=MIN_TRIALS - 1).validate()
    RunSettings(trials=MIN_TRIALS).validate()
    RunSettings(trials=2, smoke=True).validate()
    with pytest.raises(ValueError):
        RunSettings(trials=1, smoke=True).validate()


# --------------------------------------------------------------- runner with a dummy adapter
class DummyAdapter(AlgorithmAdapter):
    """Reverses the payload; records the order in which variants run."""
    name, category = "Dummy", "symmetric"

    def __init__(self, fail_on=None, limit=None):
        super().__init__()
        self.calls, self.fail_on, self.limit = [], fail_on, limit

    @property
    def variants(self):
        return ("D-1", "D-2")

    def operations(self, variant, scenario):
        if scenario != SMALL_PAYLOAD:
            return []
        return [Operation("forward", lambda ctx, d: partial(bytes, reversed(d))),
                Operation("back", lambda ctx, d: partial(bytes, reversed(ctx["outputs"]["forward"]))),
                Operation("limited", lambda ctx, d: partial(len, d), bulk=False, size_limited=True)]

    def max_input_size(self, variant):
        return self.limit

    def setup(self, variant, data, meta):
        self.calls.append(variant)
        return {"variant": variant}

    def verify(self, ctx, data, outputs):
        return ctx["variant"] != self.fail_on and outputs["back"] == data


def test_runner_rows_statistics_and_rotation():
    a = DummyAdapter()
    res = run_configuration([Unit(a, "D-1"), Unit(a, "D-2")], b"x" * 64, META, FAST, log=None)
    assert len(res.summary) == 2 * 3                              # 2 variants x 3 operations
    assert len(res.raw) == FAST.trials * 2 * 3
    assert res.failures == 0 and res.skipped == []
    assert all(r["correctness"] == "PASS 3/3" for r in res.summary)
    assert all(r["trials"] == 3 and r["size_bytes"] == 64 for r in res.summary)
    fwd = next(r for r in res.summary if r["variant"] == "D-1" and r["operation"] == "forward")
    times = [r["time_ms"] for r in res.raw if r["variant"] == "D-1" and r["operation"] == "forward"]
    assert fwd["mean_ms"] == pytest.approx(statistics.mean(times))
    assert fwd["sd_ms"] == pytest.approx(statistics.stdev(times))
    assert fwd["throughput_mbps"] > 0
    assert next(r for r in res.summary if r["operation"] == "limited")["throughput_mbps"] is None
    # calls: warm-up (D-1, D-2), then trials rotate: (D-1, D-2), (D-2, D-1), (D-1, D-2)
    assert a.calls == ["D-1", "D-2", "D-1", "D-2", "D-2", "D-1", "D-1", "D-2"]
    first = [r["variant"] for r in res.raw if r["order_position"] == 1 and r["operation"] == "forward"]
    assert first == ["D-1", "D-2", "D-1"]


def test_runner_records_correctness_failures():
    a = DummyAdapter(fail_on="D-2")
    res = run_configuration([Unit(a, "D-1"), Unit(a, "D-2")], b"abc", META, FAST, log=None)
    assert res.failures == FAST.trials
    labels = {r["variant"]: r["correctness"] for r in res.summary}
    assert labels == {"D-1": "PASS 3/3", "D-2": "FAIL 3/3"}
    assert {r["verified"] for r in res.raw if r["variant"] == "D-2"} == {"FAIL"}


def test_runner_skips_operations_above_input_limit():
    a = DummyAdapter(limit=16)
    res = run_configuration([Unit(a, "D-1")], b"y" * 17, META, FAST, log=None)
    assert {r["operation"] for r in res.summary} == {"forward", "back"}
    assert len(res.skipped) == 1 and "17 B exceeds the 16 B input limit" in res.skipped[0]


def test_units_for_filters_by_scenario():
    a = DummyAdapter()
    assert [u.variant for u in units_for([a], SMALL_PAYLOAD)] == ["D-1", "D-2"]
    assert units_for([a], SIZE_SWEEP) == []


# --------------------------------------------------------------- real adapters (AES, SHA-256)
@pytest.mark.parametrize("adapter, n_variants, category", [(AESAdapter(), 3, "symmetric"),
                                                           (SHA256Adapter(), 1, "hash")])
def test_adapter_interface(adapter, n_variants, category):
    assert adapter.available and adapter.category == category
    assert len(adapter.variants) == n_variants
    for v in adapter.variants:
        assert adapter.operations(v, SIZE_SWEEP) and adapter.operations(v, SMALL_PAYLOAD)
        assert adapter.operations(v, KEYGEN) == [] and adapter.operations(v, HYBRID) == []
        assert adapter.max_input_size(v) is None
    assert "PASS" in adapter.self_check()


def test_aes_and_sha_run_on_same_payload():
    data = make_bytes("BIN", 1024, {})
    ref = __import__("hashlib").sha256(data).hexdigest()
    units = units_for([AESAdapter(), SHA256Adapter()], SIZE_SWEEP)
    meta = {"scenario": SIZE_SWEEP, "file_type": "BIN", "size_label": "1KB", "reference_sha256": ref}
    res = run_configuration(units, data, meta, FAST, log=None)
    assert {(r["variant"], r["operation"]) for r in res.summary} == {
        ("AES-128", "encrypt"), ("AES-128", "decrypt"), ("AES-192", "encrypt"), ("AES-192", "decrypt"),
        ("AES-256", "encrypt"), ("AES-256", "decrypt"), ("SHA-256", "hash")}
    assert res.failures == 0


def test_sha_adapter_detects_wrong_reference():
    meta = dict(META, reference_sha256="0" * 64)
    res = run_configuration(units_for([SHA256Adapter()], SMALL_PAYLOAD), b"data", meta, FAST, log=None)
    assert res.summary[0]["correctness"] == "FAIL 3/3"


# --------------------------------------------------------------- RSA: missing / contract / plug-in
def fake_rsa_module(key_sizes=(2048,), drop=()):
    """Stand-in with the documented contract (test scaffolding only - not the RSA component)."""
    m = types.ModuleType("fake_rsa")
    oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
    fns = {"generate_keypair": lambda bits: (lambda k: (k, k.public_key()))(
               rsa.generate_private_key(public_exponent=65537, key_size=bits)),
           "encrypt": lambda pub, d: pub.encrypt(d, oaep),
           "decrypt": lambda priv, c: priv.decrypt(c, oaep),
           "sign": lambda priv, d: priv.sign(d, pss, hashes.SHA256()),
           "verify": lambda pub, d, s: pub.verify(s, d, pss, hashes.SHA256())}
    for name, fn in fns.items():
        if name not in drop:
            setattr(m, name, fn)
    m.VALID_KEY_SIZES = key_sizes
    return m


@pytest.fixture(scope="module")
def fake_rsa():
    adapter = RSAAdapter(module=fake_rsa_module(), module_name="fake_rsa")
    adapter.self_check()
    return adapter


def test_rsa_missing_is_skipped_cleanly():
    missing = RSAAdapter(candidates=MISSING)
    assert not missing.available and missing.variants == ()
    assert "no RSA module found" in missing.unavailable_reason
    aset = build_adapters(["aes", "sha256", "rsa", "hybrid"], rsa=missing)
    assert [a.name for a in aset.adapters] == ["AES-GCM", "SHA-256"]
    assert set(aset.skipped) == {"rsa", "hybrid"} and not aset.fatal
    assert any("WARNING: rsa skipped" in w for w in aset.warnings)


def test_rsa_module_not_matching_contract_is_skipped():
    bad = RSAAdapter(module=fake_rsa_module(drop=("decrypt",)), module_name="fake_rsa")
    assert not bad.available and "does not match the adapter contract" in bad.unavailable_reason


def test_rsa_module_is_discovered_by_name(monkeypatch):
    monkeypatch.setitem(sys.modules, "src.rsa_crypto", fake_rsa_module())
    found = RSAAdapter()
    assert found.available and found.module_name == "src.rsa_crypto" and found.variants == ("RSA-2048",)


def test_split_keypair_forms():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert split_keypair((k, k.public_key()))[0] is k
    assert split_keypair(k)[0] is k
    with pytest.raises(TypeError):
        split_keypair("not a key")


def test_rsa_adapter_plugs_in(fake_rsa):
    assert fake_rsa.available and fake_rsa.variants == ("RSA-2048",)
    assert fake_rsa.max_input_size("RSA-2048") == oaep_limit(2048) == 190
    assert [o.name for o in fake_rsa.operations("RSA-2048", SMALL_PAYLOAD)] == ["encrypt", "decrypt", "sign", "verify"]
    assert fake_rsa.operations("RSA-2048", SIZE_SWEEP) == []       # RSA is not in the size sweep
    res = run_configuration(units_for([fake_rsa], SMALL_PAYLOAD), b"z" * 190,
                            dict(META, size_label="190B"), FAST, log=None)
    assert len(res.summary) == 4 and res.failures == 0
    over = run_configuration(units_for([fake_rsa], SMALL_PAYLOAD), b"z" * 191,
                             dict(META, size_label="191B"), FAST, log=None)
    assert {r["operation"] for r in over.summary} == {"sign", "verify"} and len(over.skipped) == 2


def test_rsa_keygen_and_hybrid(fake_rsa):
    res = run_configuration(units_for([fake_rsa], KEYGEN), b"", {"scenario": KEYGEN, "file_type": "",
                                                                  "size_label": ""}, FAST, log=None)
    assert [r["operation"] for r in res.summary] == ["keygen"] and res.failures == 0
    hybrid = HybridAdapter(fake_rsa)
    assert hybrid.variants == ("RSA-2048+AES-256",)
    res = run_configuration(units_for([hybrid], HYBRID), make_bytes("BIN", 1024, {}),
                            {"scenario": HYBRID, "file_type": "BIN", "size_label": "1KB"}, FAST, log=None)
    assert [r["operation"] for r in res.summary] == ["sha256_digest", "aes_keygen", "aes_encrypt", "rsa_wrap",
                                                     "rsa_unwrap", "aes_decrypt", "sha256_verify"]
    assert res.failures == 0


# --------------------------------------------------------------- CSV schema
def test_csv_round_trip_and_schema(tmp_path):
    a = DummyAdapter()
    res = run_configuration([Unit(a, "D-1")], b"abcd", META, FAST, log=None)
    write_csv(tmp_path / "s.csv", SUMMARY_FIELDS, res.summary)
    write_csv(tmp_path / "r.csv", RAW_FIELDS, res.raw)
    check_schema(tmp_path / "s.csv", SUMMARY_FIELDS)
    check_schema(tmp_path / "r.csv", RAW_FIELDS)
    back = read_csv(tmp_path / "s.csv")
    assert back[0]["mean_ms"] == pytest.approx(res.summary[0]["mean_ms"], rel=1e-5)
    assert next(r for r in back if r["operation"] == "limited")["throughput_mbps"] is None
    with pytest.raises(ValueError):
        check_schema(tmp_path / "r.csv", SUMMARY_FIELDS)


def test_template_filling():
    text, missing = analyze.fill_template("A {{X}} B {{Y_1}}", {"X": "42"})
    assert text == "A 42 B **[missing: Y_1]**" and missing == ["Y_1"]


# --------------------------------------------------------------- end to end (--quick)
def _in_memory_dataset(ftype, label):
    return make_bytes(ftype, SIZES[label], {}), None


def _quick(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(benchmark_all, "load_dataset", _in_memory_dataset)
    code = benchmark_all.main(["--quick", "--out", str(tmp_path), "--cpu-window", "0.002"])
    assert code == 0
    for name, fields in (("combined_summary.csv", SUMMARY_FIELDS), ("combined_raw_trials.csv", RAW_FIELDS)):
        check_schema(tmp_path / name, fields)
    assert (tmp_path / "environment_combined.txt").exists()
    rows = read_csv(tmp_path / "combined_summary.csv")
    assert rows and all(r["correctness"] == "PASS 3/3" for r in rows)
    template = tmp_path / "draft.md"
    template.write_text("AES-256 1MB: {{AES256_ENCRYPT_1MB_MBPS}} MB/s, n={{TRIALS}}", encoding="utf-8")
    assert analyze.main(["--results", str(tmp_path), "--template", str(template)]) == 0
    for f in ("comparative_table.csv", "stability_summary.csv", "report_values.csv"):
        assert (tmp_path / f).exists()
    filled = (tmp_path / "member4_report_filled.md").read_text(encoding="utf-8")
    assert "missing" not in filled and "n=3" in filled
    return rows, capsys.readouterr()


def test_quick_end_to_end_without_rsa(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(adapters_pkg, "RSAAdapter", lambda: RSAAdapter(candidates=MISSING))
    rows, out = _quick(tmp_path, monkeypatch, capsys)
    assert {r["algorithm"] for r in rows} == {"AES-GCM", "SHA-256"}
    assert "WARNING: rsa skipped" in out.err
    assert {p.name for p in (tmp_path / "graphs").glob("cmp_*.png")} == {
        "cmp_throughput_vs_size.png", "cmp_time_vs_size.png", "cmp_cpu.png", "cmp_memory.png",
        "cmp_small_payload.png", "cmp_variance.png"}


def test_quick_end_to_end_with_rsa_module(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "src.rsa_crypto", fake_rsa_module())
    rows, _ = _quick(tmp_path, monkeypatch, capsys)
    assert {r["scenario"] for r in rows} == {KEYGEN, SMALL_PAYLOAD, SIZE_SWEEP, HYBRID}
    assert (tmp_path / "hybrid_breakdown.csv").exists()
    assert (tmp_path / "graphs" / "cmp_hybrid_breakdown.png").exists()
