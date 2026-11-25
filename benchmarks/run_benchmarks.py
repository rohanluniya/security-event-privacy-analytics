"""Reproducible benchmark suite for Streaming CEP, NAT-aware FP ablation, bounded state, and Iceberg V2 compaction."""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import duckdb
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ingestion.generator import generate_security_telemetry
from processing.cep_engine import CepConfig, StreamingCepEngine
from processing.identity_resolver import IdentityResolver
from services.secops_platform.config import PlatformConfig
from services.secops_platform.dq import validate_and_split_events
from services.secops_platform.pipeline import run_end_to_end_pipeline
from services.secops_platform.privacy import PrivacyVault
from services.secops_platform.storage import PrivacyLakehouse

PROFILES: dict[str, int] = {
    "smoke": 1_500,
    "local": 6_000,
    "stress": 25_000,
}

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results" / "benchmarks"
CHART_PATH = REPO_ROOT / "docs" / "assets" / "benchmark_security_cep_privacy.png"


def collect_sanitized_hardware() -> dict[str, Any]:
    """Capture hardware and runtime metadata without exposing hostnames or user paths."""
    cpu_brand = platform.processor() or "arm64"
    ram_gib: float | None = None
    if platform.system() == "Darwin":
        try:
            cpu_brand = (
                subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
            )
            mem_bytes = int(
                subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip()
            )
            ram_gib = round(mem_bytes / (1024**3), 1)
        except Exception:
            pass
    return {
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "cpu": cpu_brand,
        "cpu_cores": os.cpu_count() or 1,
        "ram_gib": ram_gib,
        "python_version": platform.python_version(),
        "runtime_mode": "local_native",
    }


def benchmark_profile(profile_name: str, target_events: int, seed: int = 42) -> dict[str, Any]:
    """Measure both pure streaming CEP throughput/latency and full Iceberg V2 E2E wall time."""
    batch = generate_security_telemetry(seed=seed, total_events=target_events)
    valid, dlq = validate_and_split_events(batch.raw_records)

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)

        # 1. Pure Streaming CEP + Identity Resolution + Tokenization (NAT-aware v2)
        vault_v2 = PrivacyVault("bench-key", "v1", td_path / "vault_v2.json")
        resolver_v2 = IdentityResolver(vault_v2)
        cep_v2 = StreamingCepEngine(CepConfig(nat_aware=True, clock_skew_retraction_enabled=True))
        t_cep0 = time.perf_counter()
        for ev in valid:
            prn = resolver_v2.resolve(ev)
            tok = vault_v2.tokenize_event(ev, prn)
            cep_v2.process_event(ev, tok)
        cep_sec = time.perf_counter() - t_cep0
        cep_v2_metrics = cep_v2.evaluate_precision_recall(batch.ground_truth_attacks)

        # 2. NAT-naive v1 Baseline Comparison on identical event stream
        vault_v1 = PrivacyVault("bench-key", "v1", td_path / "vault_v1.json")
        resolver_v1 = IdentityResolver(vault_v1)
        cep_v1 = StreamingCepEngine(CepConfig(nat_aware=False, clock_skew_retraction_enabled=False))
        for ev in valid:
            prn = resolver_v1.resolve(ev)
            tok = vault_v1.tokenize_event(ev, prn)
            cep_v1.process_event(ev, tok)
        cep_v1_metrics = cep_v1.evaluate_precision_recall(batch.ground_truth_attacks)

        # 3. Full E2E WAL -> Avro -> Tokenize -> CEP -> Apache Iceberg V2 -> DQ Gate
        cfg = PlatformConfig(data_dir=td_path / f"e2e_{profile_name}")
        t_e2e0 = time.perf_counter()
        summary = run_end_to_end_pipeline(cfg, seed=seed, batch_override=batch)
        e2e_sec = time.perf_counter() - t_e2e0

        return {
            "profile": profile_name,
            "target_events": target_events,
            "actual_events_generated": len(batch.raw_records),
            "valid_events": len(valid),
            "dlq_quarantined": len(dlq),
            "silver_unique_events": summary.events_tokenized_silver,
            "cep_stream_wall_ms": round(cep_sec * 1000.0, 2),
            "cep_stream_throughput_eps": round(len(valid) / max(cep_sec, 1e-6), 1),
            "e2e_lakehouse_wall_ms": round(e2e_sec * 1000.0, 2),
            "e2e_lakehouse_throughput_eps": round(len(batch.raw_records) / max(e2e_sec, 1e-6), 1),
            "nat_aware_v2": cep_v2_metrics,
            "nat_naive_v1": cep_v1_metrics,
            "dq_passed": f"{summary.dq_checks_passed}/{summary.dq_checks_total}",
        }


def benchmark_bounded_state_scaling(seed: int = 42) -> list[dict[str, Any]]:
    """Measure bounded CEP state growth under increasing high-cardinality volume with fixed state cap."""
    results: list[dict[str, Any]] = []
    cap_dedup = 3_000
    cap_entities = 500
    theoretical_max = cap_dedup + 5 * cap_entities

    for vol in (2_000, 6_000, 15_000, 30_000):
        batch = generate_security_telemetry(seed=seed, total_events=vol, include_poison_events=False)
        valid, _ = validate_and_split_events(batch.raw_records)
        with tempfile.TemporaryDirectory() as td:
            vault = PrivacyVault("bench-state-key", "v1", Path(td) / "v.json")
            resolver = IdentityResolver(vault)
            cep = StreamingCepEngine(
                CepConfig(
                    max_dedup_ids=cap_dedup,
                    max_ip_keys=cap_entities,
                    max_principal_keys=cap_entities,
                    max_token_keys=cap_entities,
                )
            )
            t0 = time.perf_counter()
            for ev in valid:
                prn = resolver.resolve(ev)
                tok = vault.tokenize_event(ev, prn)
                cep.process_event(ev, tok)
            dt = time.perf_counter() - t0
            results.append(
                {
                    "input_events": len(valid),
                    "peak_state_entries": cep.metrics.peak_state_entries,
                    "configured_state_cap": theoretical_max,
                    "throughput_eps": round(len(valid) / max(dt, 1e-6), 1),
                }
            )
    return results


def benchmark_iceberg_compaction(seed: int = 42) -> dict[str, Any]:
    """Measure Apache Iceberg V2 Parquet file fragmentation and DuckDB scan latency before vs after compaction."""
    batch = generate_security_telemetry(seed=seed, total_events=6_000, include_poison_events=False)
    valid, _ = validate_and_split_events(batch.raw_records)

    with tempfile.TemporaryDirectory() as td:
        cfg = PlatformConfig(data_dir=Path(td) / "compact_bench")
        lh = PrivacyLakehouse(cfg)
        vault = PrivacyVault(cfg.hmac_master_key, cfg.key_version, cfg.vault_file_path)
        resolver = IdentityResolver(vault)

        tokenized = [vault.tokenize_event(ev, resolver.resolve(ev)) for ev in valid]
        # Simulate 24 streaming micro-batch commits creating small Parquet files
        chunk_size = max(1, len(tokenized) // 24)
        for start in range(0, len(tokenized), chunk_size):
            lh.write_tokenized_events(tokenized[start : start + chunk_size], mode="append")

        files_before = lh.table_data_file_count("silver.tokenized_security_events")

        # Measure 5-run median scan + DuckDB aggregation BEFORE compaction
        before_scan_ms: list[float] = []
        before_duck_ms: list[float] = []
        for _ in range(5):
            t0 = time.perf_counter()
            arrow_tbl = lh.read_arrow("silver.tokenized_security_events")
            before_scan_ms.append((time.perf_counter() - t0) * 1000.0)
            td0 = time.perf_counter()
            con = duckdb.connect(":memory:")
            con.register("silver_ev", arrow_tbl)
            con.execute(
                "SELECT source_stream, geo_country, COUNT(*), COUNT(DISTINCT principal_token) "
                "FROM silver_ev GROUP BY 1, 2"
            ).fetchall()
            con.close()
            before_duck_ms.append((time.perf_counter() - td0) * 1000.0)

        compaction = lh.compact_table("silver.tokenized_security_events")
        files_after = compaction["data_files_after"]

        # Measure 5-run median scan + DuckDB aggregation AFTER compaction
        after_scan_ms: list[float] = []
        after_duck_ms: list[float] = []
        for _ in range(5):
            t0 = time.perf_counter()
            arrow_tbl = lh.read_arrow("silver.tokenized_security_events")
            after_scan_ms.append((time.perf_counter() - t0) * 1000.0)
            td0 = time.perf_counter()
            con = duckdb.connect(":memory:")
            con.register("silver_ev", arrow_tbl)
            con.execute(
                "SELECT source_stream, geo_country, COUNT(*), COUNT(DISTINCT principal_token) "
                "FROM silver_ev GROUP BY 1, 2"
            ).fetchall()
            con.close()
            after_duck_ms.append((time.perf_counter() - td0) * 1000.0)

        med_before = round(sorted(before_scan_ms)[2], 3)
        med_after = round(sorted(after_scan_ms)[2], 3)
        speedup = round(med_before / max(med_after, 0.001), 2)
        return {
            "table": "silver.tokenized_security_events",
            "row_count": compaction["row_count"],
            "micro_batches_written": 24,
            "parquet_files_before": files_before,
            "parquet_files_after": files_after,
            "file_reduction_pct": round((1.0 - files_after / max(1, files_before)) * 100.0, 1),
            "scan_median_before_ms": med_before,
            "scan_median_after_ms": med_after,
            "scan_speedup_x": speedup,
            "duckdb_agg_before_ms": round(sorted(before_duck_ms)[2], 3),
            "duckdb_agg_after_ms": round(sorted(after_duck_ms)[2], 3),
            "compaction_wall_ms": compaction["compaction_wall_ms"],
        }


def render_benchmark_chart(
    profile_results: list[dict[str, Any]],
    state_scaling: list[dict[str, Any]],
    compaction: dict[str, Any],
) -> None:
    """Render a clean 4-panel dark-accented benchmark visualization PNG."""
    CHART_PATH.parent.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(
        {
            "figure.facecolor": "#0b1120",
            "axes.facecolor": "#111a2e",
            "axes.edgecolor": "#334155",
            "axes.labelcolor": "#e2e8f0",
            "xtick.color": "#cbd5e1",
            "ytick.color": "#cbd5e1",
            "text.color": "#f8fafc",
            "grid.color": "#1e293b",
        }
    )

    fig, axes = plt.subplots(2, 2, figsize=(14.5, 9.2), dpi=150)
    fig.suptitle(
        "Security Event & Privacy-Preserving Analytics Platform — Measured Benchmarks (Apple M4 Pro, local_native)",
        fontsize=13.5,
        fontweight="bold",
        y=0.975,
    )

    # Panel 1: Throughput across profiles
    ax = axes[0, 0]
    names = [f"{r['profile']}\n({r['valid_events']:,} ev)" for r in profile_results]
    cep_eps = [r["cep_stream_throughput_eps"] for r in profile_results]
    e2e_eps = [r["e2e_lakehouse_throughput_eps"] for r in profile_results]
    x = list(range(len(names)))
    w = 0.36
    b1 = ax.bar([i - w / 2 for i in x], cep_eps, width=w, color="#22d3ee", label="CEP + Tokenization (in-memory)")
    b2 = ax.bar([i + w / 2 for i in x], e2e_eps, width=w, color="#818cf8", label="Full E2E (WAL + Iceberg V2 + DQ)")
    ax.set_title("A. Streaming CEP vs Full Lakehouse Throughput", fontsize=11, fontweight="bold")
    ax.set_ylabel("Throughput (events / sec)")
    ax.set_ylim(0, max(cep_eps) * 1.18)
    ax.set_xticks(x)
    ax.set_xticklabels(names)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.legend(facecolor="#0f172a", edgecolor="#334155", fontsize=8.5, loc="center right")
    for bar in list(b1) + list(b2):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h * 1.02, f"{h:,.0f}", ha="center", va="bottom", fontsize=8)

    # Panel 2: NAT-Naive (v1) vs NAT-Aware (v2) Precision / F1 / False Positives
    ax = axes[0, 1]
    ref = profile_results[-1]
    v1 = ref["nat_naive_v1"]
    v2 = ref["nat_aware_v2"]
    metrics_labels = ["Precision (%)", "Recall (%)", "F1 Score (%)", "FP Rate (%)"]
    v1_vals = [v1["precision"] * 100, v1["recall"] * 100, v1["f1_score"] * 100, v1["false_positive_rate"] * 100]
    v2_vals = [v2["precision"] * 100, v2["recall"] * 100, v2["f1_score"] * 100, v2["false_positive_rate"] * 100]
    xm = list(range(len(metrics_labels)))
    m1 = ax.bar([i - w / 2 for i in xm], v1_vals, width=w, color="#f43f5e", label=f"v1 NAT-Naive (FP={v1['false_positives']})")
    m2 = ax.bar([i + w / 2 for i in xm], v2_vals, width=w, color="#10b981", label=f"v2 NAT-Aware + Retract (FP={v2['false_positives']})")
    ax.set_title(f"B. Detection Quality Ablation ({ref['profile']} profile)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Percentage (%)")
    ax.set_ylim(0, 134)
    ax.set_xticks(xm)
    ax.set_xticklabels(metrics_labels)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.legend(facecolor="#0f172a", edgecolor="#334155", fontsize=8.5, loc="upper center", ncol=2)
    for bar in list(m1) + list(m2):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 2.0, f"{h:.1f}%", ha="center", va="bottom", fontsize=8)

    # Panel 3: Bounded State Scaling
    ax = axes[1, 0]
    vols = [s["input_events"] for s in state_scaling]
    peaks = [s["peak_state_entries"] for s in state_scaling]
    cap_val = state_scaling[0]["configured_state_cap"]
    ax.plot(vols, peaks, marker="o", linewidth=2.4, color="#f59e0b", label="Observed Peak State Entries")
    ax.axhline(cap_val, color="#ef4444", linestyle="--", linewidth=1.6, label=f"Hard Eviction Cap ({cap_val:,})")
    ax.set_title("C. Bounded CEP State Under High Cardinality", fontsize=11, fontweight="bold")
    ax.set_xlabel("Processed Security Events")
    ax.set_ylabel("Active In-Memory State Entries")
    ax.set_ylim(0, cap_val * 1.24)
    ax.grid(True, linestyle="--", alpha=0.5)
    ax.legend(facecolor="#0f172a", edgecolor="#334155", fontsize=8.5, loc="upper right")
    for vx, py in zip(vols, peaks, strict=False):
        ax.annotate(f"{py:,}", (vx, py), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=8.5)

    # Panel 4: Iceberg V2 Compaction Before vs After
    ax = axes[1, 1]
    comp_labels = ["Parquet Data Files", "Iceberg Scan Latency (ms)"]
    before_vals = [compaction["parquet_files_before"], compaction["scan_median_before_ms"]]
    after_vals = [compaction["parquet_files_after"], compaction["scan_median_after_ms"]]
    xc = [0, 1]
    c1 = ax.bar([i - w / 2 for i in xc], before_vals, width=w, color="#fb923c", label="Before Compaction (24 micro-batches)")
    c2 = ax.bar([i + w / 2 for i in xc], after_vals, width=w, color="#38bdf8", label=f"After Compaction ({compaction['scan_speedup_x']}x faster scan)")
    ax.set_title("D. Apache Iceberg V2 Compaction Impact (Silver Table)", fontsize=11, fontweight="bold")
    ax.set_ylabel("Count / Latency (ms)")
    ax.set_ylim(0, max(before_vals) * 1.28)
    ax.set_xticks(xc)
    ax.set_xticklabels(comp_labels)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.legend(facecolor="#0f172a", edgecolor="#334155", fontsize=8.5, loc="upper left")
    for bar in list(c1) + list(c2):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + max(before_vals) * 0.025, f"{h:.1f}" if h % 1 else f"{int(h)}", ha="center", va="bottom", fontsize=8.5)

    plt.tight_layout(rect=(0.0, 0.0, 1.0, 0.94))
    fig.savefig(CHART_PATH, dpi=150)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SecOps & Privacy Platform benchmarks")
    parser.add_argument(
        "--profiles",
        nargs="+",
        default=["smoke", "local", "stress"],
        choices=list(PROFILES.keys()),
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    hw = collect_sanitized_hardware()

    profile_results = [benchmark_profile(p, PROFILES[p], seed=args.seed) for p in args.profiles]
    state_scaling = benchmark_bounded_state_scaling(seed=args.seed)
    compaction = benchmark_iceberg_compaction(seed=args.seed)

    render_benchmark_chart(profile_results, state_scaling, compaction)

    summary = {
        "hardware": hw,
        "seed": args.seed,
        "profiles": profile_results,
        "bounded_state_scaling": state_scaling,
        "iceberg_compaction": compaction,
        "chart_path": "docs/assets/benchmark_security_cep_privacy.png",
    }
    (RESULTS_DIR / "benchmark_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    (RESULTS_DIR / "iceberg_compaction.json").write_text(
        json.dumps(compaction, indent=2, sort_keys=True), encoding="utf-8"
    )

    with (RESULTS_DIR / "benchmark_profiles.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "profile",
                "valid_events",
                "dlq_quarantined",
                "cep_stream_wall_ms",
                "cep_stream_throughput_eps",
                "e2e_lakehouse_wall_ms",
                "e2e_lakehouse_throughput_eps",
                "v2_precision",
                "v2_recall",
                "v2_f1",
                "v2_fp",
                "v2_retracted",
                "detection_delay_p50_ms",
                "detection_delay_p95_ms",
                "detection_delay_p99_ms",
                "peak_state_entries",
            ]
        )
        for r in profile_results:
            m2 = r["nat_aware_v2"]
            writer.writerow(
                [
                    r["profile"],
                    r["valid_events"],
                    r["dlq_quarantined"],
                    r["cep_stream_wall_ms"],
                    r["cep_stream_throughput_eps"],
                    r["e2e_lakehouse_wall_ms"],
                    r["e2e_lakehouse_throughput_eps"],
                    m2["precision"],
                    m2["recall"],
                    m2["f1_score"],
                    m2["false_positives"],
                    m2["retracted_incidents"],
                    m2["detection_delay_p50_ms"],
                    m2["detection_delay_p95_ms"],
                    m2["detection_delay_p99_ms"],
                    m2["peak_state_entries"],
                ]
            )

    with (RESULTS_DIR / "nat_ablation.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "profile",
                "ruleset",
                "ground_truth_campaigns",
                "active_incidents",
                "retracted_incidents",
                "true_positives",
                "false_positives",
                "false_negatives",
                "precision",
                "recall",
                "f1_score",
                "false_positive_rate",
            ]
        )
        for r in profile_results:
            for label, key in (("v1_nat_naive", "nat_naive_v1"), ("v2_nat_aware_retract", "nat_aware_v2")):
                m = r[key]
                writer.writerow(
                    [
                        r["profile"],
                        label,
                        m["ground_truth_campaigns"],
                        m["active_incidents"],
                        m["retracted_incidents"],
                        m["true_positives"],
                        m["false_positives"],
                        m["false_negatives"],
                        m["precision"],
                        m["recall"],
                        m["f1_score"],
                        m["false_positive_rate"],
                    ]
                )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
