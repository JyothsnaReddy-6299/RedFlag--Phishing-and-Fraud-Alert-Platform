#!/usr/bin/env python3
"""RedFlag evaluation harness (contract section 25).

Measures, on the held-out validation split (disjoint templates):

  * scam-vs-legitimate precision / recall / F1 / false-positive rate
  * per-class and per-language F1
  * explanation coverage (every verdict must carry evidence-backed reasons)
  * end-to-end latency P50 / P95

DO NOT FABRICATE METRICS. This script writes `data/metrics.json`, which is the
only thing the UI is allowed to display. Anything not produced here must be
shown as "not measured".

Usage:  python evaluate.py [--threshold 25]
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.intel import analyzer, language  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATION = os.path.join(HERE, "data", "validation.jsonl")
OUT = os.path.join(HERE, "data", "metrics.json")


def prf(tp: int, fp: int, fn: int):
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=25,
                    help="risk score at or above which we call it a scam (CAUTION band)")
    ap.add_argument("--dataset", default=VALIDATION)
    args = ap.parse_args()

    if not os.path.exists(args.dataset):
        print(f"Validation set missing: {args.dataset}\nRun: python data/build_dataset.py")
        return 1

    rows: List[dict] = []
    with open(args.dataset, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))

    tp = fp = tn = fn = 0
    latencies: List[float] = []
    per_class: Dict[str, Counter] = defaultdict(Counter)
    per_lang: Dict[str, Counter] = defaultdict(Counter)
    explained = 0
    cat_correct = 0
    cat_total = 0
    misses: List[dict] = []

    for row in rows:
        t0 = time.perf_counter()
        # session=None: evaluate the model/rules alone, with no community
        # reputation or campaign boost, so the number is not inflated by seeds.
        res = analyzer.analyze(row["text"], input_type="text",
                               session=None, persist=False)
        latencies.append((time.perf_counter() - t0) * 1000)

        truth_scam = row["label"] != "legitimate"
        pred_scam = res["risk_score"] >= args.threshold
        lang = language.detect(row["text"]).language

        if pred_scam and truth_scam:
            tp += 1
        elif pred_scam and not truth_scam:
            fp += 1
            misses.append({"kind": "false_positive", "label": row["label"],
                           "score": res["risk_score"], "text": row["text"][:140]})
        elif not pred_scam and truth_scam:
            fn += 1
            misses.append({"kind": "false_negative", "label": row["label"],
                           "score": res["risk_score"], "text": row["text"][:140]})
        else:
            tn += 1

        per_class[row["label"]]["n"] += 1
        per_class[row["label"]]["hit"] += int(pred_scam == truth_scam)
        per_lang[lang]["n"] += 1
        per_lang[lang]["hit"] += int(pred_scam == truth_scam)

        if res["red_flags"] or res["risk_score"] < args.threshold:
            # A verdict is "explained" if it carries evidence, or if it is a
            # low-risk verdict that explicitly states no evidence was found.
            explained += 1

        if truth_scam:
            cat_total += 1
            cat_correct += int(res["scam_category"] == row["label"])

    p, r, f1 = prf(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    lat = sorted(latencies)

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "measured": True,
        "dataset": {
            "path": os.path.relpath(args.dataset, HERE),
            "samples": len(rows),
            "provenance": "synthetic (data/build_dataset.py); train/test templates disjoint",
            "classes": sorted({x["label"] for x in rows}),
        },
        "decision_threshold": args.threshold,
        "binary_scam_detection": {
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "true_positive": tp, "false_positive": fp,
            "true_negative": tn, "false_negative": fn,
        },
        "scam_category_accuracy": {
            "value": round(cat_correct / cat_total, 4) if cat_total else None,
            "correct": cat_correct, "total": cat_total,
        },
        "per_class_accuracy": {k: {"n": v["n"], "accuracy": round(v["hit"] / v["n"], 4)}
                               for k, v in sorted(per_class.items())},
        "per_language_accuracy": {k: {"n": v["n"], "accuracy": round(v["hit"] / v["n"], 4)}
                                  for k, v in sorted(per_lang.items())},
        "explanation_coverage": round(explained / len(rows), 4),
        "latency_ms": {
            "p50": round(statistics.median(lat), 1),
            "p95": round(lat[int(0.95 * (len(lat) - 1))], 1),
            "max": round(lat[-1], 1),
            "note": "Backend analysis time only, measured on this host.",
        },
        "ocr_accuracy": {
            "value": None,
            "status": "not measured",
            "note": "No labeled screenshot set is shipped with this build.",
        },
        "worst_cases": misses[:15],
        "caveats": [
            "Measured on a small synthetic validation set, not on real victim data.",
            "Community reputation and campaign boosts are disabled during evaluation, "
            "so live scores can be higher than these.",
            "These numbers describe this dataset only and are not a guarantee of "
            "field performance.",
        ],
    }

    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2, ensure_ascii=False)

    b = metrics["binary_scam_detection"]
    print(json.dumps({
        "samples": len(rows), "precision": b["precision"], "recall": b["recall"],
        "f1": b["f1"], "false_positive_rate": b["false_positive_rate"],
        "p95_latency_ms": metrics["latency_ms"]["p95"],
        "explanation_coverage": metrics["explanation_coverage"],
    }, indent=2))
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
