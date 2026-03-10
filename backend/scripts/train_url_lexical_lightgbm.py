"""
Manual training utility for URL lexical phishing model (LightGBM).

Input sources are passed as local files:
- phishing datasets: PhishTank / OpenPhish / URLHaus exports
- benign dataset: Tranco domain list (or any URL/domain list)

Usage example:
  python -m scripts.train_url_lexical_lightgbm \
    --phishing-file data/phishtank.csv \
    --phishing-file data/openphish.txt \
    --phishing-file data/urlhaus.csv \
    --benign-file data/tranco_top_1m.csv \
    --output-model models/url_lexical_lightgbm.txt \
    --output-metadata models/url_lexical_lightgbm.metadata.json
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import lightgbm as lgb
import numpy as np

from app.services.url_lexical_ml_service import FEATURE_ORDER, extract_url_lexical_features


_COMMON_BENIGN_PATHS = [
    "/about",
    "/contact",
    "/products",
    "/solutions",
    "/resources",
    "/pricing",
    "/blog",
    "/security",
    "/support",
    "/terms",
]

_COMMON_BENIGN_LONG_PATHS = [
    "/resources/industry-reports/idc-report",
    "/products/security/email-protection",
    "/blog/2026/03/platform-update",
    "/knowledge-base/articles/account-setup",
]

_COMMON_BENIGN_QUERY_PATHS = [
    "/contact?utm_source=newsletter&utm_medium=email&utm_campaign=monthly_update",
    "/resources?lang=en&region=eu",
    "/support?ref=footer",
]


def _iter_urls_from_file(path: Path) -> Iterable[str]:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="ignore")

    if suffix in {".txt", ".list"}:
        for line in text.splitlines():
            raw = line.strip()
            if raw and not raw.startswith("#"):
                yield _normalize_candidate(raw)
        return

    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames:
        url_like_cols = [
            c for c in reader.fieldnames
            if c and c.lower() in {"url", "link", "indicator", "domain", "host", "hostname"}
        ]
        if url_like_cols:
            col = url_like_cols[0]
            for row in reader:
                raw = str(row.get(col) or "").strip()
                if raw:
                    yield _normalize_candidate(raw)
            return

    # Fallback line scanner
    for line in text.splitlines():
        raw = line.strip().strip('"').strip("'")
        if raw and not raw.startswith("#"):
            yield _normalize_candidate(raw)


def _normalize_candidate(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw
    # Tranco and many feeds provide bare domains.
    return f"https://{raw}"


def _load_dataset(
    phishing_files: list[Path],
    benign_files: list[Path],
    benign_limit: int,
    benign_ratio: float,
    augment_benign_paths: bool,
) -> tuple[np.ndarray, np.ndarray]:
    phishing_urls: list[str] = []
    benign_urls: list[str] = []
    for file_path in phishing_files:
        phishing_urls.extend(u for u in _iter_urls_from_file(file_path) if u)
    for file_path in benign_files:
        benign_urls.extend(u for u in _iter_urls_from_file(file_path) if u)

    phishing_urls = list(dict.fromkeys(phishing_urls))
    benign_urls = list(dict.fromkeys(benign_urls))
    ratio_limit = 0
    if benign_ratio > 0 and phishing_urls:
        ratio_limit = int(len(phishing_urls) * benign_ratio)
    effective_benign_limit = benign_limit
    if ratio_limit > 0:
        effective_benign_limit = ratio_limit if benign_limit <= 0 else min(benign_limit, ratio_limit)
    if effective_benign_limit > 0 and len(benign_urls) > effective_benign_limit:
        random.Random(42).shuffle(benign_urls)
        benign_urls = benign_urls[:effective_benign_limit]
    if augment_benign_paths:
        benign_urls = _augment_benign_urls(benign_urls)

    if not phishing_urls or not benign_urls:
        raise ValueError("Both phishing and benign URL sets must be non-empty.")

    X_rows: list[list[float]] = []
    y: list[int] = []

    for url in phishing_urls:
        feats = extract_url_lexical_features(url)
        X_rows.append([float(feats.get(name, 0.0)) for name in FEATURE_ORDER])
        y.append(1)
    for url in benign_urls:
        feats = extract_url_lexical_features(url)
        X_rows.append([float(feats.get(name, 0.0)) for name in FEATURE_ORDER])
        y.append(0)

    X = np.asarray(X_rows, dtype=np.float32)
    y_arr = np.asarray(y, dtype=np.int32)
    return X, y_arr


def _augment_benign_urls(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        out.append(u)
        parsed = urlparse(u)
        if parsed.path and parsed.path not in {"", "/"}:
            continue
        if parsed.query:
            continue
        h = int(hashlib.md5(u.encode("utf-8")).hexdigest(), 16)
        path = _COMMON_BENIGN_PATHS[h % len(_COMMON_BENIGN_PATHS)]
        out.append(f"{u.rstrip('/')}{path}")
        long_path = _COMMON_BENIGN_LONG_PATHS[h % len(_COMMON_BENIGN_LONG_PATHS)]
        out.append(f"{u.rstrip('/')}{long_path}")
        query_path = _COMMON_BENIGN_QUERY_PATHS[h % len(_COMMON_BENIGN_QUERY_PATHS)]
        out.append(f"{u.rstrip('/')}{query_path}")
    return list(dict.fromkeys(out))


def _train_lightgbm(X: np.ndarray, y: np.ndarray) -> tuple[lgb.Booster, dict]:
    idx = np.arange(len(y))
    np.random.default_rng(42).shuffle(idx)
    X = X[idx]
    y = y[idx]

    split = max(1, int(0.8 * len(y)))
    X_train, X_valid = X[:split], X[split:]
    y_train, y_valid = y[:split], y[split:]

    dtrain = lgb.Dataset(X_train, label=y_train, feature_name=FEATURE_ORDER)
    dvalid = lgb.Dataset(X_valid, label=y_valid, feature_name=FEATURE_ORDER, reference=dtrain)

    pos_count = int(y_train.sum())
    neg_count = int(len(y_train) - pos_count)
    scale_pos_weight = 1.0

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "learning_rate": 0.03,
        "num_leaves": 63,
        "feature_fraction": 0.95,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "min_data_in_leaf": 20,
        "lambda_l2": 1.0,
        "scale_pos_weight": scale_pos_weight,
        "verbosity": -1,
        "seed": 42,
    }

    model = lgb.train(
        params=params,
        train_set=dtrain,
        valid_sets=[dtrain, dvalid],
        valid_names=["train", "valid"],
        num_boost_round=1200,
        callbacks=[lgb.early_stopping(80, verbose=False)],
    )

    pred = model.predict(X_valid, num_iteration=model.best_iteration)
    pred_label = (pred >= 0.5).astype(np.int32)
    accuracy = float((pred_label == y_valid).mean()) if len(y_valid) else 0.0
    calibration = _build_calibration_bins(pred, y_valid, bins=20)
    raw_brier = float(np.mean((pred - y_valid) ** 2)) if len(y_valid) else 1.0
    calibrated_pred = _apply_calibration_bins(pred, calibration.get("bins") or [])
    cal_brier = float(np.mean((calibrated_pred - y_valid) ** 2)) if len(y_valid) else 1.0
    enabled = bool((calibration.get("bins") or []) and cal_brier < raw_brier)
    calibration["enabled"] = enabled
    calibration["raw_brier"] = round(raw_brier, 6)
    calibration["calibrated_brier"] = round(cal_brier, 6)
    metrics = {
        "train_size": int(len(y_train)),
        "valid_size": int(len(y_valid)),
        "accuracy@0.5": round(accuracy, 4),
        "best_iteration": int(model.best_iteration or 0),
        "train_pos_count": pos_count,
        "train_neg_count": neg_count,
        "scale_pos_weight": round(scale_pos_weight, 4),
        "valid_pred_q10": round(float(np.quantile(pred, 0.10)), 6),
        "valid_pred_q50": round(float(np.quantile(pred, 0.50)), 6),
        "valid_pred_q90": round(float(np.quantile(pred, 0.90)), 6),
        "valid_pred_q99": round(float(np.quantile(pred, 0.99)), 6),
        "calibration_bins": len(calibration.get("bins") or []),
    }
    return model, {"metrics": metrics, "calibration": calibration}


def _build_calibration_bins(pred: np.ndarray, y_true: np.ndarray, bins: int = 20) -> dict:
    if pred is None or y_true is None or len(pred) == 0:
        return {"method": "quantile_bin_interpolation", "bins": []}
    p = np.asarray(pred, dtype=np.float64)
    y = np.asarray(y_true, dtype=np.float64)
    quantiles = np.linspace(0.0, 1.0, bins + 1)
    edges = np.unique(np.quantile(p, quantiles))
    if len(edges) < 3:
        edges = np.linspace(0.0, 1.0, min(6, bins) + 1)
    rows: list[dict] = []
    min_count = max(200, int(len(p) * 0.002))
    for i in range(len(edges) - 1):
        lo = float(edges[i])
        hi = float(edges[i + 1])
        if i == len(edges) - 2:
            mask = (p >= lo) & (p <= hi)
        else:
            mask = (p >= lo) & (p < hi)
        cnt = int(mask.sum())
        if cnt < min_count:
            continue
        pred_mean = float(p[mask].mean())
        actual_rate = float(y[mask].mean())
        rows.append(
            {
                "lower": round(lo, 6),
                "upper": round(hi, 6),
                "count": cnt,
                "pred_mean": round(pred_mean, 6),
                "actual_rate": round(actual_rate, 6),
            }
        )
    # enforce monotonic actual rates for safer interpolation
    max_seen = 0.0
    for row in rows:
        rate = float(row["actual_rate"])
        if rate < max_seen:
            row["actual_rate"] = round(max_seen, 6)
        else:
            max_seen = rate
    return {"method": "quantile_bin_interpolation", "bins": rows}


def _apply_calibration_bins(pred: np.ndarray, bins: list[dict]) -> np.ndarray:
    if pred is None or len(pred) == 0:
        return np.asarray([], dtype=np.float64)
    if not bins:
        return np.asarray(pred, dtype=np.float64)
    points: list[tuple[float, float]] = []
    for row in bins:
        try:
            points.append((float(row["pred_mean"]), float(row["actual_rate"])))
        except Exception:
            continue
    if len(points) < 2:
        return np.asarray(pred, dtype=np.float64)
    points.sort(key=lambda t: t[0])
    xs = np.asarray([p[0] for p in points], dtype=np.float64)
    ys = np.asarray([p[1] for p in points], dtype=np.float64)
    calibrated = np.interp(np.asarray(pred, dtype=np.float64), xs, ys, left=ys[0], right=ys[-1])
    return np.clip(calibrated, 0.0, 1.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train URL lexical phishing LightGBM model")
    parser.add_argument("--phishing-file", action="append", required=True, help="CSV/TXT file containing phishing URLs/domains")
    parser.add_argument("--benign-file", action="append", required=True, help="CSV/TXT file containing benign URLs/domains (e.g., Tranco)")
    parser.add_argument("--benign-limit", type=int, default=300000, help="Maximum benign rows to keep (default: 300000)")
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=8.0,
        help="Maximum benign:phishing ratio after sampling (default: 8.0)",
    )
    parser.add_argument(
        "--augment-benign-paths",
        action="store_true",
        help="Add one realistic path variant for benign root domains to reduce path-length bias",
    )
    parser.add_argument("--output-model", default="models/url_lexical_lightgbm.txt", help="Output LightGBM model path")
    parser.add_argument("--output-metadata", default="models/url_lexical_lightgbm.metadata.json", help="Output metadata JSON path")
    args = parser.parse_args()

    phishing_files = [Path(p).resolve() for p in args.phishing_file]
    benign_files = [Path(p).resolve() for p in args.benign_file]
    for p in phishing_files + benign_files:
        if not p.exists():
            raise FileNotFoundError(f"Input file not found: {p}")

    X, y = _load_dataset(
        phishing_files,
        benign_files,
        benign_limit=max(0, int(args.benign_limit)),
        benign_ratio=max(0.0, float(args.benign_ratio)),
        augment_benign_paths=bool(args.augment_benign_paths),
    )
    model, train_out = _train_lightgbm(X, y)
    metrics = train_out["metrics"]
    calibration = train_out["calibration"]

    output_model = Path(args.output_model).resolve()
    output_metadata = Path(args.output_metadata).resolve()
    output_model.parent.mkdir(parents=True, exist_ok=True)
    output_metadata.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(output_model))

    metadata = {
        "model": "lightgbm",
        "labels": {"0": "benign", "1": "phishing"},
        "thresholds": {"low_max": 0.30, "medium_max": 0.65, "high_min": 0.65},
        "feature_order": FEATURE_ORDER,
        "training_sources": {
            "phishing_files": [str(p) for p in phishing_files],
            "benign_files": [str(p) for p in benign_files],
        },
        "samples": {"total": int(len(y)), "phishing": int(y.sum()), "benign": int(len(y) - y.sum())},
        "sampling": {
            "benign_limit": int(max(0, int(args.benign_limit))),
            "benign_ratio": float(max(0.0, float(args.benign_ratio))),
            "augment_benign_paths": bool(args.augment_benign_paths),
        },
        "metrics": metrics,
        "calibration": calibration,
    }
    output_metadata.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(f"Model saved: {output_model}")
    print(f"Metadata saved: {output_metadata}")
    print(json.dumps(metadata["metrics"], indent=2))


if __name__ == "__main__":
    main()
