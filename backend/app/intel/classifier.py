"""Lightweight scam classifier (contract section 24, MVP row).

TF-IDF (char + word n-grams) + logistic regression trained on the shipped
synthetic/permissioned dataset. It is deliberately optional:

  * if scikit-learn is missing, `predict()` returns None and the rule engine
    carries the decision alone;
  * the model can only *add* evidence weight, never veto a rule hit.

Train with:  python -m app.intel.classifier --train
"""
from __future__ import annotations

import json
import os
from typing import List, Optional, Tuple

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "scam_clf.joblib")
MODEL_PATH = os.path.abspath(MODEL_PATH)
DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "dataset.jsonl"))

_model = None
_load_attempted = False
_unavailable_reason: Optional[str] = None


def _build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline

    return Pipeline([
        ("features", FeatureUnion([
            ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2),
                                     sublinear_tf=True, min_df=1)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                     sublinear_tf=True, min_df=1)),
        ])),
        ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
    ])


def load_dataset(path: str = DATASET_PATH) -> Tuple[List[str], List[str]]:
    texts, labels = [], []
    if not os.path.exists(path):
        return texts, labels
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            texts.append(row["text"])
            labels.append(row["label"])
    return texts, labels


def train(path: str = DATASET_PATH) -> dict:
    try:
        import joblib
    except Exception as exc:
        return {"trained": False, "reason": f"joblib unavailable: {exc}"}
    texts, labels = load_dataset(path)
    if len(set(labels)) < 2:
        return {"trained": False, "reason": "Dataset needs at least two classes."}
    pipe = _build_pipeline()
    pipe.fit(texts, labels)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    return {"trained": True, "samples": len(texts),
            "classes": sorted(set(labels)), "path": MODEL_PATH}


def _load():
    global _model, _load_attempted, _unavailable_reason
    if _load_attempted:
        return _model
    _load_attempted = True
    try:
        import joblib
    except Exception as exc:
        _unavailable_reason = f"scikit-learn/joblib not installed ({exc})"
        return None
    if not os.path.exists(MODEL_PATH):
        res = train()
        if not res.get("trained"):
            _unavailable_reason = res.get("reason", "model not trained")
            return None
    try:
        _model = joblib.load(MODEL_PATH)
    except Exception as exc:                                   # pragma: no cover
        _unavailable_reason = f"model load failed: {exc}"
        _model = None
    return _model


def predict(text: str) -> Optional[Tuple[str, float]]:
    """Return (label, confidence) or None when the model is unavailable."""
    model = _load()
    if model is None or not text.strip():
        return None
    try:
        proba = model.predict_proba([text])[0]
        classes = list(model.classes_)
        idx = int(max(range(len(proba)), key=lambda i: proba[i]))
        return classes[idx], float(proba[idx])
    except Exception:                                          # pragma: no cover
        return None


def status() -> dict:
    model = _load()
    return {
        "available": model is not None,
        "model_path": MODEL_PATH if model is not None else None,
        "reason": None if model is not None else _unavailable_reason,
    }


if __name__ == "__main__":                                     # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    args = ap.parse_args()
    if args.train:
        print(json.dumps(train(), indent=2))
    else:
        print(json.dumps(status(), indent=2))
