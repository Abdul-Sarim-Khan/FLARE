# -*- coding: utf-8 -*-
"""
FLARE -- network-track FL training core (Phase B)
======================================================
Shared by dev/retrain.py (centralised) and the agent's _retrain (federated), so
the agent runs the EXACT recipe we validated (1.23% -> 0.11% FP, recall held):

  * label a flow ATTACK if its FlowStartTime is inside a ground-truth attack
    window, else BENIGN; drop ambiguous high-rate bursts with no ground truth.
  * keep the scaler FROZEN -- warm-start the MLP weights only (this is what the
    broken scaler-FL got backwards).
  * partial_fit a few epochs on a class-balanced sample.
  * evaluate baseline vs fine-tuned on a held-out split; the caller adopts/ships
    ONLY if it improves FP-rate without losing recall (is_improvement()).
"""
import csv
import numpy as np


# ── Labels ───────────────────────────────────────────────────────────────────

def parse_gt_windows(gt_csv, offset=0.0):
    """Parse a sim ground-truth CSV into [(start, end), ...] unix-second windows."""
    wins, opens = [], {}
    with open(gt_csv, newline="", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            try:
                ts = int(r["unix_us"]) / 1e6 + offset
            except (KeyError, ValueError):
                continue
            ev, atk = r.get("event", ""), r.get("attack_type", "")
            if ev == "PHASE_START":
                opens[atk] = ts
            elif ev == "PHASE_END" and atk in opens:
                wins.append((opens.pop(atk), ts))
    return wins


def label_flows(df, attack_windows, grace=30, burst_factor=5, benign_windows=None):
    """Label flows by ground-truth windows; drop ambiguous high-rate bursts that
    sit outside every window (likely undocumented attacks that would poison the
    BENIGN class). Returns (df_kept, y, n_dropped) with y 0=ATTACK, 1=BENIGN.

    benign_windows: optional list of (start, end) unix-second windows from
    dashboard false_positive feedback — flows inside these are labelled BENIGN
    even if a broad attack_window would otherwise catch them.
    """
    benign_windows = benign_windows or []
    df = df[df["FlowStartTime"].notna()].copy()
    t = df["FlowStartTime"].astype(float)

    def in_any(windows, x):
        return any((lo - grace) <= x <= (hi + grace) for lo, hi in windows)

    is_atk = t.apply(lambda x: in_any(attack_windows, x))
    is_fp  = t.apply(lambda x: in_any(benign_windows, x)) if benign_windows else \
             t.apply(lambda _: False)

    # Dashboard-confirmed BENIGN overrides any attack-window match.
    effective_atk = is_atk & ~is_fp

    binned = (t // 60).astype(int)
    counts = binned.value_counts()
    avg = counts.mean() if len(counts) else 0.0
    gt_bins = {int(x // 60) for lo, hi in attack_windows
               for x in np.arange(lo - grace, hi + grace, 60)}
    # Also protect confirmed-benign minute-bins from the burst filter.
    fp_bins = {int(x // 60) for lo, hi in benign_windows
               for x in np.arange(lo - grace, hi + grace, 60)}
    safe_bins = gt_bins | fp_bins
    ambig = {b for b, c in counts.items() if avg and c >= burst_factor * avg and b not in safe_bins}
    keep = ~binned.isin(ambig)
    y = effective_atk[keep].map({True: 0, False: 1}).to_numpy()
    return df[keep], y, int((~keep).sum())


# ── Evaluation + fine-tune ───────────────────────────────────────────────────

def evaluate(model, X, y):
    """Return {recall, fp_rate, n_attack, n_benign} on scaled features X."""
    p = model.predict(X)
    atk, ben = y == 0, y == 1
    return {
        "recall":   float((p[atk] == 0).mean()) if atk.sum() else float("nan"),
        "fp_rate":  float((p[ben] == 0).mean()) if ben.sum() else float("nan"),
        "n_attack": int(atk.sum()),
        "n_benign": int(ben.sum()),
    }


def fine_tune(mlp, Xs, y, epochs=25, seed=0, test_size=0.25):
    """Warm-start fine-tune `mlp` on already-scaled features Xs / labels y.
    Returns (mlp, before, after) metric dicts. Does NOT persist or send -- the
    caller decides based on the metrics. The scaler is the caller's, kept fixed."""
    from sklearn.model_selection import train_test_split
    rng = np.random.default_rng(seed)
    Xtr, Xte, ytr, yte = train_test_split(Xs, y, test_size=test_size,
                                          random_state=seed, stratify=y)
    before = evaluate(mlp, Xte, yte)

    ia, ib = np.where(ytr == 0)[0], np.where(ytr == 1)[0]
    k = min(len(ia), len(ib))
    if k == 0:                       # only one class present -- nothing to learn
        return mlp, before, before
    bal = np.concatenate([rng.choice(ia, k, replace=False),
                          rng.choice(ib, k, replace=False)])
    Xb, yb = Xtr[bal], ytr[bal]

    mlp.warm_start = True
    mlp.early_stopping = False
    mlp.verbose = False
    if getattr(mlp, "best_loss_", None) is None:
        mlp.best_loss_ = np.inf      # original was early_stopping=True -> None
    mlp._no_improvement_count = 0
    for _ in range(epochs):
        o = rng.permutation(len(yb))
        mlp.partial_fit(Xb[o], yb[o], classes=[0, 1])

    after = evaluate(mlp, Xte, yte)
    return mlp, before, after


def is_improvement(before, after, fp_tol=0.0, recall_tol=0.02):
    """Gate: adopt/ship only if FP-rate doesn't rise and recall doesn't drop
    materially. This is what keeps a bad local update off the network."""
    if not (np.isfinite(after["fp_rate"]) and np.isfinite(after["recall"])):
        return False
    return (after["fp_rate"] <= before["fp_rate"] + fp_tol and
            after["recall"] >= before["recall"] - recall_tol)
