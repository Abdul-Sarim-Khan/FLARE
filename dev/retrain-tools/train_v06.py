#!/usr/bin/env python3
"""
FLARE v0.6 -- Network Model Retraining
=========================================
Combines CICIDS2017 (broad attack coverage) with locally-captured labeled flows
(our specific network / attack_sim.py fingerprints) and retrains the MLP.

Local attack flows are oversampled so they carry real weight relative to the
large CICIDS2017 corpus.  Without oversampling, 9k local rows drowned by 600k+
CICIDS2017 rows would have essentially zero influence on the trained weights.

SMOTE mode (--smote):
    When local data contains multiple attack types (PortScan, Botnet, Slowloris,
    etc.) with very different sample counts, plain tiling keeps the imbalance.
    --smote uses SMOTE from imbalanced-learn to synthesise new samples for each
    minority attack type until every type reaches --smote-target samples.
    Classes with too few rows for SMOTE (< 6) are tiled to target instead.
    Requires: pip install imbalanced-learn

Usage:
    # 1. Capture + label local data:
    #    python capture_labeled_v2.py --output local_v3.csv
    #    python attack_sim_v3.py      --target <IP> --duration 60
    #    python label_by_timestamp.py --capture local_v3.csv \\
    #           --ground-truth attack_ground_truth.csv --output local_labeled_v3.csv
    #
    # 2. Retrain:
    python train_v06.py
    python train_v06.py --local local_labeled_v3.csv local_attack.csv
    python train_v06.py --oversample 30              # tune weight (no SMOTE)
    python train_v06.py --smote                      # SMOTE per attack type
    python train_v06.py --smote --smote-target 300   # aim for 300 rows per type
    #
    # 3. Deploy:
    #    Copy models/* to "Flare v0.6/client/network/models/"
"""

import argparse
import json
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE        = Path(__file__).parent
REPO_ROOT   = HERE.parent.parent                          # Flare v0.6\
MODELS_DIR  = HERE / "models"
_CICFLOW_DATA = REPO_ROOT / "CICFlowMeter" / "test_data"
CICIDS_CSV  = _CICFLOW_DATA / "cicids2017_cleaned.csv"
EVAL_CSV    = _CICFLOW_DATA / "monday_out_fixed.csv"
MODELS_DIR.mkdir(exist_ok=True)

# ── Column mappings ───────────────────────────────────────────────────────────
CICIDS_TO_FLARE = {
    "Destination Port":             "DestinationPort",
    "Flow Duration":                "FlowDurationMs",
    "Total Fwd Packets":            "TotalFwdPackets",
    "Total Length of Fwd Packets":  "TotalLenFwdPackets",
    "Fwd Packet Length Max":        "FwdPacketLenMax",
    "Fwd Packet Length Min":        "FwdPacketLenMin",
    "Fwd Packet Length Mean":       "FwdPacketLenMean",
    "Fwd Packet Length Std":        "FwdPacketLenStd",
    "Bwd Packet Length Max":        "BwdPacketLenMax",
    "Bwd Packet Length Min":        "BwdPacketLenMin",
    "Bwd Packet Length Mean":       "BwdPacketLenMean",
    "Bwd Packet Length Std":        "BwdPacketLenStd",
    "Flow Bytes/s":                 "FlowBytesPerSec",
    "Flow Packets/s":               "FlowPacketsPerSec",
    "Fwd Packets/s":                "FwdPacketsPerSec",
    "Bwd Packets/s":                "BwdPacketsPerSec",
    "Flow IAT Mean":                "FlowIATMean",
    "Flow IAT Std":                 "FlowIATStd",
    "Flow IAT Max":                 "FlowIATMax",
    "Flow IAT Min":                 "FlowIATMin",
    "Fwd IAT Total":                "FwdIATTotal",
    "Fwd IAT Mean":                 "FwdIATMean",
    "Fwd IAT Std":                  "FwdIATStd",
    "Fwd IAT Max":                  "FwdIATMax",
    "Fwd IAT Min":                  "FwdIATMin",
    "Bwd IAT Total":                "BwdIATTotal",
    "Bwd IAT Mean":                 "BwdIATMean",
    "Bwd IAT Std":                  "BwdIATStd",
    "Bwd IAT Max":                  "BwdIATMax",
    "Bwd IAT Min":                  "BwdIATMin",
    "Min Packet Length":            "MinPacketLength",
    "Max Packet Length":            "MaxPacketLength",
    "FIN Flag Count":               "FINFlagCount",
    "PSH Flag Count":               "PSHFlagCount",
    "ACK Flag Count":               "ACKFlagCount",
    "Init_Win_bytes_forward":       "InitWinBytesFwd",
    "Init_Win_bytes_backward":      "InitWinBytesBwd",
    "Average Packet Size":          "AveragePacketSize",
}
FEATURE_NAMES = list(CICIDS_TO_FLARE.values())


# ── Data loaders ──────────────────────────────────────────────────────────────

def load_cicids(path: Path):
    print(f"Loading CICIDS2017: {path}")
    df = pd.read_csv(path, low_memory=False)
    print(f"  {len(df):,} rows  |  {len(df.columns)} columns")
    df = df.rename(columns=CICIDS_TO_FLARE)
    y  = (df["Attack Type"] == "Normal Traffic").astype(int).values  # 0=ATK 1=BEN
    X  = _clean_features(df[FEATURE_NAMES])
    print(f"  BENIGN: {y.sum():,}  |  ATTACK: {(y==0).sum():,}")
    return X, y


def load_local(paths: list[Path]):
    """
    Load one or more labeled local CSVs (output from capture_labeled*.py /
    label_by_timestamp.py).  Label column: BENIGN -> 1, anything else -> 0.

    Returns:
        X_ben, y_ben          -- benign feature matrix + labels (all 1)
        X_atk, y_atk          -- attack feature matrix + labels (all 0)
        atk_type_labels       -- string array of attack-type names per attack row
                                 (e.g. 'PortScan', 'Botnet', 'DoS-Slowloris' …)
                                 Used by smote_local_attacks() for per-class SMOTE.
    """
    frames = []
    for p in paths:
        if not p.exists():
            print(f"  WARNING: local file not found, skipping: {p}")
            continue
        df = pd.read_csv(p, low_memory=False)
        print(f"  Loaded {p.name}: {len(df):,} rows")
        frames.append(df)

    if not frames:
        return None, None, None, None, None

    df_all = pd.concat(frames, ignore_index=True)

    # Ensure all feature columns exist (fill missing with 0)
    for col in FEATURE_NAMES:
        if col not in df_all.columns:
            df_all[col] = 0

    y_all = (df_all["Label"] == "BENIGN").astype(int).values
    X_all = _clean_features(df_all[FEATURE_NAMES])

    mask_attack = (y_all == 0)
    mask_benign = (y_all == 1)

    print(f"  Local BENIGN: {mask_benign.sum():,}  |  Local ATTACK: {mask_attack.sum():,}")

    label_counts = df_all["Label"].value_counts()
    for lbl, cnt in label_counts.items():
        bar = "#" * min(int(cnt / max(label_counts) * 20), 20)
        print(f"    {lbl:<22} {cnt:>6,}  {bar}")

    X_ben = X_all[mask_benign]
    y_ben = y_all[mask_benign]
    X_atk = X_all[mask_attack]
    y_atk = y_all[mask_attack]
    atk_type_labels = df_all.loc[mask_attack, "Label"].values  # string labels

    return X_ben, y_ben, X_atk, y_atk, atk_type_labels


def _clean_features(df: pd.DataFrame) -> np.ndarray:
    df = df.copy()
    df = df.apply(pd.to_numeric, errors="coerce")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    return df.values


def smote_local_attacks(
    X_atk: np.ndarray,
    atk_type_labels: np.ndarray,
    target_per_class: int = 200,
    oversample_fallback: int = 20,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Balance local attack data across attack types using SMOTE.

    For each attack type that has fewer than `target_per_class` samples:
      - If it has >= 6 samples: use SMOTE to synthesise up to target_per_class.
      - If it has < 6 samples:  tile (repeat) the rows to reach target_per_class.

    After balancing across types, the result is further tiled by
    `oversample_fallback // 5` so the local block still punches through the
    large CICIDS2017 corpus.

    Returns (X_balanced, y_binary) where y_binary is all-zeros (ATTACK=0).
    """
    try:
        from imblearn.over_sampling import SMOTE
        _has_imblearn = True
    except ImportError:
        _has_imblearn = False
        print("  WARNING: imbalanced-learn not installed.")
        print("           pip install imbalanced-learn")
        print("           Falling back to simple tiling (--oversample).")

    unique_types, counts = np.unique(atk_type_labels, return_counts=True)
    label_counts = dict(zip(unique_types, counts))

    print(f"  Attack-type distribution before augmentation:")
    for lbl, cnt in sorted(label_counts.items(), key=lambda kv: -kv[1]):
        bar = "#" * min(int(cnt / max(counts) * 20), 20)
        print(f"    {lbl:<22} {cnt:>6,}  {bar}")

    if not _has_imblearn or len(unique_types) < 2:
        # Cannot SMOTE — tile the whole block
        X_up = np.tile(X_atk, (oversample_fallback, 1))
        print(f"  Tiled x{oversample_fallback}: {len(X_up):,} rows (no SMOTE)")
        return X_up, np.zeros(len(X_up), dtype=int)

    SMOTE_MIN = 6  # need at least this many samples to call SMOTE
    smote_types  = {lbl for lbl, cnt in label_counts.items() if cnt >= SMOTE_MIN}
    tile_types   = {lbl for lbl, cnt in label_counts.items() if cnt <  SMOTE_MIN}

    if tile_types:
        print(f"  Too few samples for SMOTE (will tile): {sorted(tile_types)}")

    # -- Phase 1: SMOTE on eligible types -----------------------------------
    X_smoted     = X_atk.copy()
    labels_smoted = atk_type_labels.copy()

    if smote_types:
        # Sampling strategy: bring every eligible minority type to target_per_class.
        # Types already at or above target are left alone by SMOTE.
        strat = {
            lbl: target_per_class
            for lbl, cnt in label_counts.items()
            if lbl in smote_types and cnt < target_per_class
        }

        if strat:
            # k_neighbors capped to (min_class_size - 1)
            min_eligible = min(cnt for lbl, cnt in label_counts.items()
                               if lbl in smote_types)
            k = min(5, min_eligible - 1)
            print(f"  SMOTE k_neighbors={k}, target_per_class={target_per_class}")
            try:
                smote = SMOTE(
                    sampling_strategy=strat,
                    random_state=42,
                    k_neighbors=k,
                )
                X_smoted, labels_smoted = smote.fit_resample(X_smoted, labels_smoted)
            except Exception as exc:
                print(f"  WARNING: SMOTE failed ({exc}), falling back to tiling.")
                X_up = np.tile(X_atk, (oversample_fallback, 1))
                return X_up, np.zeros(len(X_up), dtype=int)
        else:
            print(f"  All eligible attack types already >= {target_per_class}, no SMOTE needed.")

    # -- Phase 2: tile tiny classes to target_per_class ----------------------
    extra_X, extra_L = [], []
    for lbl in tile_types:
        rows = X_atk[atk_type_labels == lbl]
        reps = max(1, -(-target_per_class // len(rows)))  # ceiling division
        tiled = np.tile(rows, (reps, 1))[:target_per_class]
        extra_X.append(tiled)
        extra_L.extend([lbl] * len(tiled))

    if extra_X:
        X_smoted     = np.vstack([X_smoted] + extra_X)
        labels_smoted = np.concatenate([labels_smoted, extra_L])

    # -- Phase 3: final oversample so local block isn't dwarfed by CICIDS2017 --
    final_reps = max(1, oversample_fallback // 5)
    X_final    = np.tile(X_smoted, (final_reps, 1))

    # Print post-SMOTE distribution
    unique2, counts2 = np.unique(
        np.tile(labels_smoted, final_reps), return_counts=True
    )
    print(f"  After SMOTE + tile x{final_reps}: {len(X_final):,} rows")
    for lbl, cnt in sorted(zip(unique2, counts2), key=lambda kv: -kv[1]):
        bar = "#" * min(int(cnt / max(counts2) * 20), 20)
        print(f"    {lbl:<22} {cnt:>6,}  {bar}")

    return X_final, np.zeros(len(X_final), dtype=int)


def load_monday_eval(path: Path, scaler) -> np.ndarray | None:
    if not path.exists():
        return None
    print(f"\nLoading eval CSV: {path}")
    # This CSV uses CICFlowMeter fork headers
    cic_to_flare = {
        "Dst Port": "DestinationPort", "Flow Duration": "FlowDurationMs",
        "Tot Fwd Pkts": "TotalFwdPackets", "TotLen Fwd Pkts": "TotalLenFwdPackets",
        "Fwd Pkt Len Max": "FwdPacketLenMax", "Fwd Pkt Len Min": "FwdPacketLenMin",
        "Fwd Pkt Len Mean": "FwdPacketLenMean", "Fwd Pkt Len Std": "FwdPacketLenStd",
        "Bwd Pkt Len Max": "BwdPacketLenMax", "Bwd Pkt Len Min": "BwdPacketLenMin",
        "Bwd Pkt Len Mean": "BwdPacketLenMean", "Bwd Pkt Len Std": "BwdPacketLenStd",
        "Flow Byts/s": "FlowBytesPerSec", "Flow Pkts/s": "FlowPacketsPerSec",
        "Fwd Pkts/s": "FwdPacketsPerSec", "Bwd Pkts/s": "BwdPacketsPerSec",
        "Flow IAT Mean": "FlowIATMean", "Flow IAT Std": "FlowIATStd",
        "Flow IAT Max": "FlowIATMax", "Flow IAT Min": "FlowIATMin",
        "Fwd IAT Tot": "FwdIATTotal", "Fwd IAT Mean": "FwdIATMean",
        "Fwd IAT Std": "FwdIATStd", "Fwd IAT Max": "FwdIATMax",
        "Fwd IAT Min": "FwdIATMin", "Bwd IAT Tot": "BwdIATTotal",
        "Bwd IAT Mean": "BwdIATMean", "Bwd IAT Std": "BwdIATStd",
        "Bwd IAT Max": "BwdIATMax", "Bwd IAT Min": "BwdIATMin",
        "Pkt Len Min": "MinPacketLength", "Pkt Len Max": "MaxPacketLength",
        "FIN Flag Cnt": "FINFlagCount", "PSH Flag Cnt": "PSHFlagCount",
        "ACK Flag Cnt": "ACKFlagCount", "Init Fwd Win Byts": "InitWinBytesFwd",
        "Init Bwd Win Byts": "InitWinBytesBwd", "Pkt Size Avg": "AveragePacketSize",
    }
    df = pd.read_csv(path, low_memory=False).rename(columns=cic_to_flare)
    for col in FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0
    X = _clean_features(df[FEATURE_NAMES])
    nonzero = (X != 0).any(axis=1)
    X = X[nonzero]
    print(f"  {len(X):,} rows (all ground-truth BENIGN)")
    return scaler.transform(X)


# ── Training ──────────────────────────────────────────────────────────────────

def build_training_set(
    X_cic: np.ndarray, y_cic: np.ndarray,
    X_ben_local: np.ndarray | None, y_ben_local: np.ndarray | None,
    X_atk_local: np.ndarray | None, y_atk_local: np.ndarray | None,
    atk_type_labels: np.ndarray | None,
    oversample: int,
    use_smote: bool = False,
    smote_target: int = 200,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Combine CICIDS2017 with local data.

    Local BENIGN flows: added once (no oversampling — CICIDS2017 benign already abundant).
    Local ATTACK flows: two strategies controlled by --smote / --oversample:

      Plain tiling (default, use_smote=False):
        All local attack rows repeated `oversample` times.
        Simple and fast; keeps the original per-class imbalance.
        Example: 3,000 rows x20 → 60,000 rows.

      SMOTE (use_smote=True):
        SMOTE synthesises new samples for each minority attack type until every
        type has `smote_target` rows, then tiles the balanced block x(oversample//5).
        Best when local data has several attack types at very different counts
        (e.g., 500 PortScan but only 12 Slowloris).
        Requires: pip install imbalanced-learn
    """
    X_parts = [X_cic]
    y_parts = [y_cic]

    if X_ben_local is not None and len(X_ben_local) > 0:
        X_parts.append(X_ben_local)
        y_parts.append(y_ben_local)
        print(f"  Added {len(X_ben_local):,} local BENIGN rows (1x)")

    if X_atk_local is not None and len(X_atk_local) > 0:
        if use_smote and atk_type_labels is not None and len(np.unique(atk_type_labels)) > 1:
            print(f"  Augmenting {len(X_atk_local):,} local ATTACK rows with SMOTE ...")
            X_atk_up, y_atk_up = smote_local_attacks(
                X_atk_local, atk_type_labels,
                target_per_class=smote_target,
                oversample_fallback=oversample,
            )
        else:
            if use_smote:
                print(f"  NOTE: --smote needs multiple attack types; falling back to tiling.")
            X_atk_up = np.tile(X_atk_local, (oversample, 1))
            y_atk_up = np.zeros(len(X_atk_up), dtype=int)
            print(f"  Added {len(X_atk_local):,} local ATTACK rows x{oversample} = {len(X_atk_up):,}")
        X_parts.append(X_atk_up)
        y_parts.append(y_atk_up)

    X_all = np.vstack(X_parts)
    y_all = np.concatenate(y_parts)
    return X_all, y_all


def train(args):
    print("=" * 62)
    print("FLARE v0.6 -- Network Model Retrain")
    print("=" * 62)

    # ── Load CICIDS2017 ───────────────────────────────────────────────────────
    print("\n[1/5] Loading CICIDS2017 ...")
    X_cic, y_cic = load_cicids(CICIDS_CSV)

    # ── Load local labeled data ───────────────────────────────────────────────
    print("\n[2/5] Loading local labeled data ...")
    local_paths = [Path(p) for p in args.local]
    X_ben_l, y_ben_l, X_atk_l, y_atk_l, atk_labels_l = load_local(local_paths)

    if X_atk_l is None or len(X_atk_l) == 0:
        print("  WARNING: no local ATTACK flows found — training on CICIDS2017 only.")
        print("  Run capture_labeled_v2.py + label_by_timestamp.py first.\n")

    # ── Combine ───────────────────────────────────────────────────────────────
    mode_str = f"SMOTE (target={args.smote_target}/class)" if args.smote else f"tile x{args.oversample}"
    print(f"\n[3/5] Building combined training set ({mode_str}) ...")
    X_all, y_all = build_training_set(
        X_cic, y_cic,
        X_ben_l, y_ben_l,
        X_atk_l, y_atk_l,
        atk_type_labels=atk_labels_l,
        oversample=args.oversample,
        use_smote=args.smote,
        smote_target=args.smote_target,
    )
    print(f"  Combined: {len(X_all):,} rows  "
          f"(BENIGN={y_all.sum():,}  ATTACK={(y_all==0).sum():,})")

    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=0.20, random_state=42, stratify=y_all,
    )
    print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── Scale ─────────────────────────────────────────────────────────────────
    print("\n[4/5] Fitting StandardScaler ...")
    scaler = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    # ── Train MLP ─────────────────────────────────────────────────────────────
    print("      Training MLPClassifier (64, 32) ...")
    t0  = time.time()
    mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        solver="adam",
        alpha=0.0001,
        batch_size=512,
        max_iter=200,
        early_stopping=True,
        validation_fraction=0.10,
        n_iter_no_change=10,
        random_state=42,
        verbose=True,
    )
    mlp.fit(X_train_sc, y_train)
    elapsed = time.time() - t0
    print(f"      Done in {elapsed:.1f}s  ({mlp.n_iter_} iterations)")

    # ── Evaluate: CICIDS2017 test set ─────────────────────────────────────────
    print("\n[5/5] Evaluation")
    print("  -- CICIDS2017 held-out test set (20%) --")
    y_pred = mlp.predict(X_test_sc)
    print(classification_report(
        y_test, y_pred,
        target_names=["ATTACK (0)", "BENIGN (1)"],
        digits=4,
    ))
    cm = confusion_matrix(y_test, y_pred)
    print("  Confusion matrix  (rows=actual, cols=predicted):")
    print("                pred:ATTACK  pred:BENIGN")
    print(f"    true:ATTACK  {cm[0,0]:>10,}  {cm[0,1]:>11,}")
    print(f"    true:BENIGN  {cm[1,0]:>10,}  {cm[1,1]:>11,}")

    # ── Evaluate: local attack data in-sample sanity check ────────────────────
    if X_atk_l is not None and len(X_atk_l) > 0:
        print("\n  -- Local ATTACK flows (sanity check — not in test set) --")
        X_atk_sc  = scaler.transform(X_atk_l)
        probs_atk = mlp.predict_proba(X_atk_sc)[:, 0]
        n_detected = int((probs_atk >= 0.50).sum())
        pct = n_detected / len(probs_atk) * 100
        print(f"    Rows: {len(X_atk_l):,}   Detected (P>=0.5): {n_detected:,}  ({pct:.1f}%)")
        print(f"    P(ATTACK): mean={probs_atk.mean():.4f}  "
              f"median={np.median(probs_atk):.4f}  "
              f"min={probs_atk.min():.4f}")
        print(f"    Distribution:")
        for t in [0.9, 0.7, 0.5, 0.3]:
            print(f"      >= {t:.1f}: {int((probs_atk >= t).sum()):>6,}")

    # ── Evaluate: false positives on ground-truth benign ─────────────────────
    X_mon_sc = load_monday_eval(EVAL_CSV, scaler)
    if X_mon_sc is not None:
        probs_mon = mlp.predict_proba(X_mon_sc)[:, 0]
        print(f"\n  -- monday_out_fixed.csv (ground-truth BENIGN) --")
        print(f"    Scored: {len(probs_mon):,}")
        print(f"    P(ATTACK): mean={probs_mon.mean():.4f}  max={probs_mon.max():.4f}")
        print(f"    FP rate at multiple thresholds:")
        for t in [0.50, 0.60, 0.65, 0.70, 0.75, 0.80]:
            n_fp   = int((probs_mon >= t).sum())
            fp_pct = n_fp / len(probs_mon) * 100
            print(f"      threshold={t:.2f}  FP={n_fp:>6,}  ({fp_pct:.3f}%)")

    # ── Evaluate: local benign flows (real desktop traffic) ───────────────────
    if X_ben_l is not None and len(X_ben_l) > 0:
        X_ben_sc   = scaler.transform(X_ben_l)
        probs_ben  = mlp.predict_proba(X_ben_sc)[:, 0]
        print(f"\n  -- Local BENIGN flows (real desktop traffic) --")
        print(f"    Rows: {len(X_ben_l):,}")
        print(f"    P(ATTACK): mean={probs_ben.mean():.4f}  max={probs_ben.max():.4f}")
        for t in [0.50, 0.65, 0.70]:
            n_fp   = int((probs_ben >= t).sum())
            fp_pct = n_fp / len(probs_ben) * 100
            print(f"      threshold={t:.2f}  FP={n_fp:>5,}  ({fp_pct:.2f}%)")

    # ── Save ──────────────────────────────────────────────────────────────────
    print(f"\nSaving to {MODELS_DIR} ...")
    joblib.dump(mlp,    MODELS_DIR / "network_mlp.pkl")
    joblib.dump(scaler, MODELS_DIR / "network_scaler.pkl")

    with open(MODELS_DIR / "feature_names.json", "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)

    weights = {
        "coefs":      [c.tolist() for c in mlp.coefs_],
        "intercepts": [b.tolist() for b in mlp.intercepts_],
    }
    with open(MODELS_DIR / "network_mlp_weights.json", "w") as f:
        json.dump(weights, f)

    print("Done.")
    v06_models = REPO_ROOT / "client" / "network" / "models"
    print(f"\nDeploy command:")
    print(f'  Copy-Item "{MODELS_DIR}\\*" "{v06_models}" -Force')


def main():
    parser = argparse.ArgumentParser(
        description="FLARE v0.6 — Retrain network MLP with local captured data"
    )
    parser.add_argument(
        "--local", nargs="*", default=[],
        metavar="CSV",
        help="Local labeled CSV files from capture_labeled.py "
             "(default: auto-discover local_*.csv in this directory)",
    )
    parser.add_argument(
        "--oversample", type=int, default=20,
        help="How many times to tile local ATTACK rows (default: 20). "
             "Ignored when --smote is set (SMOTE uses oversample//5 for final tiling).",
    )
    parser.add_argument(
        "--smote", action="store_true",
        help="Use SMOTE to balance minority attack types in local data before training. "
             "Requires: pip install imbalanced-learn",
    )
    parser.add_argument(
        "--smote-target", type=int, default=200,
        metavar="N",
        help="Target number of samples per attack type when using --smote (default: 200). "
             "Types already above this threshold are left as-is.",
    )
    args = parser.parse_args()

    # Auto-discover local CSVs if none specified
    if not args.local:
        args.local = [str(p) for p in sorted(HERE.glob("local_*.csv"))]
        if args.local:
            print(f"Auto-discovered local CSVs: {args.local}")
        else:
            print("No local_*.csv files found — will train on CICIDS2017 only.")
            print("Run capture_labeled.py first to generate local training data.")

    train(args)


if __name__ == "__main__":
    main()
