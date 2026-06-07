#!/usr/bin/env python3
# Diagnostic: score every row in net_flows.csv and show P(ATTACK) distribution.
import json, sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

MODEL_DIR  = Path(__file__).parent / "models"
CSV_PATH   = Path(__file__).parent.parent / "net_flows.csv"

mlp    = joblib.load(MODEL_DIR / "network_mlp.pkl")
scaler = joblib.load(MODEL_DIR / "network_scaler.pkl")
with open(MODEL_DIR / "feature_names.json") as f:
    features = json.load(f)

print(f"Model features : {len(features)}")
print(f"CSV            : {CSV_PATH}")

df = pd.read_csv(CSV_PATH)
print(f"CSV rows       : {len(df)}")
print(f"CSV columns    : {len(df.columns)}")
print(f"CSV header     : {list(df.columns[:6])} ... (first 6 shown)")

# Check which of our 4 new features are actually in the CSV
new_cols = ["FwdPacketsPerSec", "BwdPacketsPerSec", "MinPacketLength", "MaxPacketLength"]
for col in new_cols:
    if col in df.columns:
        print(f"  {col}: present  mean={df[col].mean():.4f}  max={df[col].max():.4f}")
    else:
        print(f"  {col}: MISSING from CSV!")

# Fill missing feature columns with 0
for col in features:
    if col not in df.columns:
        df[col] = 0

X = df[features].copy()
X = X.apply(pd.to_numeric, errors="coerce")
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(0, inplace=True)

# Drop all-zero rows
nonzero = (X.values != 0).any(axis=1)
X_clean = X[nonzero]
df_clean = df[nonzero].reset_index(drop=True)
print(f"\nNon-zero rows  : {len(X_clean)}  (dropped {(~nonzero).sum()} all-zero rows)")

X_sc  = scaler.transform(X_clean.values)
probs = mlp.predict_proba(X_sc)[:, 0]   # P(ATTACK)

print(f"\n── P(ATTACK) distribution ───────────────────────────────")
for t in [0.95, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05]:
    n = int((probs >= t).sum())
    bar = "█" * min(n // 10, 50)
    print(f"  >= {t:.2f}  {n:6d}  {bar}")

print(f"\n── Top 15 rows by P(ATTACK) ─────────────────────────────")
top_idx = np.argsort(probs)[-15:][::-1]
print(f"{'P(ATK)':>8}  {'DPort':>6}  {'DurMs':>10}  {'FwdPkts':>7}  {'BwdPPS':>8}  {'BytPS':>10}  {'MinPkt':>6}  {'FINcnt':>6}")
for i in top_idx:
    row = df_clean.iloc[i]
    print(
        f"  {probs[i]:.4f}  "
        f"{row.get('DestinationPort', 0):>6.0f}  "
        f"{row.get('FlowDurationMs', 0):>10.1f}  "
        f"{row.get('TotalFwdPackets', 0):>7.0f}  "
        f"{row.get('BwdPacketsPerSec', 0):>8.2f}  "
        f"{row.get('FlowBytesPerSec', 0):>10.1f}  "
        f"{row.get('MinPacketLength', 0):>6.0f}  "
        f"{row.get('FINFlagCount', 0):>6.0f}"
    )

# Show typical port scan flow sample
print(f"\n── Sample short-duration flows (DurMs < 1000) ───────────")
short = df_clean[df_clean["FlowDurationMs"] < 1000].head(10)
if short.empty:
    print("  (none found — port scan flows may not be in CSV yet)")
else:
    for idx, row in short.iterrows():
        p = probs[idx]
        print(
            f"  P={p:.4f}  port={row.get('DestinationPort',0):.0f}  "
            f"dur={row.get('FlowDurationMs',0):.1f}ms  "
            f"fwd={row.get('TotalFwdPackets',0):.0f}pkts  "
            f"bwdPPS={row.get('BwdPacketsPerSec',0):.1f}  "
            f"FIN={row.get('FINFlagCount',0):.0f}  "
            f"minPkt={row.get('MinPacketLength',0):.0f}"
        )
