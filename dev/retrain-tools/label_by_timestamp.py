#!/usr/bin/env python3
"""
FLARE v0.6 -- Label flows by ground-truth timestamp
=====================================================
Cross-references the timestamped capture CSV from capture_labeled_v2.py
against the ground-truth log from attack_sim_v3.py to assign a label to
every flow based on which attack phase was active when it was written.

Buffer zones (NEW):
    CICFlowMeter uses a 15-second flow timeout: a flow's last packet may
    arrive during an attack phase but the flow is only FLUSHED (written
    to disk) up to 20 seconds later.  Without buffering, those residual
    attack flows land in the quiet period and get labeled BENIGN —
    corrupting the benign training class.

    --post-buffer (default 25s): flows written within N seconds AFTER a
        PHASE_END are discarded (neither attack nor benign).
    --pre-buffer  (default 5s):  flows written within N seconds BEFORE a
        PHASE_START are discarded (avoid cross-phase bleeding).

    Any flow that falls in a discard zone is dropped from the output CSV.
    Remaining flows outside all windows are clean BENIGN.

Usage:
    python label_by_timestamp.py \\
        --capture local_v3_full.csv \\
        --ground-truth attack_ground_truth.csv \\
        --output local_labeled_clean.csv

    # Wider buffers if attacks used longer quiet gaps:
    python label_by_timestamp.py ... --post-buffer 30 --pre-buffer 10
"""

import argparse
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).parent


def load_ground_truth(path: Path) -> list[tuple[int, int, str]]:
    """
    Parse ground_truth.csv into a list of (start_us, end_us, label) windows.
    Unclosed phases (PHASE_START with no matching PHASE_END — e.g. script
    interrupted) are silently ignored: those flows will be discarded via the
    pre-buffer of the next phase, or remain unlabeled at end-of-capture.
    """
    df = pd.read_csv(path)
    windows = []
    active  = {}  # attack_type -> start_us

    for _, row in df.iterrows():
        event       = row["event"]
        attack_type = row["attack_type"]
        ts_us       = int(row["unix_us"])

        if event == "PHASE_START":
            active[attack_type] = ts_us
        elif event == "PHASE_END" and attack_type in active:
            windows.append((active.pop(attack_type), ts_us, attack_type))

    return windows


def label_flow(
    ts_us: int,
    windows: list[tuple[int, int, str]],
    post_buf_us: int,
    pre_buf_us:  int,
) -> str:
    """
    Returns the label for a flow written at ts_us:
      - attack label  : flow falls inside an attack window
      - "BENIGN"      : flow is outside all windows AND all buffer zones
      - "DISCARD"     : flow falls in a buffer zone (pre or post phase)
    """
    # Check attack windows first
    for start, end, label in windows:
        if start <= ts_us <= end:
            return label

    # Check buffer zones
    for start, end, label in windows:
        # Post-phase buffer: within post_buf_us after PHASE_END
        if end < ts_us <= end + post_buf_us:
            return "DISCARD"
        # Pre-phase buffer: within pre_buf_us before PHASE_START
        if start - pre_buf_us <= ts_us < start:
            return "DISCARD"

    return "BENIGN"


def main():
    parser = argparse.ArgumentParser(
        description="Label timestamped capture CSV using ground-truth attack log"
    )
    parser.add_argument("--capture",      required=True,
                        help="Timestamped CSV from capture_labeled_v2.py")
    parser.add_argument("--ground-truth", required=True,
                        help="Ground-truth CSV from attack_sim_v3.py")
    parser.add_argument("--output",       required=True,
                        help="Output labeled CSV for train_v06.py")
    parser.add_argument("--post-buffer",  type=float, default=25.0, metavar="SEC",
                        help="Seconds to discard after each PHASE_END (default: 25). "
                             "Covers CICFlowMeter 15s flow timeout + flush interval.")
    parser.add_argument("--pre-buffer",   type=float, default=5.0, metavar="SEC",
                        help="Seconds to discard before each PHASE_START (default: 5).")
    args = parser.parse_args()

    cap_path     = Path(args.capture)
    gt_path      = Path(args.ground_truth)
    out_path     = Path(args.output)
    post_buf_us  = int(args.post_buffer * 1_000_000)
    pre_buf_us   = int(args.pre_buffer  * 1_000_000)

    if not cap_path.exists():
        print(f"ERROR: capture file not found: {cap_path}")
        sys.exit(1)
    if not gt_path.exists():
        print(f"ERROR: ground-truth file not found: {gt_path}")
        sys.exit(1)

    print(f"Loading ground truth: {gt_path}")
    windows = load_ground_truth(gt_path)
    print(f"  {len(windows)} attack phases loaded:")
    for start, end, label in windows:
        duration = (end - start) / 1_000_000
        print(f"    {label:<20}  {duration:.1f}s window")

    print(f"\nBuffer zones: post-phase={args.post_buffer:.0f}s  "
          f"pre-phase={args.pre_buffer:.0f}s")

    print(f"\nLoading capture: {cap_path}")
    df = pd.read_csv(cap_path)
    print(f"  {len(df):,} flows")

    if "FlowTimestamp" not in df.columns:
        print("ERROR: FlowTimestamp column missing — use capture_labeled_v2.py")
        sys.exit(1)

    print("\nLabeling flows by timestamp...")
    df["Label"] = df["FlowTimestamp"].apply(
        lambda t: label_flow(int(t), windows, post_buf_us, pre_buf_us)
    )

    n_discard = (df["Label"] == "DISCARD").sum()
    df_clean  = df[df["Label"] != "DISCARD"].copy()

    counts = df_clean["Label"].value_counts()
    total  = len(df_clean)
    print(f"\n  Discarded (buffer zone): {n_discard:,} flows")
    print(f"  Kept:                    {total:,} flows")
    print("\nLabel distribution (kept flows):")
    for lbl, n in counts.items():
        bar = "#" * min(int(n / total * 40), 40)
        pct = n / total * 100
        print(f"  {lbl:<22} {n:>6,}  ({pct:.1f}%)  {bar}")

    # Drop FlowTimestamp — train_v06.py expects 38 FLARE features + Label only
    df_out = df_clean.drop(columns=["FlowTimestamp"])
    df_out.to_csv(out_path, index=False)
    print(f"\nSaved {len(df_out):,} labeled rows -> {out_path}")
    print(f"\nNext: python train_v06.py --local {out_path.name} --threshold 0.65")


if __name__ == "__main__":
    main()
