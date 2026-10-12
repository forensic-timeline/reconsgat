"""
process/attribution_performance.py

To evaluate attackers attribution performance.
"""

import re
import pandas as pd


IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def prf(tp, fp, fn):
    p = tp/(tp+fp) if (tp+fp) else 0.0
    r = tp/(tp+fn) if (tp+fn) else 0.0
    f = 2*p*r/(p+r) if (p+r) else 0.0
    return p*100, r*100, f*100


class AttributionPerformance:
    def __init__(self, dataset):
        self.dataset = dataset

        self.GROUND_TRUTH_CSV = f"results/{dataset}/result-9-2-high-level-ground-truth-unique-datetime.csv"
        self.PREDICT_CSV      = f"results/{dataset}/result-8-4-hle-summary.csv"
        self.OUTPUT_CSV       = f"results/{dataset}/result-11-attribution-evaluation.csv"

        self.ONLY_IP_ACTORS = True

    def parse_actors(self, actor_str):
        if pd.isna(actor_str) or str(actor_str).strip() in ("", "-"):
            return set()
        parts = [x.strip() for x in str(actor_str).split("|") if x.strip()]
        if self.ONLY_IP_ACTORS:
            parts = [p for p in parts if IP_PATTERN.match(p)]
        return set(parts)

    def build_actor_map(self, df):
        """datetime -> set of actors (a union if a single datetime has multiple rows)."""
        m = {}
        for _, r in df.iterrows():
            m.setdefault(r["datetime"], set()).update(self.parse_actors(r["actor"]))
        return {k: frozenset(v) for k, v in m.items()}

    def run(self):
        dataset = self.dataset
        GROUND_TRUTH_CSV = self.GROUND_TRUTH_CSV
        PREDICT_CSV = self.PREDICT_CSV
        OUTPUT_CSV = self.OUTPUT_CSV

        # ── Section 2: Load & Parsing (set of actors per event) ──
        df_gt   = pd.read_csv(GROUND_TRUTH_CSV)
        df_pred = pd.read_csv(PREDICT_CSV)

        gt_map   = self.build_actor_map(df_gt)
        pred_map = self.build_actor_map(df_pred)

        gt_dts   = set(gt_map)
        pred_dts = set(pred_map)
        matched  = gt_dts & pred_dts

        print(f"Dataset: {dataset}")
        print(f"GT events: {len(gt_dts)} | Pred events: {len(pred_dts)} | Matched: {len(matched)}")

        # ── Section 3: Calculation (event-level, directional set match) ─
        # --- Collect matched (directional) details per event ---
        rows = []
        tp = fp = fn = 0
        for dt in sorted(matched):
            g, p = gt_map[dt], pred_map[dt]
            extra   = p - g   # wrongfully attributed actors -> FP
            missing = g - p   # missed actors    -> FN

            if not extra and not missing:
                label = "TP"
                tp += 1
            else:
                labels = []
                if extra:
                    fp += 1; labels.append("FP")
                if missing:
                    fn += 1; labels.append("FN")
                label = "+".join(labels)

            rows.append({
                "datetime": dt,
                "actor_gt":   "|".join(sorted(g)) if g else "-",
                "actor_pred": "|".join(sorted(p)) if p else "-",
                "extra_actors":   "|".join(sorted(extra))   if extra   else "-",
                "missing_actors": "|".join(sorted(missing)) if missing else "-",
                "label": label,
            })
        df_detail = pd.DataFrame(rows)

        p_c, r_c, f_c = prf(tp, fp, fn)
        acc = tp / len(matched) * 100 if matched else 0.0

        print("")
        print(f"=== ATTRIBUTION PERFORMANCE (event-level, directional) — {dataset}")
        print(f"Matched events: {len(matched)}")
        print(f"Correct (exact set match): {tp}")
        print(f"  TP={tp} FP={fp} FN={fn}")
        print(f"  Precision={p_c:.2f}%  Recall={r_c:.2f}%  F1={f_c:.2f}%")
        print(f"  Attribution accuracy (TP/matched)={acc:.2f}%")

        # ── Section 4: Event inspection with incorrect attribution ──
        wrong = df_detail[df_detail["label"] != "TP"]
        print(f"Event with incorrect attribution: {len(wrong)} dari {len(df_detail)} matched\n")
        if len(wrong):
            print(wrong[["datetime", "actor_gt", "actor_pred", "extra_actors", "missing_actors", "label"]].to_string(index=False))
        else:
            print("All matched events have correct actor attributions.")

        # summary of error types
        n_fp_only = (df_detail["label"] == "FP").sum()
        n_fn_only = (df_detail["label"] == "FN").sum()
        n_both    = (df_detail["label"] == "FP+FN").sum()
        print(f"\nFP only (wrongfully attributed): {n_fp_only} | FN only (missed actors): {n_fn_only} | FP+FN: {n_both}")

        # ── Section 5: Export ────
        df_detail.to_csv(OUTPUT_CSV, index=False)
        print(f"Detail saved: {OUTPUT_CSV} ({len(df_detail)} lines)")

        summary = pd.DataFrame([{
            "dataset": dataset,
            "matched_events": len(matched),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(p_c, 2),
            "recall":    round(r_c, 2),
            "f1":        round(f_c, 2),
            "attribution_accuracy": round(acc, 2),
        }])
        print()
        print(summary.to_string(index=False))
