"""
process/eval_high_level_performance.py

To evaluate high-level performance.
"""

import csv
import sys
import pandas as pd


def normalize_actor(actor_str):
    """
    Normalize actor string by sorting the values.
    """
    if pd.isna(actor_str) or actor_str == '':
        return actor_str
    return "|".join(sorted(str(actor_str).split("|")))


def count_low_level_val(csv_path):
    """
    count low-level value (non-benign) from the timeline.
    """
    _max_int = sys.maxsize
    while True:
        try:
            csv.field_size_limit(_max_int)
            break
        except OverflowError:
            _max_int = int(_max_int / 10)
 
    non_benign = 0
    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('ground_truth_label', '').strip().lower() != 'benign':
                non_benign += 1
 
    return non_benign

class HighLevelPerformance:
    def __init__(self, dataset):
        self.dataset = dataset

        self.GROUND_TRUTH_CSV = f"results/{dataset}/result-9-2-high-level-ground-truth-unique-datetime.csv"
        self.PREDICT_CSV = f"results/{dataset}/result-8-4-hle-summary.csv"
        self.OUTPUT_CSV = f"results/{dataset}/result-10-high-level-evaluation-datetime.csv"

        # ── Toggle: actor matching consideration ─
        # True  = An event is considered a match if the datetime and the actor (its set) are identical (default).
        # False = The actor is completely ignored—the same datetime is sufficient to count as a match.
        self.REQUIRE_SAME_ACTOR = False

    def run(self):
        GROUND_TRUTH_CSV = self.GROUND_TRUTH_CSV
        PREDICT_CSV = self.PREDICT_CSV
        OUTPUT_CSV = self.OUTPUT_CSV
        REQUIRE_SAME_ACTOR = self.REQUIRE_SAME_ACTOR

        # ── Section 2: Load Data ─────────────────────────────────────────────
        df_gt = pd.read_csv(GROUND_TRUTH_CSV)
        df_pred = pd.read_csv(PREDICT_CSV)

        # asset for performance metric
        n_val = df_gt[['datetime', 'actor']].drop_duplicates().shape[0] 

        print(f"Ground Truth: {len(df_gt)} rows")
        print(f"Ground Truth unique datetime: {df_gt['datetime'].nunique()}")
        print(f"Ground Truth unique (datetime, actor): {df_gt[['datetime', 'actor']].drop_duplicates().shape[0]}")
        print()
        print(f"Predict: {len(df_pred)} rows")
        print(f"Predict unique datetime: {df_pred['datetime'].nunique()}")
        print(f"Predict unique (datetime, actor): {df_pred[['datetime', 'actor']].drop_duplicates().shape[0]}")

        # ── Section 3: count Confusion Matrix (Datetime Matching) ──────────
        df_gt['actor_norm']   = df_gt['actor'].apply(normalize_actor)
        df_pred['actor_norm'] = df_pred['actor'].apply(normalize_actor)

        # match_key = actor_norm if REQUIRE_SAME_ACTOR=True,
        # or REQUIRE_SAME_ACTOR=False (Actor ignored — the datetime alone determines the match).
        if REQUIRE_SAME_ACTOR:
            df_gt['match_key']   = df_gt['actor_norm']
            df_pred['match_key'] = df_pred['actor_norm']
        else:
            df_gt['match_key']   = '__any_actor__'
            df_pred['match_key'] = '__any_actor__'

        # use SET from combination (datetime, match_key).
        gt_key_set   = set(zip(df_gt['datetime'],   df_gt['match_key']))
        pred_key_set = set(zip(df_pred['datetime'], df_pred['match_key']))

        # count TP, FN, FP
        tp_key_set = gt_key_set & pred_key_set
        fn_key_set = gt_key_set - pred_key_set
        fp_key_set = pred_key_set - gt_key_set

        TP = len(tp_key_set)
        FN = len(fn_key_set)
        FP = len(fp_key_set)

        # count metrics
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) if (TP + FN) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        corr_val = TP

        print()
        print(f"=== MATRIX")
        print(f"True Positive (TP):  {TP:5d}")
        print(f"False Negative (FN): {FN:5d}")
        print(f"False Positive (FP): {FP:5d}")
        print()
        print("=== METRICS:")
        print(f"Precision: {precision:.3f}")
        print(f"Recall:    {recall:.3f}")
        print(f"F1-Score:  {f1_score:.3f}")

        print()
        print("=== PERFORMANCE RAW VALUES:")
        print(f"n Value: {n_val}")
        print(f"corr Value:    {corr_val}")

        low_level_val = count_low_level_val(f"results/{self.dataset}/result-3-low-level-ground-truth.csv")

        print()
        print("=== DR AND RR PERFORMANCE:")
        print(f"Detection Rate: {corr_val/len(df_gt):.3f}")
        print(f"Reduction Rate:    {1-(n_val/low_level_val):.3f}")

        # ── Section 4: Export to csv ──
        df_export = df_gt.drop_duplicates(subset=['datetime', 'match_key'], keep='first').copy().reset_index(drop=True)

        # Initialize prediction columns
        df_export['label_predict'] = '-'
        df_export['group_count'] = pd.Series(['-'] * len(df_export), dtype=object)
        df_export['low_event_ids'] = pd.Series(['-'] * len(df_export), dtype=object)
        df_export['status'] = 'FN'  # default

        # for TP, take info from matched df_pred (datetime, actor)
        for dt, match_key in tp_key_set:
            # Get GT rows with (datetime, match_key)
            gt_mask = (df_export['datetime'] == dt) & (df_export['match_key'] == match_key)

            # Get Pred rows with (datetime, match_key)
            pred_rows = df_pred[(df_pred['datetime'] == dt) & (df_pred['match_key'] == match_key)]

            if len(pred_rows) > 0:
                # take the first row from the predictions (if there are multiple, take the first)
                pred_row = pred_rows.iloc[0]

                # Set status TP
                df_export.loc[gt_mask, 'status'] = 'TP'

                # Fill prediction columns
                df_export.loc[gt_mask, 'label_predict'] = pred_row['label_predict']
                df_export.loc[gt_mask, 'group_count'] = pred_row['group_count']
                df_export.loc[gt_mask, 'low_event_ids'] = pred_row['low_event_ids']

        # Add FP rows dari Predict — (datetime, actor) predict that not in GT
        pred_keys = list(zip(df_pred['datetime'], df_pred['match_key']))
        is_fp = [k in fp_key_set for k in pred_keys]
        df_pred_fp = df_pred[is_fp].copy()
        df_pred_fp['ground_truth_label'] = '-'
        df_pred_fp['status'] = 'FP'

        # Ensure consistent column order
        columns_order = ['event_id', 'datetime', 'actor', 'display_name', 'decoded',
                         'ground_truth_label',
                         'label_predict', 'group_count',
                         'low_event_ids', 'status']

        df_export = df_export[columns_order]
        df_pred_fp = df_pred_fp[columns_order]

        # Combine GT dan FP
        df_final = pd.concat([df_export, df_pred_fp], ignore_index=True)

        # Sort by datetime
        df_final = df_final.sort_values('datetime').reset_index(drop=True)

        # Save
        df_final.to_csv(OUTPUT_CSV, index=False)

        print(f"\nExport done! File saved at: {OUTPUT_CSV}")
        print(f"Total {len(df_final)} rows exported.")
