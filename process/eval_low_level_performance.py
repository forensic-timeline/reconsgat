"""
process/low_level_evaluation.py

To evaluate low-level predictions against ground truth labels.
"""

import csv
import re


def count_lines(path):
    """Fast line count"""
    cnt = 0
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for _ in f:
            cnt += 1
    return cnt


def remove_severity(value):
    """
    Removes severity level from a string.
    Example: 'Rule Name[high]' -> 'Rule Name'
    """
    if not value:
        return value
    # Remove pattern [severity] at the end of the string
    return re.sub(r'\[(critical|high|medium|low)\]$', '', value).strip()


class LowLevelEvaluation:
    def __init__(self, dataset):
        self.dataset = dataset

        self.CSV_GROUND_TRUTH = f"results/{dataset}/result-3-low-level-ground-truth.csv"
        self.CSV_LABEL_PREDICT = f"results/{dataset}/result-4-low-level-predict.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-5-low-level-evaluation.csv"

    def run(self):
        CSV_GROUND_TRUTH = self.CSV_GROUND_TRUTH
        CSV_LABEL_PREDICT = self.CSV_LABEL_PREDICT
        CSV_OUTPUT = self.CSV_OUTPUT

        # ── Section 5: Load dan Merge Data based on event_id ──
        print("Loading ground truth labels...")
        ground_truth_dict = {}
        gt_count = 0

        with open(CSV_GROUND_TRUTH, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                event_id = row.get('event_id', '')
                ground_truth_label = row.get('ground_truth_label', '')
                ground_truth_dict[event_id] = ground_truth_label
                gt_count += 1

                if gt_count % 100000 == 0:
                    print(f"  Loaded {gt_count:,} ground truth labels...")

        print(f"✓ Loaded {gt_count:,} ground truth labels")
        print()

        # ── Section 6: Evaluation and Export to CSV ───────────────────────────
        print("Starting evaluation and merge process...")
        print()

        total_lines = count_lines(CSV_LABEL_PREDICT)
        print(f"Total lines in {CSV_LABEL_PREDICT}: {total_lines:,}")
        print()

        processed = 0
        matched = 0
        unmatched = 0

        # Confusion Matrix counters
        TP = 0
        TN = 0
        FP = 0
        FN = 0

        with open(CSV_LABEL_PREDICT, 'r', encoding='utf-8', errors='replace') as f_predict, \
             open(CSV_OUTPUT, 'w', newline='', encoding='utf-8') as f_out:

            reader = csv.DictReader(f_predict)

            # Add ground_truth_label and status columns
            fieldnames = reader.fieldnames[:]

            # Check if ground_truth_label already exists
            if 'ground_truth_label' not in fieldnames:
                # Insert ground_truth_label after decoded
                if 'decoded' in fieldnames:
                    idx = fieldnames.index('decoded') + 1
                    fieldnames.insert(idx, 'ground_truth_label')
                else:
                    fieldnames.append('ground_truth_label')

            # Add status column at the end
            if 'status' not in fieldnames:
                fieldnames.append('status')

            writer = csv.DictWriter(f_out, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                processed += 1

                event_id = row.get('event_id', '')
                label_predict = row.get('label_predict', '')
                label_predict_clean = remove_severity(label_predict)

                # Find ground_truth_label from the dictionary
                ground_truth_label = ground_truth_dict.get(event_id, '')

                if ground_truth_label:
                    matched += 1
                else:
                    unmatched += 1

                # Add ground_truth_label to the row
                row['ground_truth_label'] = ground_truth_label

                # Determine status
                label_is_benign = (ground_truth_label == 'benign')
                predict_is_benign = (label_predict_clean == 'benign')

                if ground_truth_label == '':  # If no ground truth available
                    status = 'UNKNOWN'
                elif label_is_benign and predict_is_benign:
                    TN += 1
                    status = 'TN'
                elif label_is_benign and not predict_is_benign:
                    FP += 1
                    status = 'FP'
                elif not label_is_benign and predict_is_benign:
                    FN += 1
                    status = 'FN'
                else:
                    # neither is benign (attack)
                    TP += 1
                    status = 'TP'

                row['status'] = status

                writer.writerow(row)

                # Progress tiap 50.000 baris
                if processed % 50000 == 0:
                    print(f"Processed {processed:,}/{total_lines:,} lines ({processed/total_lines:.2%})")

        print(f"\nEvaluation finished: {processed:,}/{total_lines:,} lines processed.")
        print(f"Matched events: {matched:,}")
        print(f"Unmatched events: {unmatched:,}")
        print()
        print(f"Output saved to: {CSV_OUTPUT}")

        # ── Section 7: Show Summary and Metrics ────────────────────────
        print("=== SUMMARY ===")
        print(f"Total rows processed: {processed:,}")
        print(f"Matched events:       {matched:,}")
        print(f"Unmatched events:     {unmatched:,}")
        print()
        print(f"  True Positive  (TP): {TP}")
        print(f"  True Negative  (TN): {TN}")
        print(f"  False Positive (FP): {FP}")
        print(f"  False Negative (FN): {FN}")
        print()

        # Metrics (only for matched data)
        total_evaluated = TP + TN + FP + FN

        if total_evaluated > 0:
            accuracy = (TP + TN) / total_evaluated * 100
            precision = TP / (TP + FP) * 100 if (TP + FP) > 0 else 0
            recall = TP / (TP + FN) * 100 if (TP + FN) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            print("=== METRICS ===")
            print(f"  Evaluated events: {total_evaluated:,}")
            print()
            print(f"  Accuracy:  {accuracy:.2f}%  (TP + TN) / Total")
            print(f"  Precision: {precision:.2f}%  TP / (TP + FP)")
            print(f"  Recall:    {recall:.2f}%  TP / (TP + FN)")
            print(f"  F1-Score:  {f1_score:.2f}%  2 * (Precision * Recall) / (Precision + Recall)")
        else:
            print("⚠ No events could be evaluated (no matched ground truth labels)")