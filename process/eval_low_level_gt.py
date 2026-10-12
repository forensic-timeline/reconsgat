"""
process/eval_low_level_gt.py

To label the log in timeline with ground truth labels 
based on ground truth rules.
"""

import csv
import yaml
import os


class LowLevelGroundTruth:
    def __init__(self, dataset):
        self.dataset = dataset

        self.CSV_INPUT = f"results/{dataset}/result-2-log-decoded.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-3-low-level-ground-truth.csv"

        # Path to YAML ground truth labeling rules
        self.RULES_FILE = f"rules-ground-truth/{dataset}.yaml"

    def count_lines(self, path):
        # fast line count
        cnt = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for _ in f:
                cnt += 1
        return cnt

    def load_rules_from_yaml(self, yaml_path):
        """
        Load ground truth labeling rules dari file YAML.
        """
        if not os.path.exists(yaml_path):
            print(f"File {yaml_path} NOT FOUND — rules passed (0 rules).")
            return []

        with open(yaml_path, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)

        if rules is None or not isinstance(rules, list):
            print(f"File {yaml_path} exists but is empty/invalid — rules skipped (0 rules).")
            return []

        print(f"Loaded {len(rules)} rules from {yaml_path}")
        return rules

    def match_pattern_strict(self, text, pattern):
        """
        Match pattern with strict mode (case-sensitive, respects % wildcards).
        """
        # Check wildcard positions
        starts_with_wildcard = pattern.startswith('%')
        ends_with_wildcard = pattern.endswith('%')

        # Remove wildcards
        clean_pattern = pattern.strip('%')

        # Apply matching logic based on wildcards
        if starts_with_wildcard and ends_with_wildcard:
            # %pattern% - can appear anywhere
            return clean_pattern in text
        elif starts_with_wildcard:
            # %pattern - must be at end
            return text.endswith(clean_pattern)
        elif ends_with_wildcard:
            # pattern% - must be at start
            return text.startswith(clean_pattern)
        else:
            # pattern - exact match
            return clean_pattern == text

    def match_pattern_moderate(self, text, pattern):
        """
        Match pattern with moderate mode (case-insensitive, anywhere).
        """
        text_lower = text.lower()
        pattern_lower = str(pattern).lower()
        return pattern_lower in text_lower

    def match_filters(self, text, filters, sensitivity='moderate'):
        """
        Match all filter patterns to text (AND condition).
        """
        for pattern in filters:
            pattern_str = str(pattern)

            if sensitivity == 'strict':
                # Strict mode: case-sensitive, respect % wildcards
                if not self.match_pattern_strict(text, pattern_str):
                    return False
            else:
                # Moderate mode: case-insensitive, anywhere
                if not self.match_pattern_moderate(text, pattern_str):
                    return False

        return True

    def get_labels(self, text, rules):
        """
        Get labels based on text and rules.
        """
        for rule in rules:
            filters = rule.get('filter', [])
            sensitivity = rule.get('sensitivity', 'moderate')  # Default: moderate

            if self.match_filters(text, filters, sensitivity):
                return rule['ground_truth_label']

        # Default if none match
        return 'benign'

    def run(self):
        CSV_INPUT = self.CSV_INPUT
        CSV_OUTPUT = self.CSV_OUTPUT
        RULES_FILE = self.RULES_FILE

        # ── Section 3: Load Labelling Rules from YAML ──
        labelling_rules = self.load_rules_from_yaml(RULES_FILE)

        # Preview several rules
        # if not labelling_rules:
        #     print("No main-attack rules loaded (0 rules) — all rows will fallback to 'benign'.")
        # else:
        #     for rule in labelling_rules[:3]:
        #         print(f"Rule: {rule['id']}")
        #         print(f"  Ground Truth: {rule['ground_truth_label']}")
        #         print(f"  Filters:      {rule['filter']}")
        #         print()

        # ── Section 5: Labeling execution ──
        total_lines = self.count_lines(CSV_INPUT)
        print(f"Total lines in {CSV_INPUT}: {total_lines}")

        processed = 0
        labeled_count = 0

        with open(CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(CSV_OUTPUT, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)

            # add new column
            fieldnames = reader.fieldnames + ["ground_truth_label"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                processed += 1

                # take decoded column for matching
                decoded = row.get("decoded", "")

                # Get labels based on pattern matching
                ground_truth_label = self.get_labels(decoded, labelling_rules)

                row["ground_truth_label"] = ground_truth_label

                if ground_truth_label != 'benign':
                    labeled_count += 1

                writer.writerow(row)

                # Progress each 50.000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

        print(f"\nLabeling finished: {processed}/{total_lines} lines processed.")
        print(f"Total labeled (non-benign): {labeled_count}")
        print(f"Total benign: {processed - labeled_count}")
