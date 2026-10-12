"""
process/high_level_gt.py

To create high-level ground truth from low-level ground truth data.
"""

import csv
import sys
import pandas as pd


def count_lines(path):
    # fast line count
    cnt = 0
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for _ in f:
            cnt += 1
    return cnt


class HighLevelGroundTruth:
    def __init__(self, dataset):
        self.dataset = dataset

        # improve CSV field size limit to avoid OverflowError for large fields
        _max_int = sys.maxsize
        while True:
            try:
                csv.field_size_limit(_max_int)
                break
            except OverflowError:
                _max_int = int(_max_int / 10)

        self.CSV_INPUT = f"results/{dataset}/result-3-low-level-ground-truth.csv"
        self.CSV_OUTPUT_ALL = f"results/{dataset}/result-9-1-high-level-ground-truth.csv"
        self.CSV_OUTPUT_UNIQUE = f"results/{dataset}/result-9-2-high-level-ground-truth-unique-datetime.csv"

        # ── Toggle: duplicate actor config ─
        # True  = label and actor must same for considered consecutive duplicates (default).
        # False = The same label is sufficient (the actor is ignored during the duplicate check).
        #         The output is a list of ALL unique actors involved in a single group
        #         seperated by "|" (mis. "192.168.1.1|10.0.0.5").
        self.REQUIRE_SAME_ACTOR = False

    def run(self):
        CSV_INPUT = self.CSV_INPUT
        CSV_OUTPUT_ALL = self.CSV_OUTPUT_ALL
        CSV_OUTPUT_UNIQUE = self.CSV_OUTPUT_UNIQUE
        REQUIRE_SAME_ACTOR = self.REQUIRE_SAME_ACTOR

        # ── Section 3: Export to CSV - Phase 1: all GT (with sequential duplicate filters) ──
        total_lines = count_lines(CSV_INPUT)
        print(f"Total lines in {CSV_INPUT}: {total_lines}")
        print("")
        print("=== Phase 1: All Ground Truth Events (with sequential duplicate filters)")
        print("=== Input from labeled low-level ground truth")

        processed = 0
        written_all = 0
        skipped_benign = 0
        skipped_duplicate = 0

        current_label       = None
        current_actor        = None   # used if REQUIRE_SAME_ACTOR=True (single attacker)
        current_actors_seen  = []     # used if REQUIRE_SAME_ACTOR=False (all unique actors in the group)
        current_event_ids    = []     # all event_id (low-level) that are grouped together in the current group
        current_row          = None   # data representative (first row in the current group)

        with open(CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(CSV_OUTPUT_ALL, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)
            writer = csv.writer(out)

            # Header
            writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'ground_truth_label', 'actor', 'group_count', 'low_level_ids'])

            def flush_group():
                """Write a representative row for the currently running group (if any)."""
                nonlocal written_all
                if current_row is None:
                    return
                actor_output = current_actor if REQUIRE_SAME_ACTOR else "|".join(current_actors_seen)
                writer.writerow([
                    current_row['event_id'], current_row['datetime'], current_row['display_name'],
                    current_row['decoded'], current_label,
                    actor_output, len(current_event_ids), "|".join(current_event_ids),
                ])
                written_all += 1

            for row in reader:
                processed += 1

                # take values from columns
                event_id = row.get('event_id', '')
                datetime_val = row.get('datetime', '')
                display_name = row.get('display_name', '')
                decoded = row.get('decoded', '')
                ground_truth_label = row.get('ground_truth_label', '')
                actor = row.get('actor', '')

                # 1. skip if ground_truth_label is 'benign' (do not reset the current group)
                if ground_truth_label.lower() == 'benign':
                    skipped_benign += 1
                    continue

                same_label = ground_truth_label == current_label
                same_actor = (actor == current_actor) if REQUIRE_SAME_ACTOR else True

                if same_label and same_actor:
                    # Sequential duplicate — enter the currently running group
                    skipped_duplicate += 1
                    current_event_ids.append(event_id)
                    if not REQUIRE_SAME_ACTOR and actor and actor not in current_actors_seen:
                        current_actors_seen.append(actor)
                    continue

                # different label, or (REQUIRE_SAME_ACTOR=True AND actor is different) — flush the old group, start a new group
                flush_group()
                current_label      = ground_truth_label
                current_actor       = actor
                current_actors_seen = [actor] if actor else []
                current_event_ids   = [event_id]
                current_row = {
                    'event_id': event_id, 'datetime': datetime_val,
                    'display_name': display_name, 'decoded': decoded,
                }

                # Progress every 50.000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

            # Flush the remaining group
            flush_group()

        print(f"=== Output of Phase 1")
        print(f"Total processed: {processed} lines")
        print(f"Skipped (benign): {skipped_benign} lines")
        print(f"Skipped (duplicate label): {skipped_duplicate} lines")
        print(f"Written to {CSV_OUTPUT_ALL}: {written_all} lines")

        # ── Section 4: Export to CSV - Phase 2: Unique (Datetime, Actor) ────
        # INPUT: Output phase 1
        total_lines_v2 = count_lines(CSV_OUTPUT_ALL)
        print("")
        print("=== Phase 2: Unique Datetime (take the first event per datetime)")
        print(f"=== Input is from the Output of Phase 1: {written_all} lines")

        processed_v2 = 0
        written_unique = 0
        skipped_duplicate_datetime = 0
        seen_keys = set()  # Track (datetime, actor)

        with open(CSV_OUTPUT_ALL, newline='', encoding="utf-8", errors='replace') as f, \
             open(CSV_OUTPUT_UNIQUE, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)
            writer = csv.writer(out)

            # Header
            writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'ground_truth_label', 'actor', 'group_count', 'low_level_ids'])

            for row in reader:
                processed_v2 += 1

                # Ambil nilai kolom
                event_id = row.get('event_id', '')
                datetime_val = row.get('datetime', '')
                display_name = row.get('display_name', '')
                decoded = row.get('decoded', '')
                ground_truth_label = row.get('ground_truth_label', '')
                actor = row.get('actor', '')
                group_count = row.get('group_count', '')
                low_level_ids = row.get('low_level_ids', '')

                # Skip if datetime-actor combination already exists
                # — same datetime but different actor are still considered different events
                key = (datetime_val, actor)
                if key in seen_keys:
                    skipped_duplicate_datetime += 1
                    continue

                # Write row that passes the filter
                writer.writerow([event_id, datetime_val, display_name, decoded, ground_truth_label, actor, group_count, low_level_ids])
                written_unique += 1

                # Update tracking
                seen_keys.add(key)

                # Progress every 50.000 lines
                if processed_v2 % 50000 == 0:
                    print(f"Processed {processed_v2}/{total_lines_v2} lines ({processed_v2/total_lines_v2:.2%})")
        print(f"=== Output of Phase 2")
        print(f"Total processed: {processed_v2} lines")
        print(f"Skipped (duplicate datetime): {skipped_duplicate_datetime} lines")
        print(f"Written to {CSV_OUTPUT_UNIQUE}: {written_unique} lines")

        # ── Section 5: Summary Comparison ───────────────────────────────────
        print("")
        print("=== FINAL SUMMARY - COMPARISON")
        print(f"Output of Phase 1 (All GT):                      {written_all} events")
        print(f"Output of Phase 2 (Unique Datetime):             {written_unique} events")
