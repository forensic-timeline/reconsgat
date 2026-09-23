"""
process/log_to_graph.py

To map CSV log data to a graph database (Neo4j) 
using extraction templates (YAML).
"""

import csv
import re
import sys
from datetime import datetime
from pathlib import Path

# Add path rules-graph so graph_extractor.py can be imported
sys.path.insert(0, "rules-graph")

from graph_extractor import GraphExtractor


def count_lines(path):
    # fast line count
    cnt = 0
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for _ in f:
            cnt += 1
    return cnt


def detect_log_type(desc: str, filename: str):
    if 'access.log' in filename:
        return 'access.log'
    elif 'syslog' in filename:
        return 'syslog'
    elif 'auth.log' in filename:
        return 'auth.log'
    return 'unknown'


def parse_label_predict(label_predict: str):
    """
    Parse label_predict menjadi label dan severity.
    Format: "Label Name[severity]" atau "benign"
    """
    label_predict = label_predict.strip()
    if label_predict.lower() == 'benign':
        return 'benign', 'benign'
    match = re.search(r'^(.+?)\[(\w+)\]$', label_predict)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    return label_predict, 'unknown'


def parse_timestamp(ts_str: str) -> datetime:
    """
    Parse timestamp dari CSV.
    Format: 2022-01-18T12:38:01+00:01
    """
    try:
        # Handle format with timezone offset like +00:01
        # Try parsing directly
        return datetime.fromisoformat(ts_str)
    except ValueError:
        try:
            # Fallback: parse without timezone
            ts_clean = ts_str.split('+')[0].split('-')[0:3]
            ts_clean = '-'.join(ts_clean[:3]) + ts_str[10:19]  # Ambil date + time
            return datetime.fromisoformat(ts_str[:19])
        except:
            # Last resort: return current time
            return datetime.now()


class LogToGraph:
    def __init__(self, dataset):
        self.dataset = dataset

        self.CSV_INPUT = f"results/{dataset}/result-4-low-level-predict.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-6-grap-errors-if-any.csv"
        self.IMPORT_OUTPUT = f"results/{dataset}/result-6-import-result.txt"

        # setting neo4j
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        # ── Toggle: is all 'benign' also imported into the graph? ──
        # False (default) = non-benign only (fast, smaller graph)
        # True            = All rows are imported (larger graph)
        self.INCLUDE_BENIGN = True

        # CSV Column indices
        self.COL_EVENT_ID = 0
        self.COL_TIMESTAMP = 1   # timestamp column
        self.COL_DESC = 11       # desc column (log content)
        self.COL_FILENAME = 7   # filename column (to detect log type)
        self.COL_LABEL = 13      # label_predict column
        self.COL_SOURCE_FILE = 7  # display_name column

        self.TEMPLATES_DIR = "rules-graph"

    def run(self):
        # ── Extraction Templates (YAML) — show the template ─
        for f in sorted(Path(self.TEMPLATES_DIR).glob("*.yaml")):
            print(f"  {f.name}")

        # ── Initialize GraphExtractor — read all YAML from rules-graph/ ────
        extractor = GraphExtractor(
            templates_dir=self.TEMPLATES_DIR,
            neo4j_uri=self.NEO4J_URI,
            neo4j_user=self.NEO4J_USER,
            neo4j_password=self.NEO4J_PASSWORD,
            neo4j_database=self.NEO4J_DATABASE,
            include_benign=self.INCLUDE_BENIGN,
        )

        # ── make constraint so all MERGE (Page, User, IPAddress) are fast
        ENSURE_CONSTRAINTS = [
            ("page_path_unique",  "CREATE CONSTRAINT page_path_unique IF NOT EXISTS FOR (p:Page) REQUIRE p.path IS UNIQUE"),
            ("user_username_unique", "CREATE CONSTRAINT user_username_unique IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE"),
            ("ip_address_unique", "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.ip IS UNIQUE"),
        ]

        with extractor.driver.session(database=self.NEO4J_DATABASE) as _s:
            for name, stmt in ENSURE_CONSTRAINTS:
                _s.run(stmt)
                print(f"Constraint {name} created (or already exists)")

        # count total lines
        total_lines = sum(1 for _ in open(self.CSV_INPUT, encoding='utf-8', errors='replace')) - 1
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")

        # ── CSV Column to Graph Mapping Process ──────────────────────────────
        # Load username cache from Neo4j (for matching in Pass 2)
        extractor.load_username_cache()
        print(f"Ready to process {total_lines} rows")

        # ========== Phase 1: syslog dan auth.log ==========
        print("=== Phase 1: Processing syslog and auth.log ===")

        processed = 0
        inserted  = 0
        skipped   = 0
        errors    = 0

        with open(self.CSV_INPUT, newline='', encoding='utf-8', errors='replace') as f:
            reader    = csv.reader(f)
            first_row = True

            for row in reader:
                if first_row:
                    first_row = False
                    continue
                if len(row) < 14:  # according to the actor column
                    continue

                filename = row[7]
                parser   = row[6]

                # Pass 1: skip access.log
                is_access = any(x in filename.lower() for x in ['access.log', 'access_log'])
                is_access = is_access or parser == 'text/apache_access'
                if is_access:
                    skipped += 1
                    continue

                processed += 1
                try:
                    extractor.process_row(row)
                    inserted += 1
                except Exception as e:
                    errors += 1
                    print(f"  ERROR event_id={row[0]}: {e}")
                    print(f"    line: {row[11][:80]}")  # column "decoded"

                if processed % 500 == 0:
                    print(f"  Phase 1: {processed} processed, {inserted} inserted, "
                          f"{errors} errors")

        print(f"\nPhase 1 done: {processed} processed, {inserted} inserted, "
              f"{skipped} skipped (access.log), {errors} errors")

        # Reload cache after Pass 1
        extractor.load_username_cache()

        # ========== Phase 2: access.log ==========
        print("=== Phase 2: Processing access.log - error.log ===")

        processed2 = 0
        inserted2  = 0
        errors2    = 0

        with open(self.CSV_INPUT, newline='', encoding='utf-8', errors='replace') as f:
            reader    = csv.reader(f)
            first_row = True

            for row in reader:
                if first_row:
                    first_row = False
                    continue
                if len(row) < 14:  # according to the actor column
                    continue

                filename = row[7]
                parser   = row[6]

                # Pass 2: only access.log and error.log
                is_access = any(x in filename.lower() for x in ['access.log', 'access_log', 'error.log', 'errro_log'])
                is_access = is_access or parser == 'text/apache_access'
                if not is_access:
                    continue

                processed2 += 1
                try:
                    extractor.process_row(row)
                    inserted2 += 1
                except Exception as e:
                    errors2 += 1
                    print(f"  ERROR event_id={row[0]}: {e}")
                    print(f"    line: {row[11][:80]}")  # column "decoded"

                if processed2 % 500 == 0:
                    print(f"  Phase 2: {processed2} processed, {inserted2} inserted, "
                          f"{errors2} errors")

        print(f"\nPhase 2 done: {processed2} processed, {inserted2} inserted, "
              f"{errors2} errors")

        extractor.close()
        print("Driver closed.")

        # ========== SUMMARY ==========
        summary_lines = [
            "=== FINAL SUMMARY ===",
            f"Total lines processed : {total_lines}",
            f"Total inserted        : {inserted + inserted2}",
            f"  - syslog + auth log : {inserted}",
            f"  - access + error log: {inserted2}",
            f"Total errors          : {errors + errors2}",
            f"  - syslog + auth log : {errors}",
            f"  - access + error log: {errors2}",
            f"Username cache size   : {len(extractor._username_cache)}",
            "",
            "Done!",
        ]

        summary_text = "\n".join(summary_lines)
        print("\n" + summary_text)

        with open(self.IMPORT_OUTPUT, "w", encoding="utf-8") as f:
            f.write(summary_text + "\n")

        print(f"\nSummary saved to: {self.IMPORT_OUTPUT}")
