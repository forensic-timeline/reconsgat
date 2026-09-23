"""
process/mitre_attck.py

To map High Level Event (HLE) labels to MITRE ATT&CK techniques and tactics.
"""

import os
import re
import glob
import yaml
from neo4j import GraphDatabase


TECHNIQUE_CODE_RE = re.compile(r'^attack\.t\d+(?:\.\d+)?$', re.IGNORECASE)
TACTIC_RE = re.compile(r'^attack\.[a-z][a-z\-]*$', re.IGNORECASE)


def parse_attack_tags(tags):
    """
    Find the first technique_tactic and technique_code (in order) from the list of tags.
    """
    tactic = None
    code = None
    for tag in (tags or []):
        tag_l = str(tag).strip().lower()
        if code is None and TECHNIQUE_CODE_RE.match(tag_l):
            code = tag_l
        elif tactic is None and TACTIC_RE.match(tag_l) and not TECHNIQUE_CODE_RE.match(tag_l):
            tactic = tag_l
    return tactic, code


def load_sigma_rules(rules_dir):
    """
    Read all .yml/.yaml in rules_dir.
    """
    title_to_rule = {}
    duplicate_titles = []

    patterns = [
        os.path.join(rules_dir, "**", "*.yml"),
        os.path.join(rules_dir, "**", "*.yaml"),
    ]
    rule_files = []
    for pat in patterns:
        rule_files.extend(glob.glob(pat, recursive=True))
    rule_files = sorted(set(rule_files))

    for path in rule_files:
        try:
            with open(path, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except Exception as e:
            print(f"  WARN: failed to parse {path}: {e}")
            continue

        if not rule or "title" not in rule:
            print(f"  WARN: file without 'title', skipped: {path}")
            continue

        title = rule["title"]
        tactic, code = parse_attack_tags(rule.get("tags", []))

        if title in title_to_rule:
            duplicate_titles.append((title, path))
            continue  # retain the first rule found

        title_to_rule[title] = {
            "technique_tactic": tactic,
            "technique_code": code,
            "path": path,
        }

    print(f"Total file rule found: {len(rule_files)}")
    print(f"Total unique titles loaded: {len(title_to_rule)}")
    if duplicate_titles:
        print(f"WARN: {len(duplicate_titles)} duplicate titles found (first rule used):")
        for t, p in duplicate_titles:
            print(f"  - {t!r} also exists in {p}")

    return title_to_rule


class MitreAttck:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ──
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        # ── Folder containing rules ────
        self.RULES_DIR = "rules-sigma"

        # ── Fallback if the HLE label does not match a suitable rule ─────
        self.FALLBACK_VALUE = "-"

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        RULES_DIR = self.RULES_DIR
        FALLBACK_VALUE = self.FALLBACK_VALUE

        # ── Section 3: Load & Parse Sigma Rules ─────────────────────────────
        title_to_rule = load_sigma_rules(RULES_DIR)

        # ── Section 4: Take all HLE node from Neo4j ──────────────────────
        GET_ALL_HLE_QUERY = """
MATCH (hle:HighLevelEvent)
RETURN hle.hle_id AS hle_id, hle.label AS label
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            result = session.run(GET_ALL_HLE_QUERY)
            hle_list = [{"hle_id": r["hle_id"], "label": r["label"]} for r in result]
        driver.close()

        print(f"Total node HLE found: {len(hle_list)}")
        for hle in hle_list:
            print(f"  {hle['hle_id']:10s} | {hle['label']}")

        # ── Section 5: Match HLE Labels with Sigma Rule Titles ───────────
        unmatched_labels = set()

        for hle in hle_list:
            rule = title_to_rule.get(hle["label"])
            if rule is not None:
                hle["technique_tactic"] = rule["technique_tactic"] or FALLBACK_VALUE
                hle["technique_code"] = rule["technique_code"] or FALLBACK_VALUE
            else:
                hle["technique_tactic"] = FALLBACK_VALUE
                hle["technique_code"] = FALLBACK_VALUE
                unmatched_labels.add(hle["label"])

        print(f"Total HLE matched to rules: {len(hle_list) - sum(1 for h in hle_list if h['label'] in unmatched_labels)}")
        print(f"Total HLE without matching rules: {sum(1 for h in hle_list if h['label'] in unmatched_labels)}")
        if unmatched_labels:
            print()
            print("HLE labels that did not match any Sigma rules (check the 'title' of your rules):")
            for lbl in sorted(unmatched_labels):
                print(f"  - {lbl!r}")

        print()
        print("save technique_tactic & technique_code to HLE nodes in Neo4j...")
        for hle in hle_list:
            print(f"  {hle['hle_id']:10s} | {hle['label']:45s} | tactic={hle['technique_tactic']:22s} | code={hle['technique_code']}")

        # ── Section 6: save technique_tactic & technique_code to HLE nodes ──
        UPDATE_HLE_MITRE_QUERY = """
MATCH (hle:HighLevelEvent {hle_id: $hle_id})
SET
    hle.technique_tactic = $technique_tactic,
    hle.technique_code   = $technique_code
RETURN hle.hle_id AS updated
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        updated_count = 0

        with driver.session(database=NEO4J_DATABASE) as session:
            for hle in hle_list:
                session.run(UPDATE_HLE_MITRE_QUERY,
                    hle_id           = hle["hle_id"],
                    technique_tactic = hle["technique_tactic"],
                    technique_code   = hle["technique_code"],
                )
                updated_count += 1

        driver.close()

        print(f"Updated {updated_count} node HLE with technique_tactic & technique_code")

        # ── Section 7: Summary ───────────────────────────────────────────────
        print("=== SUMMARY ===")
        print(f"Total node HLE              : {len(hle_list)}")
        print(f"Total loaded rules          : {len(title_to_rule)}")
        print(f"HLE matched to rules        : {len(hle_list) - len(unmatched_labels)}")
        print(f"HLE without matching rules  : {len(unmatched_labels)}")
