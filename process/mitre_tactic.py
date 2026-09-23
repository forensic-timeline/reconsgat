"""
process/mitre_tactic.py

To create AttackTactic nodes based on AttackTechnique nodes.
"""

from collections import defaultdict
from neo4j import GraphDatabase


def canonicalize_tactic_label(raw_tactic):
    """
    'attack.execution' -> 'Execution'
    'attack.privilege-escalation' -> 'Privilege Escalation'
    'attack.command-and-control' -> 'Command And Control'
    """
    if not raw_tactic:
        return None
    tactic = raw_tactic.strip()
    if tactic.lower().startswith("attack."):
        tactic = tactic[len("attack."):]
    words = tactic.split("-")
    return " ".join(w.capitalize() for w in words)


class MitreTactic:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ───
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        self.EXCLUDE_TACTIC_VALUES = {None, "", "-"}

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        EXCLUDE_TACTIC_VALUES = self.EXCLUDE_TACTIC_VALUES

        # ── Section 3: take all AttackTechnique node from Neo4j ───
        GET_ALL_ATTACK_TECHNIQUE_QUERY = """
MATCH (at:AttackTechnique)
RETURN at.label AS label, at.technique_tactic AS technique_tactic, at.timestamp AS timestamp
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            result = session.run(GET_ALL_ATTACK_TECHNIQUE_QUERY)
            technique_list = [dict(r) for r in result]
        driver.close()

        print(f"Total AttackTechnique node found: {len(technique_list)}")

        # ── Section 4: grouping AttackTechnique per technique_tactic ─────
        groups = defaultdict(list)
        for tech in technique_list:
            tactic_raw = tech.get("technique_tactic")
            if tactic_raw in EXCLUDE_TACTIC_VALUES:
                continue
            groups[tactic_raw].append(tech)

        attack_tactics = []
        for tactic_raw, members in groups.items():
            # sort group members by timestamp -- representative = earliest
            members_sorted = sorted(members, key=lambda m: m["timestamp"] or "")
            representative = members_sorted[0]

            attack_tactics.append({
                "label":            canonicalize_tactic_label(tactic_raw),
                "technique_tactic": representative["technique_tactic"],
                "timestamp":        representative["timestamp"],
                "member_labels":    [m["label"] for m in members_sorted],
            })

        print(f"Total AttackTactic will be created: {len(attack_tactics)}")
        for atc in attack_tactics:
            print(f"  {atc['label']:22s} | technique_tactic={atc['technique_tactic']:28s} | ts={atc['timestamp']} | anggota={atc['member_labels']}")

        # ── Section 5: create AttackTactic nodes & TACTIC relationships to AttackTechnique ──
        CREATE_ATTACK_TACTIC_QUERY = """
MERGE (tac:AttackTactic {label: $label})
SET
    tac.technique_tactic = $technique_tactic,
    tac.timestamp          = $timestamp
RETURN tac.label AS created
"""

        LINK_TACTIC_QUERY = """
MATCH (at:AttackTechnique {label: $technique_label})
MATCH (tac:AttackTactic {label: $tactic_label})
MERGE (at)-[:TACTIC]->(tac)
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session(database=NEO4J_DATABASE) as session:
            for atc in attack_tactics:
                session.run(CREATE_ATTACK_TACTIC_QUERY,
                    label            = atc["label"],
                    technique_tactic = atc["technique_tactic"],
                    timestamp        = atc["timestamp"],
                )

            for atc in attack_tactics:
                for technique_label in atc["member_labels"]:
                    session.run(LINK_TACTIC_QUERY,
                        technique_label = technique_label,
                        tactic_label    = atc["label"],
                    )

        driver.close()

        print(f"Dibuat {len(attack_tactics)} node AttackTactic")
        print(f"Dibuat {sum(len(atc['member_labels']) for atc in attack_tactics)} relasi TACTIC (AttackTechnique -> AttackTactic)")

        # ── Section 6: sort AttackTactic & create FOLLOWED_BY relationships ──
        attack_tactics_sorted = sorted(attack_tactics, key=lambda atc: atc["timestamp"] or "")

        LINK_FOLLOWED_BY_TACTIC_QUERY = """
MATCH (tac1:AttackTactic {label: $label_1})
MATCH (tac2:AttackTactic {label: $label_2})
MERGE (tac1)-[:FOLLOWED_BY]->(tac2)
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        linked_count = 0

        with driver.session(database=NEO4J_DATABASE) as session:
            for i in range(len(attack_tactics_sorted) - 1):
                session.run(LINK_FOLLOWED_BY_TACTIC_QUERY,
                    label_1 = attack_tactics_sorted[i]["label"],
                    label_2 = attack_tactics_sorted[i + 1]["label"],
                )
                linked_count += 1

        driver.close()

        print(f"Created {linked_count} FOLLOWED_BY relationships between AttackTactic nodes")
        print()
        print("Order of AttackTactic chain:")
        for atc in attack_tactics_sorted:
            print(f"  {atc['label']:22s} | {atc['timestamp']}")

        # ── Section 7: Summary ──
        print()
        print("=== SUMMARY ===")
        print(f"Total AttackTechnique node              : {len(technique_list)}")
        print(f"AttackTechnique with valid tactic       : {sum(len(atc['member_labels']) for atc in attack_tactics)}")
        print(f"AttackTechnique pass (no valid tactic)  : {len(technique_list) - sum(len(atc['member_labels']) for atc in attack_tactics)}")
        print(f"Total node AttackTactic created         : {len(attack_tactics)}")
        print(f"Total TACTIC relationships created      : {sum(len(atc['member_labels']) for atc in attack_tactics)}")
        print(f"Total FOLLOWED_BY relationships created : {max(len(attack_tactics) - 1, 0)}")
