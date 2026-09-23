"""
process/mitre_technique.py

To create AttackTechnique nodes and relationships in Neo4j based on HLE data.
"""

from collections import defaultdict
from neo4j import GraphDatabase


def canonicalize_technique_code(raw_code):
    """
    'attack.t1059' -> 'T1059'
    'attack.t1505.003' -> 'T1505.003'
    """
    if not raw_code:
        return None
    code = raw_code.strip()
    if code.lower().startswith("attack."):
        code = code[len("attack."):]
    return code.upper()


class MitreTechnique:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ───
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        self.EXCLUDE_TECHNIQUE_CODE_VALUES = {None, "", "-"}

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        EXCLUDE_TECHNIQUE_CODE_VALUES = self.EXCLUDE_TECHNIQUE_CODE_VALUES

        # ── Section 3: take all HLE node from Neo4j ───
        GET_ALL_HLE_QUERY = """
MATCH (hle:HighLevelEvent)
RETURN hle.hle_id AS hle_id, hle.technique_code AS technique_code,
       hle.technique_tactic AS technique_tactic, hle.timestamp AS timestamp
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            result = session.run(GET_ALL_HLE_QUERY)
            hle_list = [dict(r) for r in result]
        driver.close()

        print(f"Total HLE node found: {len(hle_list)}")

        # ── Section 4: group HLE per technique_code ──
        groups = defaultdict(list)
        for hle in hle_list:
            code = hle.get("technique_code")
            if code in EXCLUDE_TECHNIQUE_CODE_VALUES:
                continue
            groups[code].append(hle)

        attack_techniques = []
        for code_raw, members in groups.items():
            # sort group member by (timestamp, hle_id numeric) -- representative = earliest
            members_sorted = sorted(
                members,
                key=lambda m: (m["timestamp"] or "", int(m["hle_id"].split("-")[1]))
            )
            representative = members_sorted[0]

            attack_techniques.append({
                "label":            canonicalize_technique_code(code_raw),
                "technique_tactic": representative["technique_tactic"],
                "technique_code":   representative["technique_code"],
                "timestamp":        representative["timestamp"],
                "member_hle_ids":   [m["hle_id"] for m in members_sorted],
            })

        print(f"Total number of AttackTechnique node to be created: {len(attack_techniques)}")
        for at in attack_techniques:
            print(f"  {at['label']:12s} | tactic={at['technique_tactic']:28s} | ts={at['timestamp']} | anggota={at['member_hle_ids']}")

        # ── Section 5: create AttackTechnique node & TECHNIQUE edge to HLE ──
        CREATE_ATTACK_TECHNIQUE_QUERY = """
MERGE (at:AttackTechnique {label: $label})
SET
    at.technique_tactic = $technique_tactic,
    at.technique_code   = $technique_code,
    at.timestamp         = $timestamp
RETURN at.label AS created
"""

        LINK_TECHNIQUE_QUERY = """
MATCH (hle:HighLevelEvent {hle_id: $hle_id})
MATCH (at:AttackTechnique {label: $label})
MERGE (hle)-[:TECHNIQUE]->(at)
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session(database=NEO4J_DATABASE) as session:
            for at in attack_techniques:
                session.run(CREATE_ATTACK_TECHNIQUE_QUERY,
                    label            = at["label"],
                    technique_tactic = at["technique_tactic"],
                    technique_code   = at["technique_code"],
                    timestamp        = at["timestamp"],
                )

            for at in attack_techniques:
                for hle_id in at["member_hle_ids"]:
                    session.run(LINK_TECHNIQUE_QUERY,
                        hle_id = hle_id,
                        label  = at["label"],
                    )

        driver.close()

        print(f"Created {len(attack_techniques)} AttackTechnique nodes")
        print(f"Created {sum(len(at['member_hle_ids']) for at in attack_techniques)} TECHNIQUE relationships (HLE -> AttackTechnique)")

        # ── Section 6: sort AttackTechnique & create FOLLOWED_BY relationships ────
        attack_techniques_sorted = sorted(attack_techniques, key=lambda at: at["timestamp"] or "")

        LINK_FOLLOWED_BY_TECHNIQUE_QUERY = """
MATCH (at1:AttackTechnique {label: $label_1})
MATCH (at2:AttackTechnique {label: $label_2})
MERGE (at1)-[:FOLLOWED_BY]->(at2)
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        linked_count = 0

        with driver.session(database=NEO4J_DATABASE) as session:
            for i in range(len(attack_techniques_sorted) - 1):
                session.run(LINK_FOLLOWED_BY_TECHNIQUE_QUERY,
                    label_1 = attack_techniques_sorted[i]["label"],
                    label_2 = attack_techniques_sorted[i + 1]["label"],
                )
                linked_count += 1

        driver.close()

        print(f"Created {linked_count} FOLLOWED_BY relationships between AttackTechnique nodes")
        print()
        print("Order of AttackTechnique chain:")
        for at in attack_techniques_sorted:
            print(f"  {at['label']:12s} | {at['timestamp']}")

        # ── Section 7: Summary ───────────────────────────────────────────────
        print()
        print("=== SUMMARY ===")
        print(f"Total HLE node                              : {len(hle_list)}")
        print(f"HLE with valid technique_code               : {sum(len(at['member_hle_ids']) for at in attack_techniques)}")
        print(f"HLE dilewati (technique_code kosong)        : {len(hle_list) - sum(len(at['member_hle_ids']) for at in attack_techniques)}")
        print(f"Total node AttackTechnique created          : {len(attack_techniques)}")
        print(f"Total TECHNIQUE relationships created       : {sum(len(at['member_hle_ids']) for at in attack_techniques)}")
        print(f"Total FOLLOWED_BY relationships created     : {max(len(attack_techniques) - 1, 0)}")
