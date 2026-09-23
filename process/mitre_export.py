"""
process/mitre_export.py

To export MITRE ATT&CK graph (AttackTactic + AttackTechnique + HighLevelEvent + CONTAINS) to GraphML and CSV.
"""

import re
import csv
import networkx as nx
from neo4j import GraphDatabase


def stringify_prop(value):
    """List -> string seperated by '|'. Other value leave as is."""
    if isinstance(value, list):
        return "|".join(str(v) for v in value)
    return value


def add_node(G, node):
    """add 1 node Neo4j to graph. Return node_id (elementId)."""
    node_id = node.element_id
    if node_id in G.nodes:
        return node_id

    node_type = list(node.labels)[0] if node.labels else "Unknown"
    attrs = {"node_type": node_type}
    for k, v in dict(node).items():
        attrs[k] = stringify_prop(v)

    G.add_node(node_id, **attrs)
    return node_id


def add_edge(G, start_id, end_id, rel_type):
    G.add_edge(start_id, end_id, relationship=rel_type)


def export_graph(G, path):
    nx.write_graphml(G, path)
    print(f"Saved to: {path}")
    print(f"  Total nodes: {G.number_of_nodes()}")
    print(f"  Total edges: {G.number_of_edges()}")


MSG_PATTERN = re.compile(r'http_request:\s*(\S+)\s+(\S+)\s+HTTP')
TARGET_PATH_LEN = 22


def build_http_label(message):
    """
    for vizualization, shorten the HTTP request path to a maximum of 22 characters.
    'GET /dvwa/login.php'                                     -> as is (path <= 22 char)
    'GET /dvwa/hackable/uploads/file.php?q=WyJj...' (log)  -> 'GET .../uploads/file.php?q=Wy...'
    """
    m = MSG_PATTERN.search(message or "")
    if not m:
        return message or "(no info)"
    method, full_path = m.group(1), m.group(2)

    path_part, sep, query_rest = full_path.partition("?")
    query_part = sep + query_rest  # simpan tanda "?" kalau ada

    if len(path_part) <= TARGET_PATH_LEN:
        return f"{method} {full_path}"

    # Ambil 2 segmen terakhir path (mis. "/uploads/file.php")
    segments = [s for s in path_part.split("/") if s]
    tail = "/" + "/".join(segments[-2:]) if len(segments) >= 2 else "/" + segments[-1]

    if len(tail) >= TARGET_PATH_LEN:
        core = tail[:TARGET_PATH_LEN]
        has_more = len(tail) > TARGET_PATH_LEN or bool(query_part)
        return f"{method} ...{core}" + ("..." if has_more else "")

    remaining_needed = TARGET_PATH_LEN - len(tail)
    extra_from_query = query_part[:remaining_needed]
    core = tail + extra_from_query

    has_more_after = len(query_part) > len(extra_from_query)
    return f"{method} ...{core}" + ("..." if has_more_after else "")


def with_actor_suffix(label, actor):
    """Add '(actor)' at the end of the label, if the actor has a value."""
    actor = (actor or "").strip()
    if not actor:
        return label
    return f"{label} ({actor})"


class MitreExport:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ──
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        # ── Output GraphML ───
        self.OUTPUT_2LEVEL = f"results/{dataset}/result-8-6-mitre-export-2level.graphml"
        self.OUTPUT_3LEVEL = f"results/{dataset}/result-8-6-mitre-export-3level.graphml"
        self.OUTPUT_4LEVEL = f"results/{dataset}/result-8-6-mitre-export-4level.graphml"
        self.CSV_HLE_MITRE = f"results/{dataset}/result-8-4-hle-summary-mitre.csv"

        # ── limit num of low-level node (CONTAINS) per HLE ───
        self.CONTAINS_EXPORT_LIMIT = 4

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        OUTPUT_2LEVEL = self.OUTPUT_2LEVEL
        OUTPUT_3LEVEL = self.OUTPUT_3LEVEL
        OUTPUT_4LEVEL = self.OUTPUT_4LEVEL
        CSV_HLE_MITRE = self.CSV_HLE_MITRE
        CONTAINS_EXPORT_LIMIT = self.CONTAINS_EXPORT_LIMIT

        # ── Section 4: Export Level 2 — AttackTactic + AttackTechnique ──
        GET_TACTIC_NODES = "MATCH (tac:AttackTactic) RETURN tac"
        GET_TECHNIQUE_NODES = "MATCH (at:AttackTechnique) RETURN at"
        GET_TACTIC_EDGES = "MATCH (at:AttackTechnique)-[:TACTIC]->(tac:AttackTactic) RETURN at, tac"
        GET_TACTIC_FOLLOWED_BY = "MATCH (tac1:AttackTactic)-[:FOLLOWED_BY]->(tac2:AttackTactic) RETURN tac1, tac2"
        GET_TECHNIQUE_FOLLOWED_BY = "MATCH (at1:AttackTechnique)-[:FOLLOWED_BY]->(at2:AttackTechnique) RETURN at1, at2"

        G2 = nx.DiGraph()

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            for r in session.run(GET_TACTIC_NODES):
                add_node(G2, r["tac"])
            for r in session.run(GET_TECHNIQUE_NODES):
                add_node(G2, r["at"])
            for r in session.run(GET_TACTIC_EDGES):
                at_id = add_node(G2, r["at"])
                tac_id = add_node(G2, r["tac"])
                add_edge(G2, at_id, tac_id, "TACTIC")
            for r in session.run(GET_TACTIC_FOLLOWED_BY):
                id1 = add_node(G2, r["tac1"])
                id2 = add_node(G2, r["tac2"])
                add_edge(G2, id1, id2, "FOLLOWED_BY")
            for r in session.run(GET_TECHNIQUE_FOLLOWED_BY):
                id1 = add_node(G2, r["at1"])
                id2 = add_node(G2, r["at2"])
                add_edge(G2, id1, id2, "FOLLOWED_BY")
        driver.close()

        export_graph(G2, OUTPUT_2LEVEL)

        # ── Section 5: Export Level 3 — + HighLevelEvent ────────────────────
        GET_HLE_TECHNIQUE_EDGES = "MATCH (hle:HighLevelEvent)-[:TECHNIQUE]->(at:AttackTechnique) RETURN hle, at"
        GET_HLE_FOLLOWED_BY = "MATCH (hle1:HighLevelEvent)-[:FOLLOWED_BY]->(hle2:HighLevelEvent) RETURN hle1, hle2"

        G3 = nx.DiGraph()

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            # Level 2 (same as before)
            for r in session.run(GET_TACTIC_NODES):
                add_node(G3, r["tac"])
            for r in session.run(GET_TECHNIQUE_NODES):
                add_node(G3, r["at"])
            for r in session.run(GET_TACTIC_EDGES):
                at_id = add_node(G3, r["at"])
                tac_id = add_node(G3, r["tac"])
                add_edge(G3, at_id, tac_id, "TACTIC")
            for r in session.run(GET_TACTIC_FOLLOWED_BY):
                id1 = add_node(G3, r["tac1"])
                id2 = add_node(G3, r["tac2"])
                add_edge(G3, id1, id2, "FOLLOWED_BY")
            for r in session.run(GET_TECHNIQUE_FOLLOWED_BY):
                id1 = add_node(G3, r["at1"])
                id2 = add_node(G3, r["at2"])
                add_edge(G3, id1, id2, "FOLLOWED_BY")

            # + HighLevelEvent
            hle_ids_exported = set()
            for r in session.run(GET_HLE_TECHNIQUE_EDGES):
                hle_id = add_node(G3, r["hle"])
                at_id = add_node(G3, r["at"])
                add_edge(G3, hle_id, at_id, "TECHNIQUE")
                hle_ids_exported.add(hle_id)

            for r in session.run(GET_HLE_FOLLOWED_BY):
                id1, id2 = r["hle1"].element_id, r["hle2"].element_id
                if id1 in hle_ids_exported and id2 in hle_ids_exported:
                    add_edge(G3, id1, id2, "FOLLOWED_BY")
        driver.close()

        export_graph(G3, OUTPUT_3LEVEL)

        # ── Section 6: Export Level 4 — + CONTAINS (limited by CONTAINS_EXPORT_LIMIT) ──
        GET_HLE_CONTAINS_MEMBERS = """
MATCH (hle:HighLevelEvent {hle_id: $hle_id})-[:CONTAINS]->(e)
RETURN e, e.timestamp AS e_timestamp, e.event_id AS e_event_id
"""

        G4 = nx.DiGraph()

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            # Level 3 (same as before)
            for r in session.run(GET_TACTIC_NODES):
                add_node(G4, r["tac"])
            for r in session.run(GET_TECHNIQUE_NODES):
                add_node(G4, r["at"])
            for r in session.run(GET_TACTIC_EDGES):
                at_id = add_node(G4, r["at"])
                tac_id = add_node(G4, r["tac"])
                add_edge(G4, at_id, tac_id, "TACTIC")
            for r in session.run(GET_TACTIC_FOLLOWED_BY):
                id1 = add_node(G4, r["tac1"])
                id2 = add_node(G4, r["tac2"])
                add_edge(G4, id1, id2, "FOLLOWED_BY")
            for r in session.run(GET_TECHNIQUE_FOLLOWED_BY):
                id1 = add_node(G4, r["at1"])
                id2 = add_node(G4, r["at2"])
                add_edge(G4, id1, id2, "FOLLOWED_BY")

            hle_nodes = {}  # hle_id -> object node Neo4j (to take hle_id & timestamp)
            hle_ids_exported = set()
            for r in session.run(GET_HLE_TECHNIQUE_EDGES):
                hle_id = add_node(G4, r["hle"])
                at_id = add_node(G4, r["at"])
                add_edge(G4, hle_id, at_id, "TECHNIQUE")
                hle_ids_exported.add(hle_id)
                hle_nodes[hle_id] = r["hle"]

            for r in session.run(GET_HLE_FOLLOWED_BY):
                id1, id2 = r["hle1"].element_id, r["hle2"].element_id
                if id1 in hle_ids_exported and id2 in hle_ids_exported:
                    add_edge(G4, id1, id2, "FOLLOWED_BY")

            # + CONTAINS (limited by CONTAINS_EXPORT_LIMIT per HLE)
            for hle_id, hle_node in hle_nodes.items():
                hle_props = dict(hle_node)
                members = list(session.run(GET_HLE_CONTAINS_MEMBERS, hle_id=hle_props["hle_id"]))

                # sort group member
                same_ts = sorted(
                    [m for m in members if m["e_timestamp"] == hle_props.get("timestamp")],
                    key=lambda m: str(m["e_event_id"] or "")
                )
                other_ts = sorted(
                    [m for m in members if m["e_timestamp"] != hle_props.get("timestamp")],
                    key=lambda m: str(m["e_event_id"] or "")
                )
                candidates = same_ts + other_ts

                selected = candidates[:CONTAINS_EXPORT_LIMIT]
                for m in selected:
                    e_id = add_node(G4, m["e"])
                    add_edge(G4, hle_id, e_id, "CONTAINS")
        driver.close()

        export_graph(G4, OUTPUT_4LEVEL)

        # ── Section 7: Export HLE to CSV (with technique_code & technique_tactic) ──
        Q_SUMMARY_MITRE = """
MATCH (hle:HighLevelEvent)
OPTIONAL MATCH (hle)-[:CONTAINS]->(e)
WITH hle, e, toInteger(split(hle.hle_id, '-')[1]) AS hle_seq
ORDER BY hle.timestamp ASC, hle_seq ASC, e.timestamp ASC
WITH hle, hle_seq, collect(e)[0] AS first_event
RETURN
    hle.hle_id          AS event_id,
    hle.label           AS label_predict,
    hle.severity        AS severity,
    hle.group_count     AS group_count,
    hle.event_ids       AS low_event_ids,
    hle.timestamp       AS datetime,
    first_event.message      AS decoded,
    hle.actors               AS actors,
    first_event.source_file  AS display_name,
    hle.technique_code       AS technique_code,
    hle.technique_tactic     AS technique_tactic
ORDER BY hle.timestamp ASC, hle_seq ASC
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            results = list(session.run(Q_SUMMARY_MITRE))
        driver.close()

        with open(CSV_HLE_MITRE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["event_id",
                             "datetime",
                             "display_name",
                             "decoded",
                             "label_predict",
                             "severity",
                             "actor",
                             "group_count",
                             "low_event_ids",
                             "technique_code",
                             "technique_tactic"])
            for r in results:
                writer.writerow([
                    r["event_id"],
                    r["datetime"],
                    r["display_name"]   or "",
                    r["decoded"]       or "",
                    r["label_predict"],
                    r["severity"],
                    "|".join(r["actors"]) if r["actors"] else "",
                    r["group_count"],
                    "|".join(r["low_event_ids"]) if r["low_event_ids"] else "",
                    r["technique_code"]   or "",
                    r["technique_tactic"] or "",
                ])

        print(f"Saved: {CSV_HLE_MITRE} ({len(results)} rows)")
        for r in results:
            print(f"  {r['event_id']:10s} | {str(r['label_predict'])[:40]:40s} | {r['severity']:8s} | n={r['group_count']} | code={r['technique_code']} | tactic={r['technique_tactic']}")

        # ── Section 8: node label for CONTAINS members (Level 4) ───────
        FOUR_LEVEL_GRAPHML_INPUT = OUTPUT_4LEVEL
        FOUR_LEVEL_GRAPHML_OUTPUT = str(OUTPUT_4LEVEL).replace("-4level.graphml", "-4level-with-label.graphml")

        G_fix = nx.read_graphml(FOUR_LEVEL_GRAPHML_INPUT)

        updated_count = {"HTTPRequest": 0, "AuthEvent": 0, "HighLevelEvent": 0}
        for node_id, data in G_fix.nodes(data=True):
            node_type = data.get("node_type", "")
            actor = data.get("actor", "")

            if node_type == "HTTPRequest":
                new_label = build_http_label(data.get("message", ""))
                new_label = with_actor_suffix(new_label, actor)
                G_fix.nodes[node_id]["label"] = new_label
                updated_count["HTTPRequest"] += 1

            elif node_type == "AuthEvent":
                command = (data.get("command") or "").strip()
                if command:
                    new_label = with_actor_suffix(command, actor)
                    G_fix.nodes[node_id]["label"] = new_label
                    updated_count["AuthEvent"] += 1

            elif node_type == "HighLevelEvent":
                # HLE simpan actor di properti 'actors' (bisa gabungan "IP1|IP2")
                actors = data.get("actors", "")
                current_label = data.get("label", "")
                new_label = with_actor_suffix(current_label, actors)
                G_fix.nodes[node_id]["label"] = new_label
                updated_count["HighLevelEvent"] += 1

        nx.write_graphml(G_fix, FOUR_LEVEL_GRAPHML_OUTPUT, encoding="utf-8", prettyprint=True)

        print(f"Saved to: {FOUR_LEVEL_GRAPHML_OUTPUT}")
        print(f"(original file remains intact at: {FOUR_LEVEL_GRAPHML_INPUT})")
        print(f"  Node HTTPRequest with updated labels   : {updated_count['HTTPRequest']}")
        print(f"  Node AuthEvent with updated labels     : {updated_count['AuthEvent']}")
        print(f"  Node HighLevelEvent with updated labels: {updated_count['HighLevelEvent']}")
