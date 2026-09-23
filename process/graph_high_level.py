"""
process/graph_high_level.py

To export High-Level Events (HLE) and their relationships to GraphML format and CSV.
"""

import csv
import networkx as nx
from neo4j import GraphDatabase
from pathlib import Path


class GraphHighLevel:
    def __init__(self, dataset):
        self.dataset = dataset

        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        self.TOP_N_ACTORS = None  # num of attackers to process, None = all

        self.output_dir = Path(f"results/{dataset}")

        # ── Take TARGET_IPS from attackers ranking CSV ──
        self.ACTOR_RANKING_CSV = f"results/{dataset}/result-7-1-attacker-identification.csv"

        # ── limit of max sub-event per HLE for export GraphML (vizualization purpose) 
        self.MAX_CONTAINS_EXPORT = 10  # None = export semua (bisa sangat berat)

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        TOP_N_ACTORS = self.TOP_N_ACTORS
        MAX_CONTAINS_EXPORT = self.MAX_CONTAINS_EXPORT
        ACTOR_RANKING_CSV = self.ACTOR_RANKING_CSV

        output_dir = self.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        with open(ACTOR_RANKING_CSV, newline="", encoding="utf-8") as f:
            _rows = list(csv.DictReader(f))
        TARGET_IPS = [r["user"] for r in _rows[:TOP_N_ACTORS]]

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        print(f"Dataset      : {self.dataset}")
        print(f"TOP_N_ACTORS : {TOP_N_ACTORS}")
        print(f"TARGET_IPS   : {TARGET_IPS}")
        print(f"Output dir   : {output_dir}")
        print(f"MAX_CONTAINS_EXPORT : {MAX_CONTAINS_EXPORT}")
        print("")

        # ── Section 2: Export HLE + SubNodes → GraphML ───
        print("Exporting HLE and sub-nodes to GraphML...")
        # Fetch all HLE
        Q_ALL_HLE = """
MATCH (hle:HighLevelEvent)
RETURN hle
ORDER BY hle.timestamp ASC
"""

        # Fetch sub-nodes per HLE (batch)
        # Limit sub-event per HLE, based on MAX_CONTAINS_EXPORT
        _limit = f"LIMIT {MAX_CONTAINS_EXPORT}" if MAX_CONTAINS_EXPORT is not None else ""
        Q_HLE_CONTAINS_BATCH = f"""
MATCH (hle:HighLevelEvent {{hle_id: $hle_id}})-[:CONTAINS]->(e)
RETURN elementId(e) AS eid,
       labels(e)[0] AS ntype,
       properties(e) AS props
{_limit}
"""

        hle_nodes_o = {}
        sub_nodes_o = {}
        sub_edges_o = []

        # Step 1: fetch all HLE
        with driver.session(database=NEO4J_DATABASE) as session:
            for record in session.run(Q_ALL_HLE):
                hle = record["hle"]
                hid = hle["hle_id"]
                hle_nodes_o[hid] = {"labels": ["HighLevelEvent"], "properties": dict(hle)}

        print(f"HLE nodes fetched: {len(hle_nodes_o)}")

        # Step 2: fetch sub-nodes per HLE (batch per hle_id)
        for idx, hid in enumerate(hle_nodes_o.keys()):
            with driver.session(database=NEO4J_DATABASE) as session:
                for record in session.run(Q_HLE_CONTAINS_BATCH, hle_id=hid):
                    eid   = record["eid"]
                    ntype = record["ntype"] or "Unknown"
                    props = record["props"]
                    if eid not in sub_nodes_o:
                        sub_nodes_o[eid] = {"labels": [ntype], "properties": props}
                    if (hid, eid, "CONTAINS") not in sub_edges_o:
                        sub_edges_o.append((hid, eid, "CONTAINS"))
            if (idx + 1) % 5 == 0 or (idx + 1) == len(hle_nodes_o):
                print(f"  Processed {idx+1}/{len(hle_nodes_o)} HLE...")

        print(f"HLE nodes: {len(hle_nodes_o)}, Sub-event nodes: {len(sub_nodes_o)}, Edges: {len(sub_edges_o)}")

        G = nx.DiGraph()

        for eid, ndata in {**hle_nodes_o, **sub_nodes_o}.items():
            ntype = (ndata.get("labels") or ndata.get("node_type") or ["Unknown"])
            ntype = ntype[0] if isinstance(ntype, list) else ntype
            props = ndata.get("properties", ndata)
            safe  = {}
            for k, v in props.items():
                if isinstance(v, list): safe[k] = ",".join(str(x) for x in v)
                elif v is None:         safe[k] = ""
                elif isinstance(v, bool): safe[k] = str(v)
                else:                   safe[k] = v
            G.add_node(str(eid), node_type=ntype, **safe)

        for (src, dst, rel) in sub_edges_o:
            if str(src) in G and str(dst) in G:
                if not G.has_edge(str(src), str(dst)):
                    G.add_edge(str(src), str(dst), relationship=rel)

        out = output_dir / "result-8-1-hle-contains.graphml"
        nx.write_graphml(G, out, encoding="utf-8", prettyprint=True)
        print(f"Saved: {out} | {G.number_of_nodes()} nodes, {G.number_of_edges()} edges | {out.stat().st_size/1024:.1f} KB")
        print("")

        # ── Section 3: Export HLE Chain (FOLLOWED_BY) to GraphML 
        print("Exporting HLE chain (FOLLOWED_BY) to GraphML...")
        Q_CHAIN = """
MATCH p = (hle1:HighLevelEvent)-[:FOLLOWED_BY*]->(hle2:HighLevelEvent)
RETURN p
"""

        hle_nodes = {}
        hle_edges = []

        with driver.session(database=NEO4J_DATABASE) as session:
            for record in session.run(Q_CHAIN):
                path = record["p"]
                for node in path.nodes:
                    hid = node["hle_id"]
                    if hid not in hle_nodes:
                        hle_nodes[hid] = {"labels": ["HighLevelEvent"], "properties": dict(node)}
                for rel in path.relationships:
                    src = rel.start_node["hle_id"]
                    dst = rel.end_node["hle_id"]
                    if (src, dst, rel.type) not in hle_edges:
                        hle_edges.append((src, dst, rel.type))

        print(f"HLE nodes: {len(hle_nodes)}, Edges: {len(hle_edges)}")

        G = nx.DiGraph()

        for eid, ndata in hle_nodes.items():
            ntype = (ndata.get("labels") or ndata.get("node_type") or ["Unknown"])
            ntype = ntype[0] if isinstance(ntype, list) else ntype
            props = ndata.get("properties", ndata)
            safe  = {}
            for k, v in props.items():
                if isinstance(v, list): safe[k] = ",".join(str(x) for x in v)
                elif v is None:         safe[k] = ""
                elif isinstance(v, bool): safe[k] = str(v)
                else:                   safe[k] = v
            G.add_node(str(eid), node_type=ntype, **safe)

        for (src, dst, rel) in hle_edges:
            if str(src) in G and str(dst) in G:
                if not G.has_edge(str(src), str(dst)):
                    G.add_edge(str(src), str(dst), relationship=rel)

        out = output_dir / "result-8-2-hle-chain.graphml"
        nx.write_graphml(G, out, encoding="utf-8", prettyprint=True)
        print(f"Saved: {out} | {G.number_of_nodes()} nodes, {G.number_of_edges()} edges | {out.stat().st_size/1024:.1f} KB")
        print("")

        # ── Section 4: Export HLE + CONTAINS + FOLLOWED_BY to GraphML ─
        print("Exporting HLE + CONTAINS + FOLLOWED_BY to GraphML...")
        Q_ALL_HLE_C = """
MATCH (hle:HighLevelEvent)
RETURN hle
ORDER BY hle.timestamp ASC
"""
        Q_CONTAINS_BATCH = """
MATCH (hle:HighLevelEvent {hle_id: $hle_id})-[:CONTAINS]->(e)
RETURN elementId(e) AS eid,
       labels(e)[0] AS ntype,
       properties(e) AS props
"""
        Q_CHAIN_ONLY = """
MATCH (hle1:HighLevelEvent)-[r:FOLLOWED_BY]->(hle2:HighLevelEvent)
RETURN hle1.hle_id AS src, hle2.hle_id AS dst
"""

        hle_nodes_c = {}
        sub_nodes_c  = {}
        all_edges_c  = []

        # Step 1: fetch all HLE
        with driver.session(database=NEO4J_DATABASE) as session:
            for record in session.run(Q_ALL_HLE_C):
                hle = record["hle"]
                hid = hle["hle_id"]
                hle_nodes_c[hid] = {"labels": ["HighLevelEvent"], "properties": dict(hle)}

        print(f"HLE nodes fetched: {len(hle_nodes_c)}")

        # Step 2: fetch sub-nodes per HLE, limit MAX_CONTAINS_EXPORT
        _limit = f"LIMIT {MAX_CONTAINS_EXPORT}" if MAX_CONTAINS_EXPORT is not None else ""
        Q_CONTAINS_BATCH_L = f"""
MATCH (hle:HighLevelEvent {{hle_id: $hle_id}})-[:CONTAINS]->(e)
RETURN elementId(e) AS eid,
       labels(e)[0] AS ntype,
       properties(e) AS props
{_limit}
"""

        for idx, hid in enumerate(hle_nodes_c.keys()):
            with driver.session(database=NEO4J_DATABASE) as session:
                for record in session.run(Q_CONTAINS_BATCH_L, hle_id=hid):
                    eid   = record["eid"]
                    ntype = record["ntype"] or "Unknown"
                    props = record["props"]
                    if eid not in sub_nodes_c:
                        sub_nodes_c[eid] = {"labels": [ntype], "properties": props}
                    if (hid, eid, "CONTAINS") not in all_edges_c:
                        all_edges_c.append((hid, eid, "CONTAINS"))
            if (idx + 1) % 5 == 0 or (idx + 1) == len(hle_nodes_c):
                print(f"  Processed {idx+1}/{len(hle_nodes_c)} HLE...")

        # Step 3: fetch FOLLOWED_BY edges
        with driver.session(database=NEO4J_DATABASE) as session:
            for record in session.run(Q_CHAIN_ONLY):
                src = record["src"]
                dst = record["dst"]
                if (src, dst, "FOLLOWED_BY") not in all_edges_c:
                    all_edges_c.append((src, dst, "FOLLOWED_BY"))

        print(f"HLE: {len(hle_nodes_c)}, Sub-events: {len(sub_nodes_c)}, Edges: {len(all_edges_c)}")

        G = nx.DiGraph()

        for eid, ndata in {**hle_nodes_c, **sub_nodes_c}.items():
            ntype = (ndata.get("labels") or ndata.get("node_type") or ["Unknown"])
            ntype = ntype[0] if isinstance(ntype, list) else ntype
            props = ndata.get("properties", ndata)
            safe  = {}
            for k, v in props.items():
                if isinstance(v, list): safe[k] = ",".join(str(x) for x in v)
                elif v is None:         safe[k] = ""
                elif isinstance(v, bool): safe[k] = str(v)
                else:                   safe[k] = v
            G.add_node(str(eid), node_type=ntype, **safe)

        for (src, dst, rel) in all_edges_c:
            if str(src) in G and str(dst) in G:
                if not G.has_edge(str(src), str(dst)):
                    G.add_edge(str(src), str(dst), relationship=rel)

        out = output_dir / "result-8-3-hle-contains-chain.graphml"
        nx.write_graphml(G, out, encoding="utf-8", prettyprint=True)
        print(f"Saved: {out} | {G.number_of_nodes()} nodes, {G.number_of_edges()} edges | {out.stat().st_size/1024:.1f} KB")
        print("")

        # ── Section 5: Export HLE Summary to CSV ──
        Q_SUMMARY = """
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
    labels(first_event)      AS example_type
ORDER BY hle.timestamp ASC, hle_seq ASC
"""

        CSV_HLE = output_dir / "result-8-4-hle-summary.csv"
        with driver.session(database=NEO4J_DATABASE) as session:
            results = list(session.run(Q_SUMMARY))

        with open(CSV_HLE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["event_id",
                             "datetime",
                             "display_name",
                             "decoded",
                             "label_predict",
                             "severity",
                             "actor",
                             # "example_type",
                             "group_count",
                             "low_event_ids"])
            for r in results:
                writer.writerow([
                    r["event_id"],
                    r["datetime"],
                    r["display_name"]   or "",
                    r["decoded"]       or "",
                    r["label_predict"],
                    r["severity"],
                    "|".join(r["actors"]) if r["actors"] else "",
                    # ",".join(r["example_type"]) if r["example_type"] else "",
                    r["group_count"],
                    "|".join(r["low_event_ids"]) if r["low_event_ids"] else "",
                ])

        print("HLE summary for CSV export:")
        for r in results:
            print(f"  {r['event_id']:10s} | {str(r['label_predict'])[:40]:40s} | {r['severity']:8s} | n={r['group_count']}")
        print(f"Saved: {CSV_HLE} ({len(results)} rows)")

        driver.close()
        print("All export completed.")
