"""
process/attacker_tracking.py

To track attackers and extract subgraphs related to them from the graph.
"""

import csv
import re
from collections import Counter
from pathlib import Path

import networkx as nx
from neo4j import GraphDatabase


MSG_PATTERN = re.compile(r'http_request:\s*(\S+\s+\S+)\s+HTTP')
TRUNCATE_LEN = 20


def truncate(text, length=TRUNCATE_LEN):
    if text is None:
        return ""
    text = text.strip()
    if len(text) <= length:
        return text
    return text[:length] + "..."


def build_label(node_type, data):
    label = (data.get("label") or "").strip()
    path = (data.get("path") or "").strip()
    command = (data.get("command") or "").strip()
    message = data.get("message") or ""

    if node_type == "Page":
        return path or label or "(no path)"

    if node_type == "HTTPRequest":
        m = MSG_PATTERN.search(message)
        method_path = m.group(1) if m else path
        method_path = truncate(method_path)
        if label:
            return f"{method_path} ({label})"
        return method_path or "(no info)"

    if node_type == "AuthEvent":
        if command and label:
            return f"{command} ({label})"
        return command or label or "(no info)"

    # fallback untuk node_type lain (User, IPAddress, dll)
    username = (data.get("username") or "").strip()
    ip = (data.get("ip") or "").strip()
    return label or username or ip or "(no label)"


class AttackerTracking:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ──────────────────────────────────────────────────
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        # ── Number of top attackers processed ──────────────────────────────
        self.TOP_N_ACTORS = None  # number of top actors to process, none = all

        # ── Limit HTTPRequest per unique label ────────────────────────────────
        self.MAX_HTTP_PER_LABEL = 16  # max node per label

        # ── Output ────────────────────────────────────────────────────────────
        self.output_dir = Path(f"results/{dataset}")
        self.OUT_GRAPHML = self.output_dir / "result-7-2-graph-attacker.graphml"

        self.ACTOR_RANKING_CSV = f"results/{dataset}/result-7-1-attacker-identification.csv"

    def run(self):
        dataset = self.dataset
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        TOP_N_ACTORS = self.TOP_N_ACTORS
        MAX_HTTP_PER_LABEL = self.MAX_HTTP_PER_LABEL
        output_dir = self.output_dir
        OUT_GRAPHML = self.OUT_GRAPHML
        ACTOR_RANKING_CSV = self.ACTOR_RANKING_CSV

        print(f"Dataset       : {dataset}")
        print(f"Database      : {NEO4J_DATABASE}")
        print(f"TOP_N_ACTORS  : {TOP_N_ACTORS}")
        print(f"Output        : {OUT_GRAPHML}")
        print(f"MAX_HTTP/label: {MAX_HTTP_PER_LABEL}")

        # ── Section 2: Take Target attackers from CSV ─────────────────────────────
        with open(ACTOR_RANKING_CSV, newline="", encoding="utf-8") as f:
            _rows = list(csv.DictReader(f))

        TARGET_IPS = [r["user"] for r in _rows[:TOP_N_ACTORS]]

        print(f"Top {TOP_N_ACTORS} actor(s):")
        for i, ip in enumerate(TARGET_IPS, 1):
            print(f"  {i}. {ip}")

        # ── Section 3: Query Graph from Neo4j ───────────────────────────────
        # ── Query 1: AuthEvent from IP (SSH/PAM brute force) ────────────────
        GRAPH_QUERY_AUTH = """
UNWIND $target_ips AS target_ip
MATCH (ip:IPAddress {ip: target_ip})-[:REQUEST]->(auth:AuthEvent)
WHERE auth.label <> 'benign'
OPTIONAL MATCH (auth)-[:TARGET_USER]->(u:User)
RETURN ip, auth, u
"""

        # ── Query 2: Sudo/escalation from user related to IP via AuthEvent ──
        GRAPH_QUERY_ESCALATION_AUTH = """
UNWIND $target_ips AS target_ip
MATCH (ip:IPAddress {ip: target_ip})-[:REQUEST]->(any_auth:AuthEvent)-[:TARGET_USER]->(u:User)
WHERE any_auth.label <> 'benign'
MATCH (u)-[:PERFORMED]->(sudo_auth:AuthEvent)-[:ESCALATED_TO]->(escalated:User)
WHERE sudo_auth.label <> 'benign'
RETURN u, sudo_auth, escalated
"""

        # ── Query 3: Sudo/escalation from user related to IP via HTTPRequest ──
        GRAPH_QUERY_ESCALATION_HTTP = """
UNWIND $target_ips AS target_ip
MATCH (ip:IPAddress {ip: target_ip})-[:REQUEST]->(any_req:HTTPRequest)-[:RELATED_TO]->(u:User)
WHERE any_req.label <> 'benign'
MATCH (u)-[:PERFORMED]->(sudo_auth:AuthEvent)-[:ESCALATED_TO]->(escalated:User)
WHERE sudo_auth.label <> 'benign'
RETURN u, sudo_auth, escalated
"""

        # ── Query 4: HTTPRequest per label, limited MAX_HTTP_PER_LABEL ─────
        # Take half the activities from the beginning + half from the end for each label. 
        # to simplify the graph and avoid too many nodes for each label in vizualization.
        MAX_HTTP_HALF = MAX_HTTP_PER_LABEL // 2

        GRAPH_QUERY_HTTP = f"""
UNWIND $target_ips AS target_ip
MATCH (ip:IPAddress {{ip: target_ip}})-[:REQUEST]->(req:HTTPRequest)
WHERE req.label <> 'benign'
WITH ip, req.label AS label, req
ORDER BY req.timestamp ASC
WITH ip, label, collect(req) AS all_reqs
WITH ip, label, all_reqs,
     CASE WHEN size(all_reqs) <= {MAX_HTTP_PER_LABEL}
          THEN all_reqs
          ELSE all_reqs[0..{MAX_HTTP_HALF}] + all_reqs[-{MAX_HTTP_HALF}..]
     END AS reqs
UNWIND reqs AS req
OPTIONAL MATCH (req)-[:TARGET_PAGE]->(page:Page)
RETURN ip, req, page
"""

        # ── Query 5: HTTPRequest linkedy to User ──────────────────────
        GRAPH_QUERY_HTTP_USER = """
UNWIND $target_ips AS target_ip
MATCH (ip:IPAddress {ip: target_ip})-[:REQUEST]->(req:HTTPRequest)-[:RELATED_TO]->(u:User)
WHERE req.label <> 'benign'
OPTIONAL MATCH (req)-[:TARGET_PAGE]->(page:Page)
RETURN ip, req, u, page
"""

        # ── Query 6: SystemEvent from User linked to IP ─────────────
        GRAPH_QUERY_SYSLOG = """
UNWIND $target_ips AS target_ip
MATCH (ip:IPAddress {ip: target_ip})-[:REQUEST]->(auth:AuthEvent)-[:TARGET_USER]->(u:User)
WHERE auth.label <> 'benign'
MATCH (u)-[:TRIGGERED]->(sys:SystemEvent)
WHERE sys.label <> 'benign'
RETURN u, sys
"""

        graph_nodes = {}
        graph_edges = []

        def collect_node(n, skip_http=False):
            if n is None: return
            if not n.labels: return
            if skip_http and "HTTPRequest" in n.labels: return
            eid = n.element_id
            if eid not in graph_nodes:
                graph_nodes[eid] = {"labels": list(n.labels), "properties": dict(n)}

        def collect_edge(src_eid, dst_eid, rel_type):
            graph_edges.append((src_eid, dst_eid, rel_type))

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session(database=NEO4J_DATABASE) as session:

            # Query 1: AuthEvent directly from IP
            for rec in session.run(GRAPH_QUERY_AUTH, target_ips=TARGET_IPS):
                collect_node(rec["ip"])
                collect_node(rec["auth"])
                collect_node(rec["u"])
                if rec["ip"] and rec["auth"]:
                    collect_edge(rec["ip"].element_id, rec["auth"].element_id, "REQUEST")
                if rec["auth"] and rec["u"]:
                    collect_edge(rec["auth"].element_id, rec["u"].element_id, "TARGET_USER")

            # Query 2: Escalation via AuthEvent
            for rec in session.run(GRAPH_QUERY_ESCALATION_AUTH, target_ips=TARGET_IPS):
                collect_node(rec["u"])
                collect_node(rec["sudo_auth"])
                collect_node(rec["escalated"])
                if rec["u"] and rec["sudo_auth"]:
                    collect_edge(rec["u"].element_id, rec["sudo_auth"].element_id, "PERFORMED")
                if rec["sudo_auth"] and rec["escalated"]:
                    collect_edge(rec["sudo_auth"].element_id, rec["escalated"].element_id, "ESCALATED_TO")

            # Query 3: Escalation via HTTPRequest
            for rec in session.run(GRAPH_QUERY_ESCALATION_HTTP, target_ips=TARGET_IPS):
                collect_node(rec["u"])
                collect_node(rec["sudo_auth"])
                collect_node(rec["escalated"])
                if rec["u"] and rec["sudo_auth"]:
                    collect_edge(rec["u"].element_id, rec["sudo_auth"].element_id, "PERFORMED")
                if rec["sudo_auth"] and rec["escalated"]:
                    collect_edge(rec["sudo_auth"].element_id, rec["escalated"].element_id, "ESCALATED_TO")

            # Query 4: HTTPRequest per label with limit
            for rec in session.run(GRAPH_QUERY_HTTP, target_ips=TARGET_IPS):
                collect_node(rec["ip"])
                collect_node(rec["req"])
                collect_node(rec["page"])
                if rec["ip"] and rec["req"]:
                    collect_edge(rec["ip"].element_id, rec["req"].element_id, "REQUEST")
                if rec["req"] and rec["page"]:
                    collect_edge(rec["req"].element_id, rec["page"].element_id, "TARGET_PAGE")

            # Query 5: HTTPRequest linked to User
            for rec in session.run(GRAPH_QUERY_HTTP_USER, target_ips=TARGET_IPS):
                collect_node(rec["ip"])
                collect_node(rec["req"])
                collect_node(rec["u"])
                collect_node(rec["page"])
                if rec["ip"] and rec["req"]:
                    collect_edge(rec["ip"].element_id, rec["req"].element_id, "REQUEST")
                if rec["req"] and rec["u"]:
                    collect_edge(rec["req"].element_id, rec["u"].element_id, "RELATED_TO")
                if rec["req"] and rec["page"]:
                    collect_edge(rec["req"].element_id, rec["page"].element_id, "TARGET_PAGE")

            # Query 6: SystemEvent from User (if available — not all datasets have this)
            try:
                for rec in session.run(GRAPH_QUERY_SYSLOG, target_ips=TARGET_IPS):
                    collect_node(rec["u"])
                    collect_node(rec["sys"])
                    if rec["u"] and rec["sys"]:
                        collect_edge(rec["u"].element_id, rec["sys"].element_id, "TRIGGERED")
            except Exception as e:
                print(f"  SKIP SystemEvent: {e}")

        driver.close()

        print(f"Fetched: {len(graph_nodes)} nodes, {len(graph_edges)} edges")

        type_counts = Counter(
            (ndata["labels"] or ["Unknown"])[0]
            for ndata in graph_nodes.values()
        )
        print("\nNode types:")
        for ntype, count in sorted(type_counts.items()):
            print(f"  {ntype:20s}: {count}")

        # ── Section 4: Build NetworkX Graph & Export GraphML ────────────────
        G = nx.DiGraph()

        # add node with all its properties
        for eid, ndata in graph_nodes.items():
            ntype = (ndata["labels"] or ["Unknown"])[0]
            props = ndata["properties"]

            safe_props = {}
            for k, v in props.items():
                key = k
                if isinstance(v, list):
                    safe_props[key] = ",".join(str(x) for x in v)
                elif isinstance(v, bool):
                    safe_props[key] = str(v)
                elif v is None:
                    safe_props[key] = ""
                else:
                    safe_props[key] = v

            # Add label for IPAddress and User
            extra = {}
            if ntype == "IPAddress":
                extra["label"] = props.get("ip", "")
            elif ntype == "User":
                extra["label"] = props.get("username", "")

            G.add_node(
                eid,
                node_type=ntype,
                **safe_props,
                **extra
            )

        # add edge
        for (src, dst, rel_type) in graph_edges:
            if src in G and dst in G:
                # If edge already exists, skip (avoid duplicates)
                if not G.has_edge(src, dst):
                    G.add_edge(src, dst, relationship=rel_type)

        print(f"NetworkX graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # ── Export to GraphML ────────────────────────────────────────────────
        output_dir.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(G, OUT_GRAPHML, encoding="utf-8", prettyprint=True)

        print(f"\nSaved: {OUT_GRAPHML}")
        print(f"  Size: {OUT_GRAPHML.stat().st_size / 1024:.1f} KB")

        # ── Section 5: Add display_label (for Visualization Needs) ─
        OUT_GRAPHML_LABELED = output_dir / "result-7-2-graph-attacker-with-label.graphml"

        counts = {}
        for node_id, data in G.nodes(data=True):
            node_type = data.get("node_type", "")
            display_label = build_label(node_type, data)
            G.nodes[node_id]["display_label"] = display_label
            counts[node_type] = counts.get(node_type, 0) + 1

        nx.write_graphml(G, OUT_GRAPHML_LABELED, encoding="utf-8", prettyprint=True)

        print(f"Done. Saved to: {OUT_GRAPHML_LABELED}")
        print()
        print("Summary of nodes per type:")
        for t, c in counts.items():
            print(f"  {t}: {c}")

        print()
        print("Example display_label results:")
        shown = {}
        for node_id, data in G.nodes(data=True):
            t = data.get("node_type", "")
            if shown.get(t, 0) < 2:
                print(f"  [{t}] {data.get('display_label')}")
                shown[t] = shown.get(t, 0) + 1
