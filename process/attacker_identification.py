"""
process/attacker_identification.py

To identify attacker actors in the graph database (Neo4j)
"""

import re
import networkx as nx
import pandas as pd
from neo4j import GraphDatabase, Query
from neo4j.exceptions import Neo4jError


IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

ESCALATION_QUERY_TIMEOUT_SEC = 15  # if it takes longer than this, it is considered a failure and falls back.


def is_ip_actor(actor):
    return bool(IP_REGEX.match(actor))


def format_path(node_values, node_display, rel_types, rel_directions):
    """
    Format string path with node types at each hop:
    start -> REL1 (type1) -> REL2 (type2) -> ...
    """
    result = str(node_values[0])
    for i, rel in enumerate(rel_types):
        arrow = "->" if rel_directions[i] == "forward" else "<-"
        result += f" {arrow} {rel} ({node_display[i + 1]})"
    return result


def check_path(session, escalation_query, fallback_query, actor):
    """
    Check path for 1 actor in 2 stages:
    1. Try escalation-aware query first (cheap, targeted), with TIMEOUT —
       if it hangs/takes longer than ESCALATION_QUERY_TIMEOUT_SEC seconds, it is considered failed
       (not hanging forever) and automatically proceeds to stage 2.
    2. Fallback to general query (just check existence, no escalation requirement).
    Return (path_found: bool, rel_types_str: str).
    """
    try:
        result = session.run(Query(escalation_query, timeout=ESCALATION_QUERY_TIMEOUT_SEC), actor=actor)
        record = result.single()
        if record is not None:
            return True, format_path(record["node_values"], record["node_display"], record["rel_types"], record["rel_directions"])
    except Neo4jError as e:
        print(f"  WARN: query escalation timeout/error for actor={actor!r} ({e.code}) — proceeding to fallback")

    result = session.run(fallback_query, actor=actor)
    record = result.single()
    if record is not None:
        return True, format_path(record["node_values"], record["node_display"], record["rel_types"], record["rel_directions"])

    return False, "-"


class SimplePath:
    """A lightweight wrapper for handling paths in the graph."""
    def __init__(self, nodes, relationships):
        self.nodes = nodes
        self.relationships = relationships


def get_actual_path(session, actor, direction,
                     check_from_ip_escalation_path_query,
                     check_from_ip_path_query,
                     check_from_user_escalation_path_query,
                     check_from_user_path_query):
    """
    Retrieve the actual path object (Neo4j nodes and relationships) for 1 actor,
    using the same priority order and optimizations as check_path().
    """
    if direction == "ip_to_user":
        queries = [
            (check_from_ip_escalation_path_query, True),
            (check_from_ip_path_query, False),
        ]
    else:
        queries = [
            (check_from_user_escalation_path_query, True),
            (check_from_user_path_query, False),
        ]

    for query, is_escalation in queries:
        try:
            q = Query(query, timeout=ESCALATION_QUERY_TIMEOUT_SEC) if is_escalation else query
            result = session.run(q, actor=actor)
            record = result.single()
            if record is not None:
                return SimplePath(record["path_nodes"], record["path_rels"])
        except Neo4jError as e:
            print(f"  WARN: query timeout/error for actor={actor!r} ({e.code}) — proceeding to next query")

    return None


def add_node_to_graph(G, node):
    """Add 1 Neo4j node (original object) to the graph."""
    node_type = list(node.labels)[0] if node.labels else "Unknown"
    props = dict(node)
    G.add_node(node.element_id, node_type=node_type, **props)


class AttackerIdentification:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ──────────────────────────────────────────────────
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        # ── Output ────────────────────────────────────────────────────────────
        self.CSV_OUTPUT = f"results/{dataset}/result-7-1-attacker-identification.csv"
        self.CSV_OUTPUT_BENIGN = f"results/{dataset}/result-7-1-benign-identification.csv"

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        CSV_OUTPUT = self.CSV_OUTPUT
        CSV_OUTPUT_BENIGN = self.CSV_OUTPUT_BENIGN
        dataset = self.dataset

        # ── Section 3: Make sure Constraint/Index exist ──────────────
        ENSURE_CONSTRAINTS = [
            "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.username IS UNIQUE",
            "CREATE CONSTRAINT IF NOT EXISTS FOR (ip:IPAddress) REQUIRE ip.ip IS UNIQUE",
        ]

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            for stmt in ENSURE_CONSTRAINTS:
                session.run(stmt)
                print(f"OK: {stmt}")
        driver.close()

        # ── Section 4: Load list of the actor (distinct directly form graph) ────────
        GET_DISTINCT_ACTORS_QUERY = """
MATCH (u:User)-[]-(e)
WHERE e.label IS NOT NULL AND e.label <> 'benign'
RETURN DISTINCT u.username AS actor
UNION
MATCH (ip:IPAddress)-[]-(e)
WHERE e.label IS NOT NULL AND e.label <> 'benign'
RETURN DISTINCT ip.ip AS actor
"""

        # All actors that have a relationship to ANY node.
        GET_ALL_ACTORS_QUERY = """
MATCH (u:User)-[]-()
RETURN DISTINCT u.username AS actor
UNION
MATCH (ip:IPAddress)-[]-()
RETURN DISTINCT ip.ip AS actor
"""

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        with driver.session(database=NEO4J_DATABASE) as session:
            result = session.run(GET_DISTINCT_ACTORS_QUERY)
            actor_list = sorted(r["actor"] for r in result if r["actor"])

            all_result = session.run(GET_ALL_ACTORS_QUERY)
            all_actors = {r["actor"] for r in all_result if r["actor"]}
        driver.close()

        # all actors that have no relationship to any non-benign node.
        benign_actor_list = sorted(all_actors - set(actor_list))

        print(f"Total unique actors (User + IP Address) associated with at least one non-benign node: {len(actor_list)}")
        for a in actor_list:
            print(f"  - {a}")

        print()
        print(f"Total benign-only actors (not associated with any non-benign nodes): {len(benign_actor_list)}")
        for a in benign_actor_list:
            print(f"  - {a}")

        # ── Section 5: Cek Path in Graph — IPAddress <-> User ───────────────────
        # Step 1: escalation-aware
        CHECK_FROM_IP_ESCALATION_QUERY = """
MATCH (ip:IPAddress {ip: $actor})
MATCH front = (ip)-[:REQUEST]->()-[:RELATED_TO|TARGET_USER]->(u:User)
WITH ip, front, u
LIMIT 20
WHERE size((u)-[:PERFORMED]->()) <= 50
CALL {
    WITH u
    MATCH tail = (u)-[:PERFORMED|ESCALATED_TO*1..4]->(escalated:User)
    WHERE u <> escalated
    RETURN tail
    ORDER BY length(tail) ASC
    LIMIT 1
}
WITH ip, front, u, tail
ORDER BY length(tail) ASC
LIMIT 1
WITH nodes(front) + nodes(tail)[1..] AS all_nodes,
     relationships(front) + relationships(tail) AS all_rels
RETURN
    [n IN all_nodes | CASE
        WHEN n:IPAddress THEN n.ip
        WHEN n:User      THEN n.username
        ELSE null
    END] AS node_values,
    [n IN all_nodes | CASE
        WHEN n:User      THEN 'user: ' + n.username
        WHEN n:IPAddress THEN 'IPAddress: ' + n.ip
        ELSE labels(n)[0]
    END] AS node_display,
    [r IN all_rels | type(r)] AS rel_types,
    [i IN range(0, size(all_rels)-1) |
        CASE WHEN startNode(all_rels[i]) = all_nodes[i]
             THEN 'forward' ELSE 'backward' END
    ] AS rel_directions
LIMIT 1
"""

        CHECK_FROM_USER_ESCALATION_QUERY = """
MATCH (escalated:User {username: $actor})
WHERE size((escalated)<-[:ESCALATED_TO]-()) <= 50
CALL {
    WITH escalated
    MATCH tail = (escalated)<-[:PERFORMED|ESCALATED_TO*1..4]-(u:User)
    WHERE u <> escalated
    RETURN tail, u
    ORDER BY length(tail) ASC
    LIMIT 1
}
WITH escalated, tail, u
MATCH front = (u)<-[:RELATED_TO|TARGET_USER]-()<-[:REQUEST]-(ip:IPAddress)
WITH nodes(tail) + nodes(front)[1..] AS all_nodes,
     relationships(tail) + relationships(front) AS all_rels
RETURN
    [n IN all_nodes | CASE
        WHEN n:IPAddress THEN n.ip
        WHEN n:User      THEN n.username
        ELSE null
    END] AS node_values,
    [n IN all_nodes | CASE
        WHEN n:User      THEN 'user: ' + n.username
        WHEN n:IPAddress THEN 'IPAddress: ' + n.ip
        ELSE labels(n)[0]
    END] AS node_display,
    [r IN all_rels | type(r)] AS rel_types,
    [i IN range(0, size(all_rels)-1) |
        CASE WHEN startNode(all_rels[i]) = all_nodes[i]
             THEN 'forward' ELSE 'backward' END
    ] AS rel_directions
LIMIT 1
"""

        # Step 2: fallback (checks for the existence of any path, without escalation conditions.)
        CHECK_FROM_IP_QUERY = """
MATCH (ip:IPAddress {ip: $actor})
MATCH path = shortestPath((ip)-[rels:REQUEST|RELATED_TO|TARGET_USER|PERFORMED|ESCALATED_TO*1..6]->(u:User))
WITH path
ORDER BY length(path) ASC
LIMIT 1
RETURN
    [n IN nodes(path) | CASE
        WHEN n:IPAddress THEN n.ip
        WHEN n:User      THEN n.username
        ELSE null
    END] AS node_values,
    [n IN nodes(path) | CASE
        WHEN n:User      THEN 'user: ' + n.username
        WHEN n:IPAddress THEN 'IPAddress: ' + n.ip
        ELSE labels(n)[0]
    END] AS node_display,
    [r IN relationships(path) | type(r)] AS rel_types,
    [i IN range(0, size(relationships(path))-1) |
        CASE WHEN startNode(relationships(path)[i]) = nodes(path)[i]
             THEN 'forward' ELSE 'backward' END
    ] AS rel_directions
"""

        CHECK_FROM_USER_QUERY = """
MATCH (u:User {username: $actor})
MATCH path = shortestPath((u)<-[rels:REQUEST|RELATED_TO|TARGET_USER|PERFORMED|ESCALATED_TO*1..6]-(ip:IPAddress))
WITH path
ORDER BY length(path) ASC
LIMIT 1
RETURN
    [n IN nodes(path) | CASE
        WHEN n:IPAddress THEN n.ip
        WHEN n:User      THEN n.username
        ELSE null
    END] AS node_values,
    [n IN nodes(path) | CASE
        WHEN n:User      THEN 'user: ' + n.username
        WHEN n:IPAddress THEN 'IPAddress: ' + n.ip
        ELSE labels(n)[0]
    END] AS node_display,
    [r IN relationships(path) | type(r)] AS rel_types,
    [i IN range(0, size(relationships(path))-1) |
        CASE WHEN startNode(relationships(path)[i]) = nodes(path)[i]
             THEN 'forward' ELSE 'backward' END
    ] AS rel_directions
"""

        rows = []
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

        with driver.session(database=NEO4J_DATABASE) as session:
            for idx_actor, actor in enumerate(actor_list, 1):
                print(f"[{idx_actor}/{len(actor_list)}] Checking actor: {actor} ...", flush=True)

                path_ip_to_user, rel_ip_to_user = check_path(
                    session, CHECK_FROM_IP_ESCALATION_QUERY, CHECK_FROM_IP_QUERY, actor)
                path_user_to_ip, rel_user_to_ip = check_path(
                    session, CHECK_FROM_USER_ESCALATION_QUERY, CHECK_FROM_USER_QUERY, actor)

                # main-attack if one of the directions connects to a path
                status = "main-attack" if (path_ip_to_user or path_user_to_ip) else "noise-attack"

                rows.append({
                    "user":                  actor,
                    "path_ip_to_user":       "Yes" if path_ip_to_user else "No",
                    "relations_ip_to_user":  rel_ip_to_user,
                    "path_user_to_ip":       "Yes" if path_user_to_ip else "No",
                    "relations_user_to_ip":  rel_user_to_ip,
                    "status":                status,
                })

        driver.close()

        print(f"Selesai cek {len(rows)} actor.")

        # ── Section 6: Export to CSV ─────────────────────────────────────────
        df_result = pd.DataFrame(rows)

        # Sort
        df_result["_status_order"] = df_result["status"].map({"main-attack": 0, "noise-attack": 1}).fillna(2)
        df_result["_path_ip_order"] = df_result["path_ip_to_user"].map({"Yes": 0, "No": 1}).fillna(2)

        df_result = df_result.sort_values(
            by=["_status_order", "_path_ip_order"]
        ).drop(columns=["_status_order", "_path_ip_order"]).reset_index(drop=True)

        df_result["status"] = "attacker"
        df_result["relation_to_anomaly"] = "yes"

        cols = list(df_result.columns)
        cols.remove("relation_to_anomaly")
        user_idx = cols.index("user")
        cols.insert(user_idx + 1, "relation_to_anomaly")
        df_result = df_result[cols]

        df_result.to_csv(CSV_OUTPUT, index=False)

        print(f"Disimpan ke: {CSV_OUTPUT}")
        print()
        print(df_result.to_string(index=False))
        print()
        print("Ringkasan status:")
        print(df_result["status"].value_counts())

        # ── Section 6.1: Export Actor Benign-Only to CSV ────────────────────
        df_benign = pd.DataFrame({"user": benign_actor_list})
        df_benign["relation_to_anomaly"] = "no"

        df_benign["path_ip_to_user"] = "-"
        df_benign["relations_ip_to_user"] = "-"
        df_benign["path_user_to_ip"] = "-"
        df_benign["relations_user_to_ip"] = "-"
        df_benign["status"] = "benign"

        df_benign = df_benign[[
            "user", "relation_to_anomaly", "path_ip_to_user", "relations_ip_to_user",
            "path_user_to_ip", "relations_user_to_ip", "status",
        ]]

        df_benign.to_csv(CSV_OUTPUT_BENIGN, index=False)

        print(f"Saved to: {CSV_OUTPUT_BENIGN}")
        print()
        print(df_benign.to_string(index=False))