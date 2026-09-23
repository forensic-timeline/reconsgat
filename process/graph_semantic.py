"""
process/graph_semantic.py

To group events based on its semantic label,
create High-Level Event (HLE) nodes, contain edge, attack event sequences, 
and save it to Neo4j database.
"""

import csv
from neo4j import GraphDatabase


class GraphSemantic:
    def __init__(self, dataset):
        self.dataset = dataset

        # ── Neo4j Connection ──────
        self.NEO4J_URI      = "bolt://localhost:7687"
        self.NEO4J_USER     = "neo4j"
        self.NEO4J_PASSWORD = "adminkami"
        self.NEO4J_DATABASE = dataset

        # ── Number of top attackers processed ───
        self.TOP_N_ACTORS = None  # num of attackers to process, None = all

        # ── HLE grouping config ──
        # True  = event combined to 1 HLE if only label AND actor are the same
        # False = only label is required (actors can be different) to group events into the same HLE
        self.REQUIRE_SAME_ACTOR = False

        self.ACTOR_RANKING_CSV = f"results/{dataset}/result-7-1-attacker-identification.csv"

    def aggregate_to_hle(self, events, require_same_actor=True):
        """
        Group consecutive non-benign events with same label.
        """
        hle_list    = []
        hle_counter = 1

        current_label       = None
        current_actor       = None
        current_group       = []
        current_element_ids = []

        def flush_group():
            nonlocal hle_counter
            if not current_group:
                return
            first = current_group[0]
            # take the highest severity in the group
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
            max_sev = max(current_group, key=lambda e: sev_order.get(e["severity"], 0))
            # gather unique attacker
            actors_seen = []
            for e in current_group:
                a = e.get("actor", "")
                if a and a not in actors_seen:
                    actors_seen.append(a)
            hle_list.append({
                "hle_id":      f"HLE-{hle_counter}",
                "label":       current_label,
                "severity":    max_sev["severity"],
                "group_count": len(current_group),
                "event_ids":   [e["event_id"] for e in current_group],
                "element_ids": list(current_element_ids),
                "timestamp":   first["timestamp"],
                "node_types":  list(set(e["node_type"] for e in current_group)),
                "actors":      actors_seen,
            })
            hle_counter += 1

        for event in events:
            # Skip benign
            if event["label"].lower() == "benign":
                continue

            event_actor = event.get("actor", "")

            same_label = event["label"] == current_label
            same_actor = (event_actor == current_actor) if require_same_actor else True

            if same_label and same_actor:
                # same label, add to group
                current_group.append(event)
                current_element_ids.append(event["element_id"])
            else:
                # different label, flush, start new group
                flush_group()
                current_label       = event["label"]
                current_actor       = event_actor
                current_group       = [event]
                current_element_ids = [event["element_id"]]

        flush_group()

        return hle_list

    def save_hle_to_neo4j(self, uri, user, password, hle_list):
        CREATE_HLE_QUERY = """
MERGE (hle:HighLevelEvent {hle_id: $hle_id})
SET
    hle.label       = $label,
    hle.severity    = $severity,
    hle.group_count = $group_count,
    hle.event_ids   = $event_ids,
    hle.actors      = $actors,
    hle.timestamp   = $timestamp
RETURN hle.hle_id AS created
"""

        LINK_CONTAINS_QUERY = """
MATCH (hle:HighLevelEvent {hle_id: $hle_id})
MATCH (e) WHERE elementId(e) = $element_id
MERGE (hle)-[:CONTAINS]->(e)
"""

        LINK_FOLLOWED_BY_QUERY = """
MATCH (hle1:HighLevelEvent {hle_id: $hle_id_1})
MATCH (hle2:HighLevelEvent {hle_id: $hle_id_2})
MERGE (hle1)-[:FOLLOWED_BY]->(hle2)
"""

        driver = GraphDatabase.driver(uri, auth=(user, password))

        print(f"\nCreating HLE nodes in graph...")
        with driver.session(database=self.NEO4J_DATABASE) as session:
            # 1. create node HLE
            for hle in hle_list:
                session.run(CREATE_HLE_QUERY,
                    hle_id      = hle["hle_id"],
                    label       = hle["label"],
                    severity    = hle["severity"],
                    group_count = hle["group_count"],
                    event_ids   = hle["event_ids"],
                    actors      = hle.get("actors", []),
                    timestamp   = hle["timestamp"],
                )
                print(f"  Created: {hle['hle_id']} ({hle['label']})")

            # 2. create CONTAINS relationships to low-level events
            contains_count = 0
            for hle in hle_list:
                for eid in hle["element_ids"]:
                    session.run(LINK_CONTAINS_QUERY,
                        hle_id     = hle["hle_id"],
                        element_id = eid,
                    )
                    contains_count += 1

            # 3. create FOLLOWED_BY relationships between HLE nodes
            for i in range(len(hle_list) - 1):
                session.run(LINK_FOLLOWED_BY_QUERY,
                    hle_id_1 = hle_list[i]["hle_id"],
                    hle_id_2 = hle_list[i + 1]["hle_id"],
                )

        driver.close()
        print(f"\nDone!")
        print(f"  HLE nodes   : {len(hle_list)}")
        print(f"  CONTAINS    : {contains_count} relationships")
        print(f"  FOLLOWED_BY : {len(hle_list) - 1} relationships")

    def run(self):
        NEO4J_URI = self.NEO4J_URI
        NEO4J_USER = self.NEO4J_USER
        NEO4J_PASSWORD = self.NEO4J_PASSWORD
        NEO4J_DATABASE = self.NEO4J_DATABASE
        TOP_N_ACTORS = self.TOP_N_ACTORS
        REQUIRE_SAME_ACTOR = self.REQUIRE_SAME_ACTOR
        ACTOR_RANKING_CSV = self.ACTOR_RANKING_CSV

        # ── Section 3: Fetch Events from Neo4j ──
        # take the top TOP_N_ACTORS from CSV based on highest h_score
        with open(ACTOR_RANKING_CSV, newline="", encoding="utf-8") as f:
            _rows = list(csv.DictReader(f))

        TARGET_IPS = [r["user"] for r in _rows[:TOP_N_ACTORS]]

        print(f"Top {TOP_N_ACTORS} actor(s):")
        for i, ip in enumerate(TARGET_IPS, 1):
            print(f"  {i}. {ip}")

        # ── Query fetch events ───

        # Path 1: HTTPRequest and AuthEvent directly via REQUEST from IP
        print("Fetching events from Neo4j...")
        FETCH_QUERY_DIRECT = """
MATCH (ip:IPAddress {ip: $target_ip})-[:REQUEST]->(e)
WHERE (e:HTTPRequest OR e:AuthEvent)
  AND e.label IS NOT NULL
  AND e.label <> 'benign'
RETURN DISTINCT
    e.event_id          AS event_id,
    e.timestamp         AS timestamp,
    e.label             AS label,
    e.severity          AS severity,
    labels(e)[0]        AS node_type,
    elementId(e)        AS element_id,
    e.actor             AS node_actor
"""

        # Path 2: AuthEvent from user linked to IP via AuthEvent->TARGET_USER
        FETCH_QUERY_VIA_AUTH_USER = """
MATCH (ip:IPAddress {ip: $target_ip})-[:REQUEST]->(:AuthEvent)-[:TARGET_USER]->(u:User)
MATCH (u)-[:PERFORMED]->(e:AuthEvent)
WHERE e.label IS NOT NULL
  AND e.label <> 'benign'
RETURN DISTINCT
    e.event_id          AS event_id,
    e.timestamp         AS timestamp,
    e.label             AS label,
    e.severity          AS severity,
    labels(e)[0]        AS node_type,
    elementId(e)        AS element_id,
    e.actor             AS node_actor
"""

        # Path 3: AuthEvent from user linked to IP via HTTPRequest->RELATED_TO
        FETCH_QUERY_VIA_HTTP_USER = """
MATCH (ip:IPAddress {ip: $target_ip})-[:REQUEST]->(:HTTPRequest)-[:RELATED_TO]->(u:User)
MATCH (u)-[:PERFORMED]->(e:AuthEvent)
WHERE e.label IS NOT NULL
  AND e.label <> 'benign'
RETURN DISTINCT
    e.event_id          AS event_id,
    e.timestamp         AS timestamp,
    e.label             AS label,
    e.severity          AS severity,
    labels(e)[0]        AS node_type,
    elementId(e)        AS element_id,
    e.actor             AS node_actor
"""

        # Path 4: AuthEvent sudo with ESCALATED_TO — via AuthEvent user
        FETCH_QUERY_ESCALATED_AUTH = """
MATCH (ip:IPAddress {ip: $target_ip})-[:REQUEST]->(:AuthEvent)-[:TARGET_USER]->(u:User)
MATCH (u)-[:PERFORMED]->(e:AuthEvent)-[:ESCALATED_TO]->(:User)
WHERE e.label IS NOT NULL
  AND e.label <> 'benign'
RETURN DISTINCT
    e.event_id          AS event_id,
    e.timestamp         AS timestamp,
    e.label             AS label,
    e.severity          AS severity,
    labels(e)[0]        AS node_type,
    elementId(e)        AS element_id,
    e.actor             AS node_actor
"""

        # Path 5: AuthEvent sudo with ESCALATED_TO — via HTTPRequest user
        FETCH_QUERY_ESCALATED_HTTP = """
MATCH (ip:IPAddress {ip: $target_ip})-[:REQUEST]->(:HTTPRequest)-[:RELATED_TO]->(u:User)
MATCH (u)-[:PERFORMED]->(e:AuthEvent)-[:ESCALATED_TO]->(:User)
WHERE e.label IS NOT NULL
  AND e.label <> 'benign'
RETURN DISTINCT
    e.event_id          AS event_id,
    e.timestamp         AS timestamp,
    e.label             AS label,
    e.severity          AS severity,
    labels(e)[0]        AS node_type,
    elementId(e)        AS element_id,
    e.actor             AS node_actor
"""

        # Path 6: SystemEvent from User linked to IP
        FETCH_QUERY_SYSLOG = """
MATCH (ip:IPAddress {ip: $target_ip})-[:REQUEST]->(:AuthEvent)-[:TARGET_USER]->(u:User)
MATCH (u)-[:TRIGGERED]->(e:SystemEvent)
WHERE e.label IS NOT NULL
  AND e.label <> 'benign'
RETURN DISTINCT
    e.event_id          AS event_id,
    e.timestamp         AS timestamp,
    e.label             AS label,
    e.severity          AS severity,
    labels(e)[0]        AS node_type,
    elementId(e)        AS element_id,
    e.actor             AS node_actor
"""

        def fetch_events(target_ip):
            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
            seen   = set()
            events = []

            def collect(result):
                for record in result:
                    eid = record["element_id"]
                    if eid in seen:
                        continue
                    seen.add(eid)
                    node_actor = record["node_actor"]
                    events.append({
                        "event_id":   record["event_id"],
                        "timestamp":  record["timestamp"],
                        "label":      record["label"],
                        "severity":   record["severity"],
                        "node_type":  record["node_type"],
                        "element_id": eid,
                        "actor":      node_actor or target_ip,
                    })

            with driver.session(database=NEO4J_DATABASE) as session:
                collect(session.run(FETCH_QUERY_DIRECT,         target_ip=target_ip))
                collect(session.run(FETCH_QUERY_VIA_AUTH_USER,  target_ip=target_ip))
                collect(session.run(FETCH_QUERY_VIA_HTTP_USER,  target_ip=target_ip))
                collect(session.run(FETCH_QUERY_ESCALATED_AUTH, target_ip=target_ip))
                try:
                    collect(session.run(FETCH_QUERY_SYSLOG,     target_ip=target_ip))
                except Exception:
                    pass  
                collect(session.run(FETCH_QUERY_ESCALATED_HTTP, target_ip=target_ip))

            driver.close()
            events.sort(key=lambda e: (e["timestamp"] or "", int(e["event_id"])))
            print(f"  Fetched: {len(events)} events from IP {target_ip}")
            return events

        # Fetch events for all TARGET_IPS and combine
        all_events_per_ip = {}
        combined_events   = []
        for ip in TARGET_IPS:
            evs = fetch_events(ip)
            all_events_per_ip[ip] = evs
            combined_events.extend(evs)

        # Sort combine event based on timestamp.
        combined_events.sort(key=lambda e: (e["timestamp"] or "", int(e["event_id"])))
        print(f"\nTotal combined events: {len(combined_events)}")

        # ── Section 4: Aggregation → High-Level Events (HLE) ──
        # Aggregate all event from all attacker
        hle_list = self.aggregate_to_hle(combined_events, require_same_actor=REQUIRE_SAME_ACTOR)

        print(f"Total HLE: {len(hle_list)}")
        print()
        print("Detail:")
        for hle in hle_list:
            actors_str = ", ".join(hle["actors"])
            print(f"  {hle['hle_id']:10s} | {hle['label'][:35]:35s} | "
                  f"severity={hle['severity']:8s} | count={hle['group_count']:3d} | "
                  f"actors=[{actors_str}]")

        # ── Section 5: Save HLE to Neo4j ───
        self.save_hle_to_neo4j(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, hle_list)
