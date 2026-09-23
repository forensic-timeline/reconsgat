"""
graph_extractor.py
==================
Loader dan engine untuk extraction template YAML.
Membaca web_graph_extract.yaml, auth_graph_extract.yaml, syslog_graph_extract.yaml
dan menggunakannya untuk parse log + insert ke Neo4j.

Cara pakai:
    from graph_extractor import GraphExtractor
    extractor = GraphExtractor(
        templates_dir=".",
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="adminkami"
    )
    extractor.process_row(row)   # row = dict dari CSV
"""

import re
import yaml
from pathlib import Path
from typing import Optional
from neo4j import GraphDatabase


# ── Konstanta kolom CSV ───────────────────────────────────────
COL_EVENT_ID    = 0
COL_TIMESTAMP   = 1
COL_ACTOR       = 10
COL_DESC        = 11
COL_FILENAME    = 7
COL_LABEL       = 13
COL_SOURCE_FILE = 7


class ExtractionTemplate:
    """Merepresentasikan satu file YAML template."""

    def __init__(self, path: str):
        with open(path, encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
        self.log_type  = self.config["log_type"]
        self.node_type = self.config["node_type"]
        self.detect    = self.config.get("detect", {})
        self.patterns  = self.config.get("patterns", {})
        self.cypher    = self.config.get("cypher", {})

    def matches_file(self, filename: str, parser: str, line: str = "") -> bool:
        """Cek apakah template ini cocok untuk file/parser/line tertentu."""
        fname_lower = filename.lower()

        # Cek filename_not_contains dulu (exclude)
        for excl in self.detect.get("filename_not_contains", []):
            if excl.lower() in fname_lower:
                return False

        # Cek line_not_contains (exclude berdasarkan konten log)
        for excl in self.detect.get("line_not_contains", []):
            if excl.lower() in line.lower():
                return False

        # Cek filename_contains
        for inc in self.detect.get("filename_contains", []):
            if inc.lower() in fname_lower:
                return True

        # Cek parser
        for p in self.detect.get("parser_equals", []):
            if p.lower() == parser.lower():
                return True

        return False

    def extract_fields(self, line: str) -> dict:
        """
        Jalankan semua pattern secara berurutan dan extract field.
        Untuk auth.log: pattern pertama yang match dipakai (exclusive).
        Untuk access.log/syslog: semua pattern dijalankan (additive).
        """
        result = {}
        exclusive = self.log_type == "auth.log"

        for pattern_name, pattern_cfg in self.patterns.items():
            regex   = pattern_cfg["regex"]
            fields  = pattern_cfg.get("fields", {})
            defaults = pattern_cfg.get("defaults", {})
            sub_patterns = pattern_cfg.get("sub_patterns", {})

            m = re.search(regex, line)

            if m:
                # Apply defaults dulu
                for key, val in defaults.items():
                    if key not in result:
                        result[key] = val

                # Extract dari group
                for field_name, field_cfg in fields.items():
                    group = field_cfg["group"]
                    val   = m.group(group) if group <= m.lastindex else ""

                    # Transform
                    if field_cfg.get("transform") == "lower":
                        val = val.lower()

                    # Type cast
                    if field_cfg.get("type") == "int":
                        try:
                            val = int(val)
                        except (ValueError, TypeError):
                            val = 0

                    result[field_name] = val

                # Handle auth_type_prefix (untuk PAM)
                if "auth_type_prefix" in defaults:
                    suffix_group = defaults.get("auth_type_group", 2)
                    try:
                        suffix = m.group(suffix_group)
                        result["auth_type"] = defaults["auth_type_prefix"] + suffix
                    except IndexError:
                        result["auth_type"] = defaults["auth_type_prefix"]

                # Sub-patterns (untuk sudo)
                for sub_field, sub_cfg in sub_patterns.items():
                    sub_m = re.search(sub_cfg["regex"], line)
                    if sub_m:
                        val = sub_m.group(sub_cfg["group"])
                        if sub_cfg.get("rstrip"):
                            val = val.rstrip(sub_cfg["rstrip"])
                        result[sub_field] = val
                    else:
                        result.setdefault(sub_field, "")

                if exclusive:
                    break  # auth.log: stop di pattern pertama yang match

            else:
                # Pattern tidak match, apply defaults saja
                if not exclusive:
                    for key, val in defaults.items():
                        result.setdefault(key, val)

        return result


class GraphExtractor:
    """Engine utama yang membaca template YAML dan insert ke Neo4j."""

    def __init__(self, templates_dir: str, neo4j_uri: str,
                 neo4j_user: str, neo4j_password: str,
                 neo4j_database: str = "neo4j",
                 include_benign: bool = False):
        self.driver    = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.database  = neo4j_database
        self.templates = self._load_templates(templates_dir)
        self.include_benign = include_benign
        self._username_cache: set = set()
        print(f"Loaded {len(self.templates)} templates: "
              f"{[t.log_type for t in self.templates]}")
        print(f"  Target database: {self.database}")
        print(f"  Include benign : {self.include_benign}")

    def _load_templates(self, templates_dir: str) -> list:
        templates = []
        template_files = [
            "web_graph_extract.yaml",
            "auth_graph_extract.yaml",
            "syslog_graph_extract.yaml",
        ]
        for fname in template_files:
            path = Path(templates_dir) / fname
            if path.exists():
                templates.append(ExtractionTemplate(str(path)))
                print(f"  Loaded: {fname}")
            else:
                print(f"  SKIP (not found): {fname}")
        return templates

    def load_username_cache(self):
        """Load semua username dari Neo4j ke cache lokal."""
        with self.driver.session(database=self.database) as session:
            result = session.run("MATCH (u:User) RETURN u.username as username")
            self._username_cache = {r["username"] for r in result}
        print(f"Username cache loaded: {len(self._username_cache)} users")

    def add_to_cache(self, username: str):
        if username:
            self._username_cache.add(username)

    def find_matching_username(self, payload_items: list) -> Optional[str]:
        """Cari username dari payload yang ada di cache."""
        import json
        if isinstance(payload_items, str):
            try:
                payload_items = json.loads(payload_items)
            except Exception:
                return None
        if isinstance(payload_items, list):
            for item in payload_items:
                if isinstance(item, str) and item in self._username_cache:
                    return item
        return None

    def _get_template(self, filename: str, parser: str, line: str = "") -> Optional[ExtractionTemplate]:
        """Cari template yang cocok untuk file/parser/line ini."""
        for template in self.templates:
            if template.matches_file(filename, parser, line):
                return template
        return None

    def process_row(self, row: list):
        """Proses satu baris CSV dan insert ke Neo4j."""
        from datetime import datetime, timezone

        event_id    = row[COL_EVENT_ID]
        timestamp   = row[COL_TIMESTAMP]
        actor_from_csv = row[COL_ACTOR]
        desc        = row[COL_DESC]
        filename    = row[COL_FILENAME]
        label_raw   = row[COL_LABEL]
        source_file = row[COL_SOURCE_FILE]

        # Deteksi parser dari filename (kolom 6)
        parser = row[6]

        # Parse label dan severity
        label, severity = self._parse_label(label_raw)
        if label.lower() == "benign" and not self.include_benign:
            return  # Skip benign (kecuali include_benign=True)

        # Cari template yang cocok
        template = self._get_template(filename, parser, desc)
        if template is None:
            print(f"  WARN: Tidak ada template untuk event_id={event_id} "
                  f"file={filename} parser={parser}")
            return

        # Extract fields dari log line
        fields = template.extract_fields(desc)

        # Inject shared fields
        fields.update({
            "event_id":    event_id,
            "label":       label,
            "severity":    severity,
            "message":     desc,
            "source_file": source_file,
            "timestamp":   timestamp,
        })

        # Actor diambil LANGSUNG dari kolom 'actor' di CSV .
        fields["actor"] = actor_from_csv

        if template.log_type in ("access.log", "web_log"):
            # Cek matched username dari payload (untuk link HTTPRequest ke 
            # node User kalau payload webshell
            # menunjukkan identitas user tertentu, 
            # bukan penentuan actor itu sendiri)
            matched_user = self.find_matching_username(fields.get("decoded_payload"))
            fields["matched_username"] = matched_user

        # Pilih Cypher query dan execute
        self._execute(template, fields)

        # Update cache
        username = fields.get("username") or fields.get("extracted_username")
        if username:
            self.add_to_cache(username)

    def _execute(self, template: ExtractionTemplate, fields: dict):
        """Pilih Cypher template yang tepat dan jalankan."""
        cypher_cfg = template.cypher

        # Tentukan branch
        if template.log_type in ("access.log", "web_log"):
            matched = fields.get("matched_username")
            branch = "with_user" if matched else "orphan"
            if branch == "with_user":
                fields["username"] = matched
            # DEBUG — cek mapping username dari payload
            payload = fields.get("decoded_payload", "")
            # if payload and any(u in str(payload) for u in ["phopkins", "kford", "jwilkinson"]):
            #     print(f"[DEBUG] event_id={fields.get('event_id')} payload={str(payload)[:80]}")
            #     print(f"[DEBUG] matched_username={matched} branch={branch}")
            #     print(f"[DEBUG] username_cache sample={list(self._username_cache)[:5]}")
        elif template.log_type == "auth.log":
            auth_type = fields.get("auth_type", "")
            username  = fields.get("username", "")
            if username and auth_type == "ssh":
                branch = "with_user_ssh"
            elif username:
                branch = "with_user"
            elif auth_type.startswith("pam_") and fields.get("target_user"):
                branch = "pam_orphan"
            else:
                branch = "orphan"
        elif template.log_type == "syslog":
            branch = "with_user" if fields.get("extracted_username") else "orphan"
            if branch == "with_user":
                fields["username"] = fields["extracted_username"]
        else:
            branch = "orphan"

        if branch not in cypher_cfg:
            print(f"  WARN: branch '{branch}' tidak ada di template {template.log_type}")
            return

        cfg   = cypher_cfg[branch]
        query = cfg["query"]
        params_keys = cfg.get("params", [])

        # Build params dari fields
        params = {k: fields.get(k, "") for k in params_keys}

        # Pastikan status_code adalah int
        if "status_code" in params:
            try:
                params["status_code"] = int(params["status_code"])
            except (ValueError, TypeError):
                params["status_code"] = 0

        with self.driver.session(database=self.database) as session:
            session.run(query, **params)

    def _parse_label(self, label_raw: str):
        """Parse 'Label Name[severity]' menjadi (label, severity)."""
        label_raw = label_raw.strip()
        if label_raw.lower() == "benign":
            return "benign", "benign"
        m = re.search(r'^(.+?)\[(\w+)\]$', label_raw)
        if m:
            return m.group(1).strip(), m.group(2).strip()
        return label_raw, "unknown"

    def close(self):
        self.driver.close()