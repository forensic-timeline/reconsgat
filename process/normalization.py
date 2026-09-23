"""
process/normalization.py

Konversi dari 1_normalization.ipynb. Semua logika dipertahankan
PERSIS SAMA seperti versi notebook -- cuma dibungkus jadi class
supaya bisa dipanggil dari main.py.
"""

import csv
import re
import yaml


class Normalization:
    def __init__(self, dataset):
        self.dataset = dataset
        self.CSV_INPUT = f"dataset/{dataset}.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-1-normalization.csv"
        # path rule actor enrichment
        self.RULES_FILE = "rules-actor-enrichment/actor_enrichment.yaml"

    def count_lines(self, path):
        # fast line count
        cnt = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for _ in f:
                cnt += 1
        return cnt

    def normalize_url_encoding(self, url):
        """
        Normalisasi URL encoding pada URL.

        1. Convert ~xx to %xx (contoh: ~20 menjadi %20)
        2. Replace + with %20 (treat + as space)
        3. Replace literal spaces with %20

        Parameters:
        - url: String URL yang akan dinormalisasi

        Returns:
        - String URL yang sudah dinormalisasi
        """

        # 1. Convert ~xx to %xx (contoh: ~20, ~3D, ~2F)
        url = re.sub(r'~([0-9A-Fa-f]{2})', r'%\1', url)

        # 2. Replace + with %20
        url = url.replace('+', '%20')

        # 3. Replace literal spaces with %20
        url = url.replace(' ', '%20')

        return url

    def normalize_message(self, message):
        """
        Normalisasi message.
        - Jika http_request: normalisasi hanya bagian URL
        - Jika bukan http_request: kembalikan message apa adanya

        Parameters:
        - message: String message lengkap

        Returns:
        - String message yang sudah dinormalisasi
        """

        # Jika bukan http_request, kembalikan apa adanya
        if not message.startswith('http_request:'):
            return message

        # Pattern untuk menangkap: http_request: METHOD URL HTTP/x.x
        # Group 1: bagian awal (http_request: METHOD )
        # Group 2: URL path
        # Group 3: bagian akhir (HTTP/x.x ...)
        pattern = r'^(http_request:\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+)(\S+)(\s+HTTP/.*)$'

        match = re.match(pattern, message)

        if match:
            prefix = match.group(1)  # http_request: GET
            url = match.group(2)      # /wp-content/...
            suffix = match.group(3)   # HTTP/1.1 from: ...

            # Normalisasi hanya bagian URL
            normalized_url = self.normalize_url_encoding(url)

            return prefix + normalized_url + suffix

        # Jika tidak match pattern, kembalikan message asli
        return message

    def _load_actor_rules(self):
        # Load rules actor enrichment dari YAML
        with open(self.RULES_FILE, "r") as f:
            enrichment_config = yaml.safe_load(f)

        compiled_rules = []
        for rule in enrichment_config["rules"]:
            compiled_rules.append({
                "name": rule["name"],
                "pattern": re.compile(rule["pattern"], re.IGNORECASE),
                "group": rule["group"],
                "strip_punctuation": rule.get("strip_punctuation", False),
            })

        self.compiled_rules = compiled_rules
        self.FALLBACK_ACTOR = enrichment_config.get("fallback", {}).get("default", "-")

    def extract_actor(self, message):
        """
        Ekstrak actor dari message mentah (belum dinormalisasi),
        berdasarkan rules di actor_enrichment.yaml.
        Rule dicek berurutan, rule pertama yang match dipakai.

        Parameters:
        - message: String message asli (raw)

        Returns:
        - String actor, atau fallback default ("-") jika tidak ada rule yang cocok
        """
        desc = str(message)

        for rule in self.compiled_rules:
            match = rule["pattern"].search(desc)
            if match:
                result = match.group(rule["group"])
                if rule["strip_punctuation"]:
                    result = result.rstrip('.,;:')
                return result

        return self.FALLBACK_ACTOR

    def run(self):
        # Load rules actor enrichment dari YAML (setara Section 3.1 di notebook)
        self._load_actor_rules()

        total_lines = self.count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")

        processed = 0

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(self.CSV_OUTPUT, "w", newline='', encoding="utf-8") as out:
            reader = csv.DictReader(f)
            writer = csv.writer(out)

            # Tambahkan kolom baru di awal
            fieldnames = ["event_id"] + reader.fieldnames + ["normalized", "actor"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                processed += 1

                # Ambil dan normalisasi kolom message
                original_message = row["message"]
                normalized_message = self.normalize_message(original_message)

                # Ekstrak actor dari message asli (raw), bukan dari yang sudah dinormalisasi
                actor = self.extract_actor(original_message)

                # Replace message
                row["normalized"] = normalized_message
                row["actor"] = actor
                row["event_id"] = processed

                writer.writerow(row)

                # Progress tiap 50.000 baris
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

        print(f"Conversion finished: {processed}/{total_lines} lines processed.")
