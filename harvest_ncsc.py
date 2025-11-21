#!/usr/bin/env python3
import os
import csv
import json
import datetime
import requests
from pathlib import Path
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# ------------------------------------------------------------
# Config
# ------------------------------------------------------------
YEAR = datetime.datetime.utcnow().year
BASE_ROOT = "https://advisories.ncsc.nl/"
BASE_DIR = f"https://advisories.ncsc.nl/csaf/v2/{YEAR}/"

OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LAST_RUN_PATH = Path("output/last_run.json")


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def save_last_run(csv_path: str, count: int) -> None:
    data = {
        "last_run_at": datetime.datetime.utcnow().isoformat(),
        "todays_count": count,
        "csv_path": csv_path,
    }
    LAST_RUN_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def fetch_directory_listing() -> list[str]:
    """Return list of JSON filenames from index HTML."""
    print(f"🔎 Gebruik directory listing: {BASE_DIR}")

    r = requests.get(BASE_DIR, timeout=20)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    links = soup.find_all("a")

    json_files = []
    for a in links:
        href = a.get("href")
        if not href:
            continue
        if href.lower().endswith(".json"):
            json_files.append(href)

    return json_files


def normalize_advisory(json_data: dict) -> dict:
    """Extract normalized advisory fields."""
    doc = json_data.get("document", {})
    meta = doc.get("tracking", {})

    return {
        "AdvisoryID": meta.get("id", ""),
        "Version": str(meta.get("version", "")),
        "Severity": doc.get("category", ""),
        "Description": meta.get("summary", ""),
        "AdvisoryURL": meta.get("generator", {}).get("engine", {}),
    }


# ------------------------------------------------------------
# Main harvest logic
# ------------------------------------------------------------
def main():
    today = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    out_csv = OUTPUT_DIR / f"{today}.csv"

    json_files = fetch_directory_listing()
    print(f"📄 {len(json_files)} JSON-bestanden gevonden.")

    rows = []

    for href in json_files:
        # -------------------------------
        # URL opbouw (BELANGRIJKE FIX!)
        # -------------------------------
        if href.startswith("http://") or href.startswith("https://"):
            advisory_url = href
        elif href.startswith("csaf/"):
            advisory_url = urljoin(BASE_ROOT, href.lstrip("/"))
        else:
            advisory_url = urljoin(BASE_DIR, href)

        try:
            r = requests.get(advisory_url, timeout=20)
            if r.status_code != 200:
                print(f"⚠️ Skip {advisory_url}: {r.status_code}")
                continue

            data = r.json()
            normalized = normalize_advisory(data)
            normalized["Link"] = advisory_url
            rows.append(normalized)

        except Exception as e:
            print(f"⚠️ Error tijdens ophalen {advisory_url}: {e}")
            continue

    # ------------------------------------------------------------
    # CSV schrijven
    # ------------------------------------------------------------
    fieldnames = ["AdvisoryID", "Version", "Severity", "Description", "Link"]

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    save_last_run(str(out_csv), len(rows))

    print(f"✅ {len(rows)} advisories geschreven naar {out_csv}")
    return 0


if __name__ == "__main__":
    main()
