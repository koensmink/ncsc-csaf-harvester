# harvest_ncsc.py
import os
import re
import csv
import json
import datetime
from pathlib import Path
from typing import List, Dict, Optional
import requests

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LAST_RUN_FILE = Path("output/last_run.json")

PROVIDER_META = "https://advisories.ncsc.nl/.well-known/csaf/provider-metadata.json"
HREF_JSON_RE = re.compile(r'href="([^"]+?\.json)"', re.IGNORECASE)
ID_RE = re.compile(r"ncsc-(\d{4})-(\d{4})\.json", re.IGNORECASE)

BATCH_LIMIT = int(os.getenv("BATCH_LIMIT", "200"))  # pak laatste N files

# ---------------------------------------------------------------------
def log(msg: str) -> None:
    print(msg, flush=True)

def get_base_directory_from_metadata() -> Optional[str]:
    """Lees provider-metadata.json en retourneer directory_url (zonder trailing slash)."""
    try:
        r = requests.get(PROVIDER_META, headers={"User-Agent": "NCSC-CSAF-Harvester/1.0"}, timeout=30)
        r.raise_for_status()
        meta = r.json()
        for d in meta.get("distributions", []):
            if d.get("directory_url"):
                return d["directory_url"].rstrip("/")
        return (meta.get("base_url") or "").rstrip("/") or None
    except Exception as e:
        log(f"❌ Kon provider-metadata.json niet ophalen: {e}")
        return None

def normalize_listing_filenames(raw_links: List[str], year: int) -> List[str]:
    """
    Converteer hrefs uit HTML listing naar relatieve bestandsnamen binnen <year>/.
    Resultaat: ['ncsc-YYYY-NNNN.json', ...]
    """
    cleaned: List[str] = []
    for f in raw_links:
        f = f.strip()
        if not f:
            continue

        # Absolute URL -> extract deel na /csaf/v2/<year>/
        if f.startswith("http://") or f.startswith("https://"):
            m = re.search(rf"/csaf/v2/{year}/(.+\.json)$", f, flags=re.IGNORECASE)
            if not m:
                continue
            f = m.group(1)

        # Relatieve varianten cleanen
        f = f.lstrip("./")
        if f.startswith(f"{year}/"):
            f = f[len(f"{year}/"):]

        if ID_RE.search(f):
            cleaned.append(f)

    return cleaned

def sort_latest(files: List[str]) -> List[str]:
    """Sorteer op volgnummer in ncsc-YYYY-NNNN.json."""
    def key_fn(fn: str):
        m = ID_RE.search(fn)
        if not m:
            return (0, 0, fn.lower())
        y = int(m.group(1))
        seq = int(m.group(2))
        return (y, seq, fn.lower())
    return sorted(set(files), key=key_fn)

def fetch_ncsc_to_csv(out_csv: Path, batch_limit: int = 200) -> int:
    base_dir = get_base_directory_from_metadata()
    if not base_dir:
        log("❌ Geen directory_url in provider metadata gevonden.")
        return 0

    year = datetime.date.today().year
    dir_url = f"{base_dir}/{year}/"
    log(f"🔎 Gebruik directory listing: {dir_url}")

    try:
        r = requests.get(dir_url, headers={"User-Agent": "NCSC-CSAF-Harvester/1.0"}, timeout=30)
        r.raise_for_status()
        html = r.text
    except Exception as e:
        log(f"❌ Kan directory niet ophalen ({dir_url}): {e}")
        return 0

    raw_links = HREF_JSON_RE.findall(html)
    files = normalize_listing_filenames(raw_links, year)
    files_sorted = sort_latest(files)

    # laatste N meest recente
    to_fetch = files_sorted[-batch_limit:]

    rows: List[Dict[str, str]] = []
    for fn in to_fetch:
        url = f"{dir_url.rstrip('/')}/{fn.lstrip('/')}"
        try:
            resp = requests.get(url, headers={"User-Agent": "NCSC-CSAF-Harvester/1.0"}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log(f"⚠️ Skip {url}: {e}")
            continue

        doc = data.get("document") or {}
        tracking = doc.get("tracking") or {}
        tid = tracking.get("id") or fn.replace(".json", "")
        ver = tracking.get("version") or ""
        title = doc.get("title") or "Onbekend"
        sev = doc.get("aggregate_severity") or doc.get("severity") or ""

        # Bouw HTML advisory link
        m = re.match(r"(?i)NCSC-(\d{4})-(\d{4})", tid)
        if m:
            link = f"https://advisories.ncsc.nl/{m.group(1)}/ncsc-{m.group(1)}-{m.group(2)}.html"
        else:
            link = url

        rows.append({
            "AdvisoryID": tid,
            "Version": ver,
            "Severity": sev,
            "Description": title,
            "Link": link,
        })

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["AdvisoryID", "Version", "Severity", "Description", "Link"]
        )
        writer.writeheader()
        writer.writerows(rows)

    log(f"✅ {len(rows)} advisories geschreven naar {out_csv}")
    return len(rows)

def main() -> int:
    today = datetime.date.today().isoformat()
    out_csv = OUTPUT_DIR / f"{today}.csv"

    log(f"🔍 Start harvest run at {datetime.datetime.utcnow().isoformat()} UTC")
    count = fetch_ncsc_to_csv(out_csv, batch_limit=BATCH_LIMIT)

    LAST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    last_run = {
        "new_count": count,
        "csv_path": str(out_csv),
        "last_run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "todays_count": count,
    }
    LAST_RUN_FILE.write_text(json.dumps(last_run, indent=2, ensure_ascii=False), encoding="utf-8")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
