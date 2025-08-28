import feedparser
from pathlib import Path
import json
import csv
import re
from datetime import datetime
from zoneinfo import ZoneInfo  # Python 3.9+

FEED_URL = "https://advisories.ncsc.nl/rss/advisories"
BASE_DIR = Path("output/daily")
SEEN_FILE = Path("output/seen.json")
LAST_RUN_FILE = Path("output/last_run.json")
TZ = ZoneInfo("Europe/Amsterdam")

def load_seen():
    if SEEN_FILE.exists():
        return json.loads(SEEN_FILE.read_text(encoding="utf-8"))
    return {}  # {advisory_id: "YYYY-MM-DD"}

def save_seen(seen):
    SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    SEEN_FILE.write_text(json.dumps(seen, indent=2, ensure_ascii=False), encoding="utf-8")

def open_daily_csv(date_str):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = BASE_DIR / f"{date_str}.csv"
    file_exists = out_file.exists()
    f = open(out_file, "a", newline="", encoding="utf-8")
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow(["AdvisoryID", "Version", "Severity", "Description", "Link"])
    return out_file, f, writer

def advisory_id(entry):
    return entry.get("id") or entry.get("link")

def parse_title(title: str):
    """
    Verwachte structuur van de titel:
    NCSC-2025-0271 [1.00] [M/H] Kwetsbaarheden verholpen in ...
    """
    pattern = r"^(NCSC-\d{4}-\d{4})\s+(\[[0-9.]+\])\s+(\[[A-Z/]+\])\s+(.*)$"
    m = re.match(pattern, title)
    if m:
        return m.group(1), m.group(2), m.group(3), m.group(4)
    else:
        # fallback: als het patroon niet klopt
        return "", "", "", title

def main():
    today_str = datetime.now(TZ).date().isoformat()
    seen = load_seen()
    feed = feedparser.parse(FEED_URL)

    out_file, f, writer = open_daily_csv(today_str)
    new_count = 0

    try:
        for entry in feed.entries:
            aid = advisory_id(entry)
            if not aid:
                continue
            if aid in seen:
                continue

            title = (entry.get("title") or "").strip()
            link = entry.get("link") or ""

            advisory, version, severity, description = parse_title(title)
            writer.writerow([advisory, version, severity, description, link])

            seen[aid] = today_str
            new_count += 1
    finally:
        f.close()

    save_seen(seen)

    # info voor Telegram stap
    last_run = {
        "new_count": new_count,
        "csv_path": str(out_file)
    }
    LAST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_RUN_FILE.write_text(json.dumps(last_run, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Wrote {new_count} new advisories to {out_file}" if new_count else "No new advisories today.")

if __name__ == "__main__":
    main()
