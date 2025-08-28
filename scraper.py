import feedparser
from pathlib import Path
import json
import csv
from datetime import datetime
from zoneinfo import ZoneInfo  # Python 3.9+

FEED_URL = "https://advisories.ncsc.nl/rss/advisories"
BASE_DIR = Path("output/daily")
SEEN_FILE = Path("output/seen.json")
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
        writer.writerow(["Title", "Link"])
    return out_file, f, writer

def advisory_id(entry):
    # Gebruik stabiele sleutel: voorkeursvolgorde id → link
    return entry.get("id") or entry.get("link")

def main():
    today_str = datetime.now(TZ).date().isoformat()  # YYYY-MM-DD in NL-tijd
    seen = load_seen()
    feed = feedparser.parse(FEED_URL)

    # Schrijf alleen NIEUW geziene entries naar het CSV van vandaag
    out_file, f, writer = open_daily_csv(today_str)
    new_count = 0

    try:
        for entry in feed.entries:
            aid = advisory_id(entry)
            if not aid:
                continue

            if aid in seen:
                # Al eerder gezien: skip (we schrijven het niet nogmaals, ook niet op andere dagen)
                continue

            title = (entry.get("title") or "").strip()
            link = entry.get("link") or ""

            writer.writerow([title, link])
            seen[aid] = today_str
            new_count += 1
    finally:
        f.close()

    save_seen(seen)
    print(f"Wrote {new_count} new advisories to {out_file}") if new_count else print("No new advisories today.")

if __name__ == "__main__":
    main()
