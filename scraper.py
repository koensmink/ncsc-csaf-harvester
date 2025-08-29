import csv
import json
import re
import calendar
import feedparser
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo  # Python 3.9+

# --- Config ---
FEED_URL = "https://advisories.ncsc.nl/rss/advisories"
BASE_DIR = Path("output/daily")
SEEN_FILE = Path("output/seen.json")
LAST_RUN_FILE = Path("output/last_run.json")
TZ = ZoneInfo("Europe/Amsterdam")


# --- Helpers: state ---
def load_seen() -> dict:
    """Laad mapping {advisory_id: 'YYYY-MM-DD'} of leeg dict."""
    if SEEN_FILE.exists():
        return json.loads(SEEN_FILE.read_text(encoding="utf-8"))
    return {}


def save_seen(seen: dict) -> None:
    SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    SEEN_FILE.write_text(
        json.dumps(seen, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# --- Helpers: parsing ---
def advisory_id(entry) -> str | None:
    return entry.get("id") or entry.get("link")


def parse_title(title: str):
    """
    Verwachte structuur van de titel:
      NCSC-YYYY-NNNN [1.00] [M/H] Omschrijving...
    Retourneert: (advisory, version, severity, description)
    """
    pattern = r"^(NCSC-\d{4}-\d{4})\s+(\[[0-9.]+\])\s+(\[[A-Z/]+\])\s+(.*)$"
    m = re.match(pattern, title or "")
    if m:
        return m.group(1), m.group(2), m.group(3), m.group(4)
    # fallback (zodat we tenminste iets in de CSV hebben)
    return "", "", "", (title or "")


def entry_pubdate_local(entry) -> str | None:
    """
    Bepaal lokale (Europe/Amsterdam) datumstring 'YYYY-MM-DD'
    uit published_parsed/updated_parsed van een feed entry.
    """
    t = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
    if not t:
        return None
    dt_utc = datetime.fromtimestamp(calendar.timegm(t), tz=timezone.utc)
    return dt_utc.astimezone(TZ).date().isoformat()


# --- CSV writers ---
def write_daily_csv_for_today(feed_entries, today_str: str) -> tuple[Path, int]:
    """
    Herschrijf de dag-CSV volledig met álle items in de feed
    waarvan published/updated == vandaag (lokale tijd).
    """
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    out_file = BASE_DIR / f"{today_str}.csv"

    rows = []
    for e in feed_entries:
        if entry_pubdate_local(e) != today_str:
            continue
        title = (e.get("title") or "").strip()
        link = e.get("link") or ""
        advisory, version, severity, description = parse_title(title)
        rows.append([advisory, version, severity, description, link])

    # Sorteer optioneel op AdvisoryID voor stabiele diffs
    rows.sort(key=lambda r: r[0] or "")

    with out_file.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["AdvisoryID", "Version", "Severity", "Description", "Link"])
        w.writerows(rows)

    return out_file, len(rows)


def main():
    today_str = datetime.now(TZ).date().isoformat()
    seen = load_seen()

    # 1) Feed ophalen
    feed = feedparser.parse(FEED_URL)
    entries = getattr(feed, "entries", []) or []

    # 2) Dag-CSV herschrijven o.b.v. published==vandaag (onafhankelijk van 'seen')
    out_file, todays_count = write_daily_csv_for_today(entries, today_str)

    # 3) Bepaal 'new_count' en update seen.json (dedup over runs)
    new_count = 0
    for entry in entries:
        aid = advisory_id(entry)
        if not aid or aid in seen:
            continue
        # Markeer als nieuw gezien op vandaag
        seen[aid] = today_str
        new_count += 1

    save_seen(seen)

    # 4) Schrijf last_run.json (incl. timestamp, handig voor commits/visibiliteit)
    last_run = {
        "new_count": new_count,
        "csv_path": str(out_file),
        "last_run_at": datetime.now(TZ).isoformat(timespec="seconds"),
        "todays_count": todays_count,
    }
    LAST_RUN_FILE.parent.mkdir(parents=True, exist_ok=True)
    LAST_RUN_FILE.write_text(
        json.dumps(last_run, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"[CSV] {todays_count} items voor {today_str} → {out_file}")
    print(f"[NEW] {new_count} nieuwe advisories sinds vorige run")


if __name__ == "__main__":
    main()
