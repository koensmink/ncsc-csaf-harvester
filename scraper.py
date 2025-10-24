# scraper.py
import os, sys, csv, datetime, json, requests, re
from pathlib import Path
from typing import List, Dict, Tuple
from dedupe import filter_new_advisories, mark_sent, is_same_message

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
DEBUG      = os.getenv("DEBUG", "0") == "1"
NO_DEDUPE  = os.getenv("NO_DEDUPE", "0") == "1"

SEV_RE = re.compile(r"(\[?(H/H|M/H|H/M)\]?|High/High|Med/High|High/Med)", re.IGNORECASE)
PROVIDER_META = "https://advisories.ncsc.nl/.well-known/csaf/provider-metadata.json"

# ---------------------------------------------------------------------
# Logging + Telegram
# ---------------------------------------------------------------------
def log(msg: str) -> None:
    print(msg, flush=True)

def send_to_telegram(text: str) -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("⚠️  Telegram niet geconfigureerd; skipping.")
        return False, "no-config"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    try:
        r = requests.post(url, json=payload, timeout=25)
        if r.status_code == 200:
            log("✅ Telegram-bericht verzonden.")
            return True, "ok"
        log(f"❌ Telegram error {r.status_code}: {r.text}")
        return False, f"status-{r.status_code}"
    except Exception as e:
        log(f"❌ Telegram exception: {e}")
        return False, "exception"

# ---------------------------------------------------------------------
# 1️⃣ CSAF feed ophalen via provider-metadata + directory listing
# ---------------------------------------------------------------------
def get_base_directory_from_metadata() -> str | None:
    """Lees provider-metadata.json en retourneer directory_url."""
    try:
        r = requests.get(PROVIDER_META, headers={"User-Agent": "NCSC-CSAF-Harvester/1.0"}, timeout=30)
        r.raise_for_status()
        meta = r.json()
        for d in meta.get("distributions", []):
            if d.get("directory_url"):
                return d["directory_url"].rstrip("/")
        return meta.get("base_url")
    except Exception as e:
        log(f"❌ Kon provider-metadata.json niet ophalen: {e}")
        return None


def fetch_ncsc_to_csv(out_csv: Path, batch_limit: int = 60) -> int:
    """Gebruik de open directorylisting van NCSC om CSAF JSON's te vinden."""
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
    except Exception as e:
        log(f"❌ Kan directory niet ophalen ({dir_url}): {e}")
        return 0

    # Zoek alle .json-bestanden in de HTML-directory listing
    files = re.findall(r'href="([^"]+?\.json)"', r.text, flags=re.IGNORECASE)
    if not files:
        log("⚠️ Geen .json-bestanden gevonden in directory listing.")
        return 0

    # Sorteer op nummer, pak de laatste N
    files = sorted(set(files))[-batch_limit:]

    rows: List[Dict[str, str]] = []
    for fn in files:
        url = f"{dir_url}{fn}"
        try:
            data = requests.get(url, headers={"User-Agent": "NCSC-CSAF-Harvester/1.0"}, timeout=30).json()
        except Exception as e:
            log(f"⚠️ Skip {url}: {e}")
            continue

        doc = data.get("document") or {}
        tracking = doc.get("tracking") or {}
        tid = tracking.get("id") or fn.replace(".json", "")
        ver = tracking.get("version") or ""
        title = doc.get("title") or "Onbekend"
        sev = (
            doc.get("aggregate_severity")
            or doc.get("severity")
            or ""
        )

        # Bouw de link naar de HTML-advisory
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
        writer = csv.DictWriter(f, fieldnames=["AdvisoryID","Version","Severity","Description","Link"])
        writer.writeheader()
        writer.writerows(rows)

    log(f"✅ {len(rows)} advisories geschreven naar {out_csv}")
    return len(rows)

# ---------------------------------------------------------------------
# 2️⃣ Filtering + berichtopbouw
# ---------------------------------------------------------------------
def filter_high_risk(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return [r for r in rows if SEV_RE.search((r.get("Severity") or "").strip())]

def build_urgent_message(rows: List[Dict[str, str]]) -> str:
    header = "🚨😡 <b>URGENT</b>\n\nDetails:\n"
    lines = []
    for r in rows:
        sev = r.get("Severity") or "?"
        desc = r.get("Description") or "Onbekende melding"
        url  = r.get("Link") or ""
        if len(desc) > 300:
            desc = desc[:300].rstrip() + "…"
        line = f"• <b>[{sev}]</b> — {desc}"
        if url:
            line += f"\n  🔗 <a href='{url}'>Bekijk advisory</a>"
        lines.append(line)
    return (header + "\n".join(lines))[:3900]

def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# ---------------------------------------------------------------------
# 3️⃣ Main
# ---------------------------------------------------------------------
def main() -> int:
    log(f"🔍 Start scraper run at {datetime.datetime.utcnow().isoformat()} UTC")
    today_csv = OUTPUT_DIR / f"{datetime.date.today()}.csv"

    fetched = fetch_ncsc_to_csv(today_csv, batch_limit=80)
    log(f"Feed download: {fetched} entries opgehaald.")
    if fetched == 0:
        return 0

    rows = read_csv_rows(today_csv)
    log(f"Totaal rijen in CSV: {len(rows)}")

    high_risk = filter_high_risk(rows)
    log(f"Na severity-filter (H/H, M/H, H/M, High/High, Med/High, High/Med): {len(high_risk)} rijen")
    if not high_risk:
        log("Geen high-risk meldingen gevonden.")
        return 0

    if NO_DEDUPE:
        rows_to_send, used_ids = high_risk, []
        log("⚠️ NO_DEDUPE=1 gezet: dedupe tijdelijk uitgeschakeld.")
    else:
        rows_to_send, used_ids = filter_new_advisories(high_risk)
        log(f"Na advisory-dedupe: {len(rows_to_send)} te versturen items")

    if not rows_to_send:
        log("Geen nieuwe high-risk advisories na dedupe; niets te sturen.")
        return 0

    message_text = build_urgent_message(rows_to_send)
    if not NO_DEDUPE and is_same_message(message_text):
        log("Bericht is identiek aan vorige push; overslaan.")
        return 0

    ok, _ = send_to_telegram(message_text)
    if ok and not NO_DEDUPE:
        mark_sent(used_ids, message_text)

    log("✅ Run afgerond.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
