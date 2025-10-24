# scraper.py
import os, sys, csv, datetime, json, glob, re, requests
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

# ---------------------------------------------------------------------
# Logging + helpers
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
        else:
            log(f"❌ Telegram error {r.status_code}: {r.text}")
            return False, f"status-{r.status_code}"
    except Exception as e:
        log(f"❌ Telegram exception: {e}")
        return False, "exception"

# ---------------------------------------------------------------------
# 1️⃣ NCSC feed ophalen
# ---------------------------------------------------------------------
def fetch_ncsc_feed(output_path: Path) -> int:
    """Download de NCSC CSAF-feed en schrijf als CSV"""
    url = "https://www.ncsc.nl/documents/advisory-feed/csaf"
    headers = {
        "User-Agent": "NCSC-CSAF-Harvester/1.0",
        "Accept": "application/json, text/xml, */*;q=0.9"
    }

    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
    except Exception as e:
        log(f"❌ Fout bij ophalen CSAF feed: {e}")
        return 0

    try:
        data = r.json()
    except Exception:
        log("❌ Feed is geen JSON – mogelijk gewijzigde structuur.")
        return 0

    advisories = data.get("advisories") or data.get("documents") or []
    if not advisories:
        log("⚠️ Geen advisories gevonden in feed.")
        return 0

    rows = []
    for adv in advisories:
        t = adv.get("tracking", {}) or {}
        rows.append({
            "AdvisoryID": t.get("id", ""),
            "Version": t.get("version", ""),
            "Severity": adv.get("aggregate_severity") or adv.get("severity", ""),
            "Description": adv.get("title") or adv.get("description", ""),
            "Link": adv.get("url") or adv.get("reference_url", ""),
        })

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["AdvisoryID", "Version", "Severity", "Description", "Link"]
        )
        writer.writeheader()
        writer.writerows(rows)

    log(f"✅ {len(rows)} advisories geschreven naar {output_path}")
    return len(rows)

# ---------------------------------------------------------------------
# 2️⃣ Filter & message builders
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
    msg = header + "\n".join(lines)
    return msg[:3900]  # Telegram limiet safeguard

def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)

# ---------------------------------------------------------------------
# 3️⃣ Main
# ---------------------------------------------------------------------
def main() -> int:
    log(f"🔍 Start scraper run at {datetime.datetime.utcnow().isoformat()} UTC")
    today_csv = OUTPUT_DIR / f"{datetime.date.today()}.csv"

    fetched = fetch_ncsc_feed(today_csv)
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
