# scraper.py
import os, sys, csv, datetime, json, glob
from pathlib import Path
from typing import List, Dict, Tuple
import re
import requests

# DEDUPE
from dedupe import filter_new_advisories, mark_sent, is_same_message

# ---------------------------------------------------------------------
# Config & flags
# ---------------------------------------------------------------------
OUTPUT_DIR = Path("output/daily")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")

DEBUG      = os.getenv("DEBUG", "0") == "1"          # meer logging + optioneel debugbericht
NO_DEDUPE  = os.getenv("NO_DEDUPE", "0") == "1"      # dedupe tijdelijk uitzetten voor test

# Flexibele severity: met/zonder brackets en met woorden
SEV_RE = re.compile(
    r"(\[?(H/H|M/H|H/M)\]?|High/High|Med/High|High/Med)",
    re.IGNORECASE
)

# ---------------------------------------------------------------------
# Helpers
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
        log(f"❌ Telegram request exception: {e}")
        return False, "exception"

def build_urgent_message(rows: List[Dict[str, str]]) -> str:
    header = "🚨😡 <b>URGENT</b>\n\nDetails:\n"
    lines = []
    for r in rows:
        sev = r.get("Severity") or r.get("severity") or "?"
        desc = r.get("Description") or r.get("Title") or r.get("Naam") or r.get("Name") or "Onbekende melding"
        url  = r.get("AdvisoryURL") or r.get("URL") or r.get("Link") or ""
        # hard truncate desc (Telegram limiet ~4k)
        if len(desc) > 300:
            desc = desc[:300].rstrip() + "…"
        line = f"• <b>[{sev}]</b> — {desc}"
        if url:
            line += f"\n  🔗 <a href='{url}'>Bekijk advisory</a>"
        lines.append(line)
    body = "\n".join(lines)
    # nog een kleine safeguard op berichtlengte
    msg = header + body
    if len(msg) > 3900:
        msg = msg[:3870].rstrip() + "…"
    return msg

def csv_fieldnames_safe(reader: csv.DictReader) -> List[str]:
    return [fn.strip() if isinstance(fn, str) else fn for fn in (reader.fieldnames or [])]

def find_latest_csv() -> Path | None:
    """
    Vind het nieuwste CSV-bestand. Doorzoekt meerdere paden:
    - output/daily/*.csv
    - output/*.csv
    - *.csv (repo-root)
    """
    patterns = [
        "output/daily/*.csv",
        "output/*.csv",
        "*.csv",
    ]
    candidates = []
    for pat in patterns:
        for p in glob.glob(pat):
            try:
                mtime = os.path.getmtime(p)
                candidates.append((mtime, Path(p)))
            except OSError:
                pass
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]

def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        sample = f.read(4096); f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except Exception:
            dialect = csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        rows = list(reader)
        return rows

def filter_high_risk(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    out = []
    for r in rows:
        sev = (r.get("Severity") or r.get("severity") or "").strip()
        if SEV_RE.search(sev):
            out.append(r)
    return out

# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main() -> int:
    log(f"🔍 Start scraper run at {datetime.datetime.utcnow().isoformat()} UTC")
    log(f"TELEGRAM_BOT_TOKEN set: {bool(TELEGRAM_BOT_TOKEN)}")
    log(f"TELEGRAM_CHAT_ID set: {bool(TELEGRAM_CHAT_ID)}")
    log(f"DEBUG={DEBUG} NO_DEDUPE={NO_DEDUPE}")

    csv_path = find_latest_csv()
    log(f"Input CSV: {csv_path}")
    if not csv_path or not csv_path.exists():
        log("❌ Geen CSV-input gevonden in bekende paden.")
        if DEBUG:
            send_to_telegram("🛠️ Debug: geen CSV-input gevonden in output/daily, output/ of repo-root.")
        return 0

    all_rows = read_csv_rows(csv_path)
    log(f"Totaal rijen in CSV: {len(all_rows)}")

    high_risk = filter_high_risk(all_rows)
    log(f"Na severity-filter (H/H, M/H, H/M, High/High, Med/High, High/Med): {len(high_risk)} rijen")

    # extra zichtbaarheid: toon distinct severities
    if DEBUG:
        sevs = {}
        for r in all_rows:
            s = (r.get("Severity") or r.get("severity") or "").strip()
            sevs[s] = sevs.get(s, 0) + 1
        log(f"Severity distributie (eerste 10): {list(sevs.items())[:10]}")

    if not high_risk:
        log("Geen high-risk meldingen gevonden.")
        if DEBUG:
            send_to_telegram("🛠️ Debug: CSV gelezen maar geen high-risk rows gevonden (check severity-format in CSV).")
        return 0

    # DEDUPE laag 1: per-advisory
    if NO_DEDUPE:
        rows_to_send = high_risk
        used_ids = []
        log("⚠️ NO_DEDUPE=1 gezet: dedupe tijdelijk uitgeschakeld.")
    else:
        rows_to_send, used_ids = filter_new_advisories(high_risk)
        log(f"Na advisory-dedupe: {len(rows_to_send)} te versturen items")

    if not rows_to_send:
        log("Geen nieuwe high-risk advisories na dedupe; niets te sturen.")
        if DEBUG:
            send_to_telegram("🛠️ Debug: alle high-risk advisories waren al verzonden (dedupe hit).")
        return 0

    message_text = build_urgent_message(rows_to_send)

    # DEDUPE laag 2: bericht-hash
    if not NO_DEDUPE and is_same_message(message_text):
        log("Bericht is identiek aan vorige push; overslaan.")
        if DEBUG:
            send_to_telegram("🛠️ Debug: identiek bericht t.o.v. vorige push; overslaan.")
        return 0

    ok, _ = send_to_telegram(message_text)
    if ok and not NO_DEDUPE:
        mark_sent(used_ids, message_text)

    if DEBUG:
        send_to_telegram(
            f"🧪 Debug samenvatting:\n"
            f"- CSV: <code>{csv_path}</code>\n"
            f"- totaal: {len(all_rows)}\n"
            f"- high-risk gefilterd: {len(high_risk)}\n"
            f"- verzonden (na dedupe): {len(rows_to_send)}"
        )

    return 0

if __name__ == "__main__":
    sys.exit(main())
