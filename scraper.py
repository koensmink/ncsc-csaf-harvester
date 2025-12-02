# scraper.py
import os, sys, csv, datetime, json
from pathlib import Path
from typing import List, Dict
import requests
from dedupe import filter_new_advisories, mark_sent, is_same_message

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------
OUTPUT_DIR = Path("output/daily")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")

CSV_PATH = sorted(OUTPUT_DIR.glob("*.csv"))[-1] if any(OUTPUT_DIR.glob("*.csv")) else None

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def read_csv(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def send_to_telegram(text: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("⚠️  Telegram niet geconfigureerd; skipping.")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": False,
    }
    r = requests.post(url, json=payload, timeout=20)
    if r.status_code != 200:
        print(f"Telegram error {r.status_code}: {r.text}")
    else:
        print("✅ Telegram-bericht verzonden.")

def build_urgent_message(rows: List[Dict[str, str]]) -> str:
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    header = "🚨⚠️ <b>hoge kwetsbaarheid NCSC</b>\n\nDetails:\n"
    lines = []
    for r in rows:
        desc = r.get("Description", "Onbekende melding")
        url = r.get("AdvisoryURL") or r.get("URL") or ""
        lines.append(f"• <b>[{r.get('Severity','?')}]</b> — {desc}\n🔗 <a href='{url}'>Bekijk advisory</a>")
    return f"{header}" + "\n".join(lines)

# ---------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------
def main() -> int:
    if not CSV_PATH:
        print("Geen CSV-input gevonden.")
        return 0

    rows = read_csv(CSV_PATH)
    high_risk = [r for r in rows if any(x in r.get("Severity","") for x in ["[H/H]", "[M/H]", "[H/M]"])]

    if not high_risk:
        print("Geen high-risk meldingen gevonden.")
        return 0

    # 1️⃣ advisory-dedupe
    rows_to_send, used_ids = filter_new_advisories(high_risk)
    if not rows_to_send:
        print("Geen nieuwe high-risk advisories; niets te sturen.")
        return 0

    # 2️⃣ bericht opbouwen
    message_text = build_urgent_message(rows_to_send)

    # 3️⃣ message-dedupe
    if is_same_message(message_text):
        print("Bericht is identiek aan vorige push; overslaan.")
        return 0

    # 4️⃣ versturen
    send_to_telegram(message_text)

    # 5️⃣ cache bijwerken
    mark_sent(used_ids, message_text)
    return 0

if __name__ == "__main__":
    sys.exit(main())
