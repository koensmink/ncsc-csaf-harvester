# scraper.py
import os, sys, csv, datetime, re, json, time
from pathlib import Path
from typing import List, Dict, Tuple
import requests
from dedupe import filter_new_advisories, mark_sent, is_same_message

OUTPUT_DIR = Path("output/daily"); OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID")
DEBUG      = os.getenv("DEBUG", "0") == "1"
NO_DEDUPE  = os.getenv("NO_DEDUPE", "0") == "1"

# Herken H/H e.d. en ook woorden (fallback)
SEV_TAG_RE = re.compile(r"\b(\[?(H/H|M/H|H/M)\]?|High/High|Med/High|High/Med)\b", re.IGNORECASE)

def log(msg: str) -> None:
    print(msg, flush=True)

def send_to_telegram(text: str) -> Tuple[bool, str]:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log("⚠️  Telegram niet geconfigureerd; skipping."); return False, "no-config"
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML", "disable_web_page_preview": False}
    try:
        r = requests.post(url, json=payload, timeout=25)
        if r.status_code == 200:
            log("✅ Telegram-bericht verzonden."); return True, "ok"
        log(f"❌ Telegram error {r.status_code}: {r.text}"); return False, f"status-{r.status_code}"
    except Exception as e:
        log(f"❌ Telegram exception: {e}"); return False, "exception"

# --------------------------- CSAF FETCH --------------------------------

BASE_DIR = "https://advisories.ncsc.nl/csaf/v2"   # bewezen live directory (met jaarmappen)
LIST_LINK_RE = re.compile(r'href="(ncsc-(\d{4})-(\d{4})\.json)"', re.IGNORECASE)

def _http_get(url: str, accept: str = None) -> requests.Response:
    headers = {
        "User-Agent": "NCSC-CSAF-Harvester/1.0 (+github.com/koensmink/ncsc-csaf-harvester)"
    }
    if accept:
        headers["Accept"] = accept
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r

def list_year_documents(year: int, limit: int = 60) -> List[str]:
    """Parseer de HTML directory listing en pak de laatste N json-bestanden."""
    url = f"{BASE_DIR}/{year}/"
    try:
        html = _http_get(url, accept="text/html").text
    except Exception as e:
        log(f"❌ Kon year listing niet ophalen: {e} ({url})"); return []
    files = LIST_LINK_RE.findall(html)
    names = [m[0] for m in files]
    # De index staat vaak al chronologisch; sorteer op nummer aflopend voor zekerheid
    def keyfn(n: str):
        m = re.search(r"(\d{4})\.json$", n)
        return int(m.group(1)) if m else -1
    names = sorted(set(names), key=keyfn, reverse=True)[:limit]
    return [f"{BASE_DIR}/{year}/{name}" for name in names]

def _first_text(notes: List[Dict]) -> str:
    for n in notes or []:
        if isinstance(n.get("text"), str) and n.get("text").strip():
            return n["text"].strip()
    return ""

def _extract_severity(doc: Dict) -> str:
    # 1) eigen aggregate velden (sommige publishers gebruiken dit)
    for k in ("aggregate_severity", "severity", "urgency"):
        v = doc.get(k)
        if isinstance(v, str) and v.strip():
            if SEV_TAG_RE.search(v): return SEV_TAG_RE.search(v).group(1)
            return v.strip()

    # 2) document.notes: kijk in text of title naar tags
    notes = (doc.get("document") or {}).get("notes") or []
    blob = " ".join([_first_text(notes), (doc.get("document") or {}).get("title","")])
    m = SEV_TAG_RE.search(blob)
    if m: return m.group(1)

    # 3) CVSS indicatie (vulnerabilities[].scores[].cvss_v3.baseScore)
    vulns = doc.get("vulnerabilities") or []
    best = 0.0
    for v in vulns:
        for s in v.get("scores") or []:
            cv3 = (s.get("cvss_v3") or {})
            score = cv3.get("baseScore") or cv3.get("base_score")
            try:
                score = float(score)
                best = max(best, score)
            except (TypeError, ValueError):
                pass
    if best >= 8.0:   # high
        return "[H/H]"
    elif best >= 7.0:
        return "High/Med"
    return ""

def _html_link_for_id(tracking_id: str) -> str:
    # NCSC-YYYY-NNNN → https://advisories.ncsc.nl/YYYY/ncsc-YYYY-NNNN.html
    m = re.match(r"(?i)NCSC-(\d{4})-(\d{4})", tracking_id or "")
    if not m: return ""
    year, nr = m.group(1), m.group(2)
    return f"https://advisories.ncsc.nl/{year}/ncsc-{year}-{nr}.html"

def fetch_ncsc_to_csv(out_csv: Path, year: int = None, batch_limit: int = 60) -> int:
    """Haal recente CSAF documenten op en schrijf naar CSV (id, version, severity, description, link)."""
    year = year or datetime.date.today().year
    doc_urls = list_year_documents(year, limit=batch_limit)
    if not doc_urls:
        log("⚠️ Geen CSAF JSON links gevonden in jaarindex."); return 0

    rows: List[Dict[str,str]] = []
    for url in doc_urls:
        try:
            data = _http_get(url, accept="application/json").json()
        except Exception as e:
            log(f"⚠️ Skip {url}: {e}"); continue

        doc = data.get("document") or {}
        tracking = (doc.get("tracking") or {})
        tid = tracking.get("id") or data.get("id") or ""
        ver = tracking.get("version") or ""
        title = doc.get("title") or data.get("title") or ""
        desc = title or _first_text(doc.get("notes") or []) or ""
        sev  = _extract_severity(data)  # best-effort
        link = _html_link_for_id(tid)

        rows.append({
            "AdvisoryID": tid,
            "Version": ver,
            "Severity": sev,
            "Description": desc,
            "Link": link
        })
        # beleefd kleine pauze bij veel requests
        time.sleep(0.1)

    # Schrijf CSV
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["AdvisoryID","Version","Severity","Description","Link"])
        writer.writeheader(); writer.writerows(rows)
    log(f"✅ {len(rows)} advisories geschreven naar {out_csv}")
    return len(rows)

# --------------------------- FILTER + MESSAGE ---------------------------

def filter_high_risk(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    out = []
    for r in rows:
        sev = (r.get("Severity") or "").strip()
        if SEV_TAG_RE.search(sev):
            out.append(r)
    return out

def build_urgent_message(rows: List[Dict[str, str]]) -> str:
    header = "🚨😡 <b>URGENT</b>\n\nDetails:\n"
    lines = []
    for r in rows:
        sev = r.get("Severity") or "?"
        desc = r.get("Description") or "Onbekende melding"
        url  = r.get("Link") or ""
        if len(desc) > 300: desc = desc[:300].rstrip() + "…"
        line = f"• <b>[{sev}]</b> — {desc}"
        if url: line += f"\n  🔗 <a href='{url}'>Bekijk advisory</a>"
        lines.append(line)
    msg = header + "\n".join(lines)
    return msg[:3900]

def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# ------------------------------- MAIN ----------------------------------

def main() -> int:
    log(f"🔍 Start scraper run at {datetime.datetime.utcnow().isoformat()} UTC")
    today_csv = OUTPUT_DIR / f"{datetime.date.today()}.csv"

    fetched = fetch_ncsc_to_csv(today_csv, year=datetime.date.today().year, batch_limit=80)
    log(f"Feed download: {fetched} entries opgehaald.")
    if fetched == 0:
        return 0

    rows = read_csv_rows(today_csv)
    log(f"Totaal rijen in CSV: {len(rows)}")

    high_risk = filter_high_risk(rows)
    log(f"Na severity-filter (H/H, M/H, H/M, High/High, Med/High, High/Med): {len(high_risk)} rijen")
    if not high_risk:
        log("Geen high-risk meldingen gevonden."); return 0

    if NO_DEDUPE:
        rows_to_send, used_ids = high_risk, []
        log("⚠️ NO_DEDUPE=1 gezet: dedupe tijdelijk uitgeschakeld.")
    else:
        rows_to_send, used_ids = filter_new_advisories(high_risk)
        log(f"Na advisory-dedupe: {len(rows_to_send)} te versturen items")

    if not rows_to_send:
        log("Geen nieuwe high-risk advisories na dedupe; niets te sturen."); return 0

    message_text = build_urgent_message(rows_to_send)
    if not NO_DEDUPE and is_same_message(message_text):
        log("Bericht is identiek aan vorige push; overslaan."); return 0

    ok, _ = send_to_telegram(message_text)
    if ok and not NO_DEDUPE:
        mark_sent(used_ids, message_text)
    log("✅ Run afgerond."); return 0

if __name__ == "__main__":
    sys.exit(main())
