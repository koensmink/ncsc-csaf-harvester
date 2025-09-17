#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NCSC Telegram notifier (idempotent + batched + debounce) — afgestemd op ncsc-csaf-harvester

- Leest 'output/last_run.json' om het CSV-pad te vinden (fallback: nieuwste in output/daily/).
- Laadt CSV, filtert op tags: [H/H], [M/H], [H/M].
- Stuurt één Telegram-bericht met ALLE nog-niet-gemelde adviezen.
- Idempotent o.b.v. AdvisoryID + dag-hash (debounce).
- Cooldown (default 30 min) en lock-file tegen gelijktijdige sends.
- State in: output/sent_cache.json
- Stelt GHA outputs: filtered_count, unsent_count, sent_count, message_hash

Env:
- TELEGRAM_BOT_TOKEN
- TELEGRAM_CHAT_ID
"""

from __future__ import annotations
import os, sys, csv, json, time, hashlib, glob
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from urllib import request, parse
import argparse

# --- Pad-constanten (afgestemd op repo) ---
OUT_DIR = Path("output")
LAST_RUN_JSON = OUT_DIR / "last_run.json"
DAILY_DIR = OUT_DIR / "daily"
STATE_PATH_DEFAULT = OUT_DIR / "sent_cache.json"
LOCK_PATH = OUT_DIR / "telegram.lock"

WANTED_TAGS = {"[H/H]", "[M/H]", "[H/M]"}
COOLDOWN_MINUTES_DEFAULT = 30

# --- State I/O ---
def load_state(path: Path) -> Dict[str, Any]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"sent_ids": {}, "last_message_hash": "", "last_sent_at": ""}

def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)

# --- CSV loader met kolom-fallbacks ---
def _first_present(row: Dict[str, str], *keys: str) -> str:
    for k in keys:
        if k in row and row[k]:
            return row[k]
    return ""

def load_candidates_from_csv(csv_path: Path) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            advisory_id = _first_present(row, "AdvisoryID", "AdvisoryId", "ID", "Advisory", "Identifier").strip()
            title = _first_present(row, "Title", "Description", "AdvisoryTitle", "Summary").strip()
            tag = _first_present(row, "SeverityTag", "Severity", "Tag").strip()
            url = _first_present(row, "URL", "Url", "Link", "Reference").strip()
            if not (advisory_id or title or tag):
                continue
            items.append({
                "AdvisoryID": advisory_id,
                "Title": title,
                "SeverityTag": tag,
                "Url": url
            })
    return items

def resolve_csv_path(cli_csv: Optional[str]) -> Optional[Path]:
    if cli_csv:
        p = Path(cli_csv)
        return p if p.exists() else None
    if LAST_RUN_JSON.exists():
        try:
            data = json.loads(LAST_RUN_JSON.read_text(encoding="utf-8"))
            p = Path(data.get("csv_path", ""))
            if p.exists():
                return p
        except Exception:
            pass
    paths = sorted(glob.glob(str(DAILY_DIR / "*.csv")))
    return Path(paths[-1]) if paths else None

# --- Filter & idempotency ---
def filter_wanted_unsent(advisories: List[Dict[str, str]], state: Dict[str, Any]) -> Tuple[List[Dict[str, str]], int]:
    sent_ids: Dict[str, str] = state.get("sent_ids", {})
    filtered = [a for a in advisories if a.get("SeverityTag", "").strip() in WANTED_TAGS]
    unsent = [a for a in filtered if a.get("AdvisoryID", "") not in sent_ids]
    return unsent, len(filtered)

def message_hash(advisories: List[Dict[str, str]]) -> str:
    ids = ",".join(sorted(a.get("AdvisoryID", "") for a in advisories if a.get("AdvisoryID")))
    day = time.strftime("%Y-%m-%d", time.gmtime())
    return hashlib.sha256(f"{day}|{ids}".encode()).hexdigest() if ids else ""

def should_send_by_hash(h: str, state: Dict[str, Any]) -> bool:
    return bool(h) and h != state.get("last_message_hash", "")

def within_cooldown(state: Dict[str, Any], cooldown_minutes: int) -> bool:
    last = state.get("last_sent_at", "")
    if not last:
        return False
    try:
        last_epoch = float(last)
        return (time.time() - last_epoch) < (cooldown_minutes * 60)
    except Exception:
        return False

def mark_sent(advisories: List[Dict[str, str]], state: Dict[str, Any], h: str) -> None:
    now_epoch = time.time()
    for a in advisories:
        aid = a.get("AdvisoryID", "")
        if aid:
            state.setdefault("sent_ids", {})[aid] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    state["last_message_hash"] = h
    state["last_sent_at"] = str(now_epoch)

# --- Locking ---
def acquire_lock(timeout: float = 2.0) -> bool:
    start = time.time()
    while LOCK_PATH.exists() and (time.time() - start) < timeout:
        time.sleep(0.1)
    if LOCK_PATH.exists():
        return False
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.write_text(str(os.getpid()))
    return True

def release_lock() -> None:
    try:
        LOCK_PATH.unlink()
    except FileNotFoundError:
        pass

# --- Telegram ---
def send_telegram(text: str) -> bool:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        print("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID; skip send.")
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    data = parse.urlencode(payload).encode()
    req = request.Request(url, data=data, method="POST")
    try:
        with request.urlopen(req, timeout=20) as resp:
            if resp.status == 200:
                return True
            print(f"Telegram HTTP status: {resp.status}")
            return False
    except Exception as e:
        print(f"Telegram send error: {e}")
        return False

# --- Bericht ---
def build_message(advisories: List[Dict[str, str]]) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = [f"🚨🙂 URGENT | {ts}", "", "Details:"]
    def _key(a): return a.get("AdvisoryID", "")
    for a in sorted(advisories, key=_key):
        tag = a.get("SeverityTag", "")
        aid = a.get("AdvisoryID", "")
        title = a.get("Title", "")
        url = a.get("Url", "")
        head = f"• {tag} — {aid} — {title}".strip(" —")
        lines.append(head)
        if url:
            lines.append(f"  🔗 Bekijk advisory")
    return "\n".join(lines)

# --- GHA outputs ---
def gha_set_output(**kwargs: Any) -> None:
    out = os.getenv("GITHUB_OUTPUT")
    if not out:
        return
    with open(out, "a", encoding="utf-8") as f:
        for k, v in kwargs.items():
            f.write(f"{k}={v}\n")

# --- Main ---
def main():
    ap = argparse.ArgumentParser(description="NCSC notifier")
    ap.add_argument("--csv-path", help="Pad naar CSV met advisories (anders last_run.json -> daily/ fallback)")
    ap.add_argument("--state-path", default=str(STATE_PATH_DEFAULT), help="Pad naar sent_cache.json")
    ap.add_argument("--cooldown-minutes", type=int, default=COOLDOWN_MINUTES_DEFAULT, help="Minuten minimale interval tussen telegram-berichten")
    args = ap.parse_args()

    state_path = Path(args.state_path)
    csv_path = resolve_csv_path(args.csv_path)

    if not csv_path or not csv_path.exists():
        print("CSV niet gevonden; skip send.")
        gha_set_output(filtered_count=0, unsent_count=0, sent_count=0, message_hash="")
        sys.exit(0)

    all_items = load_candidates_from_csv(csv_path)
    state = load_state(state_path)

    unsent, total_filtered = filter_wanted_unsent(all_items, state)
    print(f"Filtered (wanted) count: {total_filtered}, Unsent: {len(unsent)}")

    gha_set_output(filtered_count=total_filtered, unsent_count=len(unsent))

    if len(unsent) == 0:
        print("Geen nieuwe (unsent) high-risk advisories -> geen bericht.")
        gha_set_output(sent_count=0, message_hash=state.get("last_message_hash", ""))
        sys.exit(0)

    if within_cooldown(state, args.cooldown_minutes):
        print(f"Binnen cooldown ({args.cooldown_minutes} min) -> skip bericht.")
        gha_set_output(sent_count=0, message_hash=state.get("last_message_hash", ""))
        sys.exit(0)

    h = message_hash(unsent)
    gha_set_output(message_hash=h)

    if not should_send_by_hash(h, state):
        print("Set ongewijzigd t.o.v. laatste bericht vandaag -> skip.")
        gha_set_output(sent_count=0)
        sys.exit(0)

    if not acquire_lock():
        print("Kon lock niet verkrijgen (simultane run?) -> skip.")
        gha_set_output(sent_count=0)
        sys.exit(0)

    try:
        text = build_message(unsent)
        ok = send_telegram(text)
        if ok:
            mark_sent(unsent, state, h)
            atomic_write_json(state_path, state)
            print(f"Telegram verzonden: {len(unsent)} items")
            gha_set_output(sent_count=len(unsent))
            sys.exit(0)
        else:
            print("Verzenden mislukt; state NIET geüpdatet.")
            gha_set_output(sent_count=0)
            sys.exit(1)
    finally:
        release_lock()

if __name__ == "__main__":
    main()
