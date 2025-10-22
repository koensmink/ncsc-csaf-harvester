# notifiers/teams.py
import os
import time
import requests
from typing import List, Dict, Optional

__all__ = ["send_to_teams", "notify_teams_brief"]

def send_to_teams(
    message: str,
    severity: str = "Info",
    title: Optional[str] = None,
    sections: Optional[List[Dict]] = None,
    webhook_env_var: str = "TEAMS_WEBHOOK_URL",
    enable_env_var: str = "ENABLE_TEAMS",
    timeout: int = 10,
    max_retries: int = 3,
    retry_backoff_seconds: int = 2,
) -> None:
    """
    Stuur een notificatie naar Microsoft Teams via een Incoming Webhook.
    - message: Markdown-achtige tekst (basisopmaak)
    - severity: Info | Low | Medium | High (bepaalt de kleur)
    - title: optionele titelregel
    - sections: optionele Teams MessageCard 'sections' (list[dict])
    - TEAMS_WEBHOOK_URL en ENABLE_TEAMS worden uit env gelezen
    """
    if os.getenv(enable_env_var, "true").lower() not in ("1", "true", "yes", "on"):
        print("[Teams] Disabled via ENABLE_TEAMS.")
        return

    webhook_url = os.getenv(webhook_env_var)
    if not webhook_url:
        print("[Teams] No webhook URL configured (env TEAMS_WEBHOOK_URL).")
        return

    color = {
        "High": "ff0000",
        "Medium": "ffa500",
        "Low": "2eb886",
        "Info": "0078d7",
    }.get(severity, "0078d7")

    if not title:
        title = f"NCSC CSAF Harvester ({severity})"

    def _truncate(txt: Optional[str], limit: int = 5000) -> Optional[str]:
        if txt is None:
            return None
        return (txt[: limit - 3] + "...") if len(txt) > limit else txt

    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": _truncate(title, 250),
        "title": _truncate(title, 250),
        "text": _truncate(message, 7000),
    }

    if sections:
        payload["sections"] = sections[:5]  # voorkom oversized payloads

    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(
                webhook_url,
                json=payload,
                timeout=timeout,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                print("[Teams] Notificatie verzonden.")
                return
            else:
                last_err = f"HTTP {resp.status_code}: {resp.text[:300]}"
                print(f"[Teams] Post failed (attempt {attempt}/{max_retries}): {last_err}")
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            print(f"[Teams] Exception (attempt {attempt}/{max_retries}): {last_err}")

        time.sleep(retry_backoff_seconds * attempt)

    print(f"[Teams] Giving up after {max_retries} attempts. Last error: {last_err}")


def notify_teams_brief(
    new_high: List[Dict],
    new_medium: List[Dict],
    total_new: int,
    run_url: Optional[str] = None,
) -> None:
    """
    Compacte wrapper om een korte status naar Teams te sturen.
    Verwacht dat elke advisory dict minimaal keys kan hebben als: id, title, url, cvss (optioneel).
    Past zich netjes aan als velden ontbreken.
    """
    def _line(ad: Dict) -> str:
        parts = []
        if ad.get("id"):
            parts.append(f"**{ad['id']}**")
        if ad.get("title"):
            parts.append(ad["title"])
        if ad.get("url"):
            parts.append(f"[link]({ad['url']})")
        if ad.get("cvss"):
            parts.append(f"(CVSS: {ad['cvss']})")
        return " — ".join(parts) if parts else "Nieuwe advisory"

    if new_high:
        title = f"{len(new_high)} nieuwe HIGH-risk NCSC CSAF meldingen"
        lines = "\n".join(f"- {_line(ad)}" for ad in new_high[:10])
        tail = "\n… (meer items in log/artefact)" if len(new_high) > 10 else ""
        footer = f"\n\n[Pipeline run]({run_url})" if run_url else ""
        send_to_teams(
            message=f"{lines}{tail}{footer}",
            severity="High",
            title=title,
            sections=[{
                "facts": [
                    {"name": "Totaal nieuw", "value": str(total_new)},
                    {"name": "High", "value": str(len(new_high))},
                    {"name": "Medium", "value": str(len(new_medium))},
                ]
            }],
        )
    else:
        send_to_teams(
            message=f"Er zijn geen nieuwe high-risk CSAF meldingen gevonden. Totaal nieuw: {total_new}.",
            severity="Info",
            title="Geen nieuwe high-risk meldingen",
            sections=[{
                "facts": [
                    {"name": "High", "value": str(len(new_high))},
                    {"name": "Medium", "value": str(len(new_medium))},
                ]
            }],
        )
