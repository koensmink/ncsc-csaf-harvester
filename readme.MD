# 🔎 NCSC Advisory Watcher

Automatisering voor het **ophalen, parseren, dedupliceren en notificeren** van NCSC-advisories.  
Ondersteunt *dagelijkse harvesting*, *severity-filtering* en real-time **Telegram-meldingen** voor relevante risico’s.

---

## 🚀 Functionaliteit

### ✔ Harvester (CSAF + HTML)
`harvest_ncsc.py` haalt advisories op via de officiële CSAF-feed en een HTML-fallback.

- Extractie van ID, titel, datum, kans/schade, classificatie, URL
- Dagelijkse CSV-output in `output/daily/`
- Metadata-tracking in `output/last_run.json`

### ✔ Deduplicatie
`dedupe.py` voorkomt dubbele meldingen via `output/seen.json`.

Een advisory wordt genegeerd wanneer:
- Het ID al eerder is gezien
- De datum eerder is verwerkt
- Het niet binnen de severity-filters valt

### ✔ Severity Filtering
Standaard worden alleen meldingen verstuurd met verhoogd risico:

| Kans | Schade | Meldingen |
|------|--------|------------|
| H | H | Ja |
| M | H | Ja |
| H | M | Je |

### ✔ Telegram Notificaties
`notify_ncsc.py` stuurt HTML-geformatteerde meldingen via de Telegram Bot API.

---

## 📁 Bestandsstructuur

```
.
├── scraper.py
├── harvest_ncsc.py
├── notify_ncsc.py
├── dedupe.py
├── output/
│   ├── daily/
│   │   └── YYYY-MM-DD.csv
│   ├── last_run.json
│   └── seen.json
├── .github/
│   └── workflows/
│       └── ncsc.yaml
└── readme.md
```

---

## 🛠 Installatie

### Vereisten
- Python **3.11+**
- Dependencies:

```bash
pip install requests beautifulsoup4 python-dateutil
```

---

## ⚙ Configuratie

### Telegram Secrets

| Variabele | Beschrijving |
|-----------|--------------|
| `TELEGRAM_BOT_TOKEN` | API token van de bot |
| `TELEGRAM_CHAT_ID` | Doel-chat voor meldingen |

---

## ▶ Gebruik

### Harvester + notificaties
```bash
python3 scraper.py
```

### Individuele functies
```bash
python3 harvest_ncsc.py
python3 notify_ncsc.py
```

---

## 🕒 GitHub Actions Workflow

Workflow: `.github/workflows/ncsc.yaml`

- Draait elk uur op werkdagen  
- Weekend- en avondruns  
- Self-hosted runner  
- CSV/JSON output commit  
- Telegram-meldingen  

---

## 📤 Output

### CSV
`output/daily/<YYYY-MM-DD>.csv`

### Metadata
`output/last_run.json`

### Deduplication
`output/seen.json`

---

## ⚠ Limitaties

- Geen retry-mechanisme  
- HTML-fallback gevoelig voor NCSC-layout wijzigingen  
- requirements.txt ontbreekt  
- Geen tests  

---

## 📄 Licentie
MIT License.

---

## 👤 Maintainer
**Koen Smink**  
https://github.com/koensmink
