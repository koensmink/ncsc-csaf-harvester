# 🔎 NCSC advisory watcher

[![GitHub Workflow Status](https://github.com/koensmink/ncsc-csaf-harvester/actions/workflows/ncsc.yaml/badge.svg)](https://github.com/koensmink/ncsc-csaf-harvester/actions/workflows/ncsc.yaml)
[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Automatisch ophalen, filteren en melden van **NCSC security advisories** via CSAF en RSS.  
Dit project helpt bij het tijdig signaleren van kritieke kwetsbaarheden en biedt directe notificaties via **Telegram**.

---

## 🚀 Features

- Haalt advisories op van [advisories.ncsc.nl](https://advisories.ncsc.nl)  
- Parseert CSAF/RSS en schrijft dagelijkse CSV + JSON outputs weg  
- **Telegram notificaties** bij kritieke combinaties: `[H/H]`, `[M/H]`, `[H/M]`  
- Slimme scheduling: doordeweeks elk uur, in het weekend alleen 23:55 (NL-tijd)  
- GitHub Actions workflow met automatische commit & push  

---

## 📂 Repository structuur

```
.github/workflows/   → CI/CD workflows (harvester + Telegram alerts)
output/              → Dagelijkse CSV/JSON resultaten
scraper.py           → Scraper code
requirements.txt     → Python dependencies
```

---

## ⚙️ Installatie & gebruik

### Lokaal draaien
```bash
git clone https://github.com/koensmink/ncsc-csaf-harvester.git
cd ncsc-csaf-harvester
pip install -r requirements.txt
python scraper.py
```

### GitHub Actions
De workflow (`.github/workflows/ncsc.yml`) draait automatisch volgens het ingestelde schema.  
Resultaten worden gecommit naar de `output/` map in de repo.

---

## 🔔 Telegram notificaties

Stel de volgende **secrets** in bij je GitHub repository settings:

- `TELEGRAM_BOT_TOKEN`  
- `TELEGRAM_CHAT_ID`  

Berichten zien er bijvoorbeeld zo uit:

```
🚨🙂 URGENT

Details:
• [H/H] — Microsoft Exchange kwetsbaarheid
  🔗 Bekijk advisory
• [M/H] — Cisco ASA Remote Code Execution
  🔗 Bekijk advisory
```

---

## 📊 Output

Elke run schrijft weg naar:

- `output/daily/YYYY-MM-DD.csv`  
- `output/last_run.json`  

Met daarin metadata over de laatste run en nieuw gedetecteerde advisories.

## 📜 License

Dit project is gelicenseerd onder de [MIT License](LICENSE).

---
## 🔐 Security Policy

Als je een kwetsbaarheid in deze code vindt:

1. Meld deze **niet** publiekelijk in een issue  
2. Neem direct contact op met de maintainer via [GitHub profiel](https://github.com/koensmink)  
3. Je melding wordt vertrouwelijk behandeld en zo snel mogelijk onderzocht  

---
✍️ Maintainer: [Koen Smink](https://github.com/koensmink)
