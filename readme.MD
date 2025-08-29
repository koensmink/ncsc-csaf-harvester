# 📡 NCSC Advisories Daily Scraper

Deze repository haalt dagelijks automatisch de **NCSC beveiligingsadviezen** op uit de officiële [NCSC RSS-feed](https://advisories.ncsc.nl/rss/advisories) en slaat deze op in **CSV-bestanden per dag**.

## 🔧 Hoe werkt het?

- De scraper (`scraper.py`) leest de NCSC RSS-feed uit.  
- Nieuwe adviezen worden herkend op basis van een **uniek ID**.  
- Elk advies wordt precies **één keer** opgeslagen: in het CSV-bestand van de dag waarop het advies voor het eerst is gezien.  
- GitHub Actions draait het script automatisch elke ochtend om 08:00 uur (NL-tijd) en commit de updates.

## 📂 Repo-structuur
```
├─ scraper.py
├─ output/
│ ├─ seen.json # lijst met reeds verwerkte adviezen
│ └─ daily/
│ ├─ 2025-08-28.csv # CSV met adviezen van die dag
│ ├─ 2025-08-29.csv
│ └─ ...
└─ .github/workflows/ncsc-scraper.yml
```

## 📊 Voorbeeld output

`output/daily/2025-08-28.csv`:

```
csv
AdvisoryID,Version,Severity,Description,Link
NCSC-2025-0271,[1.00],[M/H],Kwetsbaarheden verholpen in Arcserve Unified Data Protection,https://advisories.ncsc.nl/advisory?id=NCSC-2025-0271
```

⚙️ Zelf draaien
Lokaal:
```
pip install feedparser
python scraper.py
```
