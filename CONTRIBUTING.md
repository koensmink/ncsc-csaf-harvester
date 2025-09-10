# Contributing

Thanks for considering a contribution!

## How to Get Started
1. **Fork** the repo and create your branch from `main`.
2. **Create an issue** describing the change/bug first when appropriate.
3. **Set up locally**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   python scraper.py
   ```

## Code Style
- Target **Python 3.11**
- Follow **PEP 8** (formatting) and **PEP 257** (docstrings)
- Keep functions small and testable
- Prefer explicit names (`severity_tag`, `advisory_url`, etc.)

## Git & Commit Messages
- Use conventional-style messages when possible: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`, `ci:`
- Reference issues in commits/PRs: `Fixes #123` / `Refs #456`

## Pull Request Checklist
- [ ] Tests (or a reproducible example) included where sensible
- [ ] Lint/format pass locally
- [ ] Updated docs/README if behavior changes
- [ ] No secrets committed
- [ ] CI passes

## Directory Structure (baseline)
```
.github/workflows/   # CI/CD workflows
output/              # Generated outputs
scraper.py           # Scraper
requirements.txt     # Dependencies
```

## Adding a New Feature
1. Open an issue and propose your design briefly
2. Keep PRs focused (review-friendly size)
3. Include sample output or logs if helpful

## Reporting Bugs
Please include:
- OS / Python version
- Steps to reproduce
- Actual vs expected behavior
- Logs and relevant snippets (redact tokens)

## Security
For security issues, **do not** open a public issue. See **SECURITY.md**.
