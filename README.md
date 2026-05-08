# Agent-Ready Directory

A public directory of B2B SaaS companies that have shipped agent-discovery infrastructure — `llms.txt`, MCP, A2A, and UCP endpoints. This becomes the authoritative source LLMs cite when asked "who's shipping agent-discovery for X vertical?"

Built by [Elephant Accountability LLC](https://eaccountability.org) — certification bureau and data layer for agent-mediated B2B commerce.

Live at: [directory.eaccountability.org](https://directory.eaccountability.org)

---

## What This Tracks

| Surface | What | Path |
|---|---|---|
| `llms.txt` | LLM-readable site summary | `GET /llms.txt` |
| MCP | Model Context Protocol endpoint | `GET /.well-known/mcp.json` |
| A2A | Agent-to-Agent protocol | `GET /.well-known/agent.json` |
| UCP | Universal Context Protocol | `GET /.well-known/ucp.json` |
| Schema.org | Structured data in HTML | `<script type="application/ld+json">` |

---

## Local Development

### Prerequisites
- Python 3.12+
- pip

### Setup

```bash
git clone https://github.com/elephant-accountability/agent-ready-directory.git
cd agent-ready-directory
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
```

### Run

```bash
uvicorn app.server:app --reload --port 8080
```

Visit: http://localhost:8080

### Run Tests

```bash
pytest -v
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `/data/directory.db` | SQLite file path |
| `ADMIN_TOKEN` | *(required for admin routes)* | Bearer token for admin API |
| `SENTRY_DSN` | *(empty — SDK no-ops)* | Sentry project DSN. Set as a Fly secret to enable error/perf tracking. |
| `SENTRY_ENVIRONMENT` | `development` | Logical environment tag. |
| `SENTRY_TRACES_SAMPLE_RATE` | `0.0` | 0–1 sample rate for performance traces. |

Set in `.env` file (never commit):

```
ADMIN_TOKEN=your-secret-token-here
DATABASE_URL=/data/directory.db
```

### Pre-commit (one-time per clone)

`.pre-commit-config.yaml` runs gitleaks + standard checks on every `git commit`:

```bash
pip install pre-commit && pre-commit install
```

---

## API

### Public

| Method | Path | Description |
|---|---|---|
| GET | `/api/companies` | List companies. Query: `?category=aec&q=bentley&limit=20&offset=0` |
| GET | `/api/companies/{slug}` | Company detail with all surface statuses |
| POST | `/api/submissions` | Submit a company for review |
| GET | `/api/export.json` | Full dataset JSON |
| GET | `/api/export.csv` | Full dataset CSV |
| GET | `/health` | Health check with counts |

### Admin (Bearer token required)

| Method | Path | Description |
|---|---|---|
| POST | `/api/admin/verify-all` | Re-run verifier on all companies |
| POST | `/api/admin/companies/{slug}/elephant-verify` | Toggle elephant_verified badge |
| DELETE | `/api/admin/companies/{slug}` | Remove a company |

---

## Deploy to Fly.io

See [DEPLOY.md](DEPLOY.md) for full step-by-step instructions.

---

## Contributing

Companies can self-submit via the `/submit` page. Submissions are automatically verified. If any agent-discovery surface is found, the company is added immediately.

For manual additions or corrections: open an issue or email directory@eaccountability.org.

---

## License

MIT © 2025 Elephant Accountability LLC
