# Deploy Guide — Agent-Ready Directory

Step-by-step deployment to Fly.io using PowerShell (Windows).

---

## Prerequisites

1. Install [Fly CLI](https://fly.io/docs/flyctl/install/): `iwr https://fly.io/install.ps1 -useb | iex`
2. Login: `flyctl auth login`
3. Have Git installed: https://git-scm.com/downloads

---

## First-Time Deploy

```powershell
# 1. Clone the repo
git clone https://github.com/elephant-accountability/agent-ready-directory.git
cd agent-ready-directory

# 2. Initialize Fly app (do NOT deploy yet)
fly launch --name agent-ready-directory --region iad --no-deploy

# 3. Create persistent volume for SQLite
fly volumes create agent_dir_data --size 1 --region iad

# 4. Set your admin token (replace with a real secret)
fly secrets set ADMIN_TOKEN=your-secret-admin-token-here

# 5. Deploy
fly deploy
```

---

## Custom Domain

```powershell
# Add CNAME: directory.eaccountability.org -> agent-ready-directory.fly.dev
# (Do this in Cloudflare DNS)

# Then add SSL cert in Fly
fly certs add directory.eaccountability.org
fly certs check directory.eaccountability.org
```

---

## Verify It's Running

```powershell
curl https://agent-ready-directory.fly.dev/health
curl https://agent-ready-directory.fly.dev/api/companies
curl https://directory.eaccountability.org/health
```

---

## Subsequent Deploys

```powershell
git pull
fly deploy
```

---

## Monitoring

```powershell
# View logs
fly logs

# SSH into container
fly ssh console

# Check status
fly status
```

---

## Re-run Verifier (Admin)

```powershell
curl -X POST https://directory.eaccountability.org/api/admin/verify-all `
  -H "Authorization: Bearer your-secret-admin-token-here"
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `ADMIN_TOKEN` | Secret token for admin API routes |
| `DATABASE_URL` | Path to SQLite file (default: `/data/directory.db`) |

Set secrets via: `fly secrets set KEY=value`
