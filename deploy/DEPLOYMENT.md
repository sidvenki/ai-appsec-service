# AI AppSec Service — Deployment Guide

## Deployment Options

| Option | Best For | Database | Effort |
|--------|----------|----------|--------|
| **Option A: Internal VM** | Unit testing, team demos | SQLite or PostgreSQL | Low |
| **Option B: Docker Compose** | Internal server with PostgreSQL | PostgreSQL | Low |
| **Option C: Azure App Service** | Production, shared URL, auto-scaling | Azure PostgreSQL | Medium |

---

## Option A: Internal VM (Linux)

Deploy on an internal Ubuntu/RHEL server for team testing.

### 1. Prepare the server

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y python3.11 python3.11-venv git nginx

# Create service account
sudo useradd -m -r -s /bin/bash appsec
```

### 2. Clone and install

```bash
sudo mkdir -p /opt/ai-appsec-service
sudo chown appsec:appsec /opt/ai-appsec-service

sudo -u appsec bash << 'EOF'
cd /opt/ai-appsec-service
git clone https://github.com/sidvenki/ai-appsec-service.git .
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
EOF
```

### 3. Configure environment (optional)

```bash
# For PostgreSQL (recommended for multi-user):
# sudo -u appsec nano /opt/ai-appsec-service/.env
# DATABASE_URL=postgresql://appsec:password@localhost:5432/ai_appsec

# For AI remediation:
# PERPLEXITY_API_KEY=pplx-xxxxxxxxxxxxxxxx
```

### 4. Install systemd service

```bash
sudo cp /opt/ai-appsec-service/deploy/ai-appsec.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ai-appsec
sudo systemctl start ai-appsec
```

### 5. Install Nginx reverse proxy

```bash
sudo cp /opt/ai-appsec-service/deploy/nginx.conf /etc/nginx/sites-available/ai-appsec
sudo ln -s /etc/nginx/sites-available/ai-appsec /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6. Configure DNS

Add an A record in your internal DNS pointing `appsec.mastek.internal` to the server IP.

### 7. Open firewall

```bash
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS (when configured)
```

### Access

- **URL:** `http://appsec.mastek.internal` (or `http://<server-ip>`)
- **Logs:** `journalctl -u ai-appsec -f`
- **Restart:** `sudo systemctl restart ai-appsec`

---

## Option B: Docker Compose (Internal Server)

Includes PostgreSQL — good for persistent multi-user testing.

### 1. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo apt install -y docker-compose-plugin
```

### 2. Clone and start

```bash
git clone https://github.com/sidvenki/ai-appsec-service.git
cd ai-appsec-service

# Optional: set environment variables
export DB_PASSWORD="YourStrongPassword123!"
export PERPLEXITY_API_KEY="pplx-xxxxxxxxxxxxxxxx"

# Start
docker compose -f deploy/docker-compose.yml up -d
```

### 3. Access

- **URL:** `http://<server-ip>:8000`
- **Logs:** `docker compose -f deploy/docker-compose.yml logs -f app`
- **Stop:** `docker compose -f deploy/docker-compose.yml down`
- **Reset DB:** `docker compose -f deploy/docker-compose.yml down -v`

---

## Option C: Azure App Service (Production)

Full cloud deployment with managed PostgreSQL, auto-scaling, and HTTPS.

### Prerequisites

- Azure CLI installed (`az --version`)
- Logged in (`az login`)
- Docker installed locally (for ACR build)

### 1. Edit the deployment script

```bash
nano deploy/azure-deploy.sh
```

Update the configuration variables at the top:
- `DB_ADMIN_PASSWORD` — set a strong password
- `PERPLEXITY_API_KEY` — your Perplexity API key
- `WEB_APP_NAME` — must be globally unique
- `ACR_NAME` — must be globally unique, lowercase

### 2. Run the deployment

```bash
chmod +x deploy/azure-deploy.sh
./deploy/azure-deploy.sh
```

This creates all Azure resources (~5-10 minutes):
- Resource Group in UK South
- Azure Container Registry
- PostgreSQL Flexible Server (Burstable B1ms)
- App Service Plan (Basic B1)
- Web App with container deployment

### 3. Access

- **URL:** `https://<app-name>.azurewebsites.net`
- **Logs:** `az webapp log tail --name <app-name> --resource-group rg-ai-appsec`

### 4. Custom domain (optional)

```bash
# Add custom domain
az webapp config hostname add \
    --webapp-name <app-name> \
    --resource-group rg-ai-appsec \
    --hostname appsec.mastek.com

# Add managed SSL certificate
az webapp config ssl create \
    --resource-group rg-ai-appsec \
    --name <app-name> \
    --hostname appsec.mastek.com
```

### Azure cost estimate (B1 tier)

| Resource | Monthly Cost (approx) |
|----------|-----------------------|
| App Service B1 | ~£10/month |
| PostgreSQL B1ms | ~£12/month |
| Container Registry Basic | ~£4/month |
| **Total** | **~£26/month** |

---

## Updating the Application

### Internal VM / Docker

```bash
cd /opt/ai-appsec-service   # or your clone directory
git pull
sudo systemctl restart ai-appsec   # VM
# or
docker compose -f deploy/docker-compose.yml up -d --build   # Docker
```

### Azure App Service

```bash
# Rebuild and push new image
az acr build --registry acraiappsec \
    --image ai-appsec-service:latest \
    --file Dockerfile .

# Restart the web app to pull new image
az webapp restart --name ai-appsec-service --resource-group rg-ai-appsec
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | No | `sqlite:///ai_appsec.db` | Database connection string |
| `PERPLEXITY_API_KEY` | No | (none) | Perplexity API key for AI remediation |
| `WEBSITES_PORT` | Azure only | `8000` | Port for Azure App Service |

---

## Security Checklist (Before Sharing URL)

- [ ] Change all default passwords (admin, scanner, requester, executive)
- [ ] Set a strong `DB_ADMIN_PASSWORD` for PostgreSQL
- [ ] Configure HTTPS (SSL certificate)
- [ ] Restrict network access (internal VPN / Azure Private Endpoint)
- [ ] Set `PERPLEXITY_API_KEY` if using AI remediation
- [ ] Review firewall rules — only expose ports 80/443
