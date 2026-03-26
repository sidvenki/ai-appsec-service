#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# Azure App Service Deployment Script — AI AppSec Service (Test)
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Run from the project root (ai-appsec-service/)
#
# Usage:
#   chmod +x deploy/azure-deploy.sh
#   ./deploy/azure-deploy.sh
#
# Creates: Resource Group → ACR → PostgreSQL → App Service Plan → Web App
# Estimated cost: ~£27/month (UK South, Linux B1 + PostgreSQL B1ms)
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Test Environment Configuration ────────────────────────────────────────
RESOURCE_GROUP="rg-ai-appsec-test"
LOCATION="uksouth"
ACR_NAME="acraiappsectest"                  # Must be globally unique, lowercase, alphanumeric only
APP_SERVICE_PLAN="plan-ai-appsec-test"
WEB_APP_NAME="ai-appsec-test"              # Must be globally unique → https://ai-appsec-test.azurewebsites.net
DB_SERVER_NAME="psql-ai-appsec-test"       # Must be globally unique
DB_ADMIN_USER="appsecadmin"
DB_NAME="ai_appsec"

# ── Prompt for secrets (not hardcoded) ────────────────────────────────────
echo "═══════════════════════════════════════════════════════════════════"
echo "  AI AppSec Service — Azure Test Deployment"
echo "  Region: UK South | OS: Linux | Tier: B1 (~£27/month total)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Database password
read -sp "Enter PostgreSQL admin password (min 8 chars, mixed case + number): " DB_ADMIN_PASSWORD
echo ""
if [ ${#DB_ADMIN_PASSWORD} -lt 8 ]; then
    echo "ERROR: Password must be at least 8 characters."
    exit 1
fi

# Perplexity API key
read -p "Enter Perplexity API key (or press Enter to skip): " PERPLEXITY_API_KEY
PERPLEXITY_API_KEY="${PERPLEXITY_API_KEY:-}"

# ── Derived values ────────────────────────────────────────────────────────
IMAGE_NAME="${ACR_NAME}.azurecr.io/ai-appsec-service:latest"
DATABASE_URL="postgresql://${DB_ADMIN_USER}:${DB_ADMIN_PASSWORD}@${DB_SERVER_NAME}.postgres.database.azure.com:5432/${DB_NAME}?sslmode=require"

echo ""
echo "  Resource Group:  $RESOURCE_GROUP"
echo "  Web App URL:     https://${WEB_APP_NAME}.azurewebsites.net"
echo "  PostgreSQL:      $DB_SERVER_NAME.postgres.database.azure.com"
echo "  Container Reg:   ${ACR_NAME}.azurecr.io"
echo "  PPLX API Key:    $([ -n "$PERPLEXITY_API_KEY" ] && echo "set" || echo "not set (using fallback)")"
echo ""
read -p "Proceed with deployment? (y/N): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

echo ""

# ── Step 1: Resource Group ────────────────────────────────────────────────
echo "▶ Step 1/6: Creating Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none
echo "  ✓ Resource Group: $RESOURCE_GROUP ($LOCATION)"

# ── Step 2: Container Registry ────────────────────────────────────────────
echo ""
echo "▶ Step 2/6: Creating Azure Container Registry..."
az acr create --resource-group $RESOURCE_GROUP \
    --name $ACR_NAME \
    --sku Basic \
    --admin-enabled true \
    --output none
echo "  ✓ ACR: $ACR_NAME"

# ── Step 3: Build and push Docker image ───────────────────────────────────
echo ""
echo "▶ Step 3/6: Building and pushing Docker image (this takes 2-3 minutes)..."
az acr build --registry $ACR_NAME \
    --image ai-appsec-service:latest \
    --file Dockerfile \
    .
echo "  ✓ Image pushed: $IMAGE_NAME"

# ── Step 4: PostgreSQL Flexible Server ────────────────────────────────────
echo ""
echo "▶ Step 4/6: Creating PostgreSQL Flexible Server (this takes 3-5 minutes)..."
az postgres flexible-server create \
    --resource-group $RESOURCE_GROUP \
    --name $DB_SERVER_NAME \
    --location $LOCATION \
    --admin-user $DB_ADMIN_USER \
    --admin-password "$DB_ADMIN_PASSWORD" \
    --sku-name Standard_B1ms \
    --tier Burstable \
    --storage-size 32 \
    --version 16 \
    --yes \
    --output none

# Create the database
az postgres flexible-server db create \
    --resource-group $RESOURCE_GROUP \
    --server-name $DB_SERVER_NAME \
    --database-name $DB_NAME \
    --output none

# Allow Azure services to connect
az postgres flexible-server firewall-rule create \
    --resource-group $RESOURCE_GROUP \
    --name $DB_SERVER_NAME \
    --rule-name AllowAzureServices \
    --start-ip-address 0.0.0.0 \
    --end-ip-address 0.0.0.0 \
    --output none

echo "  ✓ PostgreSQL: $DB_SERVER_NAME (Burstable B1ms, 32GB storage)"

# ── Step 5: App Service Plan ──────────────────────────────────────────────
echo ""
echo "▶ Step 5/6: Creating App Service Plan (Linux B1)..."
az appservice plan create \
    --resource-group $RESOURCE_GROUP \
    --name $APP_SERVICE_PLAN \
    --is-linux \
    --sku B1 \
    --output none
echo "  ✓ Plan: $APP_SERVICE_PLAN (Linux B1 — 1 core, 1.75GB RAM)"

# ── Step 6: Web App ───────────────────────────────────────────────────────
echo ""
echo "▶ Step 6/6: Creating Web App and configuring..."
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv)

az webapp create \
    --resource-group $RESOURCE_GROUP \
    --plan $APP_SERVICE_PLAN \
    --name $WEB_APP_NAME \
    --docker-registry-server-url "https://${ACR_NAME}.azurecr.io" \
    --docker-registry-server-user $ACR_NAME \
    --docker-registry-server-password "$ACR_PASSWORD" \
    --container-image-name "$IMAGE_NAME" \
    --output none

# Configure environment variables
az webapp config appsettings set \
    --resource-group $RESOURCE_GROUP \
    --name $WEB_APP_NAME \
    --settings \
        DATABASE_URL="$DATABASE_URL" \
        PERPLEXITY_API_KEY="$PERPLEXITY_API_KEY" \
        WEBSITES_PORT=8000 \
    --output none

# Enable logging
az webapp log config \
    --resource-group $RESOURCE_GROUP \
    --name $WEB_APP_NAME \
    --docker-container-logging filesystem \
    --output none

# Set always-on (keeps the app warm)
az webapp config set \
    --resource-group $RESOURCE_GROUP \
    --name $WEB_APP_NAME \
    --always-on true \
    --output none

echo "  ✓ Web App: $WEB_APP_NAME"

# ── Wait for startup ──────────────────────────────────────────────────────
echo ""
echo "⏳ Waiting for the app to start (first boot creates the database tables)..."
sleep 30

# Check if the app is responding
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://${WEB_APP_NAME}.azurewebsites.net/" || echo "000")
if [ "$HTTP_STATUS" -ge 200 ] && [ "$HTTP_STATUS" -lt 400 ]; then
    echo "  ✓ App is running! (HTTP $HTTP_STATUS)"
else
    echo "  ⚠ App returned HTTP $HTTP_STATUS — it may still be starting up."
    echo "    Check logs: az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
fi

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  ✓ TEST DEPLOYMENT COMPLETE"
echo ""
echo "  URL:        https://${WEB_APP_NAME}.azurewebsites.net"
echo "  Logs:       az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
echo "  Restart:    az webapp restart --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
echo ""
echo "  Login credentials:"
echo "    admin     / admin123       (Admin — full access)"
echo "    scanner   / scanner123     (Scanner — your team)"
echo "    requester / requester123   (Requester — dev teams)"
echo "    executive / executive123   (Executive — dashboard only)"
echo ""
echo "  ⚠  IMPORTANT: Change these default passwords after first login!"
echo ""
echo "  Monthly cost estimate: ~£27/month"
echo "    App Service B1:     £9.71"
echo "    PostgreSQL B1ms:    £10.25"
echo "    PostgreSQL Storage: £3.14"
echo "    Container Registry: £3.69"
echo ""
echo "  To tear down all test resources:"
echo "    az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo "═══════════════════════════════════════════════════════════════════"
