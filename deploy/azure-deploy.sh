#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# Azure App Service Deployment Script — AI AppSec Service
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - Docker installed (for building the container)
#
# Usage:
#   chmod +x deploy/azure-deploy.sh
#   ./deploy/azure-deploy.sh
#
# This script creates:
#   1. Resource Group
#   2. Azure Container Registry (ACR)
#   3. Azure Database for PostgreSQL (Flexible Server)
#   4. Azure App Service (Linux container)
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Configuration (edit these) ────────────────────────────────────────────
RESOURCE_GROUP="rg-ai-appsec"
LOCATION="uksouth"                          # UK South for Mastek UK
ACR_NAME="acraiappsec"                      # Must be globally unique, lowercase
APP_SERVICE_PLAN="plan-ai-appsec"
WEB_APP_NAME="ai-appsec-service"            # Must be globally unique
DB_SERVER_NAME="psql-ai-appsec"             # Must be globally unique
DB_ADMIN_USER="appsecadmin"
DB_ADMIN_PASSWORD="ChangeMe!Str0ngP@ss"     # Change this!
DB_NAME="ai_appsec"
PERPLEXITY_API_KEY=""                        # Set your Perplexity API key

# ── Derived values ────────────────────────────────────────────────────────
IMAGE_NAME="${ACR_NAME}.azurecr.io/ai-appsec-service:latest"
DATABASE_URL="postgresql://${DB_ADMIN_USER}:${DB_ADMIN_PASSWORD}@${DB_SERVER_NAME}.postgres.database.azure.com:5432/${DB_NAME}?sslmode=require"

echo "═══════════════════════════════════════════════════════════════════"
echo "  AI AppSec Service — Azure Deployment"
echo "═══════════════════════════════════════════════════════════════════"

# ── Step 1: Resource Group ────────────────────────────────────────────────
echo ""
echo "▶ Step 1: Creating Resource Group..."
az group create --name $RESOURCE_GROUP --location $LOCATION --output none
echo "  ✓ Resource Group: $RESOURCE_GROUP ($LOCATION)"

# ── Step 2: Container Registry ────────────────────────────────────────────
echo ""
echo "▶ Step 2: Creating Azure Container Registry..."
az acr create --resource-group $RESOURCE_GROUP \
    --name $ACR_NAME \
    --sku Basic \
    --admin-enabled true \
    --output none
echo "  ✓ ACR: $ACR_NAME"

# ── Step 3: Build and push Docker image ───────────────────────────────────
echo ""
echo "▶ Step 3: Building and pushing Docker image..."
az acr build --registry $ACR_NAME \
    --image ai-appsec-service:latest \
    --file Dockerfile \
    . \
    --output none
echo "  ✓ Image pushed: $IMAGE_NAME"

# ── Step 4: PostgreSQL Flexible Server ────────────────────────────────────
echo ""
echo "▶ Step 4: Creating PostgreSQL Flexible Server..."
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

echo "  ✓ PostgreSQL: $DB_SERVER_NAME"

# ── Step 5: App Service Plan ──────────────────────────────────────────────
echo ""
echo "▶ Step 5: Creating App Service Plan..."
az appservice plan create \
    --resource-group $RESOURCE_GROUP \
    --name $APP_SERVICE_PLAN \
    --is-linux \
    --sku B1 \
    --output none
echo "  ✓ Plan: $APP_SERVICE_PLAN (B1 — Basic)"

# ── Step 6: Web App ───────────────────────────────────────────────────────
echo ""
echo "▶ Step 6: Creating Web App..."
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

echo "  ✓ Web App: $WEB_APP_NAME"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
echo "  ✓ Deployment Complete!"
echo ""
echo "  URL:      https://${WEB_APP_NAME}.azurewebsites.net"
echo "  Logs:     az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
echo "  SSH:      az webapp create-remote-connection --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
echo ""
echo "  Default credentials (change immediately!):"
echo "    admin / admin123"
echo "    scanner / scanner123"
echo "    requester / requester123"
echo "    executive / executive123"
echo ""
echo "  Next steps:"
echo "    1. Change the default passwords via the Admin panel"
echo "    2. Configure custom domain + SSL in Azure Portal"
echo "    3. Set up Azure AD / Entra ID for SSO (future)"
echo "═══════════════════════════════════════════════════════════════════"
