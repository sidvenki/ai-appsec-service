# ──────────────────────────────────────────────────────────────────────────
# Azure App Service Deployment Script — AI AppSec Service (Test)
# PowerShell version for Windows
#
# Prerequisites:
#   - Azure CLI installed (winget install Microsoft.AzureCLI)
#   - Logged in (az login)
#   - Run from the project root (ai-appsec-service/)
#
# Usage:
#   cd ai-appsec-service
#   .\deploy\azure-deploy.ps1
#
# Estimated cost: ~£27/month (UK South, Linux B1 + PostgreSQL B1ms)
# ──────────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Stop"

# ── Test Environment Configuration ────────────────────────────────────────
$RESOURCE_GROUP    = "rg-ai-appsec-test"
$LOCATION          = "uksouth"
$ACR_NAME          = "acraiappsectest"
$APP_SERVICE_PLAN  = "plan-ai-appsec-test"
$WEB_APP_NAME      = "ai-appsec-test"
$DB_SERVER_NAME    = "psql-ai-appsec-test"
$DB_ADMIN_USER     = "appsecadmin"
$DB_NAME           = "ai_appsec"

# ── Prompt for secrets ────────────────────────────────────────────────────
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  AI AppSec Service — Azure Test Deployment" -ForegroundColor Cyan
Write-Host "  Region: UK South | OS: Linux | Tier: B1 (~£27/month total)" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$DB_ADMIN_PASSWORD = Read-Host "Enter PostgreSQL admin password (min 8 chars, mixed case + number)" -AsSecureString
$DB_ADMIN_PASSWORD_PLAIN = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($DB_ADMIN_PASSWORD)
)
if ($DB_ADMIN_PASSWORD_PLAIN.Length -lt 8) {
    Write-Host "ERROR: Password must be at least 8 characters." -ForegroundColor Red
    exit 1
}

$PERPLEXITY_API_KEY = Read-Host "Enter Perplexity API key (or press Enter to skip)"

# ── Derived values ────────────────────────────────────────────────────────
$IMAGE_NAME   = "${ACR_NAME}.azurecr.io/ai-appsec-service:latest"
$DATABASE_URL = "postgresql://${DB_ADMIN_USER}:${DB_ADMIN_PASSWORD_PLAIN}@${DB_SERVER_NAME}.postgres.database.azure.com:5432/${DB_NAME}?sslmode=require"

Write-Host ""
Write-Host "  Resource Group:  $RESOURCE_GROUP"
Write-Host "  Web App URL:     https://${WEB_APP_NAME}.azurewebsites.net"
Write-Host "  PostgreSQL:      ${DB_SERVER_NAME}.postgres.database.azure.com"
Write-Host "  Container Reg:   ${ACR_NAME}.azurecr.io"
$pplxStatus = if ($PERPLEXITY_API_KEY) { "set" } else { "not set (using fallback)" }
Write-Host "  PPLX API Key:    $pplxStatus"
Write-Host ""

$confirm = Read-Host "Proceed with deployment? (y/N)"
if ($confirm -notmatch "^[Yy]$") {
    Write-Host "Deployment cancelled."
    exit 0
}

Write-Host ""

# ── Step 1: Resource Group ────────────────────────────────────────────────
Write-Host "▶ Step 1/6: Creating Resource Group..." -ForegroundColor Yellow
az group create --name $RESOURCE_GROUP --location $LOCATION --output none
Write-Host "  ✓ Resource Group: $RESOURCE_GROUP ($LOCATION)" -ForegroundColor Green

# ── Step 2: Container Registry ────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Step 2/6: Creating Azure Container Registry..." -ForegroundColor Yellow
az acr create --resource-group $RESOURCE_GROUP `
    --name $ACR_NAME `
    --sku Basic `
    --admin-enabled true `
    --output none
Write-Host "  ✓ ACR: $ACR_NAME" -ForegroundColor Green

# ── Step 3: Build and push Docker image ───────────────────────────────────
Write-Host ""
Write-Host "▶ Step 3/6: Building and pushing Docker image (this takes 2-3 minutes)..." -ForegroundColor Yellow
az acr build --registry $ACR_NAME `
    --image ai-appsec-service:latest `
    --file Dockerfile `
    .
Write-Host "  ✓ Image pushed: $IMAGE_NAME" -ForegroundColor Green

# ── Step 4: PostgreSQL Flexible Server ────────────────────────────────────
Write-Host ""
Write-Host "▶ Step 4/6: Creating PostgreSQL Flexible Server (this takes 3-5 minutes)..." -ForegroundColor Yellow
az postgres flexible-server create `
    --resource-group $RESOURCE_GROUP `
    --name $DB_SERVER_NAME `
    --location $LOCATION `
    --admin-user $DB_ADMIN_USER `
    --admin-password $DB_ADMIN_PASSWORD_PLAIN `
    --sku-name Standard_B1ms `
    --tier Burstable `
    --storage-size 32 `
    --version 16 `
    --yes `
    --output none

az postgres flexible-server db create `
    --resource-group $RESOURCE_GROUP `
    --server-name $DB_SERVER_NAME `
    --database-name $DB_NAME `
    --output none

az postgres flexible-server firewall-rule create `
    --resource-group $RESOURCE_GROUP `
    --name $DB_SERVER_NAME `
    --rule-name AllowAzureServices `
    --start-ip-address 0.0.0.0 `
    --end-ip-address 0.0.0.0 `
    --output none

Write-Host "  ✓ PostgreSQL: $DB_SERVER_NAME (Burstable B1ms, 32GB storage)" -ForegroundColor Green

# ── Step 5: App Service Plan ──────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Step 5/6: Creating App Service Plan (Linux B1)..." -ForegroundColor Yellow
az appservice plan create `
    --resource-group $RESOURCE_GROUP `
    --name $APP_SERVICE_PLAN `
    --is-linux `
    --sku B1 `
    --output none
Write-Host "  ✓ Plan: $APP_SERVICE_PLAN (Linux B1 — 1 core, 1.75GB RAM)" -ForegroundColor Green

# ── Step 6: Web App ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "▶ Step 6/6: Creating Web App and configuring..." -ForegroundColor Yellow
$ACR_PASSWORD = az acr credential show --name $ACR_NAME --query "passwords[0].value" -o tsv

az webapp create `
    --resource-group $RESOURCE_GROUP `
    --plan $APP_SERVICE_PLAN `
    --name $WEB_APP_NAME `
    --docker-registry-server-url "https://${ACR_NAME}.azurecr.io" `
    --docker-registry-server-user $ACR_NAME `
    --docker-registry-server-password $ACR_PASSWORD `
    --container-image-name $IMAGE_NAME `
    --output none

az webapp config appsettings set `
    --resource-group $RESOURCE_GROUP `
    --name $WEB_APP_NAME `
    --settings `
        DATABASE_URL="$DATABASE_URL" `
        PERPLEXITY_API_KEY="$PERPLEXITY_API_KEY" `
        WEBSITES_PORT=8000 `
    --output none

az webapp log config `
    --resource-group $RESOURCE_GROUP `
    --name $WEB_APP_NAME `
    --docker-container-logging filesystem `
    --output none

az webapp config set `
    --resource-group $RESOURCE_GROUP `
    --name $WEB_APP_NAME `
    --always-on true `
    --output none

Write-Host "  ✓ Web App: $WEB_APP_NAME" -ForegroundColor Green

# ── Wait for startup ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "⏳ Waiting for the app to start (first boot creates database tables)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

try {
    $response = Invoke-WebRequest -Uri "https://${WEB_APP_NAME}.azurewebsites.net/" -UseBasicParsing -TimeoutSec 15
    Write-Host "  ✓ App is running! (HTTP $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ App may still be starting up. Give it another minute." -ForegroundColor Yellow
    Write-Host "    Check logs: az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
}

# ── Done ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✓ TEST DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host ""
Write-Host "  URL:        https://${WEB_APP_NAME}.azurewebsites.net" -ForegroundColor White
Write-Host "  Logs:       az webapp log tail --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
Write-Host "  Restart:    az webapp restart --name $WEB_APP_NAME --resource-group $RESOURCE_GROUP"
Write-Host ""
Write-Host "  Login credentials:"
Write-Host "    admin     / admin123       (Admin — full access)"
Write-Host "    scanner   / scanner123     (Scanner — your team)"
Write-Host "    requester / requester123   (Requester — dev teams)"
Write-Host "    executive / executive123   (Executive — dashboard only)"
Write-Host ""
Write-Host "  ⚠  IMPORTANT: Change these default passwords after first login!" -ForegroundColor Red
Write-Host ""
Write-Host "  Monthly cost estimate: ~£27/month"
Write-Host "    App Service B1:     £9.71"
Write-Host "    PostgreSQL B1ms:    £10.25"
Write-Host "    PostgreSQL Storage: £3.14"
Write-Host "    Container Registry: £3.69"
Write-Host ""
Write-Host "  To tear down all test resources:" -ForegroundColor Yellow
Write-Host "    az group delete --name $RESOURCE_GROUP --yes --no-wait"
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
