# PowerShell script to verify certificates in Azure Key Vault
# Run this after deploying the cert-monitor to verify it's working

param(
    [Parameter(Mandatory=$true)]
    [string]$KeyVaultName,
    
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId
)

# Set subscription if provided
if ($SubscriptionId) {
    az account set --subscription $SubscriptionId
}

Write-Host "Checking certificates in Key Vault: $KeyVaultName" -ForegroundColor Green

# Get all secrets with cert-manager source tag
$secrets = az keyvault secret list --vault-name $KeyVaultName --query "[?tags.source=='cert-manager']" | ConvertFrom-Json

if ($secrets.Count -eq 0) {
    Write-Host "No cert-manager certificates found in Key Vault" -ForegroundColor Yellow
    exit
}

Write-Host "Found $($secrets.Count) cert-manager certificates:" -ForegroundColor Green

foreach ($secret in $secrets) {
    Write-Host "`n--- Certificate: $($secret.name) ---" -ForegroundColor Cyan
    
    # Get secret details with tags
    $secretDetails = az keyvault secret show --vault-name $KeyVaultName --name $secret.name | ConvertFrom-Json
    
    $tags = $secretDetails.tags
    if ($tags) {
        Write-Host "  Namespace: $($tags.'namespace')" -ForegroundColor White
        Write-Host "  Original Name: $($tags.'cert-name')" -ForegroundColor White
        Write-Host "  Common Name: $($tags.'common-name')" -ForegroundColor White
        Write-Host "  Serial Number: $($tags.'serial-number')" -ForegroundColor White
        Write-Host "  Fingerprint: $($tags.'fingerprint')" -ForegroundColor White
        Write-Host "  Valid From: $($tags.'not-before')" -ForegroundColor White
        Write-Host "  Valid Until: $($tags.'not-after')" -ForegroundColor White
        Write-Host "  Uploaded At: $($tags.'uploaded-at')" -ForegroundColor White
        
        # Check if certificate is expiring soon (within 30 days)
        $notAfter = [DateTime]::Parse($tags.'not-after')
        $daysUntilExpiry = ($notAfter - (Get-Date)).Days
        
        if ($daysUntilExpiry -lt 30) {
            Write-Host "  ⚠️  WARNING: Certificate expires in $daysUntilExpiry days!" -ForegroundColor Red
        } elseif ($daysUntilExpiry -lt 60) {
            Write-Host "  ⚠️  Certificate expires in $daysUntilExpiry days" -ForegroundColor Yellow
        } else {
            Write-Host "  ✅ Certificate expires in $daysUntilExpiry days" -ForegroundColor Green
        }
    }
    
    Write-Host "  Content Type: $($secretDetails.contentType)" -ForegroundColor White
    Write-Host "  Updated: $($secretDetails.attributes.updated)" -ForegroundColor White
}

Write-Host "`n✅ Certificate verification complete" -ForegroundColor Green
