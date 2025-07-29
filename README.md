# Certificate Monitor for AKS with cert-manager

This solution monitors cert-manager certificates in your AKS cluster and automatically uploads them in PFX format to Azure Key Vault using workload identity authentication.

## Features

- 🔍 **Automatic Certificate Discovery**: Monitors all cert-manager certificates across namespaces
- 🔄 **Smart Updates**: Only uploads certificates when they have changed (compares fingerprints)
- 🔐 **Secure Authentication**: Uses Azure Workload Identity (no secrets stored in cluster)
- 📦 **PFX Format**: Converts certificates to PFX format for easy use in Azure services
- ⏰ **Configurable Intervals**: Runs checks every 5 minutes (configurable)
- 🎯 **Filtering Support**: Can filter by namespace or certificate name patterns
- 📊 **Comprehensive Logging**: Detailed logging for monitoring and troubleshooting

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   cert-manager  │    │  cert-monitor    │    │  Azure Key      │
│   certificates  │───▶│  deployment      │───▶│  Vault          │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                       ┌────────▼────────┐
                       │ Workload Identity│
                       │ (Managed Identity)│
                       └─────────────────┘
```

## Prerequisites

1. **AKS Cluster** with:
   - cert-manager installed
   - OIDC issuer enabled
   - Workload identity enabled

2. **Azure Key Vault** in the same subscription

3. **Azure Container Registry** for storing the container image

4. **Required Tools**:
   - Azure CLI
   - kubectl
   - Docker
   - jq

## Quick Setup

1. **Clone and configure**:
   ```bash
   # Edit the configuration variables in setup.sh
   vi setup.sh
   ```

2. **Run the setup script**:
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Verify deployment**:
   ```bash
   kubectl get pods -n cert-manager -l app=cert-monitor
   kubectl logs -n cert-manager -l app=cert-monitor -f
   ```

## Manual Setup

### 1. Create Managed Identity

```bash
# Create user-assigned managed identity
az identity create \
  --name cert-monitor-identity \
  --resource-group your-resource-group

# Get the client ID
IDENTITY_CLIENT_ID=$(az identity show \
  --name cert-monitor-identity \
  --resource-group your-resource-group \
  --query clientId -o tsv)
```

### 2. Assign Key Vault Permissions

```bash
# Get the managed identity object ID
IDENTITY_OBJECT_ID=$(az identity show \
  --name cert-monitor-identity \
  --resource-group your-resource-group \
  --query principalId -o tsv)

# Assign Key Vault permissions
az role assignment create \
  --assignee $IDENTITY_OBJECT_ID \
  --role "Key Vault Certificate Officer" \
  --scope "/subscriptions/your-sub-id/resourceGroups/your-rg/providers/Microsoft.KeyVault/vaults/your-keyvault"

az role assignment create \
  --assignee $IDENTITY_OBJECT_ID \
  --role "Key Vault Secrets Officer" \
  --scope "/subscriptions/your-sub-id/resourceGroups/your-rg/providers/Microsoft.KeyVault/vaults/your-keyvault"
```

### 3. Setup Workload Identity

```bash
# Get AKS OIDC issuer
AKS_OIDC_ISSUER=$(az aks show \
  --name your-aks-cluster \
  --resource-group your-resource-group \
  --query "oidcIssuerProfile.issuerUrl" -o tsv)

# Create federated identity credential
az identity federated-credential create \
  --name cert-monitor-federation \
  --identity-name cert-monitor-identity \
  --resource-group your-resource-group \
  --issuer $AKS_OIDC_ISSUER \
  --subject "system:serviceaccount:cert-manager:cert-monitor" \
  --audience "api://AzureADTokenExchange"
```

### 4. Build and Deploy

```bash
# Build and push container
docker build -t your-registry/cert-monitor:latest .
docker push your-registry/cert-monitor:latest

# Update deployment.yaml with your values and deploy
kubectl apply -f k8s/deployment.yaml
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KEY_VAULT_URL` | Azure Key Vault URL | Required |
| `CHECK_INTERVAL_SECONDS` | Check interval in seconds | `300` (5 minutes) |
| `NAMESPACE_FILTER` | Filter certificates by namespace | `""` (all namespaces) |
| `CERT_NAME_FILTER` | Filter certificates by name pattern | `""` (all certificates) |
| `AZURE_CLIENT_ID` | Managed identity client ID | Required for workload identity |

### Filtering Examples

```yaml
# Monitor only certificates in the 'production' namespace
- name: NAMESPACE_FILTER
  value: "production"

# Monitor only certificates with 'web' in the name
- name: CERT_NAME_FILTER
  value: "web"
```

## Certificate Naming in Key Vault

Certificates are stored in Key Vault with names in the format:
- Secret: `{namespace}-{cert-name}-pfx`
- Example: `production-web-tls-pfx`

Each certificate includes metadata tags:
- `source`: `cert-manager`
- `namespace`: Original Kubernetes namespace
- `cert-name`: Original certificate name
- `common-name`: Certificate common name
- `serial-number`: Certificate serial number
- `fingerprint`: SHA256 fingerprint
- `not-before`: Valid from date
- `not-after`: Expiration date
- `uploaded-at`: Upload timestamp

## Monitoring and Troubleshooting

### Check Deployment Status
```bash
kubectl get pods -n cert-manager -l app=cert-monitor
kubectl describe pod -n cert-manager -l app=cert-monitor
```

### View Logs
```bash
# Real-time logs
kubectl logs -n cert-manager -l app=cert-monitor -f

# Recent logs
kubectl logs -n cert-manager -l app=cert-monitor --tail=100
```

### Common Issues

1. **Authentication Errors**:
   - Verify workload identity is properly configured
   - Check managed identity has correct Key Vault permissions
   - Ensure AZURE_CLIENT_ID matches the managed identity

2. **Certificate Not Found**:
   - Verify cert-manager certificates are in "Ready" state
   - Check if certificate secrets exist
   - Verify RBAC permissions for reading secrets

3. **Key Vault Access Denied**:
   - Verify managed identity has "Key Vault Certificate Officer" and "Key Vault Secrets Officer" roles
   - Check if Key Vault firewall allows AKS subnet

### Health Checks

The deployment includes:
- **Liveness Probe**: Ensures the container is running
- **Readiness Probe**: Ensures the application is ready to serve
- **Resource Limits**: Prevents resource exhaustion

## Security Features

- **Non-root container**: Runs as user 1000
- **Read-only filesystem**: Prevents runtime modifications
- **No privileged escalation**: Security context restrictions
- **Dropped capabilities**: Minimal Linux capabilities
- **Workload identity**: No secrets stored in cluster
- **RBAC**: Minimal Kubernetes permissions

## Development

### Local Testing

1. **Setup local environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r app/requirements.txt
   ```

2. **Configure environment**:
   ```bash
   export KEY_VAULT_URL="https://your-keyvault.vault.azure.net/"
   export CHECK_INTERVAL_SECONDS="60"
   ```

3. **Run locally**:
   ```bash
   cd app
   python cert_monitor.py
   ```

### Customization

The application is designed to be easily customizable:

- **Certificate Processing**: Modify `process_certificates()` method
- **Key Vault Operations**: Extend `upload_certificate_to_keyvault()` method
- **Filtering Logic**: Update `get_certificates()` method
- **Naming Convention**: Modify `_get_keyvault_name()` method

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with appropriate tests
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review application logs
3. Open an issue with detailed information about your environment and the problem
