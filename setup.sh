#!/bin/bash

# Certificate Monitor Setup Script for AKS with Workload Identity
# This script sets up the necessary Azure resources and Kubernetes configurations

set -e

# Configuration variables - EDIT THESE VALUES
SUBSCRIPTION_ID="your-subscription-id"
RESOURCE_GROUP="your-resource-group"
AKS_CLUSTER_NAME="your-aks-cluster"
KEY_VAULT_NAME="your-keyvault-name"
MANAGED_IDENTITY_NAME="cert-monitor-identity"
CONTAINER_REGISTRY="your-registry.azurecr.io"
IMAGE_NAME="cert-monitor"
IMAGE_TAG="latest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Azure CLI is installed and logged in
check_prerequisites() {
    echo_info "Checking prerequisites..."
    
    if ! command -v az &> /dev/null; then
        echo_error "Azure CLI is not installed. Please install it first."
        exit 1
    fi
    
    if ! command -v kubectl &> /dev/null; then
        echo_error "kubectl is not installed. Please install it first."
        exit 1
    fi
    
    # Check if logged into Azure
    if ! az account show &> /dev/null; then
        echo_error "Please login to Azure CLI first: az login"
        exit 1
    fi
    
    echo_info "Prerequisites check passed"
}

# Create managed identity
create_managed_identity() {
    echo_info "Creating managed identity: $MANAGED_IDENTITY_NAME"
    
    # Create user-assigned managed identity
    IDENTITY_JSON=$(az identity create \
        --name $MANAGED_IDENTITY_NAME \
        --resource-group $RESOURCE_GROUP \
        --subscription $SUBSCRIPTION_ID \
        --output json)
    
    IDENTITY_CLIENT_ID=$(echo $IDENTITY_JSON | jq -r '.clientId')
    IDENTITY_OBJECT_ID=$(echo $IDENTITY_JSON | jq -r '.principalId')
    IDENTITY_RESOURCE_ID=$(echo $IDENTITY_JSON | jq -r '.id')
    
    echo_info "Managed Identity created:"
    echo_info "  Client ID: $IDENTITY_CLIENT_ID"
    echo_info "  Object ID: $IDENTITY_OBJECT_ID"
    echo_info "  Resource ID: $IDENTITY_RESOURCE_ID"
    
    # Export for later use
    export IDENTITY_CLIENT_ID
    export IDENTITY_OBJECT_ID
    export IDENTITY_RESOURCE_ID
}

# Assign Key Vault permissions
assign_keyvault_permissions() {
    echo_info "Assigning Key Vault permissions to managed identity"
    
    # Get Key Vault resource ID
    KEY_VAULT_RESOURCE_ID=$(az keyvault show \
        --name $KEY_VAULT_NAME \
        --resource-group $RESOURCE_GROUP \
        --query "id" \
        --output tsv)
    
    # Assign Key Vault Certificate Officer role for certificate management
    az role assignment create \
        --assignee $IDENTITY_OBJECT_ID \
        --role "Key Vault Certificate Officer" \
        --scope $KEY_VAULT_RESOURCE_ID
    
    # Assign Key Vault Secrets Officer role for secret management (PFX upload)
    az role assignment create \
        --assignee $IDENTITY_OBJECT_ID \
        --role "Key Vault Secrets Officer" \
        --scope $KEY_VAULT_RESOURCE_ID
    
    echo_info "Key Vault permissions assigned successfully"
}

# Setup workload identity
setup_workload_identity() {
    echo_info "Setting up workload identity federation"
    
    # Get AKS OIDC issuer URL
    AKS_OIDC_ISSUER=$(az aks show \
        --name $AKS_CLUSTER_NAME \
        --resource-group $RESOURCE_GROUP \
        --query "oidcIssuerProfile.issuerUrl" \
        --output tsv)
    
    if [ -z "$AKS_OIDC_ISSUER" ]; then
        echo_error "AKS cluster does not have OIDC issuer enabled. Please enable it first:"
        echo_error "az aks update --name $AKS_CLUSTER_NAME --resource-group $RESOURCE_GROUP --enable-oidc-issuer"
        exit 1
    fi
    
    echo_info "AKS OIDC Issuer: $AKS_OIDC_ISSUER"
    
    # Create federated identity credential
    az identity federated-credential create \
        --name "cert-monitor-federation" \
        --identity-name $MANAGED_IDENTITY_NAME \
        --resource-group $RESOURCE_GROUP \
        --issuer $AKS_OIDC_ISSUER \
        --subject "system:serviceaccount:cert-manager:cert-monitor" \
        --audience "api://AzureADTokenExchange"
    
    echo_info "Workload identity federation configured successfully"
}

# Build and push container image
build_and_push_image() {
    echo_info "Building and pushing container image"
    
    # Build the Docker image
    docker build -t $CONTAINER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG ./docker-image
    
    # Push to registry
    az acr login --name $(echo $CONTAINER_REGISTRY | cut -d'.' -f1)
    docker push $CONTAINER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG
    
    echo_info "Container image built and pushed successfully"
}

# Update Kubernetes deployment with actual values
update_k8s_deployment() {
    echo_info "Updating Kubernetes deployment with actual values"
    
    # Create a temporary deployment file with substituted values
    cp k8s/deployment.yaml k8s/deployment-configured.yaml
    
    # Replace placeholders
    sed -i "s/YOUR_MANAGED_IDENTITY_CLIENT_ID/$IDENTITY_CLIENT_ID/g" k8s/deployment-configured.yaml
    sed -i "s|YOUR_REGISTRY|$CONTAINER_REGISTRY|g" k8s/deployment-configured.yaml
    sed -i "s/YOUR_KEYVAULT_NAME/$KEY_VAULT_NAME/g" k8s/deployment-configured.yaml
    
    echo_info "Kubernetes deployment configuration updated"
}

# Deploy to Kubernetes
deploy_to_kubernetes() {
    echo_info "Deploying to Kubernetes"
    
    # Get AKS credentials
    az aks get-credentials \
        --name $AKS_CLUSTER_NAME \
        --resource-group $RESOURCE_GROUP \
        --overwrite-existing
    
    # Apply the deployment
    kubectl apply -f k8s/deployment-configured.yaml
    
    echo_info "Deployed to Kubernetes successfully"
    echo_info "Check deployment status with: kubectl get pods -n cert-manager -l app=cert-monitor"
}

# Main execution
main() {
    echo_info "Starting Certificate Monitor setup for AKS with Workload Identity"
    echo_info "Configuration:"
    echo_info "  Subscription: $SUBSCRIPTION_ID"
    echo_info "  Resource Group: $RESOURCE_GROUP"
    echo_info "  AKS Cluster: $AKS_CLUSTER_NAME"
    echo_info "  Key Vault: $KEY_VAULT_NAME"
    echo_info "  Managed Identity: $MANAGED_IDENTITY_NAME"
    echo_info "  Container Registry: $CONTAINER_REGISTRY"
    
    read -p "Continue with setup? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo_info "Setup cancelled"
        exit 0
    fi
    
    check_prerequisites
    create_managed_identity
    assign_keyvault_permissions
    setup_workload_identity
    build_and_push_image
    update_k8s_deployment
    deploy_to_kubernetes
    
    echo_info "Setup completed successfully!"
    echo_info ""
    echo_info "Next steps:"
    echo_info "1. Verify the deployment: kubectl get pods -n cert-manager -l app=cert-monitor"
    echo_info "2. Check logs: kubectl logs -n cert-manager -l app=cert-monitor -f"
    echo_info "3. Verify certificates are being uploaded to Key Vault"
    echo_info ""
    echo_info "The monitor will check for certificate updates every 5 minutes."
}

# Run if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
