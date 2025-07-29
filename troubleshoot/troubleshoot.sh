#!/bin/bash

# Script to troubleshoot cert-monitor deployment issues
# Usage: ./troubleshoot.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

echo_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if kubectl is available and configured
check_kubectl() {
    echo_step "Checking kubectl configuration..."
    
    if ! command -v kubectl &> /dev/null; then
        echo_error "kubectl is not installed or not in PATH"
        return 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        echo_error "kubectl is not configured or cluster is unreachable"
        return 1
    fi
    
    echo_info "kubectl is properly configured"
}

# Check cert-manager installation
check_cert_manager() {
    echo_step "Checking cert-manager installation..."
    
    # Check if cert-manager namespace exists
    if ! kubectl get namespace cert-manager &> /dev/null; then
        echo_error "cert-manager namespace not found. Is cert-manager installed?"
        return 1
    fi
    
    # Check cert-manager pods
    echo_info "cert-manager pods:"
    kubectl get pods -n cert-manager
    
    # Check for running pods
    local running_pods=$(kubectl get pods -n cert-manager --field-selector=status.phase=Running --no-headers | wc -l)
    if [ $running_pods -eq 0 ]; then
        echo_error "No cert-manager pods are running"
        return 1
    fi
    
    echo_info "cert-manager appears to be running"
}

# Check certificates
check_certificates() {
    echo_step "Checking cert-manager certificates..."
    
    # Get all certificates
    local certs=$(kubectl get certificates --all-namespaces --no-headers 2>/dev/null || echo "")
    
    if [ -z "$certs" ]; then
        echo_warn "No cert-manager certificates found in the cluster"
        return 0
    fi
    
    echo_info "Found certificates:"
    kubectl get certificates --all-namespaces
    
    # Check ready certificates
    echo_info "Certificate status details:"
    kubectl get certificates --all-namespaces -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.conditions[0].status,SECRET:.spec.secretName
}

# Check cert-monitor deployment
check_cert_monitor() {
    echo_step "Checking cert-monitor deployment..."
    
    # Check if deployment exists
    if ! kubectl get deployment cert-monitor -n cert-manager &> /dev/null; then
        echo_error "cert-monitor deployment not found in cert-manager namespace"
        echo_info "To deploy: kubectl apply -f k8s/deployment.yaml"
        return 1
    fi
    
    # Get deployment status
    echo_info "Deployment status:"
    kubectl get deployment cert-monitor -n cert-manager
    
    # Get pod status
    echo_info "Pod status:"
    kubectl get pods -n cert-manager -l app=cert-monitor
    
    # Check pod events
    echo_info "Recent pod events:"
    kubectl get events -n cert-manager --field-selector involvedObject.kind=Pod --sort-by='.lastTimestamp' | tail -10
}

# Check service account and RBAC
check_rbac() {
    echo_step "Checking RBAC configuration..."
    
    # Check service account
    if ! kubectl get serviceaccount cert-monitor -n cert-manager &> /dev/null; then
        echo_error "cert-monitor service account not found"
        return 1
    fi
    
    echo_info "Service account exists"
    
    # Check workload identity annotation
    local sa_annotations=$(kubectl get serviceaccount cert-monitor -n cert-manager -o jsonpath='{.metadata.annotations}')
    if [[ $sa_annotations == *"azure.workload.identity/client-id"* ]]; then
        echo_info "Workload identity annotation found"
        kubectl get serviceaccount cert-monitor -n cert-manager -o jsonpath='{.metadata.annotations.azure\.workload\.identity/client-id}' && echo
    else
        echo_warn "Workload identity annotation not found"
    fi
    
    # Check cluster role binding
    if kubectl get clusterrolebinding cert-monitor &> /dev/null; then
        echo_info "ClusterRoleBinding exists"
    else
        echo_error "ClusterRoleBinding cert-monitor not found"
    fi
}

# Check workload identity configuration
check_workload_identity() {
    echo_step "Checking workload identity configuration..."
    
    # Get pod and check annotations
    local pod_name=$(kubectl get pods -n cert-manager -l app=cert-monitor -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -z "$pod_name" ]; then
        echo_warn "No cert-monitor pod found"
        return 1
    fi
    
    echo_info "Checking pod annotations for workload identity..."
    local pod_annotations=$(kubectl get pod $pod_name -n cert-manager -o jsonpath='{.metadata.annotations}')
    
    if [[ $pod_annotations == *"azure.workload.identity/use"* ]]; then
        echo_info "Pod has workload identity annotation"
    else
        echo_warn "Pod missing workload identity annotation"
    fi
    
    # Check environment variables
    echo_info "Checking environment variables..."
    kubectl get pod $pod_name -n cert-manager -o jsonpath='{.spec.containers[0].env[*].name}' | tr ' ' '\n' | grep -E "(AZURE_CLIENT_ID|KEY_VAULT_URL)" || echo_warn "Missing required environment variables"
}

# Get cert-monitor logs
get_logs() {
    echo_step "Getting cert-monitor logs..."
    
    local pod_name=$(kubectl get pods -n cert-manager -l app=cert-monitor -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -z "$pod_name" ]; then
        echo_warn "No cert-monitor pod found"
        return 1
    fi
    
    echo_info "Recent logs from $pod_name:"
    kubectl logs $pod_name -n cert-manager --tail=50
}

# Test Azure connectivity
test_azure_connectivity() {
    echo_step "Testing Azure connectivity from cert-monitor pod..."
    
    local pod_name=$(kubectl get pods -n cert-manager -l app=cert-monitor -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [ -z "$pod_name" ]; then
        echo_warn "No cert-monitor pod found"
        return 1
    fi
    
    echo_info "Testing Key Vault connectivity..."
    kubectl exec $pod_name -n cert-manager -- python -c "
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

try:
    kv_url = os.getenv('KEY_VAULT_URL')
    if not kv_url:
        print('ERROR: KEY_VAULT_URL not set')
        exit(1)
    
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=kv_url, credential=credential)
    
    # Try to list secrets (this will test authentication)
    secrets = list(client.list_properties_of_secrets())
    print(f'SUCCESS: Connected to Key Vault, found {len(secrets)} secrets')
    
except Exception as e:
    print(f'ERROR: {e}')
    exit(1)
" 2>/dev/null || echo_error "Failed to test Azure connectivity"
}

# Main troubleshooting function
main() {
    echo_info "Starting cert-monitor troubleshooting..."
    echo_info "============================================="
    
    check_kubectl || exit 1
    echo
    
    check_cert_manager
    echo
    
    check_certificates
    echo
    
    check_cert_monitor
    echo
    
    check_rbac
    echo
    
    check_workload_identity
    echo
    
    get_logs
    echo
    
    test_azure_connectivity
    echo
    
    echo_info "============================================="
    echo_info "Troubleshooting complete!"
    echo_info ""
    echo_info "Common solutions:"
    echo_info "1. If workload identity issues: Check managed identity and federated credentials"
    echo_info "2. If RBAC issues: Verify ClusterRole and ClusterRoleBinding are applied"
    echo_info "3. If certificate issues: Ensure cert-manager certificates are in Ready state"
    echo_info "4. If Key Vault issues: Verify managed identity has proper permissions"
    echo_info ""
    echo_info "For more help, check the logs with:"
    echo_info "kubectl logs -n cert-manager -l app=cert-monitor -f"
}

# Run if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
