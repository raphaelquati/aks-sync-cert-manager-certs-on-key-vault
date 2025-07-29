#!/usr/bin/env python3
"""
Certificate Monitor for AKS with cert-manager integration.
Monitors certificates and uploads PFX format to Azure Key Vault using workload identity.
"""

import os
import sys
import time
import logging
import hashlib
import base64
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

import kubernetes
from kubernetes import client, config
from azure.keyvault.certificates import CertificateClient, CertificatePolicy, KeyType
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CertificateInfo:
    """Certificate information structure"""
    name: str
    namespace: str
    common_name: str
    san_names: List[str]
    not_before: datetime
    not_after: datetime
    serial_number: str
    fingerprint: str
    tls_secret_name: str

class CertificateMonitor:
    """
    Monitor cert-manager certificates and upload to Azure Key Vault.
    Uses workload identity for Azure authentication.
    """
    
    def __init__(self):
        """Initialize the certificate monitor"""
        self.key_vault_url = os.getenv('KEY_VAULT_URL')
        if not self.key_vault_url:
            raise ValueError("KEY_VAULT_URL environment variable is required")
        
        self.namespace_filter = os.getenv('NAMESPACE_FILTER', '')
        self.cert_name_filter = os.getenv('CERT_NAME_FILTER', '')
        self.check_interval = int(os.getenv('CHECK_INTERVAL_SECONDS', '300'))  # 5 minutes
        
        # Initialize Azure clients with managed identity
        try:
            self.credential = DefaultAzureCredential()
            self.cert_client = CertificateClient(
                vault_url=self.key_vault_url,
                credential=self.credential
            )
            self.secret_client = SecretClient(
                vault_url=self.key_vault_url,
                credential=self.credential
            )
            logger.info(f"Successfully initialized Azure Key Vault clients for {self.key_vault_url}")
        except Exception as e:
            logger.error(f"Failed to initialize Azure clients: {e}")
            raise
        
        # Initialize Kubernetes client
        try:
            # Try in-cluster config first, fall back to local config
            try:
                config.load_incluster_config()
                logger.info("Using in-cluster Kubernetes configuration")
            except config.ConfigException:
                config.load_kube_config()
                logger.info("Using local Kubernetes configuration")
            
            self.k8s_client = client.ApiClient()
            self.custom_objects_api = client.CustomObjectsApi()
            self.core_v1_api = client.CoreV1Api()
            
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            raise
    
    def get_certificates(self) -> List[Dict]:
        """
        Get all cert-manager certificates from the cluster.
        Returns list of certificate custom resources.
        """
        try:
            # Get certificates from cert-manager CRDs
            certificates = self.custom_objects_api.list_cluster_custom_object(
                group="cert-manager.io",
                version="v1",
                plural="certificates"
            )
            
            filtered_certs = []
            for cert in certificates.get('items', []):
                name = cert['metadata']['name']
                namespace = cert['metadata']['namespace']
                
                # Apply filters if specified
                if self.namespace_filter and namespace != self.namespace_filter:
                    continue
                if self.cert_name_filter and self.cert_name_filter not in name:
                    continue
                
                # Only process certificates that are ready
                status = cert.get('status', {})
                conditions = status.get('conditions', [])
                is_ready = any(
                    condition.get('type') == 'Ready' and condition.get('status') == 'True'
                    for condition in conditions
                )
                
                if is_ready:
                    filtered_certs.append(cert)
                    logger.debug(f"Found ready certificate: {namespace}/{name}")
                else:
                    logger.debug(f"Skipping non-ready certificate: {namespace}/{name}")
            
            logger.info(f"Found {len(filtered_certs)} ready certificates to process")
            return filtered_certs
            
        except Exception as e:
            logger.error(f"Failed to get certificates: {e}")
            return []
    
    def get_certificate_info(self, cert_resource: Dict) -> Optional[CertificateInfo]:
        """
        Extract certificate information from cert-manager resource and associated secret.
        """
        try:
            metadata = cert_resource['metadata']
            spec = cert_resource['spec']
            status = cert_resource.get('status', {})
            
            name = metadata['name']
            namespace = metadata['namespace']
            
            # Get the secret name containing the certificate
            secret_name = spec.get('secretName', name)
            
            # Get the actual certificate from the secret
            try:
                secret = self.core_v1_api.read_namespaced_secret(
                    name=secret_name,
                    namespace=namespace
                )
            except client.exceptions.ApiException as e:
                if e.status == 404:
                    logger.warning(f"Secret {namespace}/{secret_name} not found")
                    return None
                raise
            
            # Extract certificate data
            secret_data = secret.data
            if 'tls.crt' not in secret_data:
                logger.warning(f"No tls.crt found in secret {namespace}/{secret_name}")
                return None
            
            cert_pem = base64.b64decode(secret_data['tls.crt']).decode('utf-8')
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            
            # Extract certificate details
            common_name = ""
            san_names = []
            
            # Get CN from subject
            for attribute in cert_obj.subject:
                if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            
            # Get SAN names
            try:
                san_extension = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_names = [name.value for name in san_extension.value]
            except x509.ExtensionNotFound:
                pass
            
            # Calculate certificate fingerprint
            cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            
            return CertificateInfo(
                name=name,
                namespace=namespace,
                common_name=common_name,
                san_names=san_names,
                not_before=cert_obj.not_valid_before.replace(tzinfo=timezone.utc),
                not_after=cert_obj.not_valid_after.replace(tzinfo=timezone.utc),
                serial_number=str(cert_obj.serial_number),
                fingerprint=fingerprint,
                tls_secret_name=secret_name
            )
            
        except Exception as e:
            logger.error(f"Failed to extract certificate info for {name}: {e}")
            return None
    
    def create_pfx_from_secret(self, namespace: str, secret_name: str, password: str = "") -> Optional[bytes]:
        """
        Create PFX data from Kubernetes TLS secret.
        """
        try:
            secret = self.core_v1_api.read_namespaced_secret(
                name=secret_name,
                namespace=namespace
            )
            
            secret_data = secret.data
            if 'tls.crt' not in secret_data or 'tls.key' not in secret_data:
                logger.error(f"Secret {namespace}/{secret_name} missing tls.crt or tls.key")
                return None
            
            # Decode certificate and private key
            cert_pem = base64.b64decode(secret_data['tls.crt'])
            key_pem = base64.b64decode(secret_data['tls.key'])
            
            # Load certificate and private key
            cert_obj = x509.load_pem_x509_certificate(cert_pem)
            key_obj = serialization.load_pem_private_key(key_pem, password=None)
            
            # Create PFX
            pfx_data = pkcs12.serialize_key_and_certificates(
                name=cert_obj.subject.rfc4514_string().encode('utf-8'),
                key=key_obj,
                cert=cert_obj,
                cas=None,  # No intermediate certificates for now
                encryption_algorithm=serialization.NoEncryption()
            )
            
            return pfx_data
            
        except Exception as e:
            logger.error(f"Failed to create PFX from secret {namespace}/{secret_name}: {e}")
            return None
    
    def is_certificate_updated_in_keyvault(self, cert_info: CertificateInfo, pfx_data: bytes) -> bool:
        """
        Check if the certificate in Key Vault is the same as the current certificate.
        Returns True if the certificate is already up to date.
        Checks both certificate and secret storage for backwards compatibility.
        """
        try:
            # Create a consistent name for the certificate in Key Vault
            kv_cert_name = self._get_keyvault_name(cert_info)
            
            # First try to get the certificate from Key Vault (preferred method)
            try:
                existing_cert = self.cert_client.get_certificate(kv_cert_name)
                
                # Get the certificate content and calculate fingerprint for comparison
                try:
                        # Get the certificate secret which contains the actual certificate data
                        cert_secret = self.secret_client.get_secret(existing_cert.name)
                        if cert_secret.value:
                            # Decode the PFX and extract certificate for fingerprint comparison
                            # Decode base64 PFX data
                            pfx_data_existing = base64.b64decode(cert_secret.value)
                            
                            # Load PFX and extract certificate
                            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                                pfx_data_existing, password=None
                            )
                            
                            if certificate:
                                # Calculate fingerprint of existing certificate
                                cert_der = certificate.public_bytes(serialization.Encoding.DER)
                                existing_fingerprint = hashlib.sha256(cert_der).hexdigest()
                                
                                if existing_fingerprint.lower() == cert_info.fingerprint.lower():
                                    logger.info(f"Certificate {kv_cert_name} is already up to date in Key Vault (as certificate)")
                                    return True
                                else:
                                    logger.info(f"Certificate {kv_cert_name} fingerprint mismatch - update needed")
                                    return False
                            else:
                                logger.info(f"Could not extract certificate from Key Vault PFX - update needed")
                                return False
                        else:
                            logger.info(f"No certificate data found in Key Vault - update needed")
                            return False
                            
                except Exception as secret_err:
                    logger.warning(f"Could not get certificate secret for comparison: {secret_err}")
                    # If we can't get the secret, assume update is needed
                    return False
                    
            except Exception as cert_e:
                if "CertificateNotFound" in str(cert_e) or "NotFound" in str(cert_e) or getattr(cert_e, 'status_code', None) == 404:
                    # Certificate not found, check if it exists as secret (legacy method)
                    try:
                        secret_name = f"{kv_cert_name}-pfx"
                        existing_secret = self.secret_client.get_secret(secret_name)
                        
                        # Check if secret has fingerprint tag for comparison
                        if existing_secret.properties.tags and 'fingerprint' in existing_secret.properties.tags:
                            existing_fingerprint = existing_secret.properties.tags['fingerprint']
                            if existing_fingerprint.lower() == cert_info.fingerprint.lower():
                                logger.info(f"Certificate {kv_cert_name} is already up to date in Key Vault (as secret)")
                                return True
                            else:
                                logger.info(f"Certificate {kv_cert_name} secret fingerprint mismatch - update needed")
                                return False
                        else:
                            # Secret exists but no fingerprint tag, assume needs update
                            logger.info(f"Certificate {kv_cert_name} secret found but no fingerprint tag - update needed")
                            return False
                            
                    except Exception as secret_e:
                        if "SecretNotFound" in str(secret_e) or "NotFound" in str(secret_e) or getattr(secret_e, 'status_code', None) == 404:
                            logger.info(f"Certificate {kv_cert_name} not found in Key Vault (neither certificate nor secret) - will upload")
                            return False
                        else:
                            logger.error(f"Error checking secret {secret_name} in Key Vault: {secret_e}")
                            return False
                else:
                    logger.error(f"Error checking certificate {kv_cert_name} in Key Vault: {cert_e}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to check certificate status in Key Vault: {e}")
            return False
    
    def upload_certificate_to_keyvault(self, cert_info: CertificateInfo, pfx_data: bytes) -> bool:
        """
        Upload certificate to Azure Key Vault as a certificate (not secret).
        """
        try:
            kv_cert_name = self._get_keyvault_name(cert_info)
            
            # Create certificate policy using Azure SDK objects
            policy = CertificatePolicy(
                issuer_name="Unknown",  # Use "Unknown" for imported certificates
                subject=f"CN={cert_info.common_name}",
                san_dns_names=cert_info.san_names,
                exportable=True,
                key_type=KeyType.rsa,
                key_size=2048,
                reuse_key=False,
                content_type="application/x-pkcs12"
            )
            
            # Set tags with metadata
            tags = {
                'source': 'cert-manager',
                'namespace': cert_info.namespace,
                'cert-name': cert_info.name,
                'common-name': cert_info.common_name,
                'serial-number': cert_info.serial_number,
                'fingerprint': cert_info.fingerprint,
                'not-before': cert_info.not_before.isoformat(),
                'not-after': cert_info.not_after.isoformat(),
                'uploaded-at': datetime.now(timezone.utc).isoformat()
            }
            
            # Import the certificate
            import_result = self.cert_client.import_certificate(
                certificate_name=kv_cert_name,
                certificate_bytes=pfx_data,
                policy=policy,
                tags=tags
            )
            
            logger.info(f"Successfully uploaded certificate {kv_cert_name} to Key Vault as certificate")
            # Log the certificate ID instead of thumbprint since thumbprint access is different
            logger.debug(f"Certificate ID: {import_result.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload certificate to Key Vault: {e}")
            # Fallback: try to upload as secret if certificate import fails
            try:
                logger.info(f"Attempting fallback upload as secret for {kv_cert_name}")
                return self._upload_as_secret_fallback(cert_info, pfx_data)
            except Exception as fallback_e:
                logger.error(f"Fallback upload also failed: {fallback_e}")
                return False
    
    def _upload_as_secret_fallback(self, cert_info: CertificateInfo, pfx_data: bytes) -> bool:
        """
        Fallback method to upload certificate as secret when certificate import fails.
        """
        try:
            kv_cert_name = self._get_keyvault_name(cert_info)
            
            # Upload as secret (PFX format)
            pfx_b64 = base64.b64encode(pfx_data).decode('utf-8')
            
            # Set secret with metadata
            tags = {
                'source': 'cert-manager',
                'namespace': cert_info.namespace,
                'cert-name': cert_info.name,
                'common-name': cert_info.common_name,
                'serial-number': cert_info.serial_number,
                'fingerprint': cert_info.fingerprint,
                'not-before': cert_info.not_before.isoformat(),
                'not-after': cert_info.not_after.isoformat(),
                'uploaded-at': datetime.now(timezone.utc).isoformat(),
                'upload-type': 'secret-fallback'
            }
            
            # Upload the PFX as a secret
            secret_name = f"{kv_cert_name}-pfx"
            self.secret_client.set_secret(
                name=secret_name,
                value=pfx_b64,
                content_type='application/x-pkcs12',
                tags=tags
            )
            
            logger.info(f"Successfully uploaded certificate {kv_cert_name} to Key Vault as secret (fallback)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload certificate as secret fallback: {e}")
            return False
    
    def _get_keyvault_name(self, cert_info: CertificateInfo) -> str:
        """
        Generate a valid Key Vault name from certificate info.
        Key Vault names must be alphanumeric and hyphens only.
        """
        # Use namespace and cert name, replace invalid characters
        base_name = f"{cert_info.namespace}-{cert_info.name}"
        # Replace invalid characters with hyphens
        kv_name = ''.join(c if c.isalnum() else '-' for c in base_name)
        # Remove consecutive hyphens and trim
        while '--' in kv_name:
            kv_name = kv_name.replace('--', '-')
        kv_name = kv_name.strip('-')
        
        # Ensure it's not too long (Key Vault names have limits)
        if len(kv_name) > 127:
            kv_name = kv_name[:120] + '-' + hashlib.md5(base_name.encode()).hexdigest()[:6]
        
        return kv_name
    
    def process_certificates(self):
        """
        Main processing loop - check all certificates and upload if needed.
        """
        logger.info("Starting certificate processing cycle")
        
        certificates = self.get_certificates()
        if not certificates:
            logger.info("No certificates found to process")
            return
        
        processed = 0
        uploaded = 0
        
        for cert_resource in certificates:
            try:
                cert_info = self.get_certificate_info(cert_resource)
                if not cert_info:
                    continue
                
                logger.info(f"Processing certificate: {cert_info.namespace}/{cert_info.name}")
                
                # Create PFX from the certificate secret
                pfx_data = self.create_pfx_from_secret(
                    cert_info.namespace,
                    cert_info.tls_secret_name
                )
                
                if not pfx_data:
                    logger.error(f"Failed to create PFX for {cert_info.namespace}/{cert_info.name}")
                    continue
                
                # Check if certificate needs updating
                if not self.is_certificate_updated_in_keyvault(cert_info, pfx_data):
                    logger.info(f"Uploading certificate {cert_info.namespace}/{cert_info.name} to Key Vault")
                    if self.upload_certificate_to_keyvault(cert_info, pfx_data):
                        uploaded += 1
                
                processed += 1
                
            except Exception as e:
                logger.error(f"Error processing certificate: {e}")
                continue
        
        logger.info(f"Processing complete: {processed} certificates processed, {uploaded} uploaded")
    
    def run(self):
        """
        Main run loop - process certificates every check_interval seconds.
        """
        logger.info(f"Starting Certificate Monitor")
        logger.info(f"Key Vault URL: {self.key_vault_url}")
        logger.info(f"Check interval: {self.check_interval} seconds")
        logger.info(f"Namespace filter: {self.namespace_filter or 'all'}")
        logger.info(f"Certificate name filter: {self.cert_name_filter or 'all'}")
        
        while True:
            try:
                self.process_certificates()
                logger.info(f"Sleeping for {self.check_interval} seconds...")
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                logger.info("Received interrupt signal, shutting down...")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                logger.info(f"Continuing after error, sleeping for {self.check_interval} seconds...")
                time.sleep(self.check_interval)

def main():
    """Main entry point"""
    try:
        monitor = CertificateMonitor()
        monitor.run()
    except Exception as e:
        logger.error(f"Failed to start certificate monitor: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
