{{/*
Expand the name of the chart.
*/}}
{{- define "aks-sync-cert-manager-certs-on-key-vault.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "aks-sync-cert-manager-certs-on-key-vault.fullname" -}}
{{- printf "%s" (include "aks-sync-cert-manager-certs-on-key-vault.name" .) -}}
{{- end -}}
