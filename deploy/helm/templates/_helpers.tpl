{{- define "immuta-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "immuta-mcp.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "immuta-mcp.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "immuta-mcp.labels" -}}
app.kubernetes.io/name: {{ include "immuta-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "immuta-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "immuta-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "immuta-mcp.apiKeySecretName" -}}
{{- if .Values.immuta.existingSecret -}}
{{- .Values.immuta.existingSecret -}}
{{- else -}}
{{- include "immuta-mcp.fullname" . -}}-immuta
{{- end -}}
{{- end -}}

{{- define "immuta-mcp.bearerSecretName" -}}
{{- if .Values.mcp.existingSecret -}}
{{- .Values.mcp.existingSecret -}}
{{- else -}}
{{- include "immuta-mcp.fullname" . -}}-bearer
{{- end -}}
{{- end -}}
