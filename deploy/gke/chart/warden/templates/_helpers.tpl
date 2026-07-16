{{- define "warden.name" -}}
{{- printf "warden-%s" .Values.customer -}}
{{- end -}}

{{- define "warden.labels" -}}
app.kubernetes.io/name: warden
app.kubernetes.io/instance: {{ .Release.Name }}
warden-customer: {{ .Values.customer }}
{{- end -}}

{{- define "warden.secretName" -}}
{{- if .Values.secret.name -}}{{ .Values.secret.name }}{{- else -}}{{ include "warden.name" . }}-secrets{{- end -}}
{{- end -}}
