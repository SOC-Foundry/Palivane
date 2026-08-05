{{- define "palivane.name" -}}
{{- printf "palivane-%s" .Values.customer -}}
{{- end -}}

{{- define "palivane.labels" -}}
app.kubernetes.io/name: palivane
app.kubernetes.io/instance: {{ .Release.Name }}
palivane-customer: {{ .Values.customer }}
{{- end -}}

{{- define "palivane.secretName" -}}
{{- if .Values.secret.name -}}{{ .Values.secret.name }}{{- else -}}{{ include "palivane.name" . }}-secrets{{- end -}}
{{- end -}}
