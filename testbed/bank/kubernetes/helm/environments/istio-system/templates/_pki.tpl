{{/*
pki.privateKey - generates the privateKey block of a cert-manager Certificate from .Values.pki
Used to switch the CA/leaf algorithm between the experimental variants (v1/v2/v3).

  algorithm: ECDSA | Ed25519 | RSA
  size     : ECDSA -> 256|384|521 ; RSA -> 2048|3072|4096 ; Ed25519 -> NOT used (omitted)

cert-manager v1.16 does NOT accept the field `size` when algorithm=Ed25519 -> it must be omitted.
Usage: privateKey:\n  {{- include "pki.privateKey" . | nindent 4 }}
*/}}
{{- define "pki.privateKey" -}}
algorithm: {{ .Values.pki.algorithm }}
{{- if ne .Values.pki.algorithm "Ed25519" }}
size: {{ .Values.pki.size }}
{{- end }}
{{- end -}}
