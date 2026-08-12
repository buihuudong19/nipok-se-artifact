{{/*
pki.privateKey — sinh block privateKey cho cert-manager Certificate theo .Values.pki
Dùng cho thử nghiệm đổi thuật toán CA/leaf giữa các biến thể (v1/v2/v3).

  algorithm: ECDSA | Ed25519 | RSA
  size     : ECDSA → 256|384|521 ; RSA → 2048|3072|4096 ; Ed25519 → KHÔNG dùng (bỏ qua)

cert-manager v1.16 KHÔNG chấp nhận field `size` khi algorithm=Ed25519 → phải bỏ.
Gọi: privateKey:\n  {{- include "pki.privateKey" . | nindent 4 }}
*/}}
{{- define "pki.privateKey" -}}
algorithm: {{ .Values.pki.algorithm }}
{{- if ne .Values.pki.algorithm "Ed25519" }}
size: {{ .Values.pki.size }}
{{- end }}
{{- end -}}
