# load-secrets.sh - sourced by the testbed scripts. Creates the missing secret files (generate-secrets.sh) and
# exports the variables of secrets/secrets.env plus SECRETS_HELM_VALUES (path of secrets/helm-secrets.yaml).
# Values are never printed.
_secrets_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$_secrets_dir/generate-secrets.sh" || { echo "ERROR: secrets/generate-secrets.sh failed" >&2; return 1 2>/dev/null || exit 1; }
while IFS= read -r _line; do
  case "$_line" in ''|\#*) continue ;; esac
  export "${_line%%=*}=${_line#*=}"
done < "$_secrets_dir/secrets.env"
export SECRETS_HELM_VALUES="$_secrets_dir/helm-secrets.yaml"
unset _secrets_dir _line
