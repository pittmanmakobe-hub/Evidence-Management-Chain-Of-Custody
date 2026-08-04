
# terraform {
#   required_version = ">= 1.6"
#   required_providers {
#     aws = { source = "hashicorp/aws", version = "~> 5.0" }
#   }
# }

- name: Install Cosign
  uses: sigstore/cosign-installer@v3
  with:
    cosign-release: 'v2.2.4'

- name: Bundle + sign + upload to vault
  id: sign
  if: always()
  env:
    VAULT: ${{ vars.EVIDENCE_VAULT }}
    RUN_ID: ${{ github.run_id }}
    SHA: ${{ github.sha }}
  run: |
    set -euo pipefail
    BUNDLE="evidence-${RUN_ID}-${SHA}.tar.gz"
    ( cd evidence && tar czf "../${BUNDLE}" . )
    shasum -a 256 "${BUNDLE}" | awk '{print $1}' > "${BUNDLE}.sha256"

    cosign sign-blob --yes --bundle "${BUNDLE}.sig.bundle" "${BUNDLE}"

    KEY_PREFIX="runs/${RUN_ID}"
    aws s3 cp "${BUNDLE}"            "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}"
    aws s3 cp "${BUNDLE}.sha256"     "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}.sha256"
    aws s3 cp "${BUNDLE}.sig.bundle" "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}.sig.bundle"

    VERSION_ID=$(aws s3api head-object --bucket "${VAULT}" --key "${KEY_PREFIX}/${BUNDLE}" --query VersionId --output text)
    cat > receipt.json <<EOF
    {
      "run_id":"${RUN_ID}",
      "vault":"${VAULT}",
      "bundle_key":"${KEY_PREFIX}/${BUNDLE}",
      "version_id":"${VERSION_ID}",
      "sha256":"$(cat ${BUNDLE}.sha256)",
      "commit":"${SHA}"
    }
    EOF
    aws s3 cp receipt.json "s3://${VAULT}/${KEY_PREFIX}/receipt.json"

eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
VAULT=<your-vault-bucket>
aws iam put-role-policy \
  --role-name cgep-grc-gate \
  --policy-name vault-write \
  --policy-document "$(cat <<EOF
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Action":["s3:PutObject","s3:GetObject","s3:GetBucketLocation"],
    "Resource":["arn:aws:s3:::${VAULT}","arn:aws:s3:::${VAULT}/*"]
  }]
}
EOF
)"
gh variable set EVIDENCE_VAULT --body "$VAULT" --repo OWNER/REPO

#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
set -euo pipefail
RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$(shasum -a 256 "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }

# 2. Authenticity + timestamp
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"

# 3. Preservation
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired"; exit 1; }

echo "CHAIN INTACT for run ${RUN_ID}"

EVIDENCE_VAULT=<your-vault> bash scripts/verify-evidence.sh <run_id> --profile <your-sandbox>

aws s3 cp "s3://${VAULT}/runs/${RUN_ID}/evidence-${RUN_ID}-${SHA}.tar.gz" /tmp/bundle.tar.gz --profile <your-sandbox>
echo "junk" >> /tmp/bundle.tar.gz
shasum -a 256 /tmp/bundle.tar.gz
# value differs from the .sha256 sidecar; verify-evidence.sh exits 1

