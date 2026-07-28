# CraftedSignal Error Reporting Ingestor

A small GCP Cloud Functions gen 2 service that receives encrypted error reports
from CraftedSignal deployments, decrypts them, and forwards notifications to
Slack.

## How it works

- The CraftedSignal platform embeds the **public** Ed25519 license key (already
  obfuscated in `pkg/license/embedded.go`).
- The platform converts that Ed25519 public key to a Curve25519 public key and
  uses NaCl sealed-box encryption to encrypt report batches.
- This Cloud Function holds the matching **Ed25519 private key**, derives the
  Curve25519 private key, and decrypts the reports.
- Only a binary holding the embedded public key can produce decryptable reports,
  which prevents spam.

## Configuration

Set these environment variables via Secret Manager in Terraform:

- `ERROR_REPORTING_PRIVATE_KEYS` — comma-separated Ed25519 expanded private keys
  (64 bytes each, hex or base64). The first key is `v1`, the second `v2`, etc.
- `SLACK_WEBHOOK_URL` — Slack incoming webhook URL.

## Local testing

```bash
make test
make run
```

Then POST an encrypted payload to `http://localhost:8080`.

## Deployment

The companion Terraform module lives in
`../infrastructure/terraform/modules/error_reporting/`.
