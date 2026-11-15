# CraftedSignal Error Reporting

A Cloud Run service that receives encrypted error reports from CraftedSignal
deployments, decrypts and deduplicates them, and sends error notifications
directly to Slack.

## How it works

- The platform converts its embedded Ed25519 public license key to a Curve25519
  public key and uses NaCl sealed-box encryption to encrypt report batches.
- The ingestor holds the matching Ed25519 private key, derives the Curve25519
  private key, and decrypts the reports received at `/logs`.
- Repeated notifications are suppressed for five minutes. Slack alerts include
  the triggering message, diagnostic attributes, build, and runtime context.

## Configuration

Set these environment variables via Secret Manager in Terraform:

- `ERROR_REPORTING_PRIVATE_KEYS` — comma-separated Ed25519 expanded private keys
  (64 bytes each, hex or base64). The first key is `v1`, the second `v2`, etc.
- `SLACK_WEBHOOK_URL` — Slack incoming webhook URL or bot token.
- `SLACK_CHANNEL` — channel ID or name when using a bot token.

## Local testing

```bash
make test
make run
```

Then POST an encrypted payload to `http://localhost:8080/logs`.

## Deployment

The companion Terraform module lives in
`../infrastructure/terraform/modules/error_reporting/`.

The Docker image contains the `/function` ingestor binary. Its `/healthz`
endpoint provides the Cloud Run readiness probe.
