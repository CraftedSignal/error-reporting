# CraftedSignal Error Reporting

A small Cloud Run service pair for platform error handling:

- `cmd/function`: receives encrypted error reports from CraftedSignal
  deployments, decrypts them, deduplicates them, and forwards notifications to
  Slack.
- `cmd/resolver`: consumes normalized incidents from Pub/Sub, collects runtime
  and deployed-source context, asks an AI model for a narrow resolution plan,
  opens a GitHub PR when the plan passes safety checks, and posts a Slack
  handoff with a mention and PR link.

## How it works

- The CraftedSignal platform embeds the **public** Ed25519 license key (already
  obfuscated in `pkg/license/embedded.go`).
- The platform converts that Ed25519 public key to a Curve25519 public key and
  uses NaCl sealed-box encryption to encrypt report batches.
- This Cloud Function holds the matching **Ed25519 private key**, derives the
  Curve25519 private key, and decrypts the reports.
- Only a binary holding the embedded public key can produce decryptable reports,
  which prevents spam.
- When `ERROR_RESOLVER_TOPIC` is configured, the ingestor also publishes each
  deduplicated report as an incident for the resolver.
- Terraform can also route selected Cloud Logging entries, including OOMKill
  events, directly into the same resolver topic.
- The resolver starts from the deployed commit in the report when available,
  fetches only bounded source context from GitHub, and creates a PR only from
  exact-match file edits returned by the model. It never mutates production.

## Configuration

Set these environment variables via Secret Manager in Terraform:

- `ERROR_REPORTING_PRIVATE_KEYS` — comma-separated Ed25519 expanded private keys
  (64 bytes each, hex or base64). The first key is `v1`, the second `v2`, etc.
- `SLACK_WEBHOOK_URL` — Slack incoming webhook URL.
- `ERROR_RESOLVER_TOPIC` — optional Pub/Sub topic name for resolver incidents.

Resolver:

- `GITHUB_TOKEN` — fine-grained GitHub token with Contents read/write and Pull
  requests read/write on configured repositories.
- `AI_API_KEY` and `AI_MODEL` — enables AI patch generation. Without these the
  resolver falls back to heuristic classification and no-PR/human-review Slack
  handoffs.
- `AI_ENDPOINT` — OpenAI-compatible chat completions endpoint.
- `SERVICE_REPOSITORIES_JSON` — service-to-repo routing map.
- `SLACK_MENTION` — mention prepended to resolver handoff messages, for example
  `<@U12345>` or `<!subteam^S12345>`.
- `DRY_RUN=true` — investigate and post Slack without creating PRs.

Example resolver Slack message:

```text
<@U12345> Auto-fix PR opened for platform error in ti-bot prod

PR: https://github.com/CraftedSignal/ti-bot/pull/123
Deployed source: CraftedSignal/ti-bot@abc1234
Status: PR opened
Impact: one publish job failed
Confidence: medium
```

## Local testing

```bash
make test
make run
make run-resolver
```

Then POST an encrypted payload to `http://localhost:8080`.

## Deployment

The companion Terraform module lives in
`../infrastructure/terraform/modules/error_reporting/`.

The Docker image contains both `/function` and `/resolver`. Cloud Run uses
`/function` as the default entrypoint for ingest; Terraform overrides the
resolver service command to `/resolver`.
