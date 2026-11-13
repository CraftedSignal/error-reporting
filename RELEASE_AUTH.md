# Main-only release authentication

Pushing a v* tag starts a dispatch-only job with a repository token scoped to
Actions write. It requests the Release workflow on main with the explicit tag;
it receives neither cloud OIDC nor production secrets. GitHub permits
[workflow_dispatch runs created by GITHUB_TOKEN](https://docs.github.com/en/actions/concepts/security/github_token).

The main workflow validates the version tag, resolves it to a full commit, and
requires that commit to be an ancestor of origin/main. Test/vet/lint/govulncheck
and the image build all check out that same validated commit. Each image is
scanned locally before cloud authentication, then the exact scanned tags are
pushed. Image tags remain vVERSION and latest. Main can advance after the tag
without changing the built source. Manual recovery uses Run workflow on main
and supplies the existing tag; selecting a non-main workflow ref cannot publish.
Failure notifications for source validation and publishing run from main only.
No production Slack credential is made available to the tag dispatch job.

Only the publishing job requests id-token write and it has no GitHub environment
label, keeping its OIDC subject tied to the main workflow ref. Source validation
runs from trusted main before checking out the release source. The cloud trust
policy must reject PR, branch and tag subjects outside this intended main path.

## Required live IAM correction

Read-only metadata inspection on 2026-11-13 found that
sa-error-reporting@craftedsignal-shared.iam.gserviceaccount.com trusts the old
subject repo:CraftedSignal/error-reporting:ref:refs/heads/main. This repository
was created on 2026-07-28 and its live OIDC settings report immutable subjects,
with prefix repo:CraftedSignal@217312886/error-reporting@1314699464. The correct
main workflow subject is therefore:

```
repo:CraftedSignal@217312886/error-reporting@1314699464:ref:refs/heads/main
```

Replace the obsolete service-account principal with that exact immutable main
principal in the existing shared GitHub pool, and independently constrain the
provider to the intended repository/main claims. Do not grant all tag subjects
to make direct tag authentication work. Default OIDC subjects differ for
[branches, tags, environments and immutable repository IDs](https://docs.github.com/en/actions/reference/security/oidc).

This source change does not mutate IAM, request an OIDC token, dispatch a hosted
run, push images or notify Slack. Private Actions availability remains an
independent rollout prerequisite. Source and metadata checks do not prove a
successful production authentication or publication.
