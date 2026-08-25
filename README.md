# iac-guardrails-lab

Sandbox for IaC policy scanning on pull requests. Uses the FCS CLI to scan
Terraform / Kubernetes YAML / Dockerfile changes, posts findings as a sticky
PR comment, and blocks merge on high-severity issues.

## What it does

Every PR that touches Terraform, Kubernetes YAML, or a Dockerfile triggers a
GitHub Action that:

1. Runs `fcs iac scan` on the changed paths
2. Renders the SARIF report as a Markdown table
3. Posts (or updates) a sticky comment on the PR with the findings
4. Uploads the SARIF to GitHub Code Scanning (only shows inline annotations if
   GitHub Advanced Security is enabled on the repo)
5. Fails the job on high-severity findings, blocking merge via branch protection

The comment updates in place on every push, so reviewers see one authoritative
status rather than a wall of comments.

## Repo layout

```
.github/workflows/fcs-iac-scan.yml   # the GHA workflow
scripts/sarif-to-md.py               # SARIF -> Markdown renderer
terraform/aws/                       # sample AWS Terraform (with intentional misconfigs)
terraform/azure/                     # sample Azure Terraform (with intentional misconfigs)
```

## Required secrets

Add these under Settings -> Secrets and variables -> Actions:

| Secret               | Purpose                                        |
| -------------------- | ---------------------------------------------- |
| `FALCON_CLIENT_ID`     | Falcon API client with IaC Scanner scope    |
| `FALCON_CLIENT_SECRET` | Falcon API client secret                    |
| `FALCON_CLOUD`         | Falcon cloud region (`us-1`, `us-2`, `eu-1`, `us-gov-1`) |

## Branch protection to demo

Settings -> Branches -> Add rule for `main`:
- Require status checks to pass before merging
- Require the check named **FCS IaC Scan** to pass

That check turns red when the scan finds high-severity issues, and the merge
button greys out.

## Demo flow

1. Open a PR that lowers `min_tls_version` from `"1.2"` to `"1.0"` in
   `terraform/azure/app_service.tf`, or opens UDP/636 in
   `terraform/aws/attack_path.tf`.
2. Wait for the FCS IaC Scan check to run (~30s).
3. Show three tabs:
   - **Files changed** — inline annotations if GHAS is on
   - **Conversation** — sticky Falcon comment with the finding table
   - **Checks** — failed status check blocks merge
4. Push a fix. Comment updates in place; check goes green; merge unblocks.
