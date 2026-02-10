# Vulnerability Spoiler Alert Action

> **Know about security patches before the CVE drops.**

[![GitHub Action](https://img.shields.io/badge/GitHub-Action-2088FF?logo=github-actions&logoColor=white)](https://github.com/marketplace)
[![Claude AI](https://img.shields.io/badge/Powered%20by-Claude%20AI-cc785c?logo=anthropic&logoColor=white)](https://anthropic.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A reusable GitHub Action that monitors open-source repositories and uses Claude AI to detect when commits are patching security vulnerabilities - often before a CVE is even assigned.

## Features

- **AI-Powered Detection** - Uses Claude to analyze commit diffs for security patterns
- **Proof of Concept Required** - Only alerts when a concrete exploit can be demonstrated
- **PR Context Aware** - Analyzes PR descriptions and labels for security indicators
- **Automatic Issue Creation** - Creates detailed issues with vulnerability analysis
- **State Management** - Tracks analyzed commits to avoid duplicates
- **Configurable** - Choose which repositories to monitor, where to create issues, and more

## Quick Start

```yaml
name: Vulnerability Monitor

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

permissions:
  contents: write
  issues: write

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: spaceraccoon/vulnerability-spoiler-alert-action@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          repositories: |
            [
              {"owner": "expressjs", "repo": "express"},
              {"owner": "lodash", "repo": "lodash"}
            ]

      - name: Commit state changes
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .vulnerability-spoiler-state.json
          git diff --staged --quiet || git commit -m "Update vulnerability monitor state"
          git push
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic-api-key` | Yes | - | Anthropic API key for Claude |
| `github-token` | No | `${{ github.token }}` | GitHub token for API access |
| `repositories` | Yes | - | JSON array of repos to monitor |
| `state-file` | No | `.vulnerability-spoiler-state.json` | Path to state file |
| `create-issues` | No | `true` | Whether to create GitHub issues |
| `issue-repo` | No | Current repo | Where to create issues (`owner/repo`) |
| `model` | No | `claude-sonnet-4-20250514` | Claude model to use |
| `max-commits` | No | `50` | Max commits to analyze per repo per run |

## Outputs

| Output | Description |
|--------|-------------|
| `vulnerabilities-found` | Number of vulnerabilities detected |
| `issues-created` | Number of issues created |
| `analyzed-commits` | Total commits analyzed |
| `results` | JSON array of detected vulnerabilities |

## Usage Examples

### Basic Usage

```yaml
- uses: spaceraccoon/vulnerability-spoiler-alert-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    repositories: '[{"owner": "facebook", "repo": "react"}]'
```

### Monitor Multiple Repositories

```yaml
- uses: spaceraccoon/vulnerability-spoiler-alert-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    repositories: |
      [
        {"owner": "expressjs", "repo": "express"},
        {"owner": "lodash", "repo": "lodash"},
        {"owner": "axios", "repo": "axios"},
        {"owner": "chalk", "repo": "chalk"}
      ]
```

### Create Issues in a Different Repository

```yaml
- uses: spaceraccoon/vulnerability-spoiler-alert-action@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    repositories: '[{"owner": "expressjs", "repo": "express"}]'
    issue-repo: 'my-org/security-alerts'
```

### Detection Only (No Issues)

```yaml
- uses: spaceraccoon/vulnerability-spoiler-alert-action@v1
  id: scan
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    repositories: '[{"owner": "expressjs", "repo": "express"}]'
    create-issues: 'false'

- name: Process results
  if: steps.scan.outputs.vulnerabilities-found > 0
  run: |
    echo "Found ${{ steps.scan.outputs.vulnerabilities-found }} vulnerabilities!"
    echo "${{ steps.scan.outputs.results }}" | jq .
```

### Send to Slack

```yaml
- uses: spaceraccoon/vulnerability-spoiler-alert-action@v1
  id: scan
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    repositories: '[{"owner": "expressjs", "repo": "express"}]'
    create-issues: 'false'

- name: Notify Slack
  if: steps.scan.outputs.vulnerabilities-found > 0
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "🚨 Detected ${{ steps.scan.outputs.vulnerabilities-found }} potential vulnerabilities!"
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

## How Detection Works

1. **Fetches new commits** from each monitored repository since the last run
2. **Retrieves PR context** including title, description, and labels
3. **Analyzes with Claude AI** using a carefully crafted prompt that:
   - Looks for security-relevant code patterns
   - Requires a concrete proof of concept exploit
   - Classifies severity based on impact
4. **Creates issues** with full vulnerability details

### What Gets Flagged

The action only flags commits where Claude can demonstrate a concrete exploit:

- Input validation/sanitization fixes
- Authentication/authorization patches
- Injection vulnerability fixes (SQL, XSS, Command, etc.)
- Path traversal protections
- Memory safety improvements

### What Gets Ignored

- General code quality improvements
- Defensive coding without security impact
- Performance optimizations
- Refactoring

## State Management

The action tracks which commits have been analyzed using a state file. This file should be committed back to your repository to persist across runs.

```yaml
- name: Commit state changes
  run: |
    git config user.name "github-actions[bot]"
    git config user.email "github-actions[bot]@users.noreply.github.com"
    git add .vulnerability-spoiler-state.json
    git diff --staged --quiet || git commit -m "Update vulnerability monitor state"
    git push
```

## Permissions

The action requires these permissions:

```yaml
permissions:
  contents: write  # To commit state file
  issues: write    # To create issues
```

## Setup

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. Add it as a repository secret named `ANTHROPIC_API_KEY`
3. Create a workflow file as shown in the examples above
4. Enable the workflow

## Security Considerations

### Prompt Injection Risk

This action sends commit diffs, commit messages, and pull request metadata from
monitored repositories to an LLM for analysis. Because these inputs are
controlled by the authors of the monitored repositories, they are inherently
attacker-controllable. A malicious actor can craft commit messages, PR
descriptions, or code diffs that contain adversarial instructions designed to
manipulate the LLM's output. This is known as **prompt injection** and it
**cannot be fully prevented** by the action itself.

Prompt injection could be used to:

- **Suppress real detections** — instructing the model to always return
  `isVulnerabilityPatch: false`, causing the action to silently miss actual
  vulnerability patches.
- **Generate false positives** — forcing the model to flag benign commits as
  vulnerabilities with fabricated descriptions and proof-of-concept exploits.
- **Influence issue content** — since the model's output is used to create
  GitHub issues, a manipulated response could include misleading or
  socially-engineered content in your issue tracker.

### Recommended Mitigations

1. **Treat all results as advisory.** Never take automated action (e.g.,
   blocking deployments, sending public notifications) based solely on this
   action's output without human review.
2. **Restrict the issue repository.** Use a private or internal repository for
   created issues (`issue-repo` input) so that injected content is not publicly
   visible.
3. **Use `create-issues: false` for untrusted sources.** When monitoring
   repositories you do not control, disable automatic issue creation and review
   the `results` output programmatically or manually instead.
4. **Apply least-privilege tokens.** Use a GitHub token scoped to only the
   permissions the action needs. Do not use tokens with broad org-level access.
5. **Review issues before acting.** Any vulnerability details, proof-of-concept
   exploits, or severity ratings in created issues originate from LLM analysis
   of external data and should be independently verified.

## Limitations

- Only analyzes public repositories (or private repos your token can access)
- Large diffs are truncated to fit API limits
- AI analysis may have false positives/negatives — all results should be treated
  as advisory and verified by a human (see [Security Considerations](#security-considerations))
- Rate limited by GitHub and Anthropic APIs

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for **defensive security research** only. Always follow responsible disclosure practices.
