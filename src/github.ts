import { Octokit } from "@octokit/rest";
import * as core from "@actions/core";
import type {
  RepoConfig,
  CommitInfo,
  VulnerabilityAnalysis,
  PullRequestInfo,
} from "./types.js";

let octokit: Octokit;

export function initOctokit(token: string): void {
  octokit = new Octokit({ auth: token });
}

export async function getCommitsSince(
  repo: RepoConfig,
  sinceSha: string | null,
  maxCommits: number
): Promise<CommitInfo[]> {
  const commits: CommitInfo[] = [];

  const { data: commitList } = await octokit.repos.listCommits({
    owner: repo.owner,
    repo: repo.repo,
    per_page: Math.min(maxCommits, 100),
  });

  let foundSinceSha = sinceSha === null;
  let count = 0;

  for (const commit of commitList) {
    if (commit.sha === sinceSha) {
      foundSinceSha = true;
      break;
    }

    if (!foundSinceSha && count < maxCommits) {
      const { data: fullCommit } = await octokit.repos.getCommit({
        owner: repo.owner,
        repo: repo.repo,
        ref: commit.sha,
        mediaType: { format: "diff" },
      });

      const diff =
        typeof fullCommit === "string"
          ? fullCommit
          : (fullCommit as unknown as { data: string }).data || "";

      const pullRequest = await getAssociatedPullRequest(repo, commit.sha);

      commits.push({
        sha: commit.sha,
        message: commit.commit.message,
        author: commit.commit.author?.name || "Unknown",
        date: commit.commit.author?.date || new Date().toISOString(),
        url: commit.html_url,
        diff: truncateDiff(diff, 15000),
        pullRequest,
      });

      count++;
    }
  }

  return commits;
}

async function getAssociatedPullRequest(
  repo: RepoConfig,
  commitSha: string
): Promise<PullRequestInfo | null> {
  try {
    const { data: prs } =
      await octokit.repos.listPullRequestsAssociatedWithCommit({
        owner: repo.owner,
        repo: repo.repo,
        commit_sha: commitSha,
      });

    if (prs.length === 0) return null;

    const pr = prs[0];
    return {
      number: pr.number,
      title: pr.title,
      body: pr.body,
      url: pr.html_url,
      labels: pr.labels.map((label) =>
        typeof label === "string" ? label : label.name || ""
      ),
      mergedAt: pr.merged_at,
    };
  } catch {
    return null;
  }
}

export async function getLatestCommitSha(repo: RepoConfig): Promise<string> {
  const { data: commits } = await octokit.repos.listCommits({
    owner: repo.owner,
    repo: repo.repo,
    per_page: 1,
  });

  if (commits.length === 0) {
    throw new Error(`No commits found for ${repo.owner}/${repo.repo}`);
  }

  return commits[0].sha;
}

export async function createVulnerabilityIssue(
  issueRepo: { owner: string; repo: string },
  repo: RepoConfig,
  commit: CommitInfo,
  analysis: VulnerabilityAnalysis
): Promise<string> {
  const severityLabel = analysis.severity?.toLowerCase() || "unknown";
  const repoFullName = `${repo.owner}/${repo.repo}`;

  const prSection = commit.pullRequest
    ? `
### Pull Request
**PR:** [#${commit.pullRequest.number} - ${commit.pullRequest.title}](${commit.pullRequest.url})
**Labels:** ${commit.pullRequest.labels.length > 0 ? commit.pullRequest.labels.join(", ") : "None"}
${commit.pullRequest.body ? `\n**Description:**\n${commit.pullRequest.body.substring(0, 500)}${commit.pullRequest.body.length > 500 ? "..." : ""}` : ""}
`
    : "";

  const body = `## Potential Security Vulnerability Detected

**Repository:** [${repoFullName}](https://github.com/${repoFullName})
**Commit:** [${commit.sha.substring(0, 7)}](${commit.url})
**Author:** ${commit.author}
**Date:** ${commit.date}

### Commit Message
\`\`\`
${commit.message}
\`\`\`
${prSection}
### Analysis

**Vulnerability Type:** ${analysis.vulnerabilityType || "Unknown"}
**Severity:** ${analysis.severity || "Unknown"}

### Description
${analysis.description || "No description available."}

### Affected Code
${analysis.affectedCode ? `\`\`\`\n${analysis.affectedCode}\n\`\`\`` : "Not specified"}

### Proof of Concept
${analysis.proofOfConcept ? `\`\`\`\n${analysis.proofOfConcept}\n\`\`\`` : "Not specified"}

---
*This issue was automatically created by [Vulnerability Spoiler Alert](https://github.com/spaceraccoon/vulnerability-spoiler-alert-action).*
*Detected at: ${new Date().toISOString()}*
`;

  try {
    const { data: issue } = await octokit.issues.create({
      owner: issueRepo.owner,
      repo: issueRepo.repo,
      title: `[Vulnerability] ${repoFullName}: ${analysis.vulnerabilityType || "Security Patch Detected"}`,
      body,
      labels: ["vulnerability", `severity:${severityLabel}`],
    });

    return issue.html_url;
  } catch (error) {
    core.warning(`Failed to create issue: ${error}`);
    throw error;
  }
}

export function truncateDiff(diff: string, maxLength: number): string {
  if (diff.length <= maxLength) return diff;
  return diff.substring(0, maxLength) + "\n\n... [diff truncated]";
}
