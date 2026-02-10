import * as core from "@actions/core";
import * as github from "@actions/github";
import { readFileSync, writeFileSync, existsSync, realpathSync } from "fs";
import { resolve, normalize, sep, basename } from "path";
import type {
  ActionInputs,
  RepoConfig,
  State,
  DetectedVulnerability,
  ActionOutputs,
} from "./types.js";
import {
  initOctokit,
  getCommitsSince,
  getLatestCommitSha,
  createVulnerabilityIssue,
} from "./github.js";
import { initAnalyzer, analyzeCommit } from "./analyzer.js";

function sanitizeStatePath(input: string): string {
  if (!input || input.includes("\0")) {
    throw new Error("Invalid state-file path");
  }

  const cwd = realpathSync(process.cwd());
  const resolved = resolve(cwd, input);
  const normalized = normalize(resolved);

  if (!normalized.startsWith(cwd + sep)) {
    throw new Error(
      `state-file path must be within the working directory. Got: ${input}`
    );
  }

  if (!basename(normalized)) {
    throw new Error(
      `state-file path must point to a file, not a directory. Got: ${input}`
    );
  }

  return normalized;
}

function getInputs(): ActionInputs {
  const reposInput = core.getInput("repositories", { required: true });
  let repositories: RepoConfig[];

  try {
    const parsed = JSON.parse(reposInput);

    if (!Array.isArray(parsed)) {
      throw new Error("Expected a JSON array");
    }

    for (const item of parsed) {
      if (
        typeof item !== "object" ||
        item === null ||
        typeof item.owner !== "string" ||
        typeof item.repo !== "string" ||
        !item.owner ||
        !item.repo
      ) {
        throw new Error(
          `Each entry must be an object with non-empty "owner" and "repo" string fields`
        );
      }
    }

    repositories = parsed as RepoConfig[];
  } catch (e) {
    throw new Error(
      `Invalid repositories input: ${e instanceof Error ? e.message : e}`
    );
  }

  const issueRepoInput = core.getInput("issue-repo");
  let issueRepo: { owner: string; repo: string };

  if (issueRepoInput) {
    const [owner, repo] = issueRepoInput.split("/");
    if (!owner || !repo) {
      throw new Error(
        `Invalid issue-repo format. Expected "owner/repo", got: ${issueRepoInput}`
      );
    }
    issueRepo = { owner, repo };
  } else {
    issueRepo = {
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
    };
  }

  return {
    anthropicApiKey: core.getInput("anthropic-api-key", { required: true }),
    githubToken: core.getInput("github-token", { required: true }),
    repositories,
    stateFile: sanitizeStatePath(core.getInput("state-file") || ".vulnerability-spoiler-state.json"),
    createIssues: core.getInput("create-issues") !== "false",
    issueRepo,
    model: core.getInput("model") || "claude-sonnet-4-20250514",
    maxCommits: parseInt(core.getInput("max-commits") || "50", 10),
  };
}

function loadState(stateFile: string): State {
  if (!existsSync(stateFile)) {
    return {};
  }
  try {
    const content = readFileSync(stateFile, "utf-8");
    return JSON.parse(content) as State;
  } catch {
    core.warning(`Failed to parse state file, starting fresh`);
    return {};
  }
}

function saveState(stateFile: string, state: State): void {
  writeFileSync(stateFile, JSON.stringify(state, null, 2) + "\n");
}

function getRepoKey(repo: RepoConfig): string {
  return `${repo.owner}/${repo.repo}`;
}

async function run(): Promise<void> {
  try {
    const inputs = getInputs();

    // Initialize clients
    initOctokit(inputs.githubToken);
    initAnalyzer(inputs.anthropicApiKey, inputs.model);

    // Load state
    const state = loadState(inputs.stateFile);

    core.info(`Monitoring ${inputs.repositories.length} repositories`);

    const outputs: ActionOutputs = {
      vulnerabilitiesFound: 0,
      issuesCreated: 0,
      analyzedCommits: 0,
      results: [],
    };

    // Process each repository
    for (const repo of inputs.repositories) {
      const repoKey = getRepoKey(repo);
      const lastSha = state[repoKey] || null;

      core.info(`\nProcessing ${repoKey}...`);

      try {
        // First run for this repo - just record HEAD
        if (lastSha === null) {
          core.info(`  First run for ${repoKey}, recording current HEAD`);
          state[repoKey] = await getLatestCommitSha(repo);
          continue;
        }

        // Get commits since last check
        const commits = await getCommitsSince(repo, lastSha, inputs.maxCommits);
        core.info(
          `  Found ${commits.length} new commits since ${lastSha.substring(0, 7)}`
        );

        if (commits.length === 0) continue;

        // Analyze each commit
        for (const commit of commits) {
          core.info(`  Analyzing commit ${commit.sha.substring(0, 7)}...`);
          outputs.analyzedCommits++;

          try {
            const analysis = await analyzeCommit(commit);

            if (analysis.isVulnerabilityPatch) {
              core.warning(
                `    VULNERABILITY DETECTED: ${analysis.vulnerabilityType} (${analysis.severity})`
              );

              const vulnerability: DetectedVulnerability = {
                repo,
                commit,
                analysis,
              };

              if (inputs.createIssues) {
                try {
                  const issueUrl = await createVulnerabilityIssue(
                    inputs.issueRepo,
                    repo,
                    commit,
                    analysis
                  );
                  vulnerability.issueUrl = issueUrl;
                  outputs.issuesCreated++;
                  core.info(`    Created issue: ${issueUrl}`);
                } catch (error) {
                  core.warning(`    Failed to create issue: ${error}`);
                }
              }

              outputs.vulnerabilitiesFound++;
              outputs.results.push(vulnerability);
            } else {
              core.info(`    No vulnerability detected`);
            }
          } catch (error) {
            core.warning(`    Error analyzing commit: ${error}`);
          }
        }

        // Update state with newest commit
        state[repoKey] = commits[0].sha;
      } catch (error) {
        core.error(`Error processing ${repoKey}: ${error}`);
      }
    }

    // Save state
    saveState(inputs.stateFile, state);
    core.info(`\nState saved to ${inputs.stateFile}`);

    // Set outputs
    core.setOutput("vulnerabilities-found", outputs.vulnerabilitiesFound);
    core.setOutput("issues-created", outputs.issuesCreated);
    core.setOutput("analyzed-commits", outputs.analyzedCommits);
    core.setOutput("results", JSON.stringify(outputs.results));

    // Summary
    core.info(`\n=== Summary ===`);
    core.info(`Commits analyzed: ${outputs.analyzedCommits}`);
    core.info(`Vulnerabilities found: ${outputs.vulnerabilitiesFound}`);
    core.info(`Issues created: ${outputs.issuesCreated}`);

    if (outputs.vulnerabilitiesFound > 0) {
      core.warning(
        `Detected ${outputs.vulnerabilitiesFound} potential vulnerabilities!`
      );
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed("An unexpected error occurred");
    }
  }
}

run();
