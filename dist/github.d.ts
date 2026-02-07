import type { RepoConfig, CommitInfo, VulnerabilityAnalysis } from "./types.js";
export declare function initOctokit(token: string): void;
export declare function getCommitsSince(repo: RepoConfig, sinceSha: string | null, maxCommits: number): Promise<CommitInfo[]>;
export declare function getLatestCommitSha(repo: RepoConfig): Promise<string>;
export declare function createVulnerabilityIssue(issueRepo: {
    owner: string;
    repo: string;
}, repo: RepoConfig, commit: CommitInfo, analysis: VulnerabilityAnalysis): Promise<string>;
export declare function truncateDiff(diff: string, maxLength: number): string;
