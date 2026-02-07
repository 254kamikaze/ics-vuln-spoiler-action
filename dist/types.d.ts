export interface RepoConfig {
    owner: string;
    repo: string;
}
export interface ActionInputs {
    anthropicApiKey: string;
    githubToken: string;
    repositories: RepoConfig[];
    stateFile: string;
    createIssues: boolean;
    issueRepo: {
        owner: string;
        repo: string;
    };
    model: string;
    maxCommits: number;
}
export interface State {
    [repoKey: string]: string;
}
export interface PullRequestInfo {
    number: number;
    title: string;
    body: string | null;
    url: string;
    labels: string[];
    mergedAt: string | null;
}
export interface CommitInfo {
    sha: string;
    message: string;
    author: string;
    date: string;
    url: string;
    diff: string;
    pullRequest: PullRequestInfo | null;
}
export interface VulnerabilityAnalysis {
    isVulnerabilityPatch: boolean;
    vulnerabilityType: string | null;
    severity: "Critical" | "High" | "Medium" | "Low" | null;
    description: string | null;
    affectedCode: string | null;
    proofOfConcept: string | null;
}
export interface DetectedVulnerability {
    repo: RepoConfig;
    commit: CommitInfo;
    analysis: VulnerabilityAnalysis;
    issueUrl?: string;
}
export interface ActionOutputs {
    vulnerabilitiesFound: number;
    issuesCreated: number;
    analyzedCommits: number;
    results: DetectedVulnerability[];
}
