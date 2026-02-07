import type { CommitInfo, VulnerabilityAnalysis } from "./types.js";
export declare function initAnalyzer(apiKey: string, model: string): void;
export declare function analyzeCommit(commit: CommitInfo): Promise<VulnerabilityAnalysis>;
