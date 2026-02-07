import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CommitInfo, VulnerabilityAnalysis, RepoConfig } from "../types.js";

const mockListCommits = vi.fn();
const mockGetCommit = vi.fn();
const mockListPRs = vi.fn();
const mockCreateIssue = vi.fn();

vi.mock("@octokit/rest", () => ({
  Octokit: class {
    repos = {
      listCommits: mockListCommits,
      getCommit: mockGetCommit,
      listPullRequestsAssociatedWithCommit: mockListPRs,
    };
    issues = {
      create: mockCreateIssue,
    };
  },
}));

vi.mock("@actions/core", () => ({
  warning: vi.fn(),
  info: vi.fn(),
}));

import {
  initOctokit,
  getLatestCommitSha,
  getCommitsSince,
  createVulnerabilityIssue,
  truncateDiff,
} from "../github.js";

const repo: RepoConfig = { owner: "testorg", repo: "testrepo" };

describe("truncateDiff", () => {
  it("returns the diff unchanged when under maxLength", () => {
    const diff = "short diff content";
    expect(truncateDiff(diff, 100)).toBe(diff);
  });

  it("returns the diff unchanged when exactly at maxLength", () => {
    const diff = "x".repeat(100);
    expect(truncateDiff(diff, 100)).toBe(diff);
  });

  it("truncates and appends marker when over maxLength", () => {
    const diff = "x".repeat(200);
    const result = truncateDiff(diff, 100);
    expect(result).toHaveLength(100 + "\n\n... [diff truncated]".length);
    expect(result).toContain("... [diff truncated]");
    expect(result.startsWith("x".repeat(100))).toBe(true);
  });
});

describe("getLatestCommitSha", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  it("returns the SHA of the most recent commit", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [{ sha: "abc123" }],
    });

    const sha = await getLatestCommitSha(repo);
    expect(sha).toBe("abc123");
    expect(mockListCommits).toHaveBeenCalledWith({
      owner: "testorg",
      repo: "testrepo",
      per_page: 1,
    });
  });

  it("throws when the repository has no commits", async () => {
    mockListCommits.mockResolvedValueOnce({ data: [] });

    await expect(getLatestCommitSha(repo)).rejects.toThrow(
      "No commits found for testorg/testrepo"
    );
  });
});

describe("getCommitsSince", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  it("returns commits up to the sinceSha", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [
        { sha: "new1", commit: { message: "fix A", author: { name: "Alice", date: "2025-01-02" } }, html_url: "https://github.com/testorg/testrepo/commit/new1" },
        { sha: "new2", commit: { message: "fix B", author: { name: "Bob", date: "2025-01-01" } }, html_url: "https://github.com/testorg/testrepo/commit/new2" },
        { sha: "old_sha", commit: { message: "old", author: { name: "Carol", date: "2024-12-31" } }, html_url: "https://github.com/testorg/testrepo/commit/old_sha" },
      ],
    });

    mockGetCommit
      .mockResolvedValueOnce({ data: "diff for new1" })
      .mockResolvedValueOnce({ data: "diff for new2" });

    mockListPRs
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({ data: [] });

    const commits = await getCommitsSince(repo, "old_sha", 50);

    expect(commits).toHaveLength(2);
    expect(commits[0].sha).toBe("new1");
    expect(commits[1].sha).toBe("new2");
  });

  it("returns empty array when no new commits exist", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [
        { sha: "old_sha", commit: { message: "old", author: { name: "Carol", date: "2024-12-31" } }, html_url: "url" },
      ],
    });

    const commits = await getCommitsSince(repo, "old_sha", 50);
    expect(commits).toHaveLength(0);
  });

  it("respects maxCommits limit", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [
        { sha: "c1", commit: { message: "m1", author: { name: "A", date: "d1" } }, html_url: "u1" },
        { sha: "c2", commit: { message: "m2", author: { name: "B", date: "d2" } }, html_url: "u2" },
        { sha: "c3", commit: { message: "m3", author: { name: "C", date: "d3" } }, html_url: "u3" },
        { sha: "old_sha", commit: { message: "old", author: { name: "D", date: "d4" } }, html_url: "u4" },
      ],
    });

    mockGetCommit.mockResolvedValue({ data: "diff" });
    mockListPRs.mockResolvedValue({ data: [] });

    const commits = await getCommitsSince(repo, "old_sha", 2);

    expect(commits).toHaveLength(2);
    expect(mockGetCommit).toHaveBeenCalledTimes(2);
  });
});

describe("createVulnerabilityIssue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  const commit: CommitInfo = {
    sha: "abc123def456",
    message: "Fix XSS in template renderer",
    author: "Jane Doe",
    date: "2025-01-15T10:30:00Z",
    url: "https://github.com/testorg/testrepo/commit/abc123def456",
    diff: "some diff",
    pullRequest: null,
  };

  const analysis: VulnerabilityAnalysis = {
    isVulnerabilityPatch: true,
    vulnerabilityType: "XSS",
    severity: "High",
    description: "Template renderer did not escape user input.",
    affectedCode: "render(userInput)",
    proofOfConcept: "<script>alert(1)</script>",
  };

  it("creates an issue with correct title, labels, and body", async () => {
    mockCreateIssue.mockResolvedValueOnce({
      data: { html_url: "https://github.com/testorg/testrepo/issues/1" },
    });

    const issueRepo = { owner: "testorg", repo: "testrepo" };
    const url = await createVulnerabilityIssue(issueRepo, repo, commit, analysis);

    expect(url).toBe("https://github.com/testorg/testrepo/issues/1");

    const call = mockCreateIssue.mock.calls[0][0];
    expect(call.title).toContain("XSS");
    expect(call.title).toContain("testorg/testrepo");
    expect(call.labels).toContain("vulnerability");
    expect(call.labels).toContain("severity:high");
    expect(call.body).toContain("XSS");
    expect(call.body).toContain("abc123d");
    expect(call.body).toContain("<script>alert(1)</script>");
  });
});
