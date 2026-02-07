import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CommitInfo } from "../types.js";

const mockCreate = vi.fn();

vi.mock("@anthropic-ai/sdk", () => ({
  default: class {
    messages = { create: mockCreate };
  },
}));

import { initAnalyzer, analyzeCommit } from "../analyzer.js";

const baseCommit: CommitInfo = {
  sha: "abc123def456",
  message: "Fix input validation in query parser",
  author: "Jane Doe",
  date: "2025-01-15T10:30:00Z",
  url: "https://github.com/example/repo/commit/abc123def456",
  diff: `--- a/src/query.ts\n+++ b/src/query.ts\n@@ -10,6 +10,7 @@\n function parseQuery(input: string) {\n+  input = sanitize(input);\n   return db.query(input);\n }`,
  pullRequest: null,
};

describe("analyzeCommit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initAnalyzer("test-api-key", "claude-sonnet-4-20250514");
  });

  it("returns vulnerability analysis when Claude detects a vuln", async () => {
    const vulnResponse = {
      isVulnerabilityPatch: true,
      vulnerabilityType: "SQL Injection",
      severity: "High",
      description: "The query parser passed unsanitized input directly to db.query().",
      affectedCode: "return db.query(input);",
      proofOfConcept: "parseQuery(\"'; DROP TABLE users; --\")",
    };

    mockCreate.mockResolvedValueOnce({
      content: [{ type: "text", text: JSON.stringify(vulnResponse).slice(1) }],
    });

    const result = await analyzeCommit(baseCommit);

    expect(result.isVulnerabilityPatch).toBe(true);
    expect(result.vulnerabilityType).toBe("SQL Injection");
    expect(result.severity).toBe("High");
    expect(result.proofOfConcept).toBeTruthy();
  });

  it("returns non-vulnerability when Claude says no vuln", async () => {
    const safeResponse = {
      isVulnerabilityPatch: false,
      vulnerabilityType: null,
      severity: null,
      description: null,
      affectedCode: null,
      proofOfConcept: null,
    };

    mockCreate.mockResolvedValueOnce({
      content: [{ type: "text", text: JSON.stringify(safeResponse).slice(1) }],
    });

    const result = await analyzeCommit(baseCommit);

    expect(result.isVulnerabilityPatch).toBe(false);
    expect(result.vulnerabilityType).toBeNull();
  });

  it("returns safe default on malformed JSON from Claude", async () => {
    mockCreate.mockResolvedValueOnce({
      content: [{ type: "text", text: "this is not valid JSON at all" }],
    });

    const result = await analyzeCommit(baseCommit);

    expect(result.isVulnerabilityPatch).toBe(false);
    expect(result.vulnerabilityType).toBeNull();
    expect(result.severity).toBeNull();
  });

  it("includes PR context in the prompt when commit has a PR", async () => {
    const commitWithPR: CommitInfo = {
      ...baseCommit,
      pullRequest: {
        number: 42,
        title: "Fix SQL injection in query parser",
        body: "This PR fixes a critical SQL injection vulnerability.",
        url: "https://github.com/example/repo/pull/42",
        labels: ["security", "bug"],
        mergedAt: "2025-01-15T12:00:00Z",
      },
    };

    mockCreate.mockResolvedValueOnce({
      content: [
        {
          type: "text",
          text: `"isVulnerabilityPatch": false, "vulnerabilityType": null, "severity": null, "description": null, "affectedCode": null, "proofOfConcept": null}`,
        },
      ],
    });

    await analyzeCommit(commitWithPR);

    const call = mockCreate.mock.calls[0][0];
    const prompt = call.messages[0].content;
    expect(prompt).toContain("PR #42");
    expect(prompt).toContain("Fix SQL injection in query parser");
    expect(prompt).toContain("security, bug");
  });

  it("omits PR section when commit has no pull request", async () => {
    mockCreate.mockResolvedValueOnce({
      content: [
        {
          type: "text",
          text: `"isVulnerabilityPatch": false, "vulnerabilityType": null, "severity": null, "description": null, "affectedCode": null, "proofOfConcept": null}`,
        },
      ],
    });

    await analyzeCommit(baseCommit);

    const call = mockCreate.mock.calls[0][0];
    const prompt = call.messages[0].content;
    expect(prompt).not.toContain("Associated Pull Request");
  });
});
