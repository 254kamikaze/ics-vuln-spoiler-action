import Anthropic from "@anthropic-ai/sdk";
import type { CommitInfo, VulnerabilityAnalysis } from "./types.js";

let client: Anthropic;
let modelId: string;

export function initAnalyzer(apiKey: string, model: string): void {
  client = new Anthropic({ apiKey });
  modelId = model;
}

const ANALYSIS_PROMPT = `You are a security researcher analyzing git commits to identify security vulnerability patches.

Analyze the following commit and determine if it is patching an EXPLOITABLE security vulnerability.

## Commit Information
**SHA:** {sha}
**Author:** {author}
**Date:** {date}
**Message:**
{message}
{prSection}
## Diff
{diff}

## Instructions
Your task is to identify commits that patch REAL, EXPLOITABLE security vulnerabilities. You must be able to demonstrate the vulnerability with a concrete proof of concept.

Only flag a commit as a vulnerability patch if ALL of the following are true:
1. The code BEFORE the patch had a clear security flaw
2. You can write a specific proof of concept showing how to exploit it
3. The vulnerability has real security impact (not just theoretical)

DO NOT flag:
- General code quality improvements or defensive coding practices
- Adding validation that prevents edge cases but has no security impact
- Performance fixes or refactoring
- Error handling improvements without security implications
- Changes that only affect internal/trusted code paths
- Commits where you cannot write a concrete exploit PoC

Respond with a JSON object (and nothing else) in the following format:
{
  "isVulnerabilityPatch": boolean,
  "vulnerabilityType": string | null,
  "severity": "Critical" | "High" | "Medium" | "Low" | null,
  "description": string | null,
  "affectedCode": string | null,
  "proofOfConcept": string | null
}

If this is NOT an exploitable security vulnerability patch, set isVulnerabilityPatch to false and all other fields to null.

If this IS patching an exploitable vulnerability:
- vulnerabilityType: The vulnerability class (e.g., "SQL Injection", "XSS", "Path Traversal", "Prototype Pollution", "Command Injection")
- severity: Based on exploitability and impact (Critical = RCE/auth bypass, High = data leak/privilege escalation, Medium = limited impact, Low = edge case)
- description: 2-3 sentences explaining the vulnerability and how the patch fixes it
- affectedCode: The vulnerable code snippet BEFORE the patch (max 5 lines)
- proofOfConcept: A CONCRETE exploit example showing malicious input and expected behavior. This must be specific code or commands that would trigger the vulnerability, not a general description.

Example proofOfConcept formats:
- For XSS: \`<script>alert(document.cookie)</script>\` in the username field
- For SQL Injection: \`' OR 1=1 --\` as the password parameter
- For Path Traversal: \`GET /api/files?path=../../../etc/passwd\`
- For Command Injection: \`; rm -rf /\` appended to the filename

If you cannot write a specific, concrete proof of concept, set isVulnerabilityPatch to false.`;

export async function analyzeCommit(
  commit: CommitInfo
): Promise<VulnerabilityAnalysis> {
  let prSection = "";
  if (commit.pullRequest) {
    const pr = commit.pullRequest;
    prSection = `
## Associated Pull Request
**PR #${pr.number}:** ${pr.title}
**URL:** ${pr.url}
**Labels:** ${pr.labels.length > 0 ? pr.labels.join(", ") : "None"}
${pr.body ? `**Description:**\n${pr.body.substring(0, 1000)}${pr.body.length > 1000 ? "..." : ""}` : ""}
`;
  }

  const prompt = ANALYSIS_PROMPT.replace("{sha}", commit.sha)
    .replace("{author}", commit.author)
    .replace("{date}", commit.date)
    .replace("{message}", commit.message)
    .replace("{prSection}", prSection)
    .replace("{diff}", commit.diff);

  const response = await client.messages.create({
    model: modelId,
    max_tokens: 1024,
    messages: [
      { role: "user", content: prompt },
      { role: "assistant", content: "{" },
    ],
  });

  const content = response.content[0];
  if (content.type !== "text") {
    throw new Error("Unexpected response type from Claude API");
  }

  try {
    const analysis = JSON.parse("{" + content.text) as VulnerabilityAnalysis;
    return analysis;
  } catch {
    return {
      isVulnerabilityPatch: false,
      vulnerabilityType: null,
      severity: null,
      description: null,
      affectedCode: null,
      proofOfConcept: null,
    };
  }
}
