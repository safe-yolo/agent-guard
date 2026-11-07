#!/usr/bin/env node
/** Claude Code PreToolUse hook: classify a Bash command before it runs.
 *
 * Reads the hook JSON from stdin, asks the classifier stack (primary +
 * optional escalation), and prints a permissionDecision for Claude Code.
 *
 * Configuration via environment:
 *   SAFE_YOLO_URL            primary systemone endpoint
 *                            (default http://127.0.0.1:8011/v1/systemone)
 *   SAFE_YOLO_MODEL          classifier model id
 *   SAFE_YOLO_API_KEY        Bearer key for the primary endpoint
 *   SAFE_YOLO_THRESHOLD      confidence gate (default 0.8)
 *   SAFE_YOLO_POLICY_FILE    policy markdown (default ~/.config/agent-guard/policy.md)
 *   SAFE_YOLO_ESCALATE_URL   second-opinion openai endpoint
 *   SAFE_YOLO_ESCALATE_MODEL model id for the escalation endpoint
 *   SAFE_YOLO_ESCALATE_API_KEY Bearer key for the escalation endpoint
 *   SAFE_YOLO_DEBUG          1 or a file path: log every decision as JSON lines
 *
 * Fail-open: when the classifier stack is unreachable, the hook exits without
 * output and Claude Code applies its own permission rules.
 */
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { classifyCommand } from "./core"

async function readStdin(): Promise<string> {
  const chunks: string[] = []
  for await (const chunk of process.stdin) chunks.push(String(chunk))
  return chunks.join("")
}

const raw = await readStdin()
let command = ""
let cwd: string | undefined
try {
  const event = JSON.parse(raw) as { tool_name?: string; tool_input?: { command?: string }; cwd?: string }
  if (event.tool_name !== "Bash") process.exit(0)
  command = String(event.tool_input?.command ?? "")
  cwd = event.cwd
} catch {
  process.exit(0)
}
if (!command) process.exit(0)

const env = process.env
const policyFile = env.SAFE_YOLO_POLICY_FILE ?? `${homedir()}/.config/agent-guard/policy.md`
let policy = ""
try {
  policy = readFileSync(policyFile, "utf8").trim()
} catch {}

const verdict = await classifyCommand(command, {
  api: "systemone",
  url: env.SAFE_YOLO_URL ?? "http://127.0.0.1:8011/v1/systemone",
  model: env.SAFE_YOLO_MODEL,
  apiKey: env.SAFE_YOLO_API_KEY,
  policy,
  cwd,
  threshold: Number(env.SAFE_YOLO_THRESHOLD ?? 0.8),
  timeoutMs: 4000,
  escalateUrl: env.SAFE_YOLO_ESCALATE_URL,
  escalateModel: env.SAFE_YOLO_ESCALATE_MODEL ?? "qwen3.6-35b",
  escalateApiKey: env.SAFE_YOLO_ESCALATE_API_KEY,
})

if (!verdict) process.exit(0) // fail-open: claude's own permission rules apply

const decision = verdict.verdict === "unsafe" ? "ask" : "allow"
process.stdout.write(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: `safe-yolo: ${verdict.reason}`,
    },
  }),
)
