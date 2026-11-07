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
 *   SAFE_YOLO_ESCALATE_URL   second-opinion endpoint
 *   SAFE_YOLO_ESCALATE_API   openai (default, vLLM) or zai (Z.ai JSON mode)
 *   SAFE_YOLO_ESCALATE_SKIP_DIRS colon-separated dirs (~ expands) that never escalate or explain
 *   SAFE_YOLO_SECRETS_FILE   extra secret patterns (default ~/.config/agent-guard/secrets.txt)
 *   SAFE_YOLO_TIMEOUT_MS     per-request timeout (default 4000)
 *   SAFE_YOLO_ESCALATE_MODEL model id for the escalation endpoint
 *   SAFE_YOLO_ESCALATE_API_KEY Bearer key for the escalation endpoint
 *   SAFE_YOLO_DEBUG          1 or a file path: log every decision as JSON lines
 *   SAFE_YOLO_LANG           ru (default) or en: language of the confirmation text
 *
 * Fail-open: when the classifier stack is unreachable, the hook exits without
 * output and Claude Code applies its own permission rules.
 */
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import {
  askMessage,
  classifyCommand,
  explainCommand,
  INTENT_REASON,
  loadSecretPatterns,
  type EngineOptions,
  type Explanation,
} from "./core"
import { lastUserMessage } from "./facts"

async function readStdin(): Promise<string> {
  const chunks: string[] = []
  for await (const chunk of process.stdin) chunks.push(String(chunk))
  return chunks.join("")
}

const raw = await readStdin()
let command = ""
let cwd: string | undefined
let why: string | undefined
let transcript: string | undefined
try {
  const event = JSON.parse(raw) as {
    tool_name?: string
    tool_input?: { command?: string; description?: string }
    cwd?: string
    transcript_path?: string
  }
  if (event.tool_name !== "Bash") process.exit(0)
  command = String(event.tool_input?.command ?? "")
  why = event.tool_input?.description
  cwd = event.cwd
  transcript = typeof event.transcript_path === "string" ? event.transcript_path : undefined
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

const engine: EngineOptions = {
  api: "systemone",
  url: env.SAFE_YOLO_URL ?? "http://127.0.0.1:8011/v1/systemone",
  model: env.SAFE_YOLO_MODEL,
  apiKey: env.SAFE_YOLO_API_KEY,
  policy,
  cwd,
  threshold: Number(env.SAFE_YOLO_THRESHOLD ?? 0.8),
  timeoutMs: Number(env.SAFE_YOLO_TIMEOUT_MS ?? 4000),
  escalateUrl: env.SAFE_YOLO_ESCALATE_URL,
  escalateApi: env.SAFE_YOLO_ESCALATE_API === "zai" ? "zai" : "openai",
  escalateSkipDirs: (env.SAFE_YOLO_ESCALATE_SKIP_DIRS ?? "")
    .split(":")
    .filter(Boolean)
    .map((d) => d.replace(/^~(?=\/|$)/, homedir())),
  secretPatterns: loadSecretPatterns(env.SAFE_YOLO_SECRETS_FILE ?? `${homedir()}/.config/agent-guard/secrets.txt`),
  escalateModel: env.SAFE_YOLO_ESCALATE_MODEL ?? "qwen3.6-35b",
  escalateApiKey: env.SAFE_YOLO_ESCALATE_API_KEY,
  language: env.SAFE_YOLO_LANG === "en" ? "en" : "ru",
}
const verdict = await classifyCommand(command, engine)

if (!verdict) process.exit(0) // fail-open: claude's own permission rules apply

const request = transcript ? lastUserMessage(transcript) : undefined
let found = verdict
let explanation: Explanation | undefined
// intent check is one-way: an unrelated request turns an unsure allow into ask, a match never allows
if (verdict.verdict === "safe" && verdict.uncertain && request) {
  explanation = await explainCommand(command, verdict.reason, engine, why, request)
  if (explanation?.intent === "unrelated") found = { ...verdict, reason: INTENT_REASON }
}
const ask = verdict.verdict === "unsafe" || found !== verdict
process.stdout.write(
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: ask ? "ask" : "allow",
      permissionDecisionReason: ask
        ? await askMessage(command, found, engine, why, { request, explanation })
        : `safe-yolo: ${verdict.reason}`,
    },
  }),
)
