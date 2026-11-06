/** Shared classification engine for the safe-yolo clients (opencode plugin, claude code hook). */
import { execFile } from "node:child_process"
import { appendFileSync, renameSync, statSync } from "node:fs"
import { homedir } from "node:os"
import { resolve } from "node:path"

export type Effect = "allow" | "ask" | "deny"
export type Verdict = "safe" | "unsafe"
export type Mode = "shadow" | "enforce"
export type Api = "openai" | "systemone"

const DEFAULT_URL = "http://127.0.0.1:8000/v1/chat/completions"
const DEFAULT_MODEL = "qwen3.6-35b"
export const DEFAULT_THRESHOLD = 0.8

export const BUILTIN_POLICY = [
  "You are a security classifier for shell commands issued by a coding agent on a user's machine.",
  "safe: project work - reading, building, tests, git without pushing, installing dependencies,",
  "editing the user's own files, project scripts. Also: read-only inspection anywhere - configs,",
  "logs, status, docker ps, port checks (nc -z), syntax checks (sh -n) - is safe even when the",
  "paths look system-level: reading never damages anything.",
  "unsafe: irreversibly destroys data, changes system state (writing fstab, sudoers, units,",
  "shutdown), executes downloaded code (curl | sh), deletes with broad paths beyond the project,",
  "pushes code, reads secrets (keys, tokens, credentials) and sends them anywhere.",
  "Pipes and command chains are evaluated as a whole. Keep the reason to one short sentence.",
].join(" ")

const QUESTION =
  "Is this shell command dangerous for the machine or its data? " +
  "safe: normal project work such as reading, building, tests, git without pushing, " +
  "installing dependencies, editing the user's own files. " +
  "unsafe: irreversibly destroys data outside the project, touches the system, " +
  "executes downloaded code, pushes code, or leaks secrets. Pipes and command chains count as a whole."

export interface EngineOptions {
  /** openai: chat completions with structured outputs (vLLM). systemone: Jev / System One decision API */
  api?: Api
  /** full endpoint URL: .../v1/chat/completions for openai, .../v1/systemone for systemone */
  url?: string
  model?: string
  apiKey?: string
  /** the user's policy text, sent to the classifier after the built-in rules */
  policy?: string
  /** drop the built-in rules: only `policy` goes to the classifier */
  noBuiltin?: boolean
  /** project directory for the hard rules (default process.cwd()) */
  cwd?: string
  /** primary confidence below this escalates to the escalation endpoint (default 0.8) */
  threshold?: number
  /** per-request curl timeout in milliseconds */
  timeoutMs?: number
  /** second-opinion endpoint: commands the primary is unsure about go here */
  escalateUrl?: string
  escalateApi?: Api
  escalateModel?: string
  escalateApiKey?: string
}

export interface ClassifyResult {
  verdict: Verdict
  reason: string
  /** calibrated probability mass on the verdict, when the endpoint reports it */
  confidence?: number
  via: "rule" | "primary" | "escalate"
}

const BEFORE = String.raw`(?:^|[\s;&|(` + "`" + String.raw`'"])`
const GIT_PUSH = new RegExp(BEFORE + String.raw`git(?:\s+-\S+(?:\s+[^\s-]\S*)?)*\s+push(?=$|[\s;&|)` + "`" + `'"])`, "m")
const PIPED_TO_SHELL = /\b(?:curl|wget)\b[^\n;]*(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/
const SHELL_OF_DOWNLOAD = /\b(?:ba|z|da|k)?sh\b[^\n|;]*(?:<\(|\$\()\s*(?:curl|wget)\b/
const RM = new RegExp(BEFORE + "rm\\s+([^\\n;&|)`<>]*)", "g")
const LEAVES_CWD = new RegExp(BEFORE + String.raw`(?:cd|pushd|ssh)\s`)
const SSH = new RegExp(BEFORE + String.raw`ssh\s`)
const TEMP_DIRS = ["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/"]
const ASSIGN = new RegExp(BEFORE + String.raw`([A-Za-z_]\w*)(\+?)=("[^"\n]*"|'[^'\n]*'|[^\s;&|]*)(?=(\s*(?:$|[;&\n]))?)`, "gm")
const BINDS = /\b(?:for|read|unset)\s+([^;\n]*)/g

/**
 * Variables the command itself sets to a plain literal before `limit`; undefined means unknown.
 * Never reads the real environment: the hook does not see the agent's shell, and secrets stay out.
 * shortcut: text only, so an assignment inside if or a subshell counts; upgrade with a shell parser.
 */
function literalVars(command: string, limit: number): Map<string, string | undefined> {
  const vars = new Map<string, string | undefined>([["HOME", homedir()]])
  for (const m of command.matchAll(ASSIGN)) {
    if (m.index >= limit) break
    const [, name, plus, raw, ended] = m
    const value = raw.replace(/^(['"])(.*)\1$/, "$2")
    const literal = ended !== undefined && !plus && !/[$`\\(]/.test(raw) && (!vars.has(name) || vars.get(name) === value)
    vars.set(name, literal ? value : undefined)
  }
  for (const m of command.slice(0, limit).matchAll(BINDS)) {
    for (const name of m[1].split(/\s+/)) vars.set(name, undefined)
  }
  return vars
}

function expand(path: string, vars: Map<string, string | undefined>): string {
  return path
    .replace(/^~(?=\/|$)/, (m) => vars.get("HOME") ?? m)
    .replace(/\$\{(\w+)\}|\$(\w+)/g, (m, braced, plain) => vars.get(braced ?? plain) ?? m)
}

/** First rm -rf target outside cwd; a relative path after cd or ssh can point anywhere. */
function rmTargetOutside(
  args: string,
  cwd: string,
  leavesCwd: boolean,
  vars: Map<string, string | undefined>,
): string | undefined {
  const tokens = args.replace(/['"]/g, "").split(/\s+/).filter(Boolean)
  const flags = tokens.filter((t) => t.startsWith("-"))
  const recursive = flags.some((f) => f === "--recursive" || /^-[^-]*r/i.test(f))
  const force = flags.some((f) => f === "--force" || /^-[^-]*f/.test(f))
  if (!recursive || !force) return undefined
  const paths = tokens.filter((t) => !t.startsWith("-"))
  if (!paths.length) return "paths from stdin"
  const isProject = cwd !== "/" && cwd !== homedir()
  return paths.find((p) => {
    const path = expand(p, vars)
    if (/^~|[$`]/.test(path) || (leavesCwd && !path.startsWith("/"))) return true
    const full = resolve(cwd, path)
    return !(isProject && full.startsWith(`${cwd}/`)) && !TEMP_DIRS.some((dir) => full.startsWith(dir))
  })
}

/**
 * Commands no model may wave through: deny in the opencode plugin, ask in the claude code hook.
 * shortcut: matches raw text, so a quoted mention also asks; upgrade to a shell parser if that gets noisy.
 */
export function hardRule(command: string, cwd: string = process.cwd()): string | undefined {
  if (GIT_PUSH.test(command)) return "hard rule: git push"
  if (PIPED_TO_SHELL.test(command) || SHELL_OF_DOWNLOAD.test(command)) return "hard rule: runs downloaded code"
  const leavesCwd = LEAVES_CWD.test(command)
  const remote = SSH.test(command) // $S and ~ inside ssh belong to the other host
  for (const match of command.matchAll(RM)) {
    const vars = remote ? new Map<string, string | undefined>() : literalVars(command, match.index)
    const target = rmTargetOutside(match[1], cwd, leavesCwd, vars)
    if (target) return `hard rule: rm -rf outside the project: ${target}`
  }
  return undefined
}

const DEBUG_LOG_MAX_BYTES = 5 * 1024 * 1024

/**
 * SAFE_YOLO_DEBUG=1 or a file path: one JSON line per classified command, full text, so keep it local.
 * Past the limit the file moves to .1, over the previous one, so disk use stays around twice the limit.
 * shortcut: no lock, two processes rotating at once can lose old lines; fine for a debug log.
 */
function debugLog(entry: object): void {
  const target = process.env.SAFE_YOLO_DEBUG
  if (!target) return
  const file = target === "1" ? `${homedir()}/.local/share/opencode/safe-yolo-debug.jsonl` : target
  try {
    if ((statSync(file, { throwIfNoEntry: false })?.size ?? 0) > DEBUG_LOG_MAX_BYTES) renameSync(file, `${file}.1`)
    appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n", { mode: 0o600 })
  } catch {}
}

/** Pure decision logic on top of a classifier verdict. Only a hard rule can produce deny. */
export function decide(
  mode: Mode,
  effect: Effect,
  verdict: Verdict,
  reason: string,
  via?: ClassifyResult["via"],
): { effect: Effect; message?: string } {
  // deny, not ask: opencode auto mode approves everything that is not an explicit deny
  if (via === "rule") return { effect: "deny", message: `safe-yolo: ${reason}` }
  if (mode !== "enforce") return { effect }
  if (verdict === "unsafe" && effect === "allow") {
    return { effect: "ask", message: `safe-yolo: ${reason}` }
  }
  if (verdict === "safe" && effect === "ask") {
    return { effect: "allow" }
  }
  return { effect }
}

/** Only a confident safe passes without a second opinion: false alarms cost a prompt each. */
function trusted(primary: ClassifyResult, threshold: number): boolean {
  return primary.verdict === "safe" && (primary.confidence == null || primary.confidence >= threshold)
}

/** Cascade: trust a confident safe primary, otherwise take the escalation. */
export function pick(
  primary: ClassifyResult | undefined,
  secondary: ClassifyResult | undefined,
  threshold: number,
): ClassifyResult | undefined {
  if (!primary) return secondary
  return trusted(primary, threshold) ? primary : (secondary ?? primary)
}

/** Extract the verdict from an OpenAI chat completions response. */
export function parseOpenAI(stdout: string): Omit<ClassifyResult, "via"> | undefined {
  try {
    const out = JSON.parse(stdout) as { choices?: { message?: { content?: string } }[] }
    const content = out?.choices?.[0]?.message?.content
    if (!content) return undefined
    const parsed = JSON.parse(content) as { verdict?: string; reason?: string }
    return {
      verdict: (parsed.verdict === "unsafe" ? "unsafe" : "safe") as Verdict,
      reason: (parsed.reason ?? "").slice(0, 120),
    }
  } catch {
    return undefined
  }
}

/**
 * Extract the verdict from a Jev / System One decision response (laya-serve, Clef,
 * cat-shell-risk-commander wrappers). Decision models return probabilities, not
 * prose, so the reason is the confidence. answer_confidence is the calibrated mass
 * on the answer - the field to gate on.
 */
export function parseSystemOne(stdout: string): (Omit<ClassifyResult, "via"> & { confidence: number }) | undefined {
  try {
    const out = JSON.parse(stdout) as {
      answers?: Record<string, { choice?: string; confidence?: number; answer_confidence?: number }>
    }
    const answer = out?.answers?.verdict
    if (!answer?.choice) return undefined
    const confidence = typeof answer.answer_confidence === "number" ? answer.answer_confidence : answer.confidence
    if (typeof confidence !== "number") return undefined
    return {
      verdict: (answer.choice.toLowerCase() === "unsafe" ? "unsafe" : "safe") as Verdict,
      reason: `model confidence ${Math.round(confidence * 100)}%`,
      confidence,
    }
  } catch {
    return undefined
  }
}

function systemOnePayload(model: string, policy: string, command: string): string {
  return JSON.stringify({
    ...(model ? { model } : {}),
    state: command,
    questions: {
      verdict: { type: "choice", instructions: policy || QUESTION, criteria: { safe: "safe", unsafe: "dangerous" } },
    },
  })
}

function openAIPayload(model: string, system: string, command: string): string {
  return JSON.stringify({
    model,
    temperature: 0,
    max_tokens: 300, // a cut reason is broken JSON, and the verdict is lost with it
    chat_template_kwargs: { enable_thinking: false },
    structured_outputs: {
      json: {
        type: "object",
        additionalProperties: false,
        required: ["verdict", "reason"],
        properties: {
          verdict: { type: "string", enum: ["safe", "unsafe"] },
          reason: { type: "string" },
        },
      },
    },
    messages: [
      ...(system ? [{ role: "system", content: system }] : []),
      { role: "user", content: `Command: ${command}` },
    ],
  })
}

/**
 * Classify one shell command: hard rules first, then the primary endpoint, then
 * escalation for anything but a confident safe. The transport goes through curl
 * because bun processes are often blocked from LAN hosts by macOS Local Network
 * privacy while Apple's curl is allowed.
 */
export async function classifyCommand(command: string, cfg: EngineOptions = {}): Promise<ClassifyResult | undefined> {
  const started = Date.now()
  const cwd = cfg.cwd ?? process.cwd()
  const rule = hardRule(command, cwd)
  if (rule) {
    const result: ClassifyResult = { verdict: "unsafe", reason: rule, via: "rule" }
    debugLog({ command, cwd, result })
    return result
  }
  const api: Api = cfg.api === "systemone" ? "systemone" : "openai"
  const url = cfg.url ?? DEFAULT_URL
  const model = cfg.model ?? DEFAULT_MODEL
  const timeoutMs = cfg.timeoutMs ?? 6000
  const threshold = typeof cfg.threshold === "number" ? cfg.threshold : DEFAULT_THRESHOLD
  const policy = cfg.policy ?? ""
  const system = cfg.noBuiltin ? policy : [BUILTIN_POLICY, policy].filter(Boolean).join("\n\n")
  const failed: Record<string, string> = {}
  const headers = ["-H", "content-type: application/json"]
  if (cfg.apiKey) headers.push("-H", `authorization: Bearer ${cfg.apiKey}`)

  const once = async (
    via: "primary" | "escalate",
    apiUrl: string,
    apiShape: Api,
    apiModel: string,
  ): Promise<Omit<ClassifyResult, "via"> | undefined> => {
    const payload = apiShape === "systemone" ? systemOnePayload(apiModel, policy, command) : openAIPayload(apiModel, system, command)
    try {
      const stdout = await new Promise<string>((resolve, reject) => {
        execFile(
          "curl",
          ["-s", "--max-time", String(Math.ceil(timeoutMs / 1000)), ...headers, "-d", payload, apiUrl],
          { timeout: timeoutMs + 2000 },
          (err, out) => (err ? reject(err) : resolve(String(out))),
        )
      })
      const parsed = apiShape === "systemone" ? parseSystemOne(stdout) : parseOpenAI(stdout)
      if (!parsed) throw new Error(`unexpected response shape: ${stdout.slice(0, 120)}`)
      return { ...parsed, via }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      failed[via] = message
      if (via === "primary") console.error(`safe-yolo: classifier fail via=${via} err=${message}`)
      return undefined
    }
  }

  const primary = await once("primary", url, api, model)
  const needSecondary = !primary || !trusted(primary, threshold)
  const escalateCfg =
    cfg.escalateUrl && cfg.escalateApi === "systemone"
      ? { url: cfg.escalateUrl, api: "systemone" as Api, model: cfg.escalateModel ?? "", apiKey: cfg.escalateApiKey }
      : cfg.escalateUrl
        ? { url: cfg.escalateUrl, api: "openai" as Api, model: cfg.escalateModel ?? "", apiKey: cfg.escalateApiKey }
        : undefined
  const secondary = needSecondary && escalateCfg ? await once("escalate", escalateCfg.url, escalateCfg.api, escalateCfg.model) : undefined
  const result = pick(primary, secondary, threshold)
  debugLog({ command, cwd, ms: Date.now() - started, primary, secondary, failed, result })
  return result
}
