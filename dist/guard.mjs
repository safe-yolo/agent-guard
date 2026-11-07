#!/usr/bin/env node

// src/guard-entry.ts
import { readFileSync } from "node:fs";
import { homedir as homedir2 } from "node:os";

// src/core.ts
import { execFile } from "node:child_process";
import { appendFileSync, renameSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
var DEFAULT_URL = "http://127.0.0.1:8000/v1/chat/completions";
var DEFAULT_MODEL = "qwen3.6-35b";
var DEFAULT_THRESHOLD = 0.8;
var BUILTIN_POLICY = [
  "You are a security classifier for shell commands issued by a coding agent on a user's machine.",
  "safe: project work - reading, building, tests, git without pushing, installing dependencies,",
  "editing the user's own files, project scripts. Also: read-only inspection anywhere - configs,",
  "logs, status, docker ps, port checks (nc -z), syntax checks (sh -n) - is safe even when the",
  "paths look system-level: reading never damages anything.",
  "unsafe: irreversibly destroys data, changes system state (writing fstab, sudoers, units,",
  "shutdown), executes downloaded code (curl | sh), deletes with broad paths beyond the project,",
  "pushes code, reads secrets (keys, tokens, credentials) and sends them anywhere.",
  "Pipes and command chains are evaluated as a whole. Keep the reason to one short sentence."
].join(" ");
var QUESTION = "Is this shell command dangerous for the machine or its data? " + "safe: normal project work such as reading, building, tests, git without pushing, " + "installing dependencies, editing the user's own files. " + "unsafe: irreversibly destroys data outside the project, touches the system, " + "executes downloaded code, pushes code, or leaks secrets. Pipes and command chains count as a whole.";
var BEFORE = String.raw`(?:^|[\s;&|(` + "`" + String.raw`'"])`;
var GIT_PUSH = new RegExp(BEFORE + String.raw`git(?:\s+-\S+(?:\s+[^\s-]\S*)?)*\s+push(?=$|[\s;&|)` + "`" + `'"])`, "m");
var PIPED_TO_SHELL = /\b(?:curl|wget)\b[^\n;]*(?<!\|)\|(?!\|)\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/;
var SHELL_OF_DOWNLOAD = /\b(?:ba|z|da|k)?sh\b[^\n|;]*(?:<\(|\$\()\s*(?:curl|wget)\b/;
var RM = new RegExp(BEFORE + "rm\\s+([^\\n;&|)`<>]*)", "g");
var LEAVES_CWD = new RegExp(BEFORE + String.raw`(?:cd|pushd|ssh)\s`);
var SSH = new RegExp(BEFORE + String.raw`ssh\s`);
var TEMP_DIRS = ["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/"];
var ASSIGN = new RegExp(BEFORE + String.raw`([A-Za-z_]\w*)(\+?)=("[^"\n]*"|'[^'\n]*'|[^\s;&|]*)(?=(\s*(?:$|[;&\n]))?)`, "gm");
var BINDS = /\b(?:for|read|unset)\s+([^;\n]*)/g;
function literalVars(command, limit) {
  const vars = new Map([["HOME", homedir()]]);
  for (const m of command.matchAll(ASSIGN)) {
    if (m.index >= limit)
      break;
    const [, name, plus, raw, ended] = m;
    const value = raw.replace(/^(['"])(.*)\1$/, "$2");
    const literal = ended !== undefined && !plus && !/[$`\\(]/.test(raw) && (!vars.has(name) || vars.get(name) === value);
    vars.set(name, literal ? value : undefined);
  }
  for (const m of command.slice(0, limit).matchAll(BINDS)) {
    for (const name of m[1].split(/\s+/))
      vars.set(name, undefined);
  }
  return vars;
}
function expand(path, vars) {
  return path.replace(/^~(?=\/|$)/, (m) => vars.get("HOME") ?? m).replace(/\$\{(\w+)\}|\$(\w+)/g, (m, braced, plain) => vars.get(braced ?? plain) ?? m);
}
function rmTargetOutside(args, cwd, leavesCwd, vars) {
  const tokens = args.replace(/['"]/g, "").split(/\s+/).filter(Boolean);
  const flags = tokens.filter((t) => t.startsWith("-"));
  const recursive = flags.some((f) => f === "--recursive" || /^-[^-]*r/i.test(f));
  const force = flags.some((f) => f === "--force" || /^-[^-]*f/.test(f));
  if (!recursive || !force)
    return;
  const paths = tokens.filter((t) => !t.startsWith("-"));
  if (!paths.length)
    return "paths from stdin";
  const isProject = cwd !== "/" && cwd !== homedir();
  return paths.find((p) => {
    const path = expand(p, vars);
    if (/^~|[$`]/.test(path) || leavesCwd && !path.startsWith("/"))
      return true;
    const full = resolve(cwd, path);
    return !(isProject && full.startsWith(`${cwd}/`)) && !TEMP_DIRS.some((dir) => full.startsWith(dir));
  });
}
function hardRule(command, cwd = process.cwd()) {
  if (GIT_PUSH.test(command))
    return "hard rule: git push";
  if (PIPED_TO_SHELL.test(command) || SHELL_OF_DOWNLOAD.test(command))
    return "hard rule: runs downloaded code";
  const leavesCwd = LEAVES_CWD.test(command);
  const remote = SSH.test(command);
  for (const match of command.matchAll(RM)) {
    const vars = remote ? new Map : literalVars(command, match.index);
    const target = rmTargetOutside(match[1], cwd, leavesCwd, vars);
    if (target)
      return `hard rule: rm -rf outside the project: ${target}`;
  }
  return;
}
var DEBUG_LOG_MAX_BYTES = 5 * 1024 * 1024;
function debugLog(entry) {
  const target = process.env.SAFE_YOLO_DEBUG;
  if (!target)
    return;
  const file = target === "1" ? `${homedir()}/.local/share/opencode/safe-yolo-debug.jsonl` : target;
  try {
    if ((statSync(file, { throwIfNoEntry: false })?.size ?? 0) > DEBUG_LOG_MAX_BYTES)
      renameSync(file, `${file}.1`);
    appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + `
`, { mode: 384 });
  } catch {}
}
function trusted(primary, threshold) {
  return primary.verdict === "safe" && (primary.confidence == null || primary.confidence >= threshold);
}
function pick(primary, secondary, threshold) {
  if (!primary)
    return secondary;
  return trusted(primary, threshold) ? primary : secondary ?? primary;
}
function parseOpenAI(stdout) {
  try {
    const out = JSON.parse(stdout);
    const content = out?.choices?.[0]?.message?.content;
    if (!content)
      return;
    const parsed = JSON.parse(content);
    return {
      verdict: parsed.verdict === "unsafe" ? "unsafe" : "safe",
      reason: (parsed.reason ?? "").slice(0, 120)
    };
  } catch {
    return;
  }
}
function parseSystemOne(stdout) {
  try {
    const out = JSON.parse(stdout);
    const answer = out?.answers?.verdict;
    if (!answer?.choice)
      return;
    const confidence = typeof answer.answer_confidence === "number" ? answer.answer_confidence : answer.confidence;
    if (typeof confidence !== "number")
      return;
    return {
      verdict: answer.choice.toLowerCase() === "unsafe" ? "unsafe" : "safe",
      reason: `model confidence ${Math.round(confidence * 100)}%`,
      confidence
    };
  } catch {
    return;
  }
}
function systemOnePayload(model, policy, command) {
  return JSON.stringify({
    ...model ? { model } : {},
    state: command,
    questions: {
      verdict: { type: "choice", instructions: policy || QUESTION, criteria: { safe: "safe", unsafe: "dangerous" } }
    }
  });
}
function openAIPayload(model, system, command) {
  return JSON.stringify({
    model,
    temperature: 0,
    max_tokens: 300,
    chat_template_kwargs: { enable_thinking: false },
    structured_outputs: {
      json: {
        type: "object",
        additionalProperties: false,
        required: ["verdict", "reason"],
        properties: {
          verdict: { type: "string", enum: ["safe", "unsafe"] },
          reason: { type: "string" }
        }
      }
    },
    messages: [
      ...system ? [{ role: "system", content: system }] : [],
      { role: "user", content: `Command: ${command}` }
    ]
  });
}
async function classifyCommand(command, cfg = {}) {
  const started = Date.now();
  const cwd = cfg.cwd ?? process.cwd();
  const rule = hardRule(command, cwd);
  if (rule) {
    const result = { verdict: "unsafe", reason: rule, via: "rule" };
    debugLog({ command, cwd, result });
    return result;
  }
  const api = cfg.api === "systemone" ? "systemone" : "openai";
  const url = cfg.url ?? DEFAULT_URL;
  const model = cfg.model ?? DEFAULT_MODEL;
  const timeoutMs = cfg.timeoutMs ?? 6000;
  const threshold = typeof cfg.threshold === "number" ? cfg.threshold : DEFAULT_THRESHOLD;
  const policy = cfg.policy ?? "";
  const system = cfg.noBuiltin ? policy : [BUILTIN_POLICY, policy].filter(Boolean).join(`

`);
  const failed = {};
  const headers = ["-H", "content-type: application/json"];
  if (cfg.apiKey)
    headers.push("-H", `authorization: Bearer ${cfg.apiKey}`);
  const once = async (via, apiUrl, apiShape, apiModel) => {
    const payload = apiShape === "systemone" ? systemOnePayload(apiModel, policy, command) : openAIPayload(apiModel, system, command);
    try {
      const stdout = await new Promise((resolve, reject) => {
        execFile("curl", ["-s", "--max-time", String(Math.ceil(timeoutMs / 1000)), ...headers, "-d", payload, apiUrl], { timeout: timeoutMs + 2000 }, (err, out) => err ? reject(err) : resolve(String(out)));
      });
      const parsed = apiShape === "systemone" ? parseSystemOne(stdout) : parseOpenAI(stdout);
      if (!parsed)
        throw new Error(`unexpected response shape: ${stdout.slice(0, 120)}`);
      return { ...parsed, via };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      failed[via] = message;
      if (via === "primary")
        console.error(`safe-yolo: classifier fail via=${via} err=${message}`);
      return;
    }
  };
  const primary = await once("primary", url, api, model);
  const needSecondary = !primary || !trusted(primary, threshold);
  const escalateCfg = cfg.escalateUrl && cfg.escalateApi === "systemone" ? { url: cfg.escalateUrl, api: "systemone", model: cfg.escalateModel ?? "", apiKey: cfg.escalateApiKey } : cfg.escalateUrl ? { url: cfg.escalateUrl, api: "openai", model: cfg.escalateModel ?? "", apiKey: cfg.escalateApiKey } : undefined;
  const secondary = needSecondary && escalateCfg ? await once("escalate", escalateCfg.url, escalateCfg.api, escalateCfg.model) : undefined;
  const result = pick(primary, secondary, threshold);
  debugLog({ command, cwd, ms: Date.now() - started, primary, secondary, failed, result });
  return result;
}

// src/guard-entry.ts
async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin)
    chunks.push(String(chunk));
  return chunks.join("");
}
var raw = await readStdin();
var command = "";
var cwd;
try {
  const event = JSON.parse(raw);
  if (event.tool_name !== "Bash")
    process.exit(0);
  command = String(event.tool_input?.command ?? "");
  cwd = event.cwd;
} catch {
  process.exit(0);
}
if (!command)
  process.exit(0);
var env = process.env;
var policyFile = env.SAFE_YOLO_POLICY_FILE ?? `${homedir2()}/.config/agent-guard/policy.md`;
var policy = "";
try {
  policy = readFileSync(policyFile, "utf8").trim();
} catch {}
var verdict = await classifyCommand(command, {
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
  escalateApiKey: env.SAFE_YOLO_ESCALATE_API_KEY
});
if (!verdict)
  process.exit(0);
var decision = verdict.verdict === "unsafe" ? "ask" : "allow";
process.stdout.write(JSON.stringify({
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: decision,
    permissionDecisionReason: `safe-yolo: ${verdict.reason}`
  }
}));
