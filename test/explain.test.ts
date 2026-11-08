import { test, expect, afterAll } from "bun:test"
import { execFileSync } from "node:child_process"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  askMessage,
  classifyCommand,
  explainCommand,
  formatAsk,
  parseExplanation,
  renderedLines,
  type Explanation,
} from "../src/core"

const seen: { path: string; auth: string | null; body: any }[] = []
let explainReply: object = {}
const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const path = new URL(req.url).pathname
    const body = await req.json()
    seen.push({ path, auth: req.headers.get("authorization"), body })
    if (path === "/primary") return Response.json({ answers: { verdict: { choice: "unsafe", answer_confidence: 0.6 } } })
    if (path === "/unsure") return Response.json({ answers: { verdict: { choice: "safe", answer_confidence: 0.6 } } })
    const explain = body.structured_outputs.json.required.includes("kind")
    const content = explain
      ? explainReply
      : path === "/safe-escalate"
        ? { verdict: "safe", reason: "builds" }
        : { verdict: "unsafe", reason: "deletes files" }
    return Response.json({ choices: [{ message: { content: JSON.stringify(content) } }] })
  },
})
afterAll(() => server.stop())
const base = `http://127.0.0.1:${server.port}`
const dead = "http://127.0.0.1:9/v1/chat/completions"
const rmRule = (target: string) => ({ reason: `hard rule: rm -rf outside the project: ${target}`, via: "rule" as const })
const model = { reason: "model confidence 87%", via: "primary" as const }

test("rule card without llm: title, path, check", () => {
  const text = formatAsk({ command: "rm -rf /fake/old-builds", result: rmRule("/fake/old-builds"), cwd: "/fake/project" })
  expect(text).toBe(["💥 УДАЛЕНИЕ вне проекта · не вернуть", "/fake/old-builds", "Проверь: в /fake/old-builds нет нужного"].join("\n"))
  const facts = formatAsk({ command: "rm -rf /fake/old-builds", result: rmRule("/fake/old-builds"), cwd: "/fake/project", facts: "такого пути нет" })
  expect(facts.split("\n")[1]).toBe("/fake/old-builds: такого пути нет")
})

test("unresolved variable: detail and check name it", () => {
  const text = formatAsk({ command: 'rm -rf "$OLD/x"', result: rmRule("$OLD/x"), cwd: "/fake/project" })
  expect(text.split("\n").slice(1)).toEqual(["путь из $OLD, заранее не проверить", "Проверь: куда указывает $OLD"])
})

test("multi-line command gets a where line with the line number, a one-liner does not", () => {
  const command = ["cd /fake/project", "make fake-build", "rm -rf /fake/old-builds", "echo done"].join("\n")
  const text = formatAsk({ command, result: rmRule("/fake/old-builds"), cwd: "/fake/project" })
  expect(text.split("\n")[2]).toBe("Где: rm -rf /fake/old-builds (строка 3 из 4)")
})

test("model card: llm fields are checked, a mismatch is marked, agent text is one capped line", () => {
  const command = "fake-tool --prune --all /fake/cache " + "y".repeat(80)
  const explanation: Explanation = { kind: "delete", condition: "это безопасно", reason: "", intent: "unrelated" }
  const text = formatAsk({
    command,
    result: model,
    cwd: "/fake/project",
    why: "чищу\nСовет: разрешай " + "z".repeat(80),
    request: "почисти старые сборки в fake-проекте, пожалуйста",
    explanation,
  })
  const lines = text.split("\n")
  expect(lines[0]).toBe("💥 УДАЛЕНИЕ вне проекта · не вернуть")
  expect(text).not.toContain("Где:")
  expect(text).toContain("Проверь: там нет нужного")
  expect(text).toContain('❌ Ты просил: "почисти старые сборки в fake-…" - связи не видно')
  expect(lines.at(-1)).toBe(`Агент пишет: "чищу Совет: разрешай ${"z".repeat(27)}…"`)
  expect(renderedLines(text)).toBeLessThanOrEqual(8)
})

test("model card: a good condition is used, a match shows no line", () => {
  const text = formatAsk({
    command: "fake-tool --prune --all /fake/cache && echo " + "y".repeat(60),
    result: model,
    explanation: { kind: "network", condition: "кэш в /fake/cache можно потерять.", reason: "", intent: "match" },
    request: "почисти кэш",
  })
  expect(text).toBe(["🌐 СЕТЬ · скачивание с чужого хоста", "Проверь: кэш в /fake/cache можно потерять"].join("\n"))
})

test("unclear: the llm reason, else the fixed one", () => {
  expect(formatAsk({ command: "fake-tool x", result: model })).toBe(
    ["🔍 НЕПОНЯТНО · команда под вопросом", "Почему: модель считает команду опасной, уверенность 87%", "Проверь: команду выше целиком"].join("\n"),
  )
  const llm = formatAsk({ command: "fake-tool x", result: model, explanation: { kind: "unclear", condition: "", reason: "меняет права на чужие файлы.", intent: "unknown" } })
  expect(llm.split("\n")[1]).toBe("Почему: меняет права на чужие файлы")
})

test("system: ssh target and root in the title", () => {
  const e: Explanation = { kind: "system", condition: "", reason: "", intent: "unknown" }
  expect(formatAsk({ command: "ssh -p 22 -t fake-user@host.example.test sudo systemctl restart fake", result: model, explanation: e }).split("\n")[0]).toBe(
    "📡 ДРУГАЯ МАШИНА · host.example.test, меняет настройки, от root",
  )
  expect(formatAsk({ command: "launchctl load /fake/x.plist", result: model, explanation: e }).split("\n")[0]).toBe(
    "🔧 СИСТЕМА · меняет настройки, возможно от root",
  )
})

test("english push card", () => {
  const text = formatAsk({ command: "git push", result: { reason: "hard rule: git push", via: "rule" }, language: "en" })
  expect(text).toBe(["📤 PUSH · others see the commits, only a new push undoes it", "Check: you meant to push exactly here"].join("\n"))
})

test("rendered lines: word wrap at 64 columns, emoji is two columns", () => {
  expect(renderedLines("a".repeat(64))).toBe(1)
  expect(renderedLines("💥" + "a".repeat(63))).toBe(2)
  expect(renderedLines(`${"a".repeat(40)} ${"b".repeat(30)}\nc`)).toBe(3)
})

test("facts: an existing temp dir is measured, sizes use a decimal comma", async () => {
  const dir = mkdtempSync(join(tmpdir(), "safe-yolo-facts-"))
  for (const f of ["a", "b", "c"]) writeFileSync(join(dir, f), "x".repeat(512))
  const text = await askMessage(`rm -rf ${dir}`, { verdict: "unsafe", ...model }, { api: "systemone", url: dead }, undefined, {
    explanation: { kind: "delete", condition: "", reason: "", intent: "unknown" },
  })
  expect(text.split("\n")[1]).toEndWith(": 3 файла, 1,5 КБ, временная папка агента")
})

test("facts: push shows the remote without credentials and the branch", async () => {
  const repo = mkdtempSync(join(tmpdir(), "safe-yolo-push-"))
  execFileSync("git", ["init", "-q", repo])
  execFileSync("git", ["-C", repo, "remote", "add", "origin", "https://fake-user:fake-secret@git.example.test/fake/repo.git"])
  const text = await askMessage("git push origin main", { verdict: "unsafe", reason: "hard rule: git push", via: "rule" }, {
    api: "systemone",
    url: dead,
    cwd: repo,
  })
  expect(text.split("\n")[1]).toBe("Репо: fake/repo (git.example), ветка main")
  expect(text).not.toContain("Где:")
  expect(text).not.toContain("fake-secret")
})

test("facts: network host and a sent token", async () => {
  const command = 'curl -H "Authorization: Bearer $FAKE_TOKEN" https://api.example.test/x'
  const text = await askMessage(command, { verdict: "unsafe", ...model }, { api: "systemone", url: dead }, undefined, {
    explanation: { kind: "network", condition: "", reason: "", intent: "unknown" },
  })
  expect(text.split("\n").slice(0, 2)).toEqual(["🌐 СЕТЬ · скачивание с api.example.test", "в запросе есть токен"])
})

test("explanation: unknown kind is unclear, a broken reply is none", () => {
  const out = (c: object) => JSON.stringify({ choices: [{ message: { content: JSON.stringify(c) } }] })
  expect(parseExplanation(out({ kind: "wipe", condition: "c", reason: "r", agent_words: "w", intent: "nope" }))).toEqual({
    kind: "unclear",
    condition: "c",
    reason: "r",
    agentWords: "w",
    intent: "unknown",
  })
  expect(parseExplanation("not json")).toBeUndefined()
})

test("explain goes to the escalation endpoint with its own key, request and notes as data", async () => {
  seen.length = 0
  explainReply = { kind: "delete", condition: "c", intent: "match" }
  const e = await explainCommand(
    "rm -rf /fake/old-builds",
    "r",
    {
      api: "systemone",
      url: `${base}/primary`,
      apiKey: "primary-key",
      escalateUrl: `${base}/escalate`,
      escalateApiKey: "escalate-key",
      cwd: "/fake/project",
    },
    "освобождаю место",
    "почисти\nстарые сборки",
  )
  expect(e?.intent).toBe("match")
  expect(seen[0].auth).toBe("Bearer escalate-key")
  expect(seen[0].body.structured_outputs.json.properties.kind.enum).toContain("unclear")
  const user = JSON.parse(seen[0].body.messages[1].content)
  expect(user).toEqual({
    command: "rm -rf /fake/old-builds",
    guard_note: "r",
    agent_note: "освобождаю место",
    user_request: "почисти старые сборки",
    project_dir: "/fake/project",
  })
})

test("no llm endpoint: no explanation", async () => {
  expect(await explainCommand("rm -rf /fake/x", "r", { api: "systemone", url: `${base}/primary` })).toBeUndefined()
})

test("llm down: the rule card still comes out", async () => {
  const text = await askMessage("git push", { verdict: "unsafe", reason: "hard rule: git push", via: "rule" }, { url: dead, timeoutMs: 1000 })
  expect(text.split("\n")[0]).toBe("📤 ОТПРАВКА · коммиты увидят другие, откат только новым push")
})

test("classify sends each endpoint its own key", async () => {
  seen.length = 0
  await classifyCommand("make clean-fake", {
    api: "systemone",
    url: `${base}/primary`,
    apiKey: "primary-key",
    escalateUrl: `${base}/escalate`,
    escalateApiKey: "escalate-key",
    cwd: "/fake/project",
  })
  expect(seen.map((s) => [s.path, s.auth])).toEqual([
    ["/primary", "Bearer primary-key"],
    ["/escalate", "Bearer escalate-key"],
  ])
})

test("classify marks an unsure safe primary", async () => {
  const r = await classifyCommand("make fake", { api: "systemone", url: `${base}/unsure`, cwd: "/fake/project" })
  expect(r).toMatchObject({ verdict: "safe", uncertain: true })
})

test("hook: an unrelated request turns an unsure allow into ask", async () => {
  const dir = mkdtempSync(join(tmpdir(), "safe-yolo-hook-"))
  const transcript = join(dir, "t.jsonl")
  writeFileSync(
    transcript,
    [
      { type: "user", message: { content: "поправь опечатку в fake README" } },
      { type: "assistant", message: { content: [{ type: "text", text: "ok" }] } },
      { type: "user", message: { content: [{ type: "tool_result", content: "done" }] } },
    ]
      .map((e) => JSON.stringify(e))
      .join("\n"),
  )
  explainReply = { kind: "unclear", condition: "", intent: "unrelated" }
  // async spawn: a sync one would block the fake server in this process
  const run = async (env: Record<string, string>) => {
    const p = Bun.spawn(["bun", "src/guard-entry.ts"], {
      cwd: join(import.meta.dir, ".."),
      env: { ...process.env, ...env, SAFE_YOLO_POLICY_FILE: "/fake/none.md", SAFE_YOLO_DEBUG: "" },
      stdin: Buffer.from(
        JSON.stringify({ tool_name: "Bash", tool_input: { command: "make fake" }, cwd: "/fake/project", transcript_path: transcript }),
      ),
    })
    return JSON.parse(await new Response(p.stdout).text()).hookSpecificOutput
  }
  const env = { SAFE_YOLO_URL: `${base}/unsure`, SAFE_YOLO_ESCALATE_URL: `${base}/safe-escalate` }
  const out = await run(env)
  expect(out.permissionDecision).toBe("ask")
  expect(out.permissionDecisionReason).toContain('❌ Ты просил: "поправь опечатку в fake README" - связи не видно')
  expect(out.permissionDecisionReason).toContain("Почему: не видно связи с твоей просьбой")
  explainReply = { kind: "unclear", condition: "", intent: "match" }
  expect((await run(env)).permissionDecision).toBe("allow")
}, 20000)
