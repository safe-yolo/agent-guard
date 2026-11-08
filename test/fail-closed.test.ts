import { test, expect, afterAll } from "bun:test"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { classifyCommand, decide, formatAsk, renderedLines } from "../src/core"

const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const path = new URL(req.url).pathname
    if (path === "/bad-gateway") return new Response("<html>bad gateway</html>", { status: 502 })
    if (path === "/garbage") return new Response("not json")
    if (path === "/unsafe") return Response.json({ answers: { verdict: { choice: "unsafe", answer_confidence: 0.6 } } })
    return Response.json({ answers: { verdict: { choice: "safe", answer_confidence: 0.99 } } })
  },
})
afterAll(() => server.stop())
const base = `http://127.0.0.1:${server.port}`
const dead = "http://127.0.0.1:9/v1/systemone"
const cfg = (url: string, extra = {}) => ({ api: "systemone" as const, url, cwd: "/fake/project", timeoutMs: 2000, ...extra })

test("primary down: refused, bad gateway and garbage fail closed", async () => {
  expect(await classifyCommand("make fake", cfg(dead))).toMatchObject({
    verdict: "unsafe",
    via: "down",
    down: { cause: "refused", host: "127.0.0.1:9" },
  })
  expect((await classifyCommand("make fake", cfg(`${base}/bad-gateway`)))?.down).toMatchObject({ cause: "http", status: 502 })
  expect((await classifyCommand("make fake", cfg(`${base}/garbage`)))?.down?.cause).toBe("shape")
  // the escalation is never asked alone
  expect(await classifyCommand("make fake", cfg(dead, { escalateUrl: `${base}/escalate` }))).toMatchObject({ via: "down" })
})

test("escalation down keeps the primary verdict", async () => {
  expect(await classifyCommand("make fake", cfg(`${base}/unsafe`, { escalateUrl: dead }))).toMatchObject({ verdict: "unsafe", via: "primary" })
})

test("plugin denies on a down primary in enforce mode, shadow stays shadow", () => {
  expect(decide("enforce", "allow", "unsafe", "primary classifier down: refused", "down").effect).toBe("deny")
  expect(decide("shadow", "allow", "unsafe", "primary classifier down: refused", "down").effect).toBe("allow")
})

test("disputed card names the dispute and keeps the primary reason", () => {
  const text = formatAsk({ command: "fake-tool x", result: { reason: "model confidence 87%", via: "primary", disputed: true } })
  expect(text.split("\n").slice(0, 3)).toEqual([
    "🔍 СПОРНО · локальная модель против, облачная не видит угрозы",
    "Почему: уверенность 87%",
    "Проверь: команду выше целиком",
  ])
  const en = formatAsk({ command: "x", result: { reason: "model confidence 87%", via: "primary", disputed: true }, language: "en" })
  expect(en.split("\n")[0]).toBe("🔍 DISPUTED · the local model objects, the cloud model sees no threat")
  expect(renderedLines(text)).toBeLessThanOrEqual(8)
})

function hook(command: string, env: Record<string, string>) {
  const p = Bun.spawnSync(["bun", "src/guard-entry.ts"], {
    cwd: join(import.meta.dir, ".."),
    env: { ...process.env, SAFE_YOLO_POLICY_FILE: "/fake/none.md", SAFE_YOLO_DEBUG: "", SAFE_YOLO_URL: dead, ...env },
    stdin: Buffer.from(JSON.stringify({ tool_name: "Bash", tool_input: { command }, cwd: "/fake/project" })),
  })
  return String(p.stdout)
}

test("hook: a dead primary stops the session with the reason and the off switch", () => {
  const off = join(mkdtempSync(join(tmpdir(), "safe-yolo-off-")), "off")
  const out = JSON.parse(hook("make fake", { SAFE_YOLO_OFF_FILE: off }))
  expect(out.continue).toBe(false)
  expect(out.hookSpecificOutput.permissionDecision).toBe("deny")
  expect(out.hookSpecificOutput.permissionDecisionReason).toBe(out.stopReason)
  expect(out.stopReason).toContain("⛔ safe-yolo: классификатор недоступен, работа остановлена")
  expect(out.stopReason).toContain("соединение отклонено 127.0.0.1:9")
  expect(out.stopReason).toContain(`touch ${off}`)
})

test("hook: with the off file only hard rules run", () => {
  const off = join(mkdtempSync(join(tmpdir(), "safe-yolo-off-")), "off")
  writeFileSync(off, "")
  expect(hook("make fake", { SAFE_YOLO_OFF_FILE: off })).toBe("")
  const rule = JSON.parse(hook("git push", { SAFE_YOLO_OFF_FILE: off }))
  expect(rule.hookSpecificOutput.permissionDecision).toBe("ask")
  expect(rule.continue).toBeUndefined()
})
