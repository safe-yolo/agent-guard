import { test, expect } from "bun:test"
import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { classifyCommand, hardRule, BUILTIN_POLICY } from "../src/core"

test("hardRule: git push in any form", () => {
  for (const c of ["git push", "rtk git push origin main", "git -C /x push", "ls && git --no-pager push -f", "ssh h 'git push'"]) {
    expect(hardRule(c, "/p")).toContain("push")
  }
  for (const c of ["git stash push", "git status", "git log --grep=pushed"]) expect(hardRule(c, "/p")).toBeUndefined()
})

test("hardRule: downloaded code piped into a shell", () => {
  for (const c of ["curl -s x | sh", "wget -qO- x | sudo bash", "curl x | tee y | zsh", 'bash -c "$(curl x)"', "sh <(curl x)"]) {
    expect(hardRule(c, "/p")).toContain("downloaded")
  }
  for (const c of ["curl x | python3 -c 'print(1)'", "curl x | tail -1 && sh run.sh", "curl x || sh fallback.sh", "curl -o y x"]) {
    expect(hardRule(c, "/p")).toBeUndefined()
  }
})

test("hardRule: rm -rf outside the project", () => {
  for (const c of [
    "rm -rf /outside/conf",
    "rm -rf ~/fake-dir",
    "rm -fr ../other",
    "rm -r -f $DIR/x",
    "rm --recursive --force /outside/app",
    "rm -rf .",
    "cd /outside/conf && rm -rf x",
    "ssh h 'rm -rf x'",
    "find . | xargs rm -rf",
    "rm -rf ok /outside/conf",
  ]) {
    expect(hardRule(c, "/p")).toContain("rm -rf")
  }
  for (const c of ["rm -rf /tmp/x", "rm -rf /private/tmp/x 2>/dev/null", "rm -f /outside/conf/x", "rm x"]) {
    expect(hardRule(c, "/p")).toBeUndefined()
  }
  const repo = mkdtempSync(join(tmpdir(), "safe-yolo-repo-"))
  execFileSync("git", ["init", "-q", repo])
  for (const c of ["rm -rf dist", "rm -rf ./node_modules dist/*", `rm -rf ${repo}/build`]) {
    expect(hardRule(c, repo, { tempDirs: [] })).toBeUndefined()
  }
})

function fakeModels(primaryAnswer: object, escalateContent: string) {
  const calls: { path: string; body: any }[] = []
  const server = Bun.serve({
    port: 0,
    fetch: async (req) => {
      const path = new URL(req.url).pathname
      calls.push({ path, body: await req.json() })
      if (path === "/primary") return Response.json({ answers: { verdict: primaryAnswer } })
      return Response.json({ choices: [{ message: { content: escalateContent } }] })
    },
  })
  const cfg = {
    api: "systemone" as const,
    url: `${server.url.href}primary`,
    escalateUrl: `${server.url.href}escalate`,
    escalateModel: "m",
    policy: "my policy",
    cwd: "/p",
  }
  return { server, calls, cfg }
}

const confidentUnsafe = { choice: "unsafe", answer_confidence: 0.9 }

test("cascade: escalation overrides confident unsafe and sees the policy", async () => {
  const { server, calls, cfg } = fakeModels(confidentUnsafe, JSON.stringify({ verdict: "safe", reason: "reads only" }))
  try {
    const r = await classifyCommand("ls /outside/conf", cfg)
    expect(r).toMatchObject({ verdict: "safe", via: "escalate", reason: "reads only" })
    const body = calls.find((c) => c.path === "/escalate")!.body
    expect(body.max_tokens).toBeGreaterThan(200)
    expect(body.messages[0].content).toContain("my policy")
    expect(body.messages[0].content).toContain(BUILTIN_POLICY)
  } finally {
    server.stop(true)
  }
})

test("cascade: truncated escalation keeps unsafe and lands in the debug log", async () => {
  const log = join(mkdtempSync(join(tmpdir(), "safe-yolo-")), "debug.jsonl")
  process.env.SAFE_YOLO_DEBUG = log
  const { server, cfg } = fakeModels(confidentUnsafe, '{"verdict":"safe","reason":"cut of')
  try {
    expect(await classifyCommand("ls /outside/conf", cfg)).toMatchObject({ verdict: "unsafe", via: "primary" })
    const entry = JSON.parse(readFileSync(log, "utf8").trim())
    expect(entry.command).toBe("ls /outside/conf")
    expect(entry.result.verdict).toBe("unsafe")
    expect(entry.failed.escalate).toContain("unexpected response")
  } finally {
    delete process.env.SAFE_YOLO_DEBUG
    server.stop(true)
  }
})

test("debug log rotates past 5 MB and keeps one old file", async () => {
  const log = join(mkdtempSync(join(tmpdir(), "safe-yolo-")), "debug.jsonl")
  const big = "x".repeat(5 * 1024 * 1024 + 1)
  writeFileSync(log, big)
  writeFileSync(`${log}.1`, "older")
  process.env.SAFE_YOLO_DEBUG = log
  try {
    await classifyCommand("rm -rf /outside/conf", { cwd: "/p" })
    await classifyCommand("rm -rf /outside/app", { cwd: "/p" })
    expect(readFileSync(`${log}.1`, "utf8")).toBe(big)
    const lines = readFileSync(log, "utf8").trim().split("\n")
    expect(lines.map((l) => JSON.parse(l).command)).toEqual(["rm -rf /outside/conf", "rm -rf /outside/app"])
  } finally {
    delete process.env.SAFE_YOLO_DEBUG
  }
})

test("cascade: hard rule wins without asking any model", async () => {
  const { server, calls, cfg } = fakeModels({ choice: "safe", answer_confidence: 0.99 }, "{}")
  try {
    expect(await classifyCommand("git push", cfg)).toMatchObject({ verdict: "unsafe", via: "rule" })
    expect(calls).toHaveLength(0)
  } finally {
    server.stop(true)
  }
})

test("builtin policy tells the model that reading is safe", () => {
  expect(BUILTIN_POLICY).toContain("read-only inspection")
})
