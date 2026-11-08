import { test, expect } from "bun:test"
import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync, symlinkSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { askMessage, formatAsk, hardRule, renderedLines } from "../src/core"

const noTemp = { home: "/fake/home", tempDirs: [] }
const dead = { api: "systemone" as const, url: "http://127.0.0.1:9/x" }
const model = { reason: "model confidence 87%", via: "primary" as const }

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), "safe-yolo-card-"))
  execFileSync("git", ["init", "-q", dir])
  return dir
}

test("rm through a path, a backslash, command or sudo still counts", () => {
  for (const c of ["\\rm -rf ../x", "/bin/rm -rf ../x", "/usr/bin/rm -rf ../x", "command rm -rf ../x", "sudo rm -rf ../x"]) {
    expect(hardRule(c, "/fake/project", noTemp)).toContain("rm -rf")
  }
})

test("a symlink to the repo root keeps working, a symlink into a subdir does not widen it", () => {
  const base = repo()
  mkdirSync(join(base, "sub"))
  const links = mkdtempSync(join(tmpdir(), "safe-yolo-links-"))
  symlinkSync(base, join(links, "root"))
  symlinkSync(join(base, "sub"), join(links, "sub"))
  expect(hardRule("rm -rf build", join(links, "root"), noTemp)).toBeUndefined()
  expect(hardRule(`rm -rf ${join(links, "root/build")}`, join(links, "root"), noTemp)).toBeUndefined()
  expect(hardRule("rm -rf ../x", join(links, "sub"), noTemp)).toBeUndefined() // ../x is base/x, inside the repo
  expect(hardRule("rm -rf ../../x", join(links, "sub"), noTemp)).toContain("rm -rf")
  expect(hardRule(`rm -rf ${join(links, "other")}`, join(links, "sub"), noTemp)).toContain("rm -rf")
})

test("C1 and bidi controls are stripped from agent text", () => {
  const text = formatAsk({ command: "fake-tool x", result: model, why: "a\u0085b\u202eevil\u2066c\u200fd" })
  expect(text.split("\n").at(-1)).toBe('Агент пишет: "a b evil c d"')
})

test("wide chars count as two columns", () => {
  expect(renderedLines("全".repeat(32))).toBe(1)
  expect(renderedLines("全".repeat(33))).toBe(2)
})

test("banned words, variants and mixed-script homoglyphs drop the LLM condition", () => {
  for (const condition of ["это бeзопасно", "ничего страшного", "смело жми да", "разрешай", "the command is safe", "go ahead", "it is harmless", "sаfe"]) {
    const text = formatAsk({ command: "chmod 777 /fake/x", result: model, explanation: { kind: "system", condition, reason: "", intent: "unknown" } })
    expect(text).toContain("Проверь: ты сам просил это менять")
  }
})

test("any input fits 8 rows", () => {
  const long = "Ж".repeat(300)
  const text = formatAsk({
    command: `curl -X DELETE https://${"a".repeat(200)}.example.test/x`,
    result: model,
    why: "全".repeat(200),
    request: long,
    explanation: { kind: "delete", condition: "x".repeat(50), reason: "", intent: "unrelated" },
    facts: long,
    repo: long,
  })
  expect(renderedLines(text)).toBeLessThanOrEqual(8)
  const rule = formatAsk({ command: `rm -rf $${"A".repeat(300)}`, result: { reason: `hard rule: rm -rf outside the project: $${"A".repeat(300)}`, via: "rule" }, why: long, request: long, repo: long, facts: long, explanation: { kind: "delete", condition: "", reason: "", intent: "match" } })
  expect(renderedLines(rule)).toBeLessThanOrEqual(8)
})

test("repo line: credentials stripped, --git-dir bare repo, leading cd, no remote", async () => {
  const work = repo()
  execFileSync("git", ["-C", work, "remote", "add", "origin", "https://fake-user:fake-pass@git.fakehost.example.test/owner/repo.git"])
  const card = await askMessage("git push origin main", { verdict: "unsafe", reason: "hard rule: git push", via: "rule" }, { ...dead, cwd: work })
  expect(card).toContain("Репо: owner/repo (git.fakehost)")
  expect(card).not.toContain("fake-pass")

  const bare = join(mkdtempSync(join(tmpdir(), "safe-yolo-bare-")), "agents.git")
  execFileSync("git", ["init", "-q", "--bare", bare])
  const bareCard = await askMessage(`git --git-dir=${bare} push`, { verdict: "unsafe", reason: "hard rule: git push", via: "rule" }, { ...dead, cwd: "/fake/project" })
  expect(bareCard).toContain("Репо: agents")

  const plain = repo()
  const cdCard = await askMessage(`cd ${plain} && git stash drop`, { verdict: "unsafe", ...model }, { ...dead, cwd: "/fake/project" }, undefined, {
    explanation: { kind: "unclear", condition: "", reason: "", intent: "unknown" },
  })
  expect(cdCard).toContain(`Репо: ${plain.split("/").at(-1)}`)
  expect(cdCard).not.toContain("Где:")

  const none = await askMessage("fake-tool x", { verdict: "unsafe", ...model }, { ...dead, cwd: "/fake/project" })
  expect(none).not.toContain("Репо:")
})

test("agent words: translated into the card language only when needed and clean", async () => {
  const e = (agentWords: string): { kind: "unclear"; condition: string; reason: string; intent: "unknown"; agentWords: string } => ({
    kind: "unclear",
    condition: "",
    reason: "",
    intent: "unknown",
    agentWords,
  })
  const card = (why: string, agentWords: string, language: "ru" | "en" = "ru") =>
    formatAsk({ command: "fake-tool x", result: model, why, explanation: e(agentWords), language }).split("\n").at(-1)
  expect(card("Free disk space by removing old builds", "освобождаю место, удаляю старые сборки")).toBe(
    'Агент пишет: "освобождаю место, удаляю старые сборки"',
  )
  expect(card("чищу старые сборки", "cleaning old builds")).toBe('Агент пишет: "чищу старые сборки"')
  expect(card("Remove old builds", "удаляю, это безопасно")).toBe('Агент пишет: "Remove old builds"')
  expect(card("чищу старые сборки", "cleaning old builds", "en")).toBe('Agent says: "cleaning old builds"')
  const none = await askMessage("fake-tool x", { verdict: "unsafe", ...model }, { ...dead, cwd: "/fake/project" }, "Remove old builds")
  expect(none.split("\n").at(-1)).toBe('Агент пишет: "Remove old builds"')
})
