// QA findings, fixed: kept as regression tests
import { test, expect } from "bun:test"
import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync, symlinkSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { formatAsk, hardRule, renderedLines } from "../src/core"

// tmpdir is a temp dir for the rule, so the rule gets no temp dirs here
const opts = { home: "/fake/home", tempDirs: [] }

test("symlinked cwd into a repo subdir does not widen the project", () => {
  const base = mkdtempSync(join(tmpdir(), "safe-yolo-qa-"))
  mkdirSync(join(base, "repo/sub"), { recursive: true })
  execFileSync("git", ["init", "-q", join(base, "repo")])
  mkdirSync(join(base, "a/b"), { recursive: true })
  symlinkSync(join(base, "repo/sub"), join(base, "a/b/link"))
  // show-cdup is "../", resolved lexically from the link it gives base/a/b as the project
  expect(hardRule(`rm -rf ${join(base, "a/b/other")}`, join(base, "a/b/link"), opts)).toBeDefined()
})

test("card stays within 8 rows for a long variable name or host", () => {
  const v = "A".repeat(300)
  const del = formatAsk({ command: `rm -rf $${v}`, result: { reason: `hard rule: rm -rf outside the project: $${v}`, via: "rule" }, cwd: "/fake" })
  const host = formatAsk({
    command: `curl https://${"a".repeat(200)}.example.invalid/x -o y`,
    result: { reason: "odd", via: "primary" },
    cwd: "/fake",
    explanation: { kind: "network", condition: "", reason: "", intent: "unknown" },
  })
  expect(renderedLines(del)).toBeLessThanOrEqual(8)
  expect(renderedLines(host)).toBeLessThanOrEqual(8)
})
