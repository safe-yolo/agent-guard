import { test, expect } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// the plugin logs under $HOME, so it runs in a child process with a fake home
const script = `
import plugin from ${JSON.stringify(join(import.meta.dir, "../src/index.ts"))}
const server = Bun.serve({ port: 0, fetch: () => Response.json({ answers: { verdict: { choice: "unsafe", answer_confidence: 0.95 } } }) })
let evaluate
const ctx = {
  options: { mode: "enforce", api: "systemone", url: server.url.href + "primary", policyFile: "/fake/none.md", secretsFile: "/fake/none.txt" },
  directory: "/fake/project",
  permission: { hook: async (_name, fn) => { evaluate = fn } },
}
await plugin.setup(ctx)
const event = { action: "bash", resources: ["fake-tool --wipe"], effect: "ask" }
await evaluate(event)
server.stop(true)
console.log(JSON.stringify(event))
`

function run(env: Record<string, string>) {
  const home = mkdtempSync(join(tmpdir(), "safe-yolo-home-"))
  mkdirSync(join(home, ".local/share/opencode"), { recursive: true })
  const file = join(home, "run.ts")
  writeFileSync(file, script)
  const p = Bun.spawnSync(["bun", file], { env: { ...process.env, HOME: home, SAFE_YOLO_OFF_FILE: "/fake/none", SAFE_YOLO_DEBUG: "", ...env } })
  return { event: JSON.parse(String(p.stdout).trim().split("\n").at(-1)!), home }
}

test("plugin: an ask from the user's own rules keeps the effect and gets the card", () => {
  const { event, home } = run({})
  expect(event.effect).toBe("ask")
  expect(event.message.split("\n")[0]).toBe("🔍 НЕПОНЯТНО · команда под вопросом")
  expect(existsSync(join(home, ".local/share/opencode/safe-yolo-train.jsonl"))).toBe(false)
})

test("plugin: the training log is written only with SAFE_YOLO_DEBUG", () => {
  const debug = join(mkdtempSync(join(tmpdir(), "safe-yolo-dbg-")), "debug.jsonl")
  const { home } = run({ SAFE_YOLO_DEBUG: debug })
  expect(existsSync(join(home, ".local/share/opencode/safe-yolo-train.jsonl"))).toBe(true)
})
