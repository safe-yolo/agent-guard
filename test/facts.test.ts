import { test, expect } from "bun:test"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { bareRemote, lastUserMessage } from "../src/facts"

test("last user message skips tool results, wrappers and meta entries", () => {
  const file = join(mkdtempSync(join(tmpdir(), "safe-yolo-transcript-")), "t.jsonl")
  const lines = [
    { type: "user", message: { content: "x".repeat(400) } },
    { type: "user", message: { content: [{ type: "text", text: "почисти старые сборки" }] } },
    { type: "assistant", message: { content: [{ type: "text", text: "ok" }] } },
    { type: "user", message: { content: "<command-name>/fake</command-name>" } },
    { type: "user", isMeta: true, message: { content: "meta" } },
    { type: "user", message: { content: [{ type: "tool_result", content: "done" }] } },
  ]
  writeFileSync(file, lines.map((l) => JSON.stringify(l)).join("\n") + "\nnot json")
  expect(lastUserMessage(file)).toBe("почисти старые сборки")
  // the tail starts mid-line: the cut line is dropped, the rest still parses
  const tail = Buffer.byteLength("\n" + lines.slice(2).map((l) => JSON.stringify(l)).join("\n") + "\nnot json") + 5
  expect(lastUserMessage(file, tail)).toBeUndefined()
  expect(lastUserMessage("/fake/missing.jsonl")).toBeUndefined()
})

test("remote without scheme and credentials", () => {
  expect(bareRemote("https://fake-user:fake-token@git.example.test/a/b.git")).toBe("git.example.test/a/b.git")
  expect(bareRemote("git@git.example.test:a/b.git")).toBe("git.example.test:a/b.git")
})
