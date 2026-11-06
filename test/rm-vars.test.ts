import { test, expect } from "bun:test"
import { homedir } from "node:os"
import { decide, hardRule } from "../src/core"

test("rm -rf: literal variable from the same command is resolved", () => {
  for (const c of [
    'S=/tmp/fake; rm -rf "$S"',
    'cd ~ && S=/private/tmp/fake/ship; rm -rf "$S"',
    "S=/tmp/fake; rm -rf ${S}/x",
    "export S=/tmp/fake; rm -rf $S/x",
    `S='/tmp/fake'; rm -rf "$S"`,
    'S=/tmp/fake; S=/tmp/fake; rm -rf "$S"',
    "S=build; rm -rf $S",
  ]) {
    expect(hardRule(c, "/p")).toBeUndefined()
  }
})

test("rm -rf: a variable that cannot be proven still asks", () => {
  for (const c of [
    'S=/outside/conf; rm -rf "$S"',
    'S=/tmp/../outside/conf; rm -rf "$S"',
    'S=$(pwd); rm -rf "$S"',
    'S=/tmp/a; S=$(echo a b); rm -rf "$S"',
    'S=/tmp/a; S=/outside/conf; rm -rf "$S"',
    'S=/tmp/a; S+=/../../outside; rm -rf "$S"',
    'S=/tmp/a rm -rf "$S"',
    'rm -rf "$S"; S=/tmp/a',
    'for S in /outside/a; do rm -rf "$S"; done',
    'S=/tmp/a; for S in /outside/a; do rm -rf "$S"; done',
    'S=/tmp/a; read S; rm -rf "$S"',
    "S=/tmp/a; ssh h 'rm -rf $S'",
    'rm -rf "$UNSET"',
  ]) {
    expect(hardRule(c, "/p")).toContain("rm -rf")
  }
})

test("rm -rf: home resolves, but home itself is not a project", () => {
  const home = homedir()
  expect(hardRule("rm -rf ~/fake-proj/dist", `${home}/fake-proj`)).toBeUndefined()
  expect(hardRule("rm -rf $HOME/fake-proj/dist", `${home}/fake-proj`)).toBeUndefined()
  expect(hardRule("rm -rf ~", `${home}/fake-proj`)).toContain("rm -rf")
  expect(hardRule("rm -rf ~/fake-dir", home)).toContain("rm -rf")
  expect(hardRule("ssh h 'rm -rf ~/fake-proj/dist'", `${home}/fake-proj`)).toContain("rm -rf")
})

test("hard rule denies in any mode, so auto approval cannot pass it", () => {
  const denied = { effect: "deny", message: "safe-yolo: hard rule: x" }
  for (const mode of ["shadow", "enforce"] as const) {
    for (const effect of ["allow", "ask", "deny"] as const) {
      expect(decide(mode, effect, "unsafe", "hard rule: x", "rule")).toEqual(denied)
    }
  }
  expect(decide("shadow", "allow", "unsafe", "model", "escalate")).toEqual({ effect: "allow" })
})
