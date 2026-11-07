import { test, expect } from "bun:test"
import { execFileSync } from "node:child_process"
import { mkdirSync, mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { decide, hardRule } from "../src/core"

/** A git repo under the OS temp dir; tests pass tempDirs: [] so its location does not allow everything. */
function repo(sub = ""): string {
  const dir = mkdtempSync(join(tmpdir(), "safe-yolo-repo-"))
  execFileSync("git", ["init", "-q", dir])
  if (sub) mkdirSync(join(dir, sub), { recursive: true })
  return join(dir, sub)
}
const noTemp = { tempDirs: [] }

test("rm -rf: literal variable from the same command is resolved", () => {
  for (const c of [
    'S=/tmp/fake; rm -rf "$S"',
    'cd ~ && S=/private/tmp/fake/ship; rm -rf "$S"',
    "S=/tmp/fake; rm -rf ${S}/x",
    'S=/tmp/fake; rm -rf "${S:?}"/x "${S?}/y"',
    "export S=/tmp/fake; rm -rf $S/x",
    `S='/tmp/fake'; rm -rf "$S"`,
    'S=/tmp/fake; S=/tmp/fake; rm -rf "$S"',
  ]) {
    expect(hardRule(c, "/fake/p")).toBeUndefined()
  }
  expect(hardRule("S=build; rm -rf $S", repo(), noTemp)).toBeUndefined()
})

test("rm -rf: a variable that cannot be proven still asks", () => {
  for (const c of [
    'S=/outside/conf; rm -rf "$S"',
    'S=/tmp/../outside/conf; rm -rf "$S"',
    'S=$(pwd); rm -rf "$S"',
    'S=/tmp/a; S=$(echo a b); rm -rf "$S"',
    'S=/tmp/a; S=/outside/conf; rm -rf "$S"',
    'S=/tmp/a; S+=/../../outside; rm -rf "$S"',
    'rm -rf "$S"; S=/tmp/a',
    'for S in /outside/a; do rm -rf "$S"; done',
    'S=/tmp/a; for S in /outside/a; do rm -rf "$S"; done',
    'S=/tmp/a; read S; rm -rf "$S"',
    "S=/tmp/a; ssh h 'rm -rf $S'",
    'rm -rf "$UNSET"',
  ]) {
    expect(hardRule(c, "/fake/p")).toContain("rm -rf")
  }
})

test("rm -rf: env-prefix assignment is expanded after the line, so only an earlier equal one counts", () => {
  expect(hardRule('S=/tmp/a rm -rf "$S"', "/fake/p")).toContain("rm -rf")
  expect(hardRule('S=/tmp/a; S=/outside rm -rf "$S"', "/fake/p")).toContain("rm -rf")
  expect(hardRule('S=/tmp/a; S=/tmp/a rm -rf "$S"', "/fake/p")).toBeUndefined()
})

test("rm -rf: a mktemp -d variable is a temp dir", () => {
  for (const c of [
    'd=$(mktemp -d) && rm -rf "$d"',
    'd="$(mktemp -d -t fake)"; rm -rf $d/x',
    "d=$(mktemp -dt fake); rm -rf $d",
    'd=$(mktemp -d /tmp/fake.XXXX)\nrm -rf "$d"',
  ]) {
    expect(hardRule(c, "/fake/p")).toBeUndefined()
  }
  for (const c of [
    'd=$(mktemp -d fake.XXXX); rm -rf "$d"',
    'd=$(mktemp); rm -rf "$d"',
    'd=$(mktemp -d); rm -rf "$d/../.."',
    'd=$(mktemp -d); d=/outside; rm -rf "$d"',
  ]) {
    expect(hardRule(c, "/fake/p")).toContain("rm -rf")
  }
})

test("rm -rf: the project is the git root of cwd", () => {
  const cwd = repo("pkg/sub")
  const root = join(cwd, "../..")
  expect(hardRule("rm -rf build", cwd, noTemp)).toBeUndefined()
  expect(hardRule("rm -rf ../../dist", cwd, noTemp)).toBeUndefined()
  expect(hardRule(`rm -rf ${root}`, cwd, noTemp)).toContain("rm -rf")
  expect(hardRule("rm -rf ../../../x", cwd, noTemp)).toContain("rm -rf")
})

test("rm -rf: no repo, home or an ancestor of home is no project", () => {
  expect(hardRule("rm -rf build", "/fake/project", noTemp)).toContain("rm -rf")
  expect(hardRule("rm -rf fake-sub", "/fake/home/.config", { home: "/fake/home", tempDirs: [] })).toContain("rm -rf")
  const parent = repo()
  expect(hardRule("rm -rf build", parent, { home: join(parent, "fake-home"), tempDirs: [] })).toContain("rm -rf")
  expect(hardRule("rm -rf build", parent, { home: parent, tempDirs: [] })).toContain("rm -rf")
})

test("rm -rf: claude temp dirs of any session are allowed", () => {
  expect(hardRule("rm -rf /private/tmp/claude-501/fake-other-session/scratchpad", "/fake/project")).toBeUndefined()
  expect(hardRule("rm -rf /tmp/claude-501/fake-session", "/fake/project")).toBeUndefined()
})

test("rm -rf: home resolves, but home itself is not a project", () => {
  const home = mkdtempSync(join(tmpdir(), "safe-yolo-home-"))
  execFileSync("git", ["init", "-q", join(home, "fake-proj")])
  const opts = { home, tempDirs: [] }
  expect(hardRule("rm -rf ~/fake-proj/dist", `${home}/fake-proj`, opts)).toBeUndefined()
  expect(hardRule("rm -rf $HOME/fake-proj/dist", `${home}/fake-proj`, opts)).toBeUndefined()
  expect(hardRule("rm -rf ~", `${home}/fake-proj`, opts)).toContain("rm -rf")
  expect(hardRule("rm -rf ~/fake-dir", home, opts)).toContain("rm -rf")
  expect(hardRule("ssh h 'rm -rf ~/fake-proj/dist'", `${home}/fake-proj`, opts)).toContain("rm -rf")
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
