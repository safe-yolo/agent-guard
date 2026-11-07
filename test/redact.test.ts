import { test, expect, afterAll } from "bun:test"
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { classifyCommand, curlRequest, explainCommand, loadSecretPatterns, parseSecretPatterns, redact } from "../src/core"

// fake values are built at run time, so no secret-looking literal sits in the repo
const fake = (n: number) => Array.from({ length: n }, (_, i) => "aZ3q"[i % 4]).join("")
const upper = (n: number) => Array.from({ length: n }, (_, i) => "Q7"[i % 2]).join("")

test("known token formats", () => {
  const cases: [string, string][] = [
    ["npm_" + fake(36), "npm"],
    ["ghp_" + fake(36), "github"],
    ["gho_" + fake(36), "github"],
    ["github_pat_" + fake(30), "github"],
    ["glpat-" + fake(20), "gitlab"],
    ["sk-ant-api03-" + fake(30), "sk"],
    ["sk-" + fake(24), "sk"],
    ["xoxb-" + fake(12), "slack"],
    ["AKIA" + upper(16), "aws"],
    [`eyJ${fake(10)}.eyJ${fake(10)}.${fake(10)}`, "jwt"],
  ]
  for (const [value, label] of cases) {
    const r = redact(`fake-tool --flag x ${value} end`)
    expect(r.text).toBe(`fake-tool --flag x <секрет:${label}> end`)
    expect(r.hits).toEqual([label])
  }
  const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${fake(20)}\n-----END OPENSSH PRIVATE KEY-----`
  expect(redact(`echo '${pem}' > k`).text).toBe("echo '<секрет:приватный ключ>' > k")
  expect(redact("x " + "ghp_" + fake(36), [], "en").text).toBe("x <secret:github>")
})

test("values next to markers keep the syntax around them", () => {
  const v = "fakeval" + fake(5)
  const cases: [string, string][] = [
    [`curl -H "Authorization: Bearer ${v}" https://api.example.test`, `curl -H "Authorization: Bearer <секрет:authorization>" https://api.example.test`],
    [`curl -H 'PRIVATE-TOKEN: ${v}' x`, `curl -H 'PRIVATE-TOKEN: <секрет:private-token>' x`],
    [`curl -H "X-Api-Key: ${v}" x`, `curl -H "X-Api-Key: <секрет:x-api-key>" x`],
    [`mysql password=${v} db`, `mysql password=<секрет:password> db`],
    [`FAKE_TOKEN=${v} make`, `FAKE_TOKEN=<секрет:FAKE_TOKEN> make`],
    [`export DB_PASSWORD="${v}"`, `export DB_PASSWORD="<секрет:DB_PASSWORD>"`],
    [`fake-cli --api-key ${v} run`, `fake-cli --api-key <секрет:--api-key> run`],
    [`fake-cli --token=${v}`, `fake-cli --token=<секрет:--token>`],
    [`echo //registry.example.test/:_authToken=${v} >> .npmrc`, `echo //registry.example.test/:_authToken=<секрет:_authToken> >> .npmrc`],
    [`git clone https://fake-user:${v}@git.example.test/a.git`, `git clone https://fake-user:<секрет:url>@git.example.test/a.git`],
    [`echo ${fake(40)}`, "echo <секрет:длинная строка>"],
  ]
  for (const [input, want] of cases) expect(redact(input).text).toBe(want)
})

test("references, names, paths and short hashes are left alone", () => {
  for (const c of [
    "git log --oneline -20",
    "ls /private/tmp/claude-501/-Volumes-fake-repo/02fc44fd-44c2-4098-a2d4-0cd177e2c229/scratchpad",
    "cat src/components/fake-component-name-with-digits-123/index.ts",
    "sha256sum file",
    'curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://git.example.test/api',
    'curl -H "Authorization: Bearer ${FAKE_TOKEN}" x',
    "NPM_TOKEN=$(secrets get npm_token) npm whoami",
    "export FAKE_KEY=$(~/scripts/secrets get fake_key)",
    "echo $GITLAB_TOKEN",
    "SSH_KEY=~/.ssh/id_fake ssh h",
    "sort_key=name fake-tool",
    "git clone https://fake-user:$PASS@git.example.test/a.git",
  ]) {
    expect(redact(c)).toEqual({ text: c, hits: [] })
  }
})

test("user patterns: prefixes, regex lines, invalid lines skipped", () => {
  const { patterns, invalid } = parseSecretPatterns("# my corp\n\nfk_\n/corp-[0-9]{6}/i\n/([/\n")
  expect(invalid).toEqual([5])
  const r = redact(`fake-tool fk_${fake(8)}.x CORP-123456 fk_`, patterns)
  expect(r.text).toBe("fake-tool <секрет:свой шаблон 3> <секрет:свой шаблон 4> fk_")
})

test("invalid regex line lands in the debug log by number", () => {
  const dir = mkdtempSync(join(tmpdir(), "safe-yolo-secrets-"))
  const file = join(dir, "secrets.txt")
  writeFileSync(file, "fk_\n/([/\n")
  process.env.SAFE_YOLO_DEBUG = join(dir, "debug.jsonl")
  try {
    expect(loadSecretPatterns(file)).toHaveLength(1)
    expect(JSON.parse(readFileSync(join(dir, "debug.jsonl"), "utf8")).invalidLines).toEqual([2])
  } finally {
    delete process.env.SAFE_YOLO_DEBUG
  }
  expect(loadSecretPatterns("/fake/missing.txt")).toEqual([])
})

test("curl: the key goes through a config on stdin, not argv", () => {
  const key = 'fake"key\\' + fake(4)
  const { args, stdin } = curlRequest("http://127.0.0.1:9/x", "{}", key, 4000)
  expect(args.join(" ")).not.toContain("fake")
  expect(args).toContain("-K")
  expect(stdin).toBe(`header = "Authorization: Bearer fake\\"key\\\\${fake(4)}"\n`)
  expect(curlRequest("http://127.0.0.1:9/x", "{}", undefined, 4000).stdin).toBe("")
})

const seen: { path: string; auth: string | null; raw: string }[] = []
const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const path = new URL(req.url).pathname
    const raw = await req.text()
    seen.push({ path, auth: req.headers.get("authorization"), raw })
    if (path === "/primary") return Response.json({ answers: { verdict: { choice: "unsafe", answer_confidence: 0.6 } } })
    const body = JSON.parse(raw)
    const content = body.messages[0].content.includes('"kind"')
      ? { kind: "network", condition: "", intent: "unknown" }
      : { verdict: "unsafe", reason: "sends a token" }
    return Response.json({ choices: [{ message: { content: JSON.stringify(content) } }] })
  },
})
afterAll(() => server.stop())
const base = `http://127.0.0.1:${server.port}`

test("escalation and explain get redacted text in zai shape, the key in a header", async () => {
  seen.length = 0
  const secret = "ghp_" + fake(36)
  const command = `curl -H "Authorization: Bearer ${secret}" https://api.example.test`
  const cfg = {
    api: "systemone" as const,
    url: `${base}/primary`,
    escalateUrl: `${base}/zai`,
    escalateApi: "zai" as const,
    escalateApiKey: "fake-escalate-key",
    cwd: "/fake/project",
  }
  expect(await classifyCommand(command, cfg)).toMatchObject({ verdict: "unsafe", via: "escalate" })
  expect(await explainCommand(command, "r", cfg, `sending ${secret}`, `use ${secret}`)).toMatchObject({ kind: "network" })
  const [primary, escalate, explain] = seen
  expect(primary.raw).toContain(secret) // the local primary keeps raw text
  for (const s of [escalate, explain]) {
    expect(s.raw).not.toContain(secret)
    expect(s.auth).toBe("Bearer fake-escalate-key")
    const body = JSON.parse(s.raw)
    expect(body.structured_outputs).toBeUndefined()
    expect(body.chat_template_kwargs).toBeUndefined()
    expect(body.response_format).toEqual({ type: "json_object" })
    expect(body.thinking).toEqual({ type: "disabled" })
  }
  expect(escalate.raw).toContain("<секрет:authorization>")
})

test("skip dirs: no escalation and no explain call", async () => {
  seen.length = 0
  const cfg = {
    api: "systemone" as const,
    url: `${base}/primary`,
    escalateUrl: `${base}/zai`,
    escalateApi: "zai" as const,
    escalateSkipDirs: ["/fake/corp"],
    cwd: "/fake/corp/repo",
  }
  expect(await classifyCommand("make fake", cfg)).toMatchObject({ via: "primary" })
  expect(await explainCommand("make fake", "r", cfg)).toBeUndefined()
  expect(seen.map((s) => s.path)).toEqual(["/primary"])
})

test("json bodies, query params, lowercase and glued words, login flags, cookies", () => {
  const v = "fakeval" + fake(9)
  const cases: [string, string][] = [
    [`curl -d '{"token":"${v}"}' x`, `curl -d '{"token":"<секрет:token>"}' x`],
    [`curl -d '{"Client_Secret": "${v}", "n": 1}' x`, `curl -d '{"Client_Secret": "<секрет:client_secret>", "n": 1}' x`],
    [`curl "https://api.example.test/x?token=${v}&page=2"`, `curl "https://api.example.test/x?token=<секрет:token>&page=2"`],
    [`curl "https://api.example.test/x?a=1&key=${v}"`, `curl "https://api.example.test/x?a=1&key=<секрет:key>"`],
    [`export token=${v}`, "export token=<секрет:token>"],
    [`api_key=${v} fake-tool`, "api_key=<секрет:api_key> fake-tool"],
    [`TOKEN=${v} fake-tool`, "TOKEN=<секрет:TOKEN> fake-tool"],
    [`true && KEY=${v}`, "true && KEY=<секрет:KEY>"],
    [`TOKEN='${v}'"${v}" fake-tool`, "TOKEN=<секрет:TOKEN> fake-tool"],
    [`curl -u fake-user:${v} x`, "curl -u fake-user:<секрет:password> x"],
    [`mysql -u root -p${v} db`, "mysql -u root -p<секрет:password> db"],
    [`mysql --password=${v} db`, "mysql --password=<секрет:--password> db"],
    [`docker login -p ${v} registry.example.test`, "docker login -p <секрет:password> registry.example.test"],
    [`docker login --password ${v} r`, "docker login --password <секрет:--password> r"],
    [`curl -H "Cookie: sid=${v}; theme=dark" x`, `curl -H "Cookie: <секрет:cookie>" x`],
    [`curl -H 'Set-Cookie: sid=${v}' x`, `curl -H 'Set-Cookie: <секрет:cookie>' x`],
    [`fake-cli --api-key "fake ${v}" run`, `fake-cli --api-key "<секрет:--api-key>" run`],
  ]
  for (const [input, want] of cases) expect(redact(input).text).toBe(want)
  for (const c of [
    'curl -d \'{"token":"$FAKE_TOKEN"}\' x',
    "curl https://api.example.test/x?token=short",
    "TOKEN=$FAKE_TOKEN fake-tool",
    'API_KEY="$(secrets get fake)" fake-tool',
    "mysql -p db",
    "mkdir -p /fake/dir && cp -p a b",
  ]) {
    expect(redact(c).hits).toEqual([])
  }
})
