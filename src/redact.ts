/** Secret redaction for text that leaves the machine (escalation and explain requests). Pure. */

export interface SecretPattern {
  re: RegExp
  /** line number in the secrets file */
  line: number
}

type Lang = "ru" | "en"

const WORDS = {
  ru: { secret: "секрет", key: "приватный ключ", long: "длинная строка", own: (n: number) => `свой шаблон ${n}` },
  en: { secret: "secret", key: "private key", long: "long string", own: (n: number) => `custom pattern ${n}` },
}

const B = String.raw`(?<![A-Za-z0-9_])` // token start: not inside a longer word

/** Known token formats: [label, regex]. Lengths are strict so names like npm_token stay. */
const FORMATS: [string, RegExp][] = [
  ["npm", new RegExp(B + String.raw`npm_[A-Za-z0-9]{36}`, "g")],
  ["github", new RegExp(B + String.raw`(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})`, "g")],
  ["gitlab", new RegExp(B + String.raw`glpat-[A-Za-z0-9_-]{20,}`, "g")],
  ["sk", new RegExp(B + String.raw`sk-[A-Za-z0-9_-]{20,}`, "g")],
  ["slack", new RegExp(B + String.raw`xox[abpr]-[A-Za-z0-9-]{10,}`, "g")],
  ["aws", new RegExp(B + String.raw`AKIA[0-9A-Z]{16}(?![0-9A-Z])`, "g")],
  ["jwt", new RegExp(B + String.raw`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, "g")],
]

/** A whole shell word: quoted and bare parts glued together, like TOKEN='abc'"def". */
const WORD = String.raw`((?:'[^'\n]*'|"[^"\n]*"|[^\s'";&|()<>])+)`
/** A header value inside an already quoted argument: stops at the closing quote. */
const BARE = String.raw`()([^\s"';&|)]+)`
const NAMES = "token|access_token|api_key|apikey|secret|password|passwd|client_secret"

/** Marker before a value: [label (undefined: the marker itself), marker source, value source, flags]. */
const MARKERS: [string | undefined, string, string, string][] = [
  ["authorization", String.raw`\b(authorization\s*:\s*(?:bearer\s+|basic\s+|token\s+)?)`, BARE, "gi"],
  ["private-token", String.raw`\b(private-token\s*:\s*)`, BARE, "gi"],
  ["x-api-key", String.raw`\b(x-api-key\s*:\s*)`, BARE, "gi"],
  ["bearer", String.raw`\b(bearer\s+)`, BARE, "gi"],
  ["password", String.raw`((?<![\w-])(?:-u|--user)(?:\s+|=)["']?[^\s:'"]+:)`, BARE, "g"], // curl -u user:pass
  ["password", String.raw`(\b(?:mysql|mysqldump|mariadb)\b[^;&|\n]*?\s-p)`, BARE, "g"], // -pPASS, glued
  ["password", String.raw`(\bdocker\s+login\b[^;&|\n]*?\s-p\s+)`, WORD, "g"],
  ["_authToken", String.raw`(:_authToken=)`, WORD, "g"],
  [undefined, String.raw`((?<![\w$-])--(?:api-key|token|password)(?:=|\s+))`, WORD, "g"],
  // case-sensitive: sort_key=name is not a secret, FAKE_KEY=x is
  [undefined, String.raw`((?<![\w$])(?:[A-Za-z_]\w*)?(?:TOKEN|KEY|SECRET|PASSWORD)\w*=)`, WORD, "g"],
  [undefined, String.raw`((?<![\w$?&])(?:[a-z_]*_)?(?:token|api_key|apikey|secret|password|passwd|pwd|access_key|secret_key)=)`, WORD, "g"],
]

/** References and paths are not values: $VAR, ${VAR}, $(secrets get x), ~/x, /x, ./x, a placeholder. */
function isReference(value: string): boolean {
  return /^[$~/.<]/.test(value.replace(/^['"]/, ""))
}

/** A long random-looking run; paths with a plain word segment (src/, node_modules/) are not one. */
function looksRandom(run: string): boolean {
  if (run.startsWith("/") || !/[A-Za-z]/.test(run) || !/[0-9]/.test(run)) return false
  return !(run.includes("/") && run.split("/").some((part) => /^[a-z][a-z._-]*$/.test(part)))
}

/** Parse a secrets file: `/regex/flags` lines or literal token prefixes; returns invalid line numbers too. */
export function parseSecretPatterns(text: string): { patterns: SecretPattern[]; invalid: number[] } {
  const patterns: SecretPattern[] = []
  const invalid: number[] = []
  text.split("\n").forEach((raw, i) => {
    const line = raw.trim()
    if (!line || line.startsWith("#")) return
    const rx = /^\/(.+)\/([a-z]*)$/.exec(line)
    try {
      const re = rx
        ? new RegExp(rx[1], rx[2].includes("g") ? rx[2] : rx[2] + "g")
        : new RegExp(line.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&") + "[A-Za-z0-9_./+=-]+", "g")
      patterns.push({ re, line: i + 1 })
    } catch {
      invalid.push(i + 1)
    }
  })
  return { patterns, invalid }
}

/**
 * Replace secret values with `<секрет:label>`, keeping the syntax around them so a model still sees
 * that a token is sent. hits lists the labels, never the values.
 */
export function redact(text: string, extra: SecretPattern[] = [], language: Lang = "ru"): { text: string; hits: string[] } {
  const W = WORDS[language]
  const hits: string[] = []
  const mark = (label: string) => {
    hits.push(label)
    return `<${W.secret}:${label}>`
  }
  /** A value word: one quoted part keeps its quotes, anything glued is replaced as a whole. */
  const value = (word: string, label: string) => {
    const quoted = /^(['"])([^'"]*)\1$/.exec(word)
    return quoted ? `${quoted[1]}${mark(label)}${quoted[1]}` : mark(label)
  }
  let out = text.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, () => mark(W.key))
  out = out.replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s:@/'"]+):([^\s@/'"]+)@/gi, (m, head: string, pass: string) =>
    isReference(pass) ? m : `${head}:${mark("url")}@`,
  )
  out = out.replace(new RegExp(String.raw`("(${NAMES})"\s*:\s*")((?:[^"\\]|\\.)*)"`, "gi"), (m, head: string, key: string, v: string) =>
    !v || isReference(v) ? m : `${head}${mark(key.toLowerCase())}"`,
  )
  out = out.replace(new RegExp(String.raw`([?&](${NAMES}|key)=)([^&\s'"#]{8,})`, "gi"), (m, head: string, key: string, v: string) =>
    isReference(v) ? m : `${head}${mark(key.toLowerCase())}`,
  )
  out = out.replace(/\b((?:set-)?cookie\s*:\s*)([^"'\n]+)/gi, (m, head: string, v: string) =>
    isReference(v) ? m : `${head}${mark("cookie")}`,
  )
  for (const [label, marker, val, flags] of MARKERS) {
    out = out.replace(new RegExp(marker + val, flags), (...g: string[]) => {
      const [m, head] = g
      const word = val === BARE ? g[3] : g[2]
      return !word || isReference(word) ? m : `${head}${value(word, label ?? head.replace(/[=\s]+$/, ""))}`
    })
  }
  for (const [label, re] of FORMATS) out = out.replace(re, () => mark(label))
  for (const p of extra) out = out.replace(p.re, () => mark(W.own(p.line)))
  out = out.replace(/(^|[\s"'=:(,])([A-Za-z0-9+/=_-]{32,})(?=$|[\s"'),;&|])/g, (m, head: string, run: string) =>
    looksRandom(run) ? `${head}${mark(W.long)}` : m,
  )
  return { text: out, hits }
}
