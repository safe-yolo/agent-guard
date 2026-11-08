/** Read-only probes for the hard rules and the confirmation card: cheap, capped, never throw. */
import { execFile, execFileSync } from "node:child_process"
import { closeSync, fstatSync, lstatSync, openSync, readdirSync, readSync, realpathSync } from "node:fs"
import { basename, dirname, join, resolve } from "node:path"

const PROBE_MS = 500

// cached per dir for the life of the process: the user asked not to hammer the disk
const gitCache = new Map<string, Promise<string | undefined>>()
const rootCache = new Map<string, string | undefined>()

/** Trimmed git output in dir, undefined on any failure or timeout. */
export function git(dir: string, ...args: string[]): Promise<string | undefined> {
  const key = [dir, ...args].join("\0")
  let hit = gitCache.get(key)
  if (!hit) {
    hit = new Promise((done) =>
      execFile("git", ["-C", dir, ...args], { timeout: PROBE_MS }, (err, out) => done(err ? undefined : String(out).trim())),
    )
    gitCache.set(key, hit)
  }
  return hit
}

/** The path with symlinks resolved, or the path itself when it does not exist. */
export function realPath(path: string): string {
  try {
    return realpathSync(path)
  } catch {
    return path
  }
}

/** Real path of the parent plus the last name: rm removes a symlink itself, not what it points to. */
export function realTarget(path: string): string {
  const parent = realPath(dirname(path))
  return parent === "/" ? `/${basename(path)}` : join(parent, basename(path))
}

/** Real path of the git work tree root of cwd (pass a real cwd), so symlinks cannot widen the project. */
export function gitRoot(cwd: string): string | undefined {
  if (rootCache.has(cwd)) return rootCache.get(cwd)
  let root: string | undefined
  try {
    const top = execFileSync("git", ["-C", cwd, "rev-parse", "--show-toplevel"], {
      timeout: PROBE_MS,
      stdio: ["ignore", "pipe", "ignore"],
    })
    root = realPath(String(top).trim()) || undefined
  } catch {}
  rootCache.set(cwd, root)
  return root
}

/** Files and bytes under path, without following symlinks; stops early and says so. */
export function measure(path: string, maxEntries = 2000, maxMs = 200): { files: number; bytes: number; capped: boolean } {
  const deadline = Date.now() + maxMs
  const stack = [path]
  let files = 0
  let bytes = 0
  for (let seen = 0; stack.length; seen++) {
    if (seen >= maxEntries || Date.now() > deadline) return { files, bytes, capped: true }
    const p = stack.pop()!
    try {
      const st = lstatSync(p)
      if (st.isDirectory()) for (const name of readdirSync(p)) stack.push(join(p, name))
      else {
        files++
        bytes += st.size
      }
    } catch {}
  }
  return { files, bytes, capped: false }
}

export function exists(path: string): boolean {
  try {
    return !!lstatSync(path, { throwIfNoEntry: false })
  } catch {
    return false
  }
}

export function isDir(path: string): boolean {
  try {
    return !!lstatSync(path, { throwIfNoEntry: false })?.isDirectory()
  } catch {
    return false
  }
}

const URL_HOST = /\bhttps?:\/\/(?:[^\s/'"`@]*@)?([A-Za-z0-9.-]+)/g
const SENDS_TOKEN = /\b(?:authorization|private-token|x-api-key)\s*:|\bbearer\s+\S|\$\{?\w*(?:TOKEN|KEY)\b/i

/** Hosts of the URLs in a command, in order, without duplicates. */
export function urlHosts(command: string): string[] {
  return [...new Set([...command.matchAll(URL_HOST)].map((m) => m[1].toLowerCase()))]
}

export function sendsToken(command: string): boolean {
  return SENDS_TOKEN.test(command)
}

/** host/path of a git remote, without scheme and credentials. */
export function bareRemote(url: string): string {
  return url.replace(/^[a-z+]+:\/\//i, "").replace(/^[^@/]*@/, "")
}

const sshCache = new Map<string, Promise<string>>()

/** The real hostname behind an ssh alias (`ssh -G` only reads the config), or the alias itself when that is an IP. */
function sshHostname(alias: string): Promise<string> {
  let hit = sshCache.get(alias)
  if (!hit) {
    hit = new Promise((done) =>
      execFile("ssh", ["-G", alias], { timeout: PROBE_MS }, (err, out) => {
        const host = !err && /^hostname (\S+)$/m.exec(String(out))?.[1]
        done(host && !/^[\d.]+$|:/.test(host) ? host : alias)
      }),
    )
    sshCache.set(alias, hit)
  }
  return hit
}

/** "owner/repo (host)" from a remote URL: no scheme, user or password; host cut to two labels. */
export async function shortRemote(url: string): Promise<string> {
  const bare = bareRemote(url)
  const scp = !/^[a-z+]+:\/\//i.test(url) && /^[^/]+:/.test(bare)
  const m = scp ? /^([^:/]+):(.*)$/.exec(bare) : /^([^/:]+)(?::\d+)?\/(.*)$/.exec(bare)
  const name = (m?.[2] ?? bare).replace(/\/+$/, "").replace(/\.git$/, "").split("/").slice(-2).join("/")
  if (!m) return basename(name)
  const host = scp || /^ssh:/i.test(url) ? await sshHostname(m[1]) : m[1]
  const labels = host.split(".")
  const short = /^[\d.]+$/.test(host) || labels.length < 3 ? host : labels.slice(0, 2).join(".")
  return `${name} (${short})`
}

/** Short name of the repo at dir: its remote (the given one, else origin, else the first), else the folder. */
export async function repoLabel(dir: string, prefer = "origin"): Promise<string | undefined> {
  const [top, gitDir, list] = await Promise.all([
    git(dir, "rev-parse", "--show-toplevel"),
    git(dir, "rev-parse", "--absolute-git-dir"),
    git(dir, "remote"),
  ])
  if (!top && !gitDir) return undefined
  const remotes = list?.split("\n").filter(Boolean) ?? []
  const name = remotes.includes(prefer) ? prefer : remotes.includes("origin") ? "origin" : remotes[0]
  const url = name ? await git(dir, "remote", "get-url", name) : undefined
  return url ? shortRemote(url) : basename(top || gitDir!).replace(/\.git$/, "")
}

/**
 * The user's last real message in a Claude Code transcript (JSONL). Reads only the tail, skips
 * tool results and system or command wrappers (text starting with "<").
 */
export function lastUserMessage(file: string, tailBytes = 256 * 1024): string | undefined {
  let text: string
  try {
    const fd = openSync(file, "r")
    try {
      const size = fstatSync(fd).size
      const start = Math.max(0, size - tailBytes)
      const buf = Buffer.alloc(size - start)
      readSync(fd, buf, 0, buf.length, start)
      text = buf.toString("utf8")
      if (start > 0) text = text.slice(text.indexOf("\n") + 1)
    } finally {
      closeSync(fd)
    }
  } catch {
    return undefined
  }
  const lines = text.split("\n")
  for (let i = lines.length - 1; i >= 0; i--) {
    let entry: { type?: string; isMeta?: boolean; message?: { content?: unknown } }
    try {
      entry = JSON.parse(lines[i])
    } catch {
      continue
    }
    if (entry?.type !== "user" || entry.isMeta) continue
    const content = entry.message?.content
    const blocks = (typeof content === "string" ? [{ type: "text", text: content }] : Array.isArray(content) ? content : []) as {
      type?: string
      text?: unknown
    }[]
    if (blocks.some((b) => b?.type === "tool_result")) continue
    const said = blocks
      .filter((b) => b?.type === "text" && typeof b.text === "string")
      .map((b) => b.text)
      .join("\n")
      .trim()
    if (said && !said.startsWith("<")) return said
  }
  return undefined
}
