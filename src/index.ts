/** OpenCode plugin: safe-yolo guard on the permission.evaluate hook. */
import { Plugin } from "@opencode/plugin"
import { appendFileSync, readFileSync } from "node:fs"
import { homedir } from "node:os"
import { classifyCommand, decide, type Api, type Mode } from "./core"

interface PluginOptions {
  /** shadow logs verdicts only, enforce also changes decisions */
  mode?: Mode
  /** markdown file with your policy; default ~/.config/opencode/safe-yolo-policy.md */
  policyFile?: string
  /** extra policy lines as a one-liner; combined with the policy file */
  policyHint?: string
  /** drop the built-in policy: only your policyFile/policyHint goes to the classifier */
  disableDefaultPolicyHint?: boolean
  api?: Api
  url?: string
  model?: string
  apiKey?: string
  timeoutMs?: number
  threshold?: number
  escalateUrl?: string
  escalateApi?: Api
  escalateModel?: string
  escalateApiKey?: string
}

export default Plugin.define({
  id: "safe-yolo",
  async setup(ctx) {
    const options = (ctx.options ?? {}) as PluginOptions
    const mode: Mode = options.mode === "enforce" ? "enforce" : "shadow"
    const policyFile = options.policyFile ?? `${homedir()}/.config/opencode/safe-yolo-policy.md`
    let userPolicy = ""
    try {
      userPolicy = readFileSync(policyFile, "utf8").trim()
    } catch {}
    const engine = {
      api: options.api,
      url: options.url,
      model: options.model,
      apiKey: options.apiKey,
      timeoutMs: options.timeoutMs,
      threshold: options.threshold,
      escalateUrl: options.escalateUrl,
      escalateApi: options.escalateApi,
      escalateModel: options.escalateModel,
      escalateApiKey: options.escalateApiKey,
      policy: userPolicy,
      noBuiltin: options.disableDefaultPolicyHint,
      cwd: (ctx as any).directory,
    }
    const cache = new Map<string, Awaited<ReturnType<typeof classifyCommand>>>()
    const log = (text: string) => {
      try {
        appendFileSync(`${homedir()}/.local/share/opencode/safe-yolo.log`, `${new Date().toISOString()} ${text}\n`)
      } catch {}
    }

    const permissionAny = ctx.permission as any
    if (typeof permissionAny?.hook !== "function") {
      log(`permission.evaluate hook unavailable in this opencode build, plugin is passive`)
      return
    }

    await permissionAny.hook("evaluate", async (event: any) => {
      if (event.action !== "shell" && event.action !== "bash") return
      const command = (event.resources ?? []).join(" && ")
      let found = cache.get(command)
      if (!found) {
        found = await classifyCommand(command, engine)
        if (found) cache.set(command, found)
      }
      if (!found) return
      const conf = found.confidence != null ? ` conf=${Math.round(found.confidence * 100)}%` : ""
      const result = decide(mode, event.effect, found.verdict, found.reason, found.via)
      log(`mode=${mode} effect=${event.effect} verdict=${found.verdict} -> ${result.effect} via=${found.via}${conf} cmd=${command.slice(0, 160)} reason=${found.reason}`)
      // JSONL for fine-tuning: one line per command, both cascade stages
      try {
        appendFileSync(
          `${homedir()}/.local/share/opencode/safe-yolo-train.jsonl`,
          JSON.stringify({
            ts: new Date().toISOString(),
            command,
            mode,
            effect_before: event.effect,
            effect_after: result.effect,
            verdict: found.verdict,
            via: found.via,
            reason: found.reason,
            confidence: found.confidence ?? null,
          }) + "\n",
        )
      } catch {}
      if (result.effect !== event.effect) {
        event.effect = result.effect
        if (result.message) event.message = result.message
      }
    })

    log(`loaded mode=${mode} api=${engine.api} url=${engine.url} model=${engine.model} threshold=${engine.threshold} escalate=${options.escalateUrl ?? "none"} policy=${userPolicy ? `${userPolicy.length}b` : "generic"}`)
  },
})
