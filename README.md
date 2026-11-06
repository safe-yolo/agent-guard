<div align="center">

# agent-guard

**Run your coding agent yolo. Safely.**

English | [Русский](README.ru.md)

An [OpenCode](https://opencode.ai) plugin that classifies every shell command on a local LLM
before it runs: safe commands pass silently, unsafe ones stop and ask you why.

</div>

## Why

Permission prompts in coding agents are binary: either you click "Allow" all day, or you turn
everything off and hope. Safe-yolo adds the missing middle layer: a small local model reads each
command and decides: routine project work, or something that can wipe data, touch the system,
or leak secrets.

Pair it with an all-allowed agent and you get yolo UX with a guardian:

- safe command, allowed by rules -> runs instantly
- safe command, not covered by rules -> passes without a prompt
- unsafe command, allowed by rules -> escalates and shows you the classifier's reason

## Let your agent do it

Paste this into your OpenCode session and the agent will set everything up itself - plugin,
config, and whatever else it needs (it may connect an MCP or fetch docs to get it right):

```text
Install the agent-guard plugin for me: add it to the plugins list in my opencode.json
with mode "shadow". Point it at a local classifier endpoint - a Jev / System One decision server (laya-serve
or the cat-shell-risk-commander wrapper in examples/catshell) or any vLLM server with
structured outputs; check if one is already running on this machine or my LAN, if not, set one up or ask
me for the address. Then verify the plugin loads, run a harmless test shell command, and show
the verdict lines in ~/.local/share/opencode/safe-yolo.log. Use the docs at
https://github.com/ishpagin/agent-guard and connect any MCP or documentation source
you need to do this correctly.
```

## How it works

The plugin registers a `permission.evaluate` hook in the OpenCode server. For every shell
permission decision it sends the command to an OpenAI-compatible endpoint (built and tested
against vLLM with structured outputs) and gets back `{"verdict": "safe"|"unsafe",
"reason": "..."}`:

- `shadow` mode only logs verdicts, changing nothing. Run it for a few days first.
- `enforce` mode escalates unsafe-but-allowed commands to `ask`, and auto-approves safe commands
  that would have prompted. Configured `deny` rules are never touched, the hook does not even
  fire for them.

Verdicts are cached per command, so repeats are free.

> **macOS note**: the request goes through `curl` instead of `fetch`. Bun, and therefore
> OpenCode, is often blocked from LAN hosts by macOS Local Network privacy (`EHOSTUNREACH`),
> while Apple's own `curl` is allowed.

## Run a classifier locally

The plugin speaks two API shapes: `openai` (chat completions with structured outputs) and
`systemone` (the Jev / System One decision API). Pick whatever runs on your hardware:

**Cat Shell Risk Commander - the default pick, runs on CPU.** A purpose-built shell command
risk scorer (TF-IDF + linear model, 36K of weights, Apache-2.0): about 1 ms per command,
published metrics of 92.6% recall at 0.86% FPR. A ready Jev-compatible wrapper ships in
`examples/catshell/`:

```sh
cd examples/catshell && docker compose up --build -d
```

```jsonc title="opencode.json"
{
  "options": {
    "api": "systemone",
    "url": "http://127.0.0.1:8011/v1/systemone"
  }
}
```

**Laya - if your commands are heavily non-English.** Multilingual decision model (100+
languages), calibrated confidence, 200-450 ms per command on CPU. It also ships a Docker
quickstart with `laya-serve` in the image:

```sh
pip install "laya[serve]"
LAYA_PORT=8010 laya-serve
```

```jsonc title="opencode.json"
{
  "options": {
    "api": "systemone",
    "url": "http://127.0.0.1:8010/v1/systemone",
    "model": "multilingual"
  }
}
```

**Clef / Clef-flash - for GPU boxes.** Cloudflare's open decision models (Apache 2.0),
Jev-compatible, median 39 ms for clef-flash. Serve with SGLang per the model card and use
`api: "systemone"`, or run them through Workers AI or Ollama cloud with an `apiKey`.

**Any small LLM on vLLM - the generic path.** Heavier: gigabytes of weights and hundreds of ms
per command. But it answers with a verbal reason, which is what the cascade stage quotes back
to you. Configure it with `api: "openai"`.

## Cascade

Decision models are fast but sometimes unsure, and they answer in probabilities, not words.
Point `escalateUrl` at a stronger LLM and unsure commands get a second opinion:

- a `safe` primary verdict with confidence at or above `threshold` (default 0.8) is trusted
- anything else goes to the escalation endpoint: every `unsafe`, low confidence, a primary that
  is down. Its verdict and its verbal reason are what you see
- escalation failed -> the primary verdict stands
- both stages down -> configured permission rules decide, as before

Hard rules run before any model and no model can override them: `git push`, downloaded code
piped into a shell (`curl | sh`), `rm -rf` outside the project and temp dirs. The opencode plugin
denies them in any mode, because auto approval passes everything but an explicit deny; run such a
command yourself. The Claude Code hook asks. A relative `rm -rf` after `cd` or inside
`ssh` counts as outside. So does a variable, unless the command itself sets it to a plain literal
before `rm`. Values are never read from the real environment.

Set `SAFE_YOLO_DEBUG=1` (or a file path) to log every decision with both stages, timings and
failures to `~/.local/share/opencode/safe-yolo-debug.jsonl`. Past 5 MB it moves to `.jsonl.1`, so
disk use stays around 10 MB. It holds full command text, so keep
it local.

The log shows both stages:

```
via=primary verdict=unsafe conf=61% -> via=escalate verdict=unsafe reason=curl pipes a remote script into sh
```

Full example: catshell on a homelab box, an LLM on another host as the second opinion:

```jsonc title="opencode.json"
{
  "plugins": [
    {
      "package": "@safe-yolo/agent-guard@0.2.10",
      "options": {
        "mode": "shadow",
        "api": "systemone",
        "url": "http://127.0.0.1:8010/v1/systemone",
        "model": "multilingual",
        "threshold": 0.8,
        "escalateUrl": "http://llm.lan:8000/v1/chat/completions",
        "escalateModel": "qwen3.6-35b"
      }
    }
  ]
}
```

## Install

Pin an exact version. This plugin sits on the permission path of every shell command, so an
update must never land silently:

```jsonc title="opencode.json"
{
  "plugins": ["@safe-yolo/agent-guard@0.2.10"]
}
```

With options (for example, a classifier on another host):

```jsonc title="opencode.json"
{
  "plugins": [
    {
      "package": "@safe-yolo/agent-guard@0.2.10",
      "options": {
        "mode": "shadow",
        "url": "http://127.0.0.1:8000/v1/chat/completions",
        "model": "qwen3.6-35b"
      }
    }
  ]
}
```

The package publishes to the Forgejo npm registry on my homelab. Version numbers in these
examples are injected by `scripts/sync-version.sh` from `package.json`, and CI fails when
they drift. To update: bump the version, run the script, review the diff.

Until a public npm release, install from a local checkout: point `package` at the directory
with the clone.

Start in `shadow`, read the log for a few days, then switch to `enforce`.

If you previously enabled blanket auto-approve, turn it off in enforce mode: it would press
"Allow" on the very prompts safe-yolo escalates for your review.

## Options

| Option | Default | What it does |
|---|---|---|
| `mode` | `shadow` | `shadow` logs only, `enforce` changes decisions |
| `api` | `openai` | `openai` or `systemone` |
| `url` | `http://127.0.0.1:8000/v1/chat/completions` | chat completions or systemone endpoint |
| `model` | `qwen3.6-35b` | classifier model id |
| `apiKey` | - | Bearer key when the endpoint needs one |
| `timeoutMs` | `6000` | per-classification curl timeout |
| `threshold` | `0.8` | primary confidence below this escalates |
| `policyFile` | `~/.config/opencode/safe-yolo-policy.md` | markdown file with your policy rules |
| `policyHint` | - | the same as a one-liner in the config |
| `disableDefaultPolicyHint` | `false` | drop the built-in rules: only your policyFile/policyHint goes to the classifier |
| `escalateUrl` | - | second-opinion endpoint |
| `escalateApi` | `openai` | API shape of the escalation endpoint |
| `escalateModel` | - | model id for the escalation endpoint |
| `escalateApiKey` | - | Bearer key for escalation |

## Your policy

The classifier knows general security rules but not your setup. Teach it the specifics of your
environment - your hosts, your routines, your language - in a plain markdown file. Create
`~/.config/opencode/safe-yolo-policy.md` (or point `policyFile` elsewhere); the whole file is
appended to the classifier prompt on every call. A starter template lives in
`examples/policy.md`.

```md title="~/.config/opencode/safe-yolo-policy.md"
hosts nas-1 and home-server are the user's own machines administered over ssh:
managing their docker services and reading their logs is safe.
deploying to prod-1 requires an explicit ask.
```

Write it like an explanation to a new teammate: concrete hosts and workflows, what counts as
routine, what requires a human. Keep it short - every line costs attention on every
classification. The file stays on your machine; the plugin ships with a generic policy. After
editing, touch `opencode.json` or run `/reload` so the plugin re-reads it.

Prefer one line instead of a file? Put it in `policyHint` - both work, both are appended.
Want only your rules? `disableDefaultPolicyHint: true` drops the built-in policy, and your
file is all the classifier sees - keep the safe/unsafe semantics in it.

## Logs

Verdicts land in `~/.local/share/opencode/safe-yolo.log`:

```
2026-11-04T12:30:29.863Z mode=shadow effect=ask verdict=safe -> ask cmd=make build && go test ./... reason=Builds the project and runs tests
```

To audit the classifier: `grep 'verdict=unsafe' ~/.local/share/opencode/safe-yolo.log` and check
whether any safe commands were flagged.

## What it is not

- Not a sandbox: the classifier is advisory, a determined agent can still do harm between
  verdicts. Keep real `deny` rules for catastrophic patterns.
- Not a prompt-injection defense: it judges the command text, not the intent behind it.

## License

[PolyForm Noncommercial 1.0.0](LICENSE).
