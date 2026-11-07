<div align="center">

# agent-guard

**Запускай кодинг-агента в йоло. Безопасно.**

[English](README.md) | Русский

Страховка для [OpenCode](https://opencode.ai) и [Claude Code](https://claude.com/claude-code):
локальная модель проверяет каждую shell-команду перед запуском. Безопасные проходят молча, опасные
останавливаются и спрашивают тебя.

</div>

## Зачем

Диалоги разрешений в кодинг-агентах бинарные: либо ты весь день жмёшь "Allow", либо выключаешь
всё и надеешься. agent-guard добавляет недостающий средний слой: маленькая локальная модель читает
команду и решает - это обычная работа с проектом или то, что может снести данные, тронуть
систему или утянуть секреты.

В паре с агентом, которому разрешено всё, получаешь йоло-UX под присмотром:

- безопасная команда, покрытая правилами -> выполняется мгновенно
- безопасная команда, не покрытая правилами -> проходит без диалога
- опасная команда, разрешённая правилами -> поднимается в диалог с причиной классификатора

## Пусть агент сделает сам

Вставь это в сессию OpenCode или Claude Code, и агент сам всё настроит:

```text
Установи мне agent-guard из https://github.com/safe-yolo/agent-guard, действуй по его README.
Выбери плагин OpenCode или хук Claude Code, смотря какой ты агент. Для OpenCode режим "shadow".
Классификатор локальный: decision-сервер Jev / System One (laya-serve или обёртка из
examples/catshell), для OpenCode подойдёт и любой vLLM-сервер со structured outputs. Проверь, не
запущен ли уже такой на этой машине или в локальной сети, если нет, подними или спроси у меня
адрес. Потом выполни безобидную тестовую команду и покажи, что решила защита.
```

## Как это работает

Обе интеграции работают на одном движке: сначала жёсткие правила, потом классификатор, потом
второе мнение, если оно настроено. Вердикт: `safe` или `unsafe` с короткой причиной. В Claude Code
это хук `PreToolUse`, см. [Установку](#claude-code).

Плагин OpenCode регистрирует хук `permission.evaluate` и работает в двух режимах:

- режим `shadow` только пишет вердикты в лог, ничего не меняя. Погоняй его так несколько дней.
- режим `enforce` поднимает опасные, но разрешённые правилами команды в диалог `ask`, а
  безопасные, которые вызвали бы диалог, пропускает молча. Настроенные `deny`-правила плагин не
  трогает вовсе: хук для них даже не вызывается.

Вердикты кэшируются по тексту команды, повторные вызовы бесплатны.

> **Про macOS**: запрос идёт через `curl`, а не `fetch`. Bun, а значит и OpenCode, часто
> отрезан от LAN-хостов macOS Local Network privacy (`EHOSTUNREACH`), а родному `curl` от Apple
> ход разрешён.

## Установка

Фиксируй точную версию. Защита стоит на пути разрешений каждой shell-команды, и обновление не
должно приезжать молча. Как обновиться: подними версию, прочитай изменения, перезапусти агента.

### OpenCode

```jsonc title="opencode.json"
{
  "plugins": ["@safe-yolo/agent-guard@0.2.11"]
}
```

С опциями (например, классификатор на другом хосте):

```jsonc title="opencode.json"
{
  "plugins": [
    {
      "package": "@safe-yolo/agent-guard@0.2.11",
      "options": {
        "mode": "shadow",
        "url": "http://127.0.0.1:8000/v1/chat/completions",
        "model": "qwen3.6-35b"
      }
    }
  ]
}
```

Запуск из локального клона: укажи в `package` путь к каталогу с репозиторием.

Начни с `shadow`, несколько дней читай лог, потом переключайся на `enforce`.

Если у тебя включено глобальное авто-одобрение разрешений, в режиме `enforce` его выключи:
иначе оно будет жать "Allow" на тех самых диалогах, которые safe-yolo поднял для тебя.

### Claude Code

Хук это бинарь `safe-yolo-guard` из того же пакета:

```sh
npm install -g @safe-yolo/agent-guard@0.2.11
```

Добавь его в настройки:

```json title="~/.claude/settings.json"
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "SAFE_YOLO_URL=http://127.0.0.1:8011/v1/systemone safe-yolo-guard"
          }
        ]
      }
    ]
  }
}
```

Что происходит с командой:

- безопасная -> выполняется без вопроса
- опасная или жёсткое правило -> Claude Code спрашивает тебя и показывает причину
- классификатор недоступен -> хук молчит, решают твои правила разрешений Claude Code

Режима `shadow` у хука нет, он работает с первой команды. Все настройки задаются переменными
окружения:

| Переменная | По умолчанию | Что делает |
|---|---|---|
| `SAFE_YOLO_URL` | `http://127.0.0.1:8011/v1/systemone` | основной endpoint, только API systemone |
| `SAFE_YOLO_MODEL` | - | id модели классификатора |
| `SAFE_YOLO_API_KEY` | - | Bearer-ключ основного endpoint |
| `SAFE_YOLO_THRESHOLD` | `0.8` | ниже этой уверенности команда идёт на вторую ступень |
| `SAFE_YOLO_POLICY_FILE` | `~/.config/agent-guard/policy.md` | markdown-файл с твоими правилами |
| `SAFE_YOLO_ESCALATE_URL` | - | endpoint второго мнения, API openai |
| `SAFE_YOLO_ESCALATE_MODEL` | `qwen3.6-35b` | id модели второй ступени |
| `SAFE_YOLO_ESCALATE_API_KEY` | - | Bearer-ключ второй ступени |
| `SAFE_YOLO_DEBUG` | - | `1` или путь к файлу: писать каждое решение |

## Запустить классификатор локально

Плагин говорит на двух протоколах: `openai` (chat completions со structured outputs) и
`systemone` (decision API Jev / System One). Берите то, что работает на вашем железе:

**Cat Shell Risk Commander - выбор по умолчанию, работает на CPU.** Заточенный скорер
shell-команд (TF-IDF + линейная модель, 36К весов, Apache-2.0): около 1 мс на команду,
опубликованные метрики recall 92.6% при FPR 0.86%. Готовая Jev-обёртка лежит в
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

**Laya - если команды в основном не на английском.** Мультиязычная decision-модель (100+
языков), калиброванная уверенность, 200-450 мс на CPU. У Laya есть Docker quickstart с
`laya-serve` в образе:

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

**Clef / Clef-flash - для GPU.** Открытые decision-модели Cloudflare (Apache 2.0), совместимы с
Jev, медиана 39 мс у clef-flash. Поднимите через SGLang по карточке модели и включите
`api: "systemone"` - или гоняйте через Workers AI / Ollama cloud с `apiKey`.

**Любая маленькая LLM на vLLM - универсальный путь.** Тяжелее: гигабайты весов и сотни
миллисекунд на команду. Зато отвечает словесной причиной - её каскад потом показывает вам.
Включается `api: "openai"`.

## Каскад

Decision-модели быстры, но иногда не уверены, и отвечают вероятностями, а не словами.
Укажите `escalateUrl` на более сильную LLM - неуверенные команды уйдут на второе мнение:

- вердикт `safe` первой ступени с уверенностью на уровне `threshold` (по умолчанию 0.8) и выше - trusted
- всё остальное уходит на escalation endpoint: любой `unsafe`, низкая уверенность, упавшая первая
  ступень. Её вердикт и словесную причину вы и видите
- вторая ступень не ответила - остаётся вердикт первой
- упали обе ступени - решают настроенные правила разрешений, как раньше

Полный пример: catshell на сервере дома, LLM на другом хосте как второе мнение:

```jsonc title="opencode.json"
{
  "plugins": [
    {
      "package": "@safe-yolo/agent-guard@0.2.11",
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

## Жёсткие правила

Они срабатывают раньше моделей, и модель их не отменит:

- `git push`
- скачанный код в шелл (`curl | sh`)
- `rm -rf` вне проекта и временных папок

Плагин OpenCode запрещает их в любом режиме: автоподтверждение пропускает всё, кроме явного deny,
так что такую команду запускай сам. Хук Claude Code спрашивает.

Относительный `rm -rf` после `cd` или внутри `ssh` считается "вне проекта". Как и переменная, если
команда сама не задала её простым значением до `rm`. Настоящее окружение не читается.

## Опции

| Опция | По умолчанию | Что делает |
|---|---|---|
| `mode` | `shadow` | `shadow` только логирует, `enforce` меняет решения |
| `api` | `openai` | `openai` или `systemone` |
| `url` | `http://127.0.0.1:8000/v1/chat/completions` | endpoint chat completions или systemone |
| `model` | `qwen3.6-35b` | id модели-классификатора |
| `apiKey` | - | Bearer-ключ, если endpoint его требует |
| `timeoutMs` | `6000` | таймаут curl на классификацию |
| `threshold` | `0.8` | уверенность первой ступени ниже порога - escalate |
| `policyFile` | `~/.config/opencode/safe-yolo-policy.md` | markdown-файл с твоими правилами |
| `policyHint` | - | то же одной строкой в конфиге |
| `disableDefaultPolicyHint` | `false` | убрать встроенные правила: классификатор видит только твой policyFile/policyHint |
| `escalateUrl` | - | endpoint второго мнения |
| `escalateApi` | `openai` | протокол escalation endpoint |
| `escalateModel` | - | id модели на escalation endpoint |
| `escalateApiKey` | - | Bearer-ключ для escalation |

## Твой policy-файл

Классификатор знает общие правила безопасности, но не твоё окружение. Научи его specifics -
твои хосты, рутины, язык - простым markdown-файлом. Создай
`~/.config/opencode/safe-yolo-policy.md` (или укажи свой путь в `policyFile`); весь файл
добавляется к промпту классификатора на каждый вызов. Стартовый шаблон - `examples/policy.md`.

```md title="~/.config/opencode/safe-yolo-policy.md"
хосты nas-1 и home-server - твои машины по ssh:
управление их docker-сервисами и чтение их логов - safe.
деплой на prod-1 - только по явной просьбе.
```

Пиши как объяснение новому коллеге: конкретные хосты и рутины, что считается нормой, что
требует человека. Коротко - каждая строка тратит внимание на каждый вызов. Файл остаётся на
твоей машине; плагин несёт generic-политику. После правки тронь `opencode.json` или запусти
`/reload`, чтобы плагин перечитал файл.

Нужна одна строка вместо файла - положи её в `policyHint`, работают оба и складываются.
Хочешь только свои правила - `disableDefaultPolicyHint: true`: встроенная политика
убирается, классификатор видит только твой файл (держи в нём определения safe/unsafe).

Хук Claude Code читает `~/.config/agent-guard/policy.md` или файл из `SAFE_YOLO_POLICY_FILE`.

## Логи

Вердикты пишутся в `~/.local/share/opencode/safe-yolo.log`:

```
2026-11-04T12:30:29.863Z mode=shadow effect=ask verdict=safe -> ask cmd=make build && go test ./... reason=Builds the project and runs tests
```

Проверка классификатора: `grep 'verdict=unsafe' ~/.local/share/opencode/safe-yolo.log` - смотри,
не помечены ли безопасные команды.

`SAFE_YOLO_DEBUG=1` (или путь к файлу) пишет каждое решение с обеими ступенями, временем и сбоями в
`~/.local/share/opencode/safe-yolo-debug.jsonl`. После 5 МБ файл уезжает в `.jsonl.1`, на диске около
10 МБ. Там полный текст команд, так что файл только локальный.

В отладочном логе видны обе ступени:

```
via=primary verdict=unsafe conf=61% -> via=escalate verdict=unsafe reason=curl pipes a remote script into sh
```

## Чем это не является

- Не песочница: классификатор рекомендательный, целеустремлённый агент навредит и между
  вердиктами. Держи настоящие `deny`-правила на катастрофические шаблоны.
- Не защита от prompt injection: он оценивает текст команды, а не намерение за ним.

## Лицензия

[PolyForm Noncommercial 1.0.0](LICENSE).
