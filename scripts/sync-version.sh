#!/bin/sh
# Подставляет версию из package.json в примеры pin в README.
# Обновление пакета: bump версии, этот скрипт, diff, коммит. CI проверяет, что после прогона diff пустой.
set -eu
v=$(bun -e 'console.log(require("./package.json").version)')
for f in README.md README.ru.md; do
  bun -e '
    const fs = require("node:fs")
    const [file, version] = process.argv.slice(1)
    const out = fs.readFileSync(file, "utf8").replace(
      /(@[a-z0-9-]+\/)?agent-guard@[0-9]+\.[0-9]+\.[0-9]+/g,
      (m, scope) => (scope ?? "") + "agent-guard@" + version,
    )
    fs.writeFileSync(file, out)
  ' "$f" "$v"
done
echo "README pins: agent-guard@$v"
