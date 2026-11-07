#!/bin/sh
# Публикация на github: чистое дерево одним коммитом поверх main (force push) и тег v<версия>,
# по которому github actions публикует пакет в npm. Полная история остаётся в приватном
# opensource на Forgejo; в паблик уходит только то, что прошло public-hygiene.
# .forgejo в паблик не идёт: там имена хостов. Запуск после мерджа в opensource.
set -eu
sh scripts/public-hygiene.sh
v=$(bun -e 'console.log(require("./package.json").version)')
index=$(mktemp -u)
trap 'rm -f "$index"' EXIT
GIT_INDEX_FILE=$index git read-tree HEAD
GIT_INDEX_FILE=$index git rm -r -q --cached .forgejo
tree=$(GIT_INDEX_FILE=$index git write-tree)
commit=$(git commit-tree "$tree" -m "agent-guard $v")
git push -f github "$commit:refs/heads/main"
git push github "$commit:refs/tags/v$v"
echo "github main и тег v$v -> $commit"
