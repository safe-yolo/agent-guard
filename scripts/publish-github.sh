#!/bin/sh
# Публикация на github: чистое дерево одним коммитом поверх main (force push).
# Полная история остаётся в приватном opensource на Forgejo; в паблик уходит
# только то, что прошло public-hygiene. Запуск после мерджа в opensource.
set -eu
sh scripts/public-hygiene.sh
v=$(bun -e 'console.log(require("./package.json").version)')
commit=$(git commit-tree 'HEAD^{tree}' -m "agent-guard $v")
git push -f github "$commit:refs/heads/main"
echo "github main -> $commit"
