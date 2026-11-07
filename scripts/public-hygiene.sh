#!/bin/sh
# Публичная гигиена: в репо не должно быть приватных строк - имена хостов и машин
# домашней сети, приватные адреса, домены. CI гоняет на MR: нашлось - MR красный.
# Ложное срабатывание - скажи, строчку в списке поправим.
# Исключения: сам скрипт (в нём список) и .forgejo (там адрес раннера в runs-on).
set -eu
bad='\b(pillow|spark|ark|velox|homenet|shpagin)\b|192\.168\.'
hits=$(git grep -n -i -E "$bad" -- . ':(exclude)scripts/public-hygiene.sh' ':(exclude).forgejo' || true)
if [ -n "$hits" ]; then
	echo "private strings found:"
	echo "$hits"
	exit 1
fi
echo "hygiene ok"
