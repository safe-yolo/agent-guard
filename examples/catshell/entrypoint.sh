#!/bin/sh
set -e
mkdir -p /model
# the whole model is ~4 MB; it downloads once and stays in the image layer
if [ ! -f /model/model.json ]; then
  python -c "from huggingface_hub import snapshot_download; p = snapshot_download('patronus-studio/cat-shell-risk-commander', allow_patterns=['model.json', 'shell_cat_guard_a1.py', 'shell_tokens.py'], local_dir='/model'); print('model at', p)"
fi
exec python -m uvicorn app:app --host 0.0.0.0 --port "${CATSHELL_PORT:-8011}"
