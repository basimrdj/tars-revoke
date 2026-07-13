#!/usr/bin/env bash
# TARS Phase 1 — local model launcher
#
# Starts mlx_lm.server with the configured model. Designed to be invoked
# either directly by the user (for manual testing / standalone runs) or as a
# fallback by tars_inner_voice.LocalModelServer when the in-process spawn
# paths fail.
#
# Usage:
#   scripts/start_local_model.sh                                     (defaults)
#   scripts/start_local_model.sh 127.0.0.1 8765                       (host, port)
#   scripts/start_local_model.sh 127.0.0.1 8765 mlx-community/...     (host, port, model)
#
# Env overrides:
#   TARS_LOCAL_MODEL_HOST   default 127.0.0.1
#   TARS_LOCAL_MODEL_PORT   default 8765
#   TARS_LOCAL_MODEL        default mlx-community/gemma-4-e4b-it-4bit
#   TARS_MLX_PYTHON         optional Python with mlx_lm installed
#   TARS_MLX_VENV           optional venv path, default ~/.venvs/mlx-gemma
#   TARS_LOCAL_CHAT_TEMPLATE_ARGS default {"enable_thinking": false}
#   TARS_LOCAL_MAX_TOKENS   default 512
#
# Exit codes:
#   0   ran cleanly to completion (server stopped normally)
#   1   model server invocation failed in every available form
#   2   environment is missing required tooling (mlx_lm)

set -u

HOST="${1:-${TARS_LOCAL_MODEL_HOST:-127.0.0.1}}"
PORT="${2:-${TARS_LOCAL_MODEL_PORT:-8765}}"
MODEL="${3:-${TARS_LOCAL_MODEL:-mlx-community/gemma-4-e4b-it-4bit}}"
MAX_TOKENS="${TARS_LOCAL_MAX_TOKENS:-512}"
CHAT_TEMPLATE_ARGS="${TARS_LOCAL_CHAT_TEMPLATE_ARGS:-}"
if [[ -z "$CHAT_TEMPLATE_ARGS" ]]; then
  CHAT_TEMPLATE_ARGS='{"enable_thinking": false}'
fi
MLX_VENV="${TARS_MLX_VENV:-$HOME/.venvs/mlx-gemma}"
PYTHON_BIN="${TARS_MLX_PYTHON:-${TARS_LOCAL_PYTHON:-}}"
if [[ -z "$PYTHON_BIN" && -x "$MLX_VENV/bin/python3" ]]; then
  PYTHON_BIN="$MLX_VENV/bin/python3"
fi
if [[ -z "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi
MLX_SERVER_BIN="${TARS_MLX_SERVER:-}"
if [[ -z "$MLX_SERVER_BIN" && -x "$MLX_VENV/bin/mlx_lm.server" ]]; then
  MLX_SERVER_BIN="$MLX_VENV/bin/mlx_lm.server"
fi

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

echo "[start_local_model] host=$HOST port=$PORT model=$MODEL"

# Sanity check: ensure mlx_lm is importable in the selected Python.
if ! "$PYTHON_BIN" -c "import mlx_lm" >/dev/null 2>&1; then
  echo "[start_local_model] ERROR: 'mlx_lm' is not importable in $PYTHON_BIN."
  echo "[start_local_model] Install it with: $PYTHON_BIN -m pip install mlx-lm"
  exit 2
fi

# Build the argument list once and reuse across invocation forms.
ARGS=(
  --host "$HOST"
  --port "$PORT"
  --model "$MODEL"
  --use-default-chat-template
  --chat-template-args "$CHAT_TEMPLATE_ARGS"
  --max-tokens "$MAX_TOKENS"
)

if [[ -f "$PROJECT_DIR/scripts/start_mlx_server.py" ]]; then
  exec "$PYTHON_BIN" "$PROJECT_DIR/scripts/start_mlx_server.py" "${ARGS[@]}"
fi

# Try preferred → fallback invocations.
if [[ -n "$MLX_SERVER_BIN" ]]; then
  exec "$MLX_SERVER_BIN" "${ARGS[@]}"
fi

if command -v mlx_lm.server >/dev/null 2>&1; then
  exec "$(command -v mlx_lm.server)" "${ARGS[@]}"
fi

if "$PYTHON_BIN" -m mlx_lm server --help >/dev/null 2>&1; then
  exec "$PYTHON_BIN" -m mlx_lm server "${ARGS[@]}"
fi

# Final fallback: direct module invocation (deprecated but still works).
exec "$PYTHON_BIN" -m mlx_lm.server "${ARGS[@]}"
