#!/bin/sh
# Generic scenario injector/runner from local terminal.
# Usage:
#   ./scenarios/scenario_setup.sh <scenario_name> [container_name]
# Example:
#   ./scenarios/scenario_setup.sh redis_drift

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <scenario_name> [container_name]" >&2
  exit 1
fi

SCENARIO_NAME="$1"
CONTAINER_OVERRIDE="${2:-}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/$SCENARIO_NAME"
SCENARIO_SCRIPT="$SCENARIO_DIR/scenario.sh"
METADATA_FILE="$SCENARIO_DIR/metadata.json"
SCRIPT_DEST="/tmp/${SCENARIO_NAME}_scenario.sh"

if [ ! -f "$SCENARIO_SCRIPT" ]; then
  echo "scenario script not found: $SCENARIO_SCRIPT" >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command is required" >&2
  exit 1
fi

get_container_from_metadata() {
  metadata_path="$1"
  if [ ! -f "$metadata_path" ]; then
    echo ""
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$metadata_path" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fp:
    payload = json.load(fp)
print(str(payload.get("container_name") or "").strip())
PY
    return 0
  fi

  if command -v python >/dev/null 2>&1; then
    python - "$metadata_path" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fp:
    payload = json.load(fp)
print(str(payload.get("container_name") or "").strip())
PY
    return 0
  fi

  echo ""
}

CONTAINER_NAME="$CONTAINER_OVERRIDE"
if [ -z "$CONTAINER_NAME" ]; then
  CONTAINER_NAME="$(get_container_from_metadata "$METADATA_FILE")"
fi

if [ -z "$CONTAINER_NAME" ]; then
  echo "container name is required. set metadata.json.container_name or pass it as 2nd argument." >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
  echo "container not running: $CONTAINER_NAME" >&2
  exit 1
fi

docker cp "$SCENARIO_SCRIPT" "$CONTAINER_NAME:$SCRIPT_DEST"
docker exec "$CONTAINER_NAME" chmod +x "$SCRIPT_DEST"
docker exec "$CONTAINER_NAME" sh -lc "pkill -f '$SCRIPT_DEST' >/dev/null 2>&1 || true"
docker exec -d "$CONTAINER_NAME" sh "$SCRIPT_DEST"

echo "scenario started"
echo "- name: $SCENARIO_NAME"
echo "- container: $CONTAINER_NAME"
echo "- script_dest: $SCRIPT_DEST"
echo "- monitor: docker exec -it $CONTAINER_NAME sh -lc \"ps -ef | grep -E 'scenario|redis|nc' && netstat -tpln\""
