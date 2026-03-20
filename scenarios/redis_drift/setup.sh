#!/bin/sh

# Copies the drift scenario into the current Redis lab container and runs it.

CONTAINER_NAME="${1:-vuln-redis-4-unacc}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

docker cp "$SCRIPT_DIR/scenario.sh" "$CONTAINER_NAME:/data/scenario.sh"
docker exec "$CONTAINER_NAME" chmod +x /data/scenario.sh
docker exec -d "$CONTAINER_NAME" sh /data/scenario.sh

echo "redis_drift scenario started in container: $CONTAINER_NAME"
