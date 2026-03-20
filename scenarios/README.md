# Scenario Authoring Guide

Use this folder to manage shared drift scenarios.

## Folder Layout

```text
scenarios/
  scenario_setup.sh
  <scenario_name>/
    scenario.sh
    metadata.json
```

Examples:

- `scenarios/redis_drift/scenario.sh`
- `scenarios/redis_drift/metadata.json`
- `scenarios/samba_drift/scenario.sh`
- `scenarios/samba_drift/metadata.json`

## Rules

1. Keep the scenario body in one file: `scenario.sh`.
2. Assume `scenario.sh` runs inside the target container.
3. Do not hardcode container or host in the script; use backend registry metadata instead.
4. Do not kill the container main process.
5. Make drift behavior explicit (ports and/or services must clearly change over time).

## Runtime Preconditions

1. `scenario.sh` should fail fast with a clear log when required binaries are missing.
2. For `redis_drift`:
- `redis-server` and `redis-cli` are required.
- `nc` is required for tcp/22 and tcp/80 simulation.
- If Redis is PID 1 in the container, 6379 start/stop drift must be disabled to avoid killing the main process.
3. Always keep a preflight check at startup so unsupported environments do not silently pass.

## Backend Registry Fields (`metadata.json`)

Each scenario folder should include `metadata.json`.

Required fields:

- `name`: scenario name
- `target_hint`: target identifier hint
- `container_name`: target container name
- `script_path`: script path (example: `scenarios/redis_drift/scenario.sh`)
- `description`: scenario description

Example:

```json
{
  "name": "redis_drift",
  "target_hint": "redis-4-unacc.lab.local",
  "container_name": "vuln-redis-4-unacc",
  "script_path": "scenarios/redis_drift/scenario.sh",
  "description": "Randomly toggles Redis/SSH/HTTP ports to induce drift."
}
```

## Run

From local terminal:

```sh
./scenario_setup.sh redis_drift
```

Or:

```sh
./scenarios/scenario_setup.sh redis_drift
```

Container status check:

```sh
docker exec -it vuln-redis-4-unacc sh -lc "ps -ef | grep -E 'scenario|redis|nc' && netstat -tpln"
```
