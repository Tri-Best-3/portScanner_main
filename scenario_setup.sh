#!/bin/sh
# Convenience wrapper.
exec "$(dirname "$0")/scenarios/scenario_setup.sh" "$@"
