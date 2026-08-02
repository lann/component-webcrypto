#!/usr/bin/env bash
# Run `just <recipe>` for every recipe named in the arguments, in parallel,
# buffering each recipe's output to <log-dir>/<recipe>.log and printing it
# whole as each finishes (in argument order), so failures read per recipe.
# Exits nonzero if any recipe failed — after every recipe's verdict and log
# have been printed, so one failure never hides another's outcome.
#
# The recipes must be independent: anything they share (build artifacts,
# node_modules, generated bindings) must already exist, and anything they
# write must be theirs alone.
#
# Usage: parallel-recipes.sh <log-dir> <recipe> [<recipe>...]
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 <log-dir> <recipe> [<recipe>...]" >&2
    exit 2
fi

logdir="$1"
shift
mkdir -p "$logdir"

echo "running in parallel: $* (logs in $logdir/)"
pids=()
for recipe in "$@"; do
    just "$recipe" > "$logdir/$recipe.log" 2>&1 &
    pids+=($!)
done

status=0
i=0
for recipe in "$@"; do
    verdict=ok
    wait "${pids[$i]}" || { verdict="FAILED (exit $?)"; status=1; }
    echo "--- $recipe: $verdict ---"
    cat "$logdir/$recipe.log"
    i=$((i + 1))
done
exit $status
