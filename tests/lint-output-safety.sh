#!/usr/bin/env bash
# Lint: enforce no NEW unsafe `OUTPUT=$(acme ...)` sites in tests/test.sh.
#
# A site is "unsafe" when ALL of the following hold:
#   - matches `OUTPUT=$(acme ...)` (single- or multi-line)
#   - NOT prefixed with `if ` (which makes the assignment conditional)
#   - NOT inside a `set +e` / `set -e` block
#   - command does NOT end with `|| true)` (inline error suppression)
#   - NOT followed by `RC=$?` on the next non-blank line (RC capture pattern)
#
# Unsafe sites under `set -euo pipefail` cause the entire test suite to abort
# silently on any non-zero `acme` exit (no diagnostic, no log line), which is
# how the SEC-08/10/13 sweeps broke TC-02/03/38 without warning.
#
# Today the codebase has FROZEN_COUNT legitimate unsafe sites — most are
# expected-success operations where abort-on-failure is intended behavior.
# This linter freezes that count so any NEW unsafe site added in a PR fails
# CI with a pointer to the file:line range to investigate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_FILE="${SCRIPT_DIR}/test.sh"
FROZEN_COUNT=43

if [[ ! -f "${TEST_FILE}" ]]; then
  echo "ERROR: ${TEST_FILE} not found" >&2
  exit 2
fi

UNSAFE_LINES=$(awk '
  BEGIN { in_unsafe=0; in_cmd=0; cmd_start=0; full_cmd="" }
  /^[[:space:]]*set \+e[[:space:]]*$/ { in_unsafe=1 }
  /^[[:space:]]*set -e[[:space:]]*$/ { in_unsafe=0 }
  {
    if (in_cmd) {
      full_cmd = full_cmd " " $0
      if ($0 ~ /\)/ && !($0 ~ /\\$/)) {
        getline nextline
        is_safe = (full_cmd ~ /\|\|[[:space:]]*true[[:space:]]*\)/) || (nextline ~ /RC=\$\?/)
        if (!is_safe) print cmd_start
        in_cmd = 0
        full_cmd = ""
        if (nextline ~ /^[[:space:]]*set \+e/) in_unsafe=1
        if (nextline ~ /^[[:space:]]*set -e/) in_unsafe=0
      }
    } else if (/OUTPUT=\$\(acme/ && !($0 ~ /^[[:space:]]*if /) && !in_unsafe) {
      cmd_start = NR
      full_cmd = $0
      if ($0 ~ /\)/ && !($0 ~ /\\$/)) {
        getline nextline
        is_safe = (full_cmd ~ /\|\|[[:space:]]*true[[:space:]]*\)/) || (nextline ~ /RC=\$\?/)
        if (!is_safe) print cmd_start
        full_cmd = ""
        if (nextline ~ /^[[:space:]]*set \+e/) in_unsafe=1
        if (nextline ~ /^[[:space:]]*set -e/) in_unsafe=0
      } else {
        in_cmd = 1
      }
    }
  }
' "${TEST_FILE}")

CURRENT_COUNT=$(echo "${UNSAFE_LINES}" | grep -c . || true)

if [[ ${CURRENT_COUNT} -gt ${FROZEN_COUNT} ]]; then
  echo "ERROR: ${TEST_FILE} has ${CURRENT_COUNT} unsafe OUTPUT=\$(acme ...) sites, frozen budget is ${FROZEN_COUNT}." >&2
  echo "       New unsafe site(s) introduced. Choose ONE remediation:" >&2
  echo "         1. Wrap in 'if OUTPUT=\$(...); then ... fi'" >&2
  echo "         2. Suffix with '|| true' if non-zero exit is expected" >&2
  echo "         3. Wrap in 'set +e ... RC=\$? ... set -e' block" >&2
  echo "" >&2
  echo "       All current unsafe sites (${CURRENT_COUNT}):" >&2
  echo "${UNSAFE_LINES}" | sed 's/^/         tests\/test.sh:/' >&2
  exit 1
fi

if [[ ${CURRENT_COUNT} -lt ${FROZEN_COUNT} ]]; then
  echo "INFO: unsafe site count dropped from ${FROZEN_COUNT} to ${CURRENT_COUNT}. Update FROZEN_COUNT in $0." >&2
  exit 0
fi

echo "OK: tests/test.sh has ${CURRENT_COUNT} unsafe OUTPUT sites (frozen budget: ${FROZEN_COUNT})"
