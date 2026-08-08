#!/usr/bin/env bash
#
# Guardrail checks — SPEC §8.8.
#
# Three classes of failure this catches, all of which are easy to introduce and
# hard to notice in review:
#
#   1. Logging plaintext or key material.
#   2. Marketing language forbidden by §2.4.
#   3. Relay access logging silently re-enabled.
#
# Every check prints what it found and exits non-zero. None of them are
# advisory.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

fail=0
note() { printf '\n\033[1m%s\033[0m\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
good() { printf '  pass  %s\n' "$1"; }

# A line carrying this marker is exempt from the greps below.
#
# The exemption is per line and has to be written deliberately next to the code
# it covers, which is the property that matters: a test asserting that a banned
# term never renders necessarily contains the banned term, and blanket-excluding
# whole files to cope with that would punch a hole exactly where the checks are
# most needed. The marker keeps the hole one line wide and visible in review.
ALLOW='guardrail-allow'

# Runs a git grep and drops exempt lines. Returns 0 when something survived.
scan() {
  local out
  out=$(git grep "$@" 2>/dev/null | grep -v "$ALLOW")
  [ -n "$out" ] && { printf '%s\n' "$out"; return 0; }
  return 1
}

# Paths that are allowed to talk about these things: the docs that define the
# rules, and this script. Everything else is subject to the greps.
EXCLUDES=(
  ':(exclude)scripts/check-guardrails.sh'
  ':(exclude)docs/DECISIONS.md'
  ':(exclude)docs/DESIGN_SYSTEM.md'
  ':(exclude)docs/LIMITATIONS.md'
  ':(exclude)docs/THREAT_MODEL.md'
  ':(exclude)docs/PROGRESS.md'
  ':(exclude)README.md'
  ':(exclude)docs/CONTEXT.md'
  ':(exclude)SPEC.md'
  # Implementation plans, not shipped documentation or product copy — they
  # necessarily quote the prime directives they must satisfy (same reason
  # SPEC.md and DECISIONS.md are excluded above) and often contain literal
  # test code asserting these terms are absent from the UI.
  ':(exclude)docs/superpowers/plans/**'
)

# ---------------------------------------------------------------------------
note "1. Plaintext and key material must never reach a log"

# Matches a logging macro or console call whose arguments mention something
# secret. Deliberately broad: a false positive costs a rename, a false negative
# costs the property the whole product is built on.
SECRET_LOG='(println!|eprintln!|dbg!|print!|log::(trace|debug|info|warn|error)!|tracing::(trace|debug|info|warn|error)!|console\.(log|debug|info|warn|error))[^;]*\b(plaintext|secret_key|private_key|secret|passphrase|password|key_material|session_key|file_key|derived_key|seed|nonce)\b'

if hits=$(scan -nInE "$SECRET_LOG" -- . "${EXCLUDES[@]}"); then
  bad "logging statement referencing secret material:"
  printf '%s\n' "$hits" | sed 's/^/        /'
else
  good "no logging statement references secret material"
fi

# `dbg!` prints whatever it is given and is never intentional in committed code.
if hits=$(scan -nIn 'dbg!(' -- '*.rs' "${EXCLUDES[@]}"); then
  bad "dbg! left in committed code:"
  printf '%s\n' "$hits" | sed 's/^/        /'
else
  good "no dbg! in committed code"
fi

# ---------------------------------------------------------------------------
note "2. Forbidden marketing language (SPEC §2.4)"

# Word-boundary anchored so that legitimate prose is not caught. "absolute" is
# excluded from this list on purpose: it collides with CSS `position: absolute`
# and `absolute path`, and the claim it would make is already covered by the
# other terms.
BANNED='\b(unbreakable|uncrackable|military[ -]?grade|bank[ -]?grade|NSA[ -]?proof|quantum[ -]?proof|hacker[ -]?proof|100% secure|unhackable)\b'

if hits=$(scan -nIniE "$BANNED" -- . "${EXCLUDES[@]}"); then
  bad "forbidden marketing term:"
  printf '%s\n' "$hits" | sed 's/^/        /'
else
  good "no forbidden marketing terms"
fi

# The excluded docs may *name* these terms in order to forbid them, but must
# never make the claim. Catch the assertion form specifically.
# SPEC.md is the specification, not product copy: it quotes these terms in
# order to ban them. Everything else — including the docs excluded above — is
# checked, because a doc that *asserts* a banned claim is the exact failure
# this second pass exists to catch.
if hits=$(scan -nIniE '\b(is|are|it.s) (unbreakable|uncrackable|100% secure|unhackable)\b' -- . ':(exclude)SPEC.md'); then
  bad "a document asserts a forbidden claim rather than forbidding it:"
  printf '%s\n' "$hits" | sed 's/^/        /'
else
  good "no document asserts a forbidden claim"
fi

# ---------------------------------------------------------------------------
note "3. Relay access logging must be explicitly disabled (SPEC §2.3)"

if [ -f server/src/main.rs ]; then
  # tower-http's TraceLayer is the standard way an axum service starts logging
  # requests. Its presence in the relay is a defect, not a debugging aid.
  #
  # Matched on *usage* (`TraceLayer::…`, or the module import) rather than the
  # bare word, so documentation explaining why the relay has no tracing does
  # not trip the check that enforces it.
  if hits=$(scan -nInE 'TraceLayer::|tower_http::trace|use tower_http::\{[^}]*trace' -- server/); then
    bad "relay pulls in request tracing:"
    printf '%s\n' "$hits" | sed 's/^/        /'
  else
    good "relay does not use TraceLayer"
  fi

  # A positive assertion, not merely the absence of one: the relay must contain
  # the marker constant that its no-logging test asserts against.
  if git grep -qIn 'ACCESS_LOGGING_DISABLED' -- server/ 2>/dev/null; then
    good "relay declares ACCESS_LOGGING_DISABLED"
  else
    bad "relay does not declare ACCESS_LOGGING_DISABLED (see server/src/main.rs)"
  fi
else
  good "relay not yet implemented — skipped"
fi

# ---------------------------------------------------------------------------
note "4. Forbidden primitives and weak randomness (SPEC §2.1)"

SRC=('*.rs' '*.ts' '*.tsx' '*.js' '*.mjs' '*.kt' '*.css')
if hits=$(scan -nIniE '\b(Math\.random|ECB|rand::random\b)' -- "${SRC[@]}" "${EXCLUDES[@]}"); then
  bad "non-CSPRNG or ECB mode reference:"
  printf '%s\n' "$hits" | sed 's/^/        /'
else
  good "no Math.random, no ECB"
fi

# ---------------------------------------------------------------------------
if [ "$fail" -eq 0 ]; then
  printf '\n\033[1mAll guardrail checks passed.\033[0m\n'
else
  printf '\n\033[1mGuardrail checks failed.\033[0m See SPEC §2.1–2.4.\n'
fi
exit "$fail"
