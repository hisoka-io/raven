#!/usr/bin/env bash
#
# Layering gate for the two-repo doctrine: Raven core stays a general-purpose PIR
# framework, and every application specific lives in an adapter.
#
# Enforces two properties over `crates/` (the framework), and nothing else:
#
#   1. No application vocabulary. A DNS-privacy or medical-records consumer must be
#      able to depend on these crates without inheriting one consumer's domain.
#   2. No framework crate depends on an adapter crate. The edge runs adapter ->
#      framework, never back.
#
# `crates/inspire` is EXCLUDED: it is a vendored submodule with its own history and
# its own upstream, corrected through a submodule change rather than here.
# `adapters/`, `examples/` and `benches/` are EXCLUDED by design - the eth-state
# example is a second adapter and Ethereum vocabulary is correct there.
#
# Patterns are deliberately identifier-shaped where a bare word would collide with
# ordinary English: `memo` is word-anchored so it cannot match `memory`, and `Note`
# is matched only in declaration or compound form so that `/// Note: ...` stays legal.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=0
fail() { echo "LAYERING: $1"; failed=1; }

SCOPE=(-- 'crates/**' ':!:crates/inspire/*')

# Unambiguous application names: any occurrence, any case.
APP_WORDS='railgun|darkpool|nullifier|hisoka|ppoi'
# Chain specifics. `evm` is word-anchored so it cannot match `evmulate`-style names.
CHAIN_WORDS='ethereum|\bevm\b|eth_call|eth_getLogs|eth_chainId'
# Ambiguous in English, so matched only where they denote the application type.
DOMAIN_IDENTS='note_commitment|NoteCommitment|(struct|enum) Note\b|\bmemo\b|blinded_commitment'
# A 20-byte address literal has no business in a scheme-agnostic framework.
ADDRESS_LITERAL='0x[0-9a-fA-F]{40}'

for pat in "$APP_WORDS" "$CHAIN_WORDS" "$DOMAIN_IDENTS" "$ADDRESS_LITERAL"; do
  hits="$(git grep -InE "$pat" "${SCOPE[@]}" 2>/dev/null)"
  if [[ -n "$hits" ]]; then
    echo "$hits"
    fail "application vocabulary in crates/ (pattern: $pat)"
  fi
done

# Direction of the dependency edge. Adapter package names are `raven-railgun-*`.
dep_hits="$(git grep -InE '^\s*raven-railgun|raven-railgun[a-z-]*\s*=' -- 'crates/*/Cargo.toml' 2>/dev/null)"
if [[ -n "$dep_hits" ]]; then
  echo "$dep_hits"
  fail "a framework crate declares a dependency on an adapter crate"
fi

if [[ $failed -ne 0 ]]; then
  echo "scripts/check-layering.sh: failed."
  exit 1
fi

echo "scripts/check-layering.sh: clean."
exit 0
