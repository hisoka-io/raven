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
# A 20-byte address literal has no business in a scheme-agnostic framework.
ADDRESS_LITERAL='0x[0-9a-fA-F]{40}'

# `evm` and `memo` are matched CASE-SENSITIVELY and shape-by-shape. A `\b` anchor cannot
# express these: `_` is a regex word character and CamelCase has no boundary, so `\bevm\b`
# passes `evm_state()`, `"evm_chain_id"`, `EvmClient`, `memo_bytes()` and `MemoField` -
# every realistic leak. A bare `memo` cannot be used instead because `memory` is a real
# word in this tree (`crates/core/src/lib.rs`, `crates/binary-fuse-filter/src/filter.rs`).
CHAIN_WORDS_CI='ethereum|eth_call|eth_getLogs|eth_chainId'
CHAIN_IDENTS_CS='\bevm\b|\bevm_|_evm\b|_evm_|\bEvm[A-Z]|[a-z]Evm'
DOMAIN_IDENTS_CI='note_commitment|blinded_commitment'
DOMAIN_IDENTS_CS='NoteCommitment|(struct|enum) Note\b|\bmemo\b|\bmemo_|_memo\b|_memo_|\bMemo[A-Z]|[a-z]Memo'

# `-i` because the patterns above are documented as any-case, and a case-sensitive run
# passes `pub struct Nullifier` (measured: 2146 vs 2734 hits over adapters/, a 588-line
# CamelCase blind spot).
#
# The exit status is checked rather than the output emptiness. `git grep` exits 0 on a
# match, 1 on none, and >=2 on an error - so an invalid pattern or a git failure yields
# empty output, which an emptiness test reads as a clean tree. Stderr is NOT discarded.
# `--untracked`: `git grep` scans tracked files only, so a brand-new
# `crates/core/src/leak.rs` full of application vocabulary read clean until it was added.
# `-a` rather than `-I`: one NUL byte, or a committed `.gitattributes` `binary` or `-diff`
# entry, removes an entire file from a binary-skipping scan. Verified no file under
# `crates/` (excluding the submodule) contains a NUL, so this adds no noise.
scan() { # case_flag ('-i' or '') then pattern
  local hits rc
  if [[ -n "$1" ]]; then
    hits="$(git grep --untracked -anE "$1" "$2" "${SCOPE[@]}")"
  else
    hits="$(git grep --untracked -anE "$2" "${SCOPE[@]}")"
  fi
  rc=$?
  case "$rc" in
    0) echo "$hits"; fail "application vocabulary in crates/ (pattern: $2)" ;;
    1) : ;;
    *) fail "git grep failed with status $rc on pattern: $2 (a broken gate is not a clean tree)" ;;
  esac
}

scan -i "$APP_WORDS"
scan -i "$ADDRESS_LITERAL"
scan -i "$CHAIN_WORDS_CI"
scan ''  "$CHAIN_IDENTS_CS"
scan -i "$DOMAIN_IDENTS_CI"
scan ''  "$DOMAIN_IDENTS_CS"

# Direction of the dependency edge, by PATH rather than by package name: the name probe
# was subsumed by APP_WORDS over a wider pathspec and missed any adapter not called
# `raven-railgun`. A framework manifest may never point into `adapters/`.
dep_hits="$(git grep --untracked -anE 'path\s*=\s*"[^"]*adapters/|^\s*raven-railgun|raven-railgun[a-z-]*\s*=' -- 'crates/*/Cargo.toml')"
dep_rc=$?
case "$dep_rc" in
  0) echo "$dep_hits"; fail "a framework crate declares a dependency on an adapter crate" ;;
  1) : ;;
  *) fail "git grep failed with status $dep_rc on the dependency probe" ;;
esac

if [[ $failed -ne 0 ]]; then
  echo "scripts/check-layering.sh: failed."
  exit 1
fi

echo "scripts/check-layering.sh: clean."
exit 0
