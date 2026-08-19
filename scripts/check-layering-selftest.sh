#!/usr/bin/env bash
#
# Red-proof for check-layering.sh: a gate ships with proof it can fail.
#
# The gate shipped green and was believed working because it was only ever exercised on
# the lowercase path. It passed `pub struct Nullifier` and it printed "clean." on an
# invalid regex. A gate is not verified by observing it pass; it is verified by observing
# it fail on each class it claims to catch, and pass on a clean tree.
#
# Runs in a scratch clone so the real tree is never mutated.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/check-layering.sh"
failed=0

check() {
  local want="$1" got="$2" what="$3"
  if [[ "$want" == "$got" ]]; then
    echo "  ok    $what (exit $got)"
  else
    echo "  FAIL  $what: expected exit $want, got $got"
    failed=1
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git -C "$ROOT" archive HEAD | tar -x -C "$work"
git -C "$work" init -q .
git -C "$work" add -A >/dev/null 2>&1
cp "$GATE" "$work/scripts/check-layering.sh"

run_gate() { ( cd "$work" && ./scripts/check-layering.sh >/dev/null 2>&1; echo $?; ); }

check 0 "$(run_gate)" "a clean tree passes"

printf '\npub struct Nullifier;\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "a CamelCase application type is refused"
git -C "$work" checkout -- crates/core/src/lib.rs

printf '\n// railgun\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "a lowercase application name is refused"
git -C "$work" checkout -- crates/core/src/lib.rs

printf '\n// contact 0x1234567890abcdef1234567890abcdef12345678\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "a 20-byte address literal is refused"
git -C "$work" checkout -- crates/core/src/lib.rs

# CHAIN_WORDS and DOMAIN_IDENTS had zero coverage: two of four classes is a false banner.
printf '\n// see eth_getLogs for the shape\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "a chain-specific RPC name is refused"
git -C "$work" checkout -- crates/core/src/lib.rs

printf '\nstruct NoteCommitment;\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "an application domain type is refused"
git -C "$work" checkout -- crates/core/src/lib.rs

# The shapes a `\b` anchor cannot express. Each of these passed the anchored gate.
printf '\nfn evm_state() {}\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "an underscore-joined chain identifier is refused (evm_state)"
git -C "$work" checkout -- crates/core/src/lib.rs

printf '\nstruct EvmClient;\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "a CamelCase chain identifier is refused (EvmClient)"
git -C "$work" checkout -- crates/core/src/lib.rs

printf '\nfn memo_bytes() {}\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "an underscore-joined domain identifier is refused (memo_bytes)"
git -C "$work" checkout -- crates/core/src/lib.rs

printf '\nstruct MemoField;\n' >> "$work/crates/core/src/lib.rs"
check 1 "$(run_gate)" "a CamelCase domain identifier is refused (MemoField)"
git -C "$work" checkout -- crates/core/src/lib.rs

# The false positive the anchor existed to prevent must still not fire.
printf '\nfn memory_budget() {}\nstruct MemoryPool;\n' >> "$work/crates/core/src/lib.rs"
check 0 "$(run_gate)" "the word 'memory' is NOT mistaken for the memo field"
git -C "$work" checkout -- crates/core/src/lib.rs

# git grep scans tracked files only, so an unadded file read clean.
printf 'pub struct Nullifier;\n' > "$work/crates/core/src/leak.rs"
check 1 "$(run_gate)" "an UNTRACKED file is scanned, not invisible"
rm -f "$work/crates/core/src/leak.rs"

# One NUL byte removed an entire file from a binary-skipping scan.
printf 'pub struct Nullifier;\n\x00\n' > "$work/crates/core/src/nul.rs"
git -C "$work" add crates/core/src/nul.rs >/dev/null 2>&1
check 1 "$(run_gate)" "a NUL byte does not hide a file from the scan"
git -C "$work" rm -q -f --cached crates/core/src/nul.rs >/dev/null 2>&1
rm -f "$work/crates/core/src/nul.rs"

# Direction of the dependency edge, enforced by path so a rename cannot evade it.
# Deliberately NOT `adapters/railgun/...`: that string contains an application word and
# would be caught by APP_WORDS anyway, which is how the old name-based probe came to be
# enforced by nothing of its own.
printf '\n[dependencies]\nsome-adapter = { path = "../../adapters/zzz/core" }\n' \
  >> "$work/crates/core/Cargo.toml"
check 1 "$(run_gate)" "a framework manifest pointing into a NON-railgun adapter is refused"
git -C "$work" checkout -- crates/core/Cargo.toml

sed -i "s|APP_WORDS='railgun|APP_WORDS='railgun(|" "$work/scripts/check-layering.sh"
check 1 "$(run_gate)" "a broken pattern fails closed rather than reading as clean"
cp "$GATE" "$work/scripts/check-layering.sh"

# And the dependency probe must be able to fail too: deleting it outright left the old
# selftest green, which meant that branch was enforced by nothing.
sed -i 's|fail "a framework crate declares a dependency on an adapter crate"|:|' \
  "$work/scripts/check-layering.sh"
printf '\n[dependencies]\nsome-adapter = { path = "../../adapters/zzz/core" }\n' \
  >> "$work/crates/core/Cargo.toml"
check 0 "$(run_gate)" "(control) with the dep probe disabled the same plant is missed"
git -C "$work" checkout -- crates/core/Cargo.toml
cp "$GATE" "$work/scripts/check-layering.sh"

if [[ $failed -ne 0 ]]; then
  echo "scripts/check-layering-selftest.sh: FAILED - the gate does not catch what it claims."
  exit 1
fi
echo "scripts/check-layering-selftest.sh: the gate fires on every class it claims."
exit 0
