#!/usr/bin/env bash
# A branch that moves the wire shape claims exactly the base's protocol
# number + 1 (#2695, architecture review 2026-11-21 finding X4, item 2).
#
# Usage:
#   scripts/protocol-bump-gate.sh            # check against origin/main
#   scripts/protocol-bump-gate.sh <base-ref> # check against another base
#
# WHAT `mix grappa.wire_pin --check` CANNOT SEE. That gate proves a branch
# agrees WITH ITSELF: the shape digest and the number in priv/wire/shape.pin
# match the tree. Two branches cut at 64 that both bump to 65 for different
# shapes are each consistent on their own, so both pass it, and whichever
# lands second ships a 65 that means two different shapes. Until now the cure
# was a ritual typed into protocol.ex by hand ("Checked for a collision before
# claiming N" appears 30 times). This is that ritual as a red build.
#
# THE BEFORE IS THE BASE REF'S TIP, NOT THE MERGE BASE. The collision lands on
# main AFTER the branch was cut; at the merge base main is still at 64 and the
# branch's 65 looks like a correct +1. Same finding as design-notes-gate.sh's
# check 3, and easy to undo by tidying.
#
# The verdict, with B the base's pin and H this tree's:
#
#   H.version <  B.version        FAIL  behind the base: rebase
#   H.version >  B.version + 1    FAIL  skips a number: claim B + 1
#   H.version == B.version, digest moved
#                                 FAIL  the shape changed without a bump, or
#                                       another branch landed this number first
#   anything else                 pass  (unchanged; +1 with the shape; or +1
#                                        with no shape change, which the ruling
#                                        allows — it bumps on EVERY shape
#                                        change, it does not forbid other bumps)
#
# Reads two files and runs `git show`; no mix, no network beyond what the
# checkout already fetched. CI needs fetch-depth: 0, as the DESIGN_NOTES gate
# does, so that origin/main resolves.
#
# Exit 0 = the claim is right. Exit 1 = a finding, an unreadable pin, or a base
# ref that does not resolve: a gate that cannot reach its base FAILS, it never
# passes vacuously.

set -euo pipefail

readonly PIN="priv/wire/shape.pin"
BASE_REF="${1:-origin/main}"

# The repo we are IN — the bats suite runs this inside a scratch repository.
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

die() {
	printf 'protocol-bump-gate: %s\n' "$*" >&2
	exit 1
}

# One field of a pin's text, or die naming it. A missing line is an error,
# never a default: a pin that reads as a default is a gate that passes on a
# file nobody wrote (the same rule as WirePin.parse_pin/1).
field() {
	local text="$1" key="$2" where="$3" value
	value="$(printf '%s\n' "$text" | sed -n "s/^${key} = //p")"
	[ -n "$value" ] || die "$where has no \`${key} = …\` line"
	printf '%s' "$value"
}

git rev-parse --verify --quiet "${BASE_REF}^{commit}" >/dev/null \
	|| die "base ref '$BASE_REF' does not resolve. In CI this means the checkout is shallow — actions/checkout needs fetch-depth: 0."

base_text="$(git show "${BASE_REF}:${PIN}" 2>/dev/null)" \
	|| die "$BASE_REF has no $PIN"
[ -f "$PIN" ] || die "this tree has no $PIN"
head_text="$(cat "$PIN")"

base_version="$(field "$base_text" protocol_version "$BASE_REF:$PIN")"
base_digest="$(field "$base_text" shape_digest "$BASE_REF:$PIN")"
head_version="$(field "$head_text" protocol_version "$PIN")"
head_digest="$(field "$head_text" shape_digest "$PIN")"

case "$base_version$head_version" in
	*[!0-9]*) die "protocol_version is not an integer ($BASE_REF: '$base_version', tree: '$head_version')" ;;
esac

next=$((base_version + 1))

if [ "$head_version" -lt "$base_version" ]; then
	die "this tree's protocol $head_version is below $BASE_REF's $base_version — the branch is behind its base. Rebase it, then claim $next if it moves the shape."
fi

if [ "$head_version" -gt "$next" ]; then
	die "this tree claims protocol $head_version but $BASE_REF is at $base_version — a bump is +1 and never skips: claim $next."
fi

if [ "$head_version" -eq "$base_version" ] && [ "$head_digest" != "$base_digest" ]; then
	{
		printf 'protocol-bump-gate: the wire shape changed and the protocol number is %s on both sides.\n\n' "$head_version"
		printf '  shape digest   %s %s\n' "$BASE_REF" "$base_digest"
		printf '                 tree %s\n\n' "$head_digest"
		printf 'Either this branch moved the shape without a bump, or another branch landed\n'
		printf 'a bump first and %s already carries %s for a DIFFERENT shape. Both cures are\n' "$BASE_REF" "$head_version"
		printf 'the same: rebase, set @protocol_version to %s, run mix grappa.gen_wire_types\n' "$next"
		printf 'and mix grappa.wire_pin --update, and claim %s.\n' "$next"
	} >&2
	exit 1
fi

if [ "$head_version" -eq "$base_version" ]; then
	printf 'protocol-bump-gate: shape and protocol %s unchanged against %s.\n' "$head_version" "$BASE_REF"
elif [ "$head_digest" != "$base_digest" ]; then
	printf 'protocol-bump-gate: the shape moved and the number moved with it, %s -> %s against %s.\n' \
		"$base_version" "$head_version" "$BASE_REF"
else
	printf 'protocol-bump-gate: protocol %s -> %s against %s with the shape unchanged.\n' \
		"$base_version" "$head_version" "$BASE_REF"
fi
