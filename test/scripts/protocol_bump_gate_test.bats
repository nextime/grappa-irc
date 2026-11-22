#!/usr/bin/env bats
#
# scripts/protocol-bump-gate.sh — a branch that moves the wire shape claims
# exactly the base's protocol number + 1 (#2695, review X4 item 2).
#
# `mix grappa.wire_pin --check` proves a branch is consistent WITH ITSELF:
# the shape and the number in `priv/wire/shape.pin` agree. It cannot see two
# branches that both bumped 64 -> 65 for different shapes, because each is
# consistent on its own. Today `protocol.ex` holds the ritual for that by hand
# ("Checked for a collision before claiming N", 30 times). This gate turns it
# into a red build: the BEFORE is the base ref's pin, at the base's TIP, since
# the colliding bump lands on main after the branch was cut.
#
# Every case builds a scratch repo, so what is judged is what git holds, not
# a fixture string. The gate takes the base ref as its argument for that
# reason, and resolves the repo it is run IN rather than the one it was
# copied from.

load ../bats_helpers

setup() {
    GATE_SRC="$BATS_TEST_DIRNAME/../../scripts/protocol-bump-gate.sh"
}

write_pin() {
    local version="$1" digest="$2"
    mkdir -p priv/wire
    printf '# comment\nprotocol_version = %s\nshape_digest = sha256:%s\n' \
        "$version" "$digest" > priv/wire/shape.pin
}

# A repo whose `main` carries pin (64, aaaa) and a `feat` branch cut from it.
# Leaves `feat` checked out, so each case writes the branch's pin next.
scratch() {
    REPO="$BATS_TEST_TMPDIR/repo"
    rm -rf "$REPO"
    mkdir -p "$REPO/scripts"
    cp "$GATE_SRC" "$REPO/scripts/protocol-bump-gate.sh"
    chmod 0755 "$REPO/scripts/protocol-bump-gate.sh"
    cd "$REPO"
    git -c init.defaultBranch=main init -q .
    git config user.email bats@example.invalid
    git config user.name bats
    write_pin 64 aaaa
    git add -A
    git commit -qm base
    git checkout -q -b feat
}

gate() {
    run scripts/protocol-bump-gate.sh main
}

@test "an unchanged shape at an unchanged number passes" {
    scratch
    gate
    [ "$status" -eq 0 ]
    [[ "$output" == *"protocol 64"* ]]
}

@test "a shape change that claims the base's number + 1 passes" {
    scratch
    write_pin 65 bbbb
    gate
    [ "$status" -eq 0 ]
    [[ "$output" == *"64 -> 65"* ]]
}

@test "a shape change at the base's own number fails" {
    scratch
    write_pin 64 bbbb
    gate
    [ "$status" -eq 1 ]
    [[ "$output" == *"shape changed"* ]]
    [[ "$output" == *"claim 65"* ]]
}

@test "the collision: another branch landed the same number first, and this one fails" {
    # Both branches were cut at 64 and both claimed 65. `main` lands first.
    scratch
    write_pin 65 bbbb
    git commit -qam 'feat claims 65'
    git checkout -q main
    write_pin 65 cccc
    git commit -qam 'another branch lands 65'
    git checkout -q feat

    # Precondition: feat is consistent with ITSELF — the case wire_pin --check
    # passes and this gate exists for.
    grep -qx 'protocol_version = 65' priv/wire/shape.pin

    gate
    [ "$status" -eq 1 ]
    [[ "$output" == *"main already carries 65"* ]]
    [[ "$output" == *"claim 66"* ]]
}

@test "a number that skips past the base's + 1 fails" {
    scratch
    write_pin 66 bbbb
    gate
    [ "$status" -eq 1 ]
    [[ "$output" == *"claim 65"* ]]
}

@test "a number below the base's fails — the branch is behind" {
    scratch
    write_pin 63 aaaa
    gate
    [ "$status" -eq 1 ]
    [[ "$output" == *"below"* ]]
}

@test "a bump without a shape change passes — the ruling bumps on every shape change, not only on one" {
    scratch
    write_pin 65 aaaa
    gate
    [ "$status" -eq 0 ]
}

@test "the base's pin is read at the base's TIP, not at the merge base" {
    # The collision does not exist at the merge base: there, main is still at
    # 64 and feat's 65 looks like a correct +1. A gate measuring against the
    # merge base passes every real occurrence.
    scratch
    write_pin 65 bbbb
    git commit -qam 'feat claims 65'
    git checkout -q main
    write_pin 65 cccc
    git commit -qam 'another branch lands 65'
    git checkout -q feat
    [ "$(git show "$(git merge-base main feat)":priv/wire/shape.pin | sed -n 's/^protocol_version = //p')" = 64 ]

    gate
    [ "$status" -eq 1 ]
}

@test "an unresolvable base ref fails rather than passing vacuously" {
    scratch
    run scripts/protocol-bump-gate.sh no-such-ref
    [ "$status" -eq 1 ]
    [[ "$output" == *"no-such-ref"* ]]
}

@test "a pin missing its version line fails rather than reading a default" {
    scratch
    printf 'shape_digest = sha256:bbbb\n' > priv/wire/shape.pin
    gate
    [ "$status" -eq 1 ]
    [[ "$output" == *"protocol_version"* ]]
}

@test "the committed pin passes against itself" {
    # The real repo, against its own HEAD: the gate reads the committed pin
    # format, not only the scratch one.
    cd "$BATS_TEST_DIRNAME/../.."
    run "$GATE_SRC" HEAD
    [ "$status" -eq 0 ]
}
