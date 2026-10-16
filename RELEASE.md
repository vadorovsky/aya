# Releasing the aya project

This document describes the process of releasing the crates in this repository.
This project does not use cargo-smart-release; releases are cut manually.

## Who can release?

Only members of [aya-rs/owners][owners-team] have the permissions to:

- Push packages to crates.io
- Push release tags to the default branch

## The dependency graph

Release order is constrained by which crate depends on which:

```text
aya-obj ──────────────> aya ──────────────> aya-log
aya-log-common ──> aya-log-parser ──> aya-log-ebpf-macros ──> aya-log-ebpf
aya-ebpf-cty ──> aya-ebpf-bindings ──> aya-ebpf ──────────────┘
aya-ebpf-macros ───────────────────────> aya-ebpf
```

In addition, `aya-build` is a *build* dependency of `aya-ebpf-cty`,
`aya-ebpf-bindings`, and `aya-ebpf` (declared with a `version` constraint in
their `[build-dependencies]`). Build dependencies are resolved from
crates.io for a crate's users and are checked by `cargo publish --dry-run`,
so `aya-build` must already be on crates.io at the version the constraint
allows before those crates can be published, and the constraint must be
updated in the same release commit if `aya-build` jumps a major or minor
version that the old caret constraint no longer admits.

A crate can only be published after all of its published dependencies are on
crates.io, so publish in this wave order:

1. `aya-build`, `aya-ebpf-macros`, `aya-obj`, `aya-log-common` (no published
   dependencies)
2. `aya-ebpf-cty`, `aya`, `aya-log-parser`
3. `aya-ebpf-bindings`, `aya-log-ebpf-macros`
4. `aya-ebpf`
5. `aya-log-ebpf`, `aya-log`

Within a wave the crates are independent and can be published in any order.

## Step 1: Find which crates changed since their last release

For every published crate, compare its latest tag with `HEAD`:

```sh
for d in aya aya-build aya-ebpf-macros aya-log-common aya-log-ebpf-macros \
         aya-log-parser aya-log aya-obj ebpf/aya-ebpf ebpf/aya-ebpf-bindings \
         ebpf/aya-ebpf-cty ebpf/aya-log-ebpf; do
  name=$(sed -n 's/^name = "\(.*\)"/\1/p' "$d/Cargo.toml" | head -1)
  tag=$(git tag -l "$name-v*" | sort -V | tail -1)
  echo "$name ($tag): $(git rev-list --count "$tag..HEAD" -- $d) commits"
done
```

A crate needs a release when the commit range contains user-visible changes
(source, dependency changes, MSRV). Commits that only touch docs or build
files (e.g. the Bazel graph) do not require a new version by themselves, but
if the crate is released anyway for another reason, the patch version still
advances.

## Step 2: Choose the version bumps

Determine for each crate whether the changes since its last release are
breaking, additive, or neither. The reliable signal is the public API fixture
in `xtask/public-api/<crate>.txt`:

```sh
cargo +nightly xtask public-api --bless --target x86_64-unknown-linux-gnu
git diff -- xtask/public-api/
```

Compare the diff for each crate against its latest tag
(`git diff $(git tag -l aya-v* | sort -V | tail -1) HEAD --
xtask/public-api/aya.txt`):

- **Major bump** (`x.y.0` → `x+1.0.0`): the fixture contains removed or
  changed public items (functions, types, impls, trait bounds). Examples of
  breaking changes: removing a `pub fn`, changing a signature, removing a
  trait impl such as `Borrow` or `From`.
- **Minor bump** (`x.y.z` → `x.y+1.0`): the fixture only grows (new types,
  functions, or impls).
- **Patch bump** (`x.y.z` → `x.y.z+1`): the fixture is unchanged, or only
  cosmetic (e.g. `Self` vs fully-qualified type in derive-generated
  signatures); or the change is internal (dependency bumps, build fixes,
  MSRV bump).

Note: a workspace-wide MSRV bump is a breaking change for users pinned to the
old MSRV. If the MSRV in `Cargo.toml` (`rust-version`) increased since the
crate's last release, the bump must be at least minor, and usually major is
more honest for pre-1.0 crates.

## Step 3: Bump the versions

On a fresh branch based on the default branch:

1. In every released crate's `Cargo.toml`, update `version = "..."`.
2. In every released crate that has a published intra-workspace dependency
   that also changed version, update that dependency's `version = "^x.y.z"`
   constraint to the new version, in both `[dependencies]` and
   `[build-dependencies]`. The affected pairs are exactly the edges of the
   dependency graph above.
3. Update `Cargo.lock` with `cargo update -w` (or a plain `cargo build` will
   pick it up).

## Step 4: Write changelog entries

Every published crate has a `CHANGELOG.md` in Keep a Changelog format with an
`## [Unreleased]` section at the top. For each released crate, move the
relevant entries from `## [Unreleased]` into a new
`## v<version> (<YYYY-MM-DD>)` section, and leave a fresh empty
`## [Unreleased]` above it. Group entries under `### Added`, `### Changed`,
`### Fixed`, `### Removed`, `### Chore` etc. If the crate's `Unreleased`
section is empty (e.g. the only change was a dependency or MSRV bump), write
a short entry describing that under `### Chore`.

## Step 5: Verify the public API fixtures

If any crate's public API changed, step 2 already blessed the fixtures.
Confirm the fixture diff matches the intended changes and that the blessed
fixtures are part of the release commit. The fixtures must be regenerated for
Linux x86-64 GNU (see AGENTS.md).

## Step 6: Commit and tag

Create one commit containing all version bumps, changelogs, and blessed
fixtures. The commit message lists every released crate and its version, e.g.

```
Bump aya v0.15.0, aya-obj v0.4.0, aya-ebpf v0.3.0, ...
```

Then create one annotated tag per released crate, all pointing at the same
commit, using the `crate-name-vX.Y.Z` convention:

```sh
for t in aya-v0.15.0 aya-obj-v0.4.0 aya-ebpf-v0.3.0; do
  git tag -a "$t" -m "Release $t"
done
```

## Step 7: Publish

Publish in wave order (see the dependency graph section), from the workspace
root. The local toolchain must satisfy the workspace MSRV
(`rust-version` in the root `Cargo.toml`).

```sh
# Wave 1
cargo publish --dry-run -p aya-build      && cargo publish -p aya-build
cargo publish --dry-run -p aya-ebpf-macros && cargo publish -p aya-ebpf-macros
cargo publish --dry-run -p aya-obj        && cargo publish -p aya-obj
cargo publish --dry-run -p aya-log-common && cargo publish -p aya-log-common

# Wave 2
cargo publish --dry-run -p aya-ebpf-cty   && cargo publish -p aya-ebpf-cty
cargo publish --dry-run -p aya            && cargo publish -p aya
cargo publish --dry-run -p aya-log-parser && cargo publish -p aya-log-parser

# Wave 3
cargo publish --dry-run -p aya-ebpf-bindings && cargo publish -p aya-ebpf-bindings
cargo publish --dry-run -p aya-log-ebpf-macros && cargo publish -p aya-log-ebpf-macros

# Wave 4
cargo publish --dry-run -p aya-ebpf     && cargo publish -p aya-ebpf

# Wave 5
cargo publish --dry-run -p aya-log-ebpf && cargo publish -p aya-log-ebpf
cargo publish --dry-run -p aya-log      && cargo publish -p aya-log
```

A `--dry-run` failure on `cargo package` (e.g. "file not included" or a
dependency version that is not yet on crates.io) means the ordering or the
manifest is wrong; fix that before publishing the real crate.

## Step 8: Push and open a pull request

Push the branch and the tags:

```sh
git push origin my-release-branch
git push origin --tags
```

Open a PR against the default branch and merge it with a **fast-forward
merge** so the release commit (and therefore the tags) stays reachable from
the default branch.

## Debugging

### A published dependency is not on crates.io yet

`cargo publish --dry-run` downloads the published versions of a crate's
dependencies. If a sibling crate in the same release has not been published
yet, the dry run fails with "no matching package ... found". This is the wave
order doing its job: publish the dependency first.

### `rustc X is not supported by the following package`

The local toolchain is below the crate's MSRV. Install the default or a
newer toolchain: `rustup default stable`.

### The public API fixture diff looks wrong

Regenerate with the exact command from step 2 and re-inspect. Do not edit
`xtask/public-api/*.txt` by hand.

### A crate's changelog `Unreleased` section is empty

Write a one-line entry under `### Chore` describing what actually changed
(dependency bump, MSRV bump, build fix). Do not release a crate whose
published artifact is byte-identical to the previous release for no reason.

[owners-team]: https://github.com/orgs/aya-rs/teams/owners
