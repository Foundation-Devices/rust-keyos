# Rust for KeyOS

This is a fork of [rust-lang/rust](https://github.com/rust-lang/rust) carrying
the KeyOS patches to the Rust standard library. It builds `std` for KeyOS,
(which itself is based on Xous), targeting `armv7a-unknown-xous-elf`.

The patches live as a small stack of commits on top of an upstream release. Each
branch is named `<stable>-xous-arm` (e.g. `1.96.0-xous-arm`) and is upstream Rust
at that `<stable>` tag plus the KeyOS stack. For historic reasons, the target
and many paths are named after `xous`, the Rust OS target. The patches are
KeyOS-specific, though, which is why the build uses `--cfg keyos` and the repo
is called `rust-keyos`.

## Building

The build toolchain is pinned in `rust-toolchain.toml`; rustup installs and
selects it on the first build. You also need an `arm-none-eabi` GCC on the path,
which `rebuild.sh` picks up as `CC`/`AR`.

Build `std` and install it into the active toolchain's sysroot:

```sh
./rebuild.sh
```

`rebuild.sh` compiles libstd and copies the resulting rlibs into
`$(rustc --print sysroot)/lib/rustlib/armv7a-unknown-xous-elf/lib`.

## Testing

Test a libstd change by building the KeyOS OS image against it. Once `rebuild.sh`
has installed libstd into the sysroot, a KeyOS build picks it up automatically,
so building and running the image exercises your change.

## Releases

A release is a prebuilt copy of the installed libstd, so consumers don't each run
`rebuild.sh` themselves.

### Publishing

On a tag push, `rust-xous-release.yml` zips
`lib/rustlib/armv7a-unknown-xous-elf/` and attaches it to the GitHub release for
the tag.

### Tag names

Release tags are `<stable>-nightly-YYYY-MM-DD`, e.g. `1.96.0-nightly-2026-04-11`,
and the name is load-bearing in two places. CI parses the `nightly-YYYY-MM-DD`
part out of it to pick the toolchain it builds with. And the `<stable>-nightly`
prefix is exactly what `rustc --version` prints for that toolchain, which is how
the installer finds a matching release.

### Installing

KeyOS pulls a release in with its `scripts/install-stdlib.sh`, which reads your
`rustc --version` (e.g. `1.96.0-nightly`), finds the most recent rust-keyos
release whose tag starts with that string, and unzips its asset into your
sysroot.

### Re-releasing

To publish another release from the same branch later, fix whatever needs fixing
and tag again with a suffix after the date, e.g. `1.96.0-nightly-2026-04-11-2`
(bump the number each time). CI reads only the `nightly-YYYY-MM-DD` part, so the
suffix doesn't change the build toolchain; and since the installer takes the most
recent match, the new tag supersedes the previous release.

## Rebasing onto a new Rust release

Rebasing moves the KeyOS stack onto a newer upstream release with as few changes
as possible, then rebuilds libstd to make sure it still compiles and tags the
result so CI publishes a sysroot archive.

### What has to survive the rebase

Roughly this handful of **base commits**, give or take:

- the README (`README.markdown`)
- the build scripts (`rebuild.sh`, `rebuild.ps1`)
- the release workflow (`.github/workflows/rust-xous-release.yml`)
- the `rust-toolchain.toml` nightly pin
- the target spec `armv7a-unknown-xous-elf.json`
- the libstd patches, the `stdlib: reapply xous patches` commit
- `Cargo.lock`

The branch you start from won't be this tidy. Follow-up commits accumulate after
the base ones: target-spec tweaks (`target: add llvm-floatabi required value`),
`ci: update`, the odd `rebuild.sh` fix, and occasionally whole side branches.
Squashing all of it back into the base commits above is part of the rebase, not
a separate cleanup. See step 2.

### 1. Pick the version and the matching nightly

Look up the latest stable on <https://releases.rs/> and note when it **branched
from master** (the "branches from master to beta" date). The compiler that builds
libstd has to match the libstd source, so you want the nightly from that branch
date. For example, 1.96.0 branched on 2026-04-11, so the build toolchain is
`nightly-2026-04-11`.

Hold onto two strings for the rest of the process:

- `<stable>`, e.g. `1.96.0`
- `<nightly>`, e.g. `nightly-2026-04-11`

### 2. Rebase the stack onto the new release

Rebase the old `<old>-xous-arm` branch onto the upstream `<stable>` commit (from
rust-lang/rust; it needs to be present locally):

```sh
git switch -c <stable>-xous-arm <old>-xous-arm
git rebase -i <stable>
```

In the todo list:

- **Drop everything older than `README: initial xous commit`.** That commit is
  the base of the KeyOS stack; anything older is an upstream Rust commit unique
  to the old release, dragged in because the old branch diverged from the new
  base. The new base already carries the right upstream, so don't replay them.
- **Drop the `Cargo.lock` commit.** It would conflict against the new lockfile
  for no reason; we regenerate it in step 5.
- **Squash everything else into the base commits.** `fixup`/`squash` each
  leftover commit into the base commit it belongs to: target tweaks into `Add
  armv7a-unknown-xous-elf.json`, libstd changes into `stdlib: reapply xous
  patches`, and so on. The stack then collapses back to the handful from "What
  has to survive".

Resolve conflicts as they come up. Most of the work lands in `stdlib: reapply
xous patches`, since that's the commit that touches upstream libstd, which
upstream reshuffles between releases.

### 3. Pin the new nightly

Edit `rust-toolchain.toml` so the channel is `<nightly>`, and amend it into the
`rust-toolchain.toml: update to ...` commit rather than adding a new one. rustup
reads this file and installs the toolchain on the first build, so there's no
separate install step.

### 4. Rebuild libstd

```sh
(cd library && cargo clean)                                  # drop artifacts built against the old compiler
rm -rf "$(rustc --print sysroot)/lib/rustlib/armv7a-unknown-xous-elf"   # clear stale rlibs from the old version
./rebuild.sh                                                 # build libstd and install it into the sysroot
```

`rebuild.sh` defaults to the `armv7a-unknown-xous-elf` target and needs an
`arm-none-eabi` GCC on the path for `CC`/`AR`.

Fix whatever the build turns up: upstream churns the internal `sys`/`pal`
layout between releases, so the patches usually need a few adjustments. These
fixes go into the base commits too, the same way you squashed in step 2:
`git commit --fixup <base commit>` then `git rebase --autosquash`, landing in
`stdlib: reapply xous patches` or wherever the original change lives, not in
new commits of their own. The cleaner the stack stays, the easier the next
rebase is.

### 5. Re-lock and commit Cargo.lock

Once it builds, commit the regenerated lockfile on its own as a `Cargo.lock`
commit at the tip of the stack, mirroring the one you dropped in step 2.

### 6. Tag the release

```sh
git tag <stable>-<nightly>      # e.g. 1.96.0-nightly-2026-04-11
git push origin <stable>-<nightly>
```

Pushing the tag is what triggers CI to build and publish the archive; a push
without a tag only does a test build. See [Releases](#releases) for the tag-name
rules and for publishing follow-up releases from the branch.
