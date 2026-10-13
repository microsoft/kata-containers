# AGENTS.md

Guidance for AI coding agents working on `microsoft/kata-containers`. Keep this
file short: always-relevant context only. Step-by-step procedures live in skills
under `.claude/skills/`.

## What this repo is

- Microsoft's fork of [kata-containers](https://github.com/kata-containers/kata-containers),
  used for Pod Sandboxing and Confidential Containers on AKS with Azure Linux.
- `msft-main` is the fork's default branch. It is periodically rebased onto an
  upstream release tag. The `upstream` remote is upstream; `origin` is the fork.
- Upstream conventions apply unless this file says otherwise. Read
  `CONTRIBUTING.md` for coding style, patch format, and the AI policy.

## Where the fork differs from upstream

Most fork changes live in:

- `src/runtime-rs/`: Azure CLH/OpenVMM configs, static sandbox sizing,
  snapshot/restore, agent reconnect.
- `src/runtime/` (runtime-go): static sandbox sizing, VM templating (factory).
- `src/agent/`, `src/tools/genpolicy/`, `src/agent/samples/policy/`: policy.
- `tools/osbuilder/node-builder/azure-linux/`, `tools/osbuilder/igvm-builder/`:
  Azure Linux packaging and UVM build.
- `.github/workflows/`, `tools/testing/gatekeeper/required-tests.yaml`: fork CI.

List the fork's commits on top of its upstream base:

```bash
git log --oneline $(git merge-base msft-main upstream/main)..msft-main
```

Before changing behavior that also exists upstream, check whether upstream
already changed it (`git log upstream/main -S '<symbol>' -- <path>`).

## Fork invariants

Do not break these. Background and file lists are in the `msft-rebase` skill.

- With `static_sandbox_resource_mgmt=true`, unset workload limits fall back to
  `static_sandbox_default_workload_mem` / `_vcpus`, and specified limits get no
  extra CPU or memory added. Applies to both runtime-go and runtime-rs.
- Every runtime-rs config template that enables `static_sandbox_resource_mgmt`
  also sets both `static_sandbox_default_workload_*` keys.
- VM templating (factory) builds from `oci.StaticHypervisorConfig()`, never the
  raw `HypervisorConfig`.
- Node-builder passes `STATIC=no` to the `src/runtime` make (Azure Linux Go
  needs CGO for systemcrypto) and zeroes `DEFOVERHEADMEMSZ_CLH` /
  `DEFOVERHEADVCPUS_CLH` for runtime-rs.
- Node-builder shim config names match the runtime Makefiles
  (`configuration-clh.toml`, `configuration-clh-azure-runtime-rs.toml`, and
  their `-debug` variants).
- Do not re-pin Cloud Hypervisor to fork repositories in `versions.yaml`.

## Build and test

Run the narrowest check that covers the change, and run it before reporting the
work as done. The Rust toolchain is pinned by `rust-toolchain.toml`; the root
`Cargo.toml` is a workspace, so `cargo test -p <crate>` works from the root.

| Area | Command |
|--|--|
| One Rust crate | `cargo test -p <crate>` (e.g. `resource`, `kata-types`, `genpolicy`) |
| runtime-rs | `make -C src/runtime-rs test`, `make -C src/runtime-rs check` |
| agent | `make -C src/agent test`, `make -C src/agent check` |
| genpolicy | `make -C src/tools/genpolicy test` |
| runtime-go | `cd src/runtime && go test ./pkg/<package>` |
| node-builder | `bash -n tools/osbuilder/node-builder/azure-linux/*.sh` and `shellcheck` |

Some tests need root, KVM, or a container runtime. If a test can't run in the
current environment, say so; do not skip or delete it.

## Commits and PRs

- Patch format is in `CONTRIBUTING.md`: `subsystem: summary` (75 characters max),
  a body explaining why, and `Signed-off-by:`. Common fork subsystems:
  `runtime-rs`, `runtime`, `agent`, `genpolicy`, `node-builder`, `tests`, `ci`.
- One logical change per commit. Keep fork-only changes separate from changes
  meant for upstream.
- Fork PRs target `msft-main`. Fixes that are not fork-specific should land
  upstream first, then be cherry-picked one commit at a time with
  `git cherry-pick -x`.
- AI disclosure: follow the AI policy in `CONTRIBUTING.md` (`Assisted-By:` or
  `Generated-By:` trailers). Upstream asks contributors to write their own commit
  messages and PR descriptions, so only draft them when asked, as a starting
  point for the human to rewrite.

## Don't

- Commit, push, rebase `msft-main`, or open PRs unless explicitly asked.
- Edit generated files. Edit the source (for example `*.toml.in`, `*.proto`)
  and regenerate.
- Bump dependencies or touch `Cargo.lock` / `go.mod` / `go.sum` unless the task
  requires it.
- Reformat or refactor code unrelated to the task.

## Skills

- `msft-rebase`: rebase `msft-main` onto a new upstream release.
- `mkdocs-docs` (from upstream): write or edit pages under `docs/`.
