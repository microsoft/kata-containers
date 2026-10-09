# Kata Containers Agent Guide

This file tells an AI coding agent how to work in this repository: what the
tree contains, which checks to run before proposing a change, how commits must
be formatted, and which mistakes are made over and over again here.

Humans are welcome to read it too. Everything below is also good advice for a
first-time contributor, and it complements rather than replaces
[`CONTRIBUTING.md`](CONTRIBUTING.md), which owns the project-wide process, and
[`docs/code-pr-advice.md`](docs/code-pr-advice.md), which owns code style.

If you only remember one thing, remember that nothing you do becomes visible to
anyone else, nothing irreversible happens, and no prose goes out under the
user's name, unless the user asks for it. See
[What the agent must not do](#what-the-agent-must-not-do).

## What the agent must not do

These are hard rules, and they matter more than anything else in this file
(unless specifically instructed otherwise by the user).

- Never post anything to GitHub.
- Never write the prose that goes out in the user's name: commit message bodies,
  pull request descriptions, issue reports, review replies. See
  [`CONTRIBUTING.md`](CONTRIBUTING.md#dont-use-ai-for-prose). Hand over the raw
  material instead and let the user write it up.
- Never rewrite or discard history that exists outside your own session. Consent
  is per push; an earlier "yes" is not a standing permission.
- Never take any other irreversible action unasked.

Generally: you can read anything, change files in the working tree and make
local commits freely. Anything that other people can see, or that cannot be
undone with a command you know how to run, is the user's decision.

## Project overview

Kata Containers runs each pod inside a lightweight virtual machine so that
container workloads get hardware-backed isolation while still looking and
behaving like ordinary containers to Kubernetes and containerd.

The moving parts you will most often touch:

| Part | Runs where | Language | Path |
| --- | --- | --- | --- |
| Shim (`containerd-shim-kata-v2`) | Host | Go | `src/runtime` |
| Shim (`containerd-shim-kata-v2`) | Host | Rust | `src/runtime-rs` |
| Agent (`kata-agent`) | Guest, as PID 1 or under an init | Rust | `src/agent` |
| Dragonball hypervisor | Host, in-process VMM | Rust | `src/dragonball` |
| Shared Rust libraries | Both | Rust | `src/libs` |
| Policy generator (`genpolicy`) | Host, build time | Rust | `src/tools/genpolicy` |
| Guest image and asset builders | Host, build time | Shell | `tools/packaging` |
| Deployment (`kata-deploy`, Helm chart) | Kubernetes | Rust, YAML | `tools/packaging/kata-deploy` |
| Tests | CI and locally | Shell, Go, Rust | `tests` |
| Documentation | - | Markdown | `docs` |

Two shims exist because Kata is midway through a rewrite. Since Kata 4.0
`runtime-rs` is the default shim, and the Go runtime is deprecated: still
shipped and still supported, but closed to new functionality.

## Repository map

Beyond `src/` and `tools/`, four things at the top level matter more than their
size suggests:

- `versions.yaml` — the single source of truth for every external dependency
  version (Go, Rust, QEMU, kernel, `golangci-lint`, and so on). Never hardcode
  a version elsewhere; read it from here.
- `Makefile` and `utils.mk` — the per-component `build`/`check`/`test`/`install`
  rules, plus `standard_rust_check`, the shared `cargo fmt` and `cargo clippy`
  invocation.
- `tools/packaging/kata-deploy/local-build/Makefile` — every `*-tarball` target
  that produces a shippable artefact. It is included by the root `Makefile`, so
  those targets work from the repository root.
- `.github/workflows/` — the definitive answer to "what will CI actually run on
  my pull request". `static-checks.yaml` and `build-checks.yaml` gate almost
  every change.

## Commit format

[`CONTRIBUTING.md`](CONTRIBUTING.md#patch-format) is the canonical statement of
the format. What matters operationally is that
`.github/workflows/commit-message-check.yaml` checks **every commit** in the
pull request, not just the tip. A malformed commit anywhere in the series blocks
the whole PR. To see the subsystem prefixes in use, run
`git log --no-merges --pretty=%s | cut -d: -f1 | sort | uniq -c | sort -rn | head -20`.

Three things CI does not check and reviewers do. Put the `Generated-By:` or
`Assisted-By:` disclosure *above* `Signed-off-by:` so the human sign-off comes
last. Never use `Co-authored-by:` for a tool, since that trailer is for humans
and carries a DCO implication. And add `Fixes: #NNN` to one commit in the series
when the change resolves a reported issue, or `Related: #NNN` when it does not
close it.

### Verifying before you push

```bash
base=upstream/main   # or whatever you branched from
rc=0
for commit in $(git rev-list --no-merges "${base}..HEAD"); do
	subject=$(git show -s --format=%s "${commit}")
	body=$(git show -s --format=%b "${commit}")
	id="${commit:0:12}"
	[[ "${#subject}" -le 75 ]] || { echo "${id}: subject is ${#subject} characters, the limit is 75"; rc=1; }
	[[ "${subject}" =~ ^[^:[:space:]]+: ]] || { echo "${id}: subject has no 'subsystem:' prefix"; rc=1; }
	grep -q '^Signed-off-by:' <<<"${body}" || { echo "${id}: no Signed-off-by trailer"; rc=1; }
	grep -qE '^[^[:space:]]' <<<"$(grep -viE '^([a-z-]+-by|fixes|related|closes):|^$' <<<"${body}")" \
		|| { echo "${id}: no commit body, only a subject"; rc=1; }
	awk -v id="${id}" 'length > 150 && /^[a-zA-Z]/ { print id": body line is " length " characters, the limit is 150" }' <<<"${body}"
done
exit "${rc}"
```

## Before you submit

Every commit has to build and pass the checks for the components it touches, not
just the branch tip, so that a later bisect lands on something that works.

Work down this ladder. Each rung is cheap relative to the one below it, and
skipping a rung is how a pull request ends up with a red CI run over a
missing newline.

### Rung 0: the components you touched

CI runs exactly three commands in each component directory
(`.github/workflows/build-checks.yaml`), so run the same ones:

```bash
make -C src/agent check          # cargo fmt --check + cargo clippy -D warnings
make -C src/agent test           # cargo test
sudo -E PATH="$PATH" make -C src/agent test
```

Substitute the component you changed. `make check-all` and `make test-all` from
the repository root fan out to most components, but not to
`src/tools/genpolicy` even though CI checks it, so run
`make -C src/tools/genpolicy check test` yourself if you touched it.

Two exceptions worth knowing:

- **`make -C src/runtime check` does nothing.** The target is declared `.PHONY`
  and `make -C src/runtime help` advertises it, but it has no recipe. For the
  Go runtime run `make -C src/runtime lint`, which builds everything and then
  runs `golangci-lint` against `tests/.golangci.yml`, and
  `make -C src/runtime test`. `make -C src/runtime pre-commit` is `lint` plus a
  faster test pass. `golangci-lint` has to be on your `PATH` already; the
  version is pinned in `versions.yaml`.
- **`runtime-rs` and `dragonball` tests need virtualization**, and CI runs them
  differently:

  ```bash
  sudo -E env PATH="$PATH" LIBC=gnu SUPPORT_VIRTUALIZATION=true make -C src/runtime-rs test
  sudo -E env PATH="$PATH" LIBC=gnu SUPPORT_VIRTUALIZATION=true make -C src/dragonball test
  ```

The `kata-deploy` crates under `tools/packaging/kata-deploy/binary` and
`tools/packaging/kata-deploy/job-dispatcher` are not part of `make check-all`,
and have their own CI job:

```bash
cargo fmt -p kata-deploy --check
cargo clippy -p kata-deploy --all-targets --all-features -- -D warnings
RUSTFLAGS="-D warnings" cargo test -p kata-deploy -- --test-threads=1
```

### Rung 1: whole-tree static checks

```bash
make static-checks
```

This is `tests/static-checks.sh`, and it is the check that surprises people
most often. Two things to know before running it:

- It needs `moreutils` (for `chronic`), and depending on which checks fire it
  also wants `yamllint`, `jq`, `xmllint`, `hadolint`, `opa`, and `regorus`.
  `tests/install_opa.sh` and `tests/install_regorus.sh` handle the last two.
  `golangci-lint` is downloaded automatically if missing.
- It works out what you changed by diffing against `origin/<branch>`. The
  remote name `origin` is hardcoded and no flag overrides it; `--branch` only
  chooses the branch, which otherwise defaults to whatever `origin`'s HEAD
  points at. In CI `origin` is the upstream repository, so this works out. On a
  developer machine `origin` is usually your fork, and anything upstream has
  that your fork's default branch does not is counted as part of your change.
  Point the tracking ref at upstream before running the script:

  ```bash
  git fetch <your-upstream-remote> '+main:refs/remotes/origin/main'   # before
  git fetch origin '+main:refs/remotes/origin/main'                   # after
  ```

  Only the local `origin/main` tracking ref changes, never your fork, and the
  second command puts it back so that later `git log origin/main` and branch
  comparisons mean what you expect again.

In general, prefer running the script directly:

```bash
test_path=tests bash tests/static-checks.sh --repo-path "$(pwd)"
```

To iterate quickly, run one check at a time. `bash tests/static-checks.sh --list`
prints them all; the useful flags are:

| Flag | What it checks |
| --- | --- |
| `--golang` | `golangci-lint` over every changed Go package |
| `--scripts` | `bash -n` over changed shell scripts |
| `--licenses` | SPDX and copyright headers on new files (Markdown is exempt) |
| `--json`, `--xml` | That changed data files still parse |
| `--dockerfiles` | `hadolint` |
| `--rego` | `opa parse` and `regorus parse` over policy files |
| `--versions` | `yamllint versions.yaml` |
| `--force --files` | TODO and FIXME comments without a linked issue |

Beware: `--commits` and `--docs` appear in the help output but are not wired
up. Use the commit snippet above instead.

### Rung 2: the checks that only fire for certain changes

These are separate CI jobs, and each one is a single local command:

| If you changed | Run | Why |
| --- | --- | --- |
| Any Go file, `go.mod`, `go.sum`, or `versions.yaml` | `find . -name go.mod -execdir go mod tidy \; && git diff --exit-code` | The `go-mod-tidy` job fails on any diff |
| `src/libs/protocols/protos/**` | `make -C src/agent generate-protocols && git diff --exit-code` | The `codegen` job regenerates and diffs the bindings |
| Agent RPC surface or the policy | `bash ci/check_agent_policy_coverage.sh` | Every agent endpoint needs policy coverage |
| `Cargo.toml` or `Cargo.lock` | `cargo deny check bans licenses sources` | The `cargo-deny` job |
| Anything under `tools/packaging/kernel/` other than its README | Bump `tools/packaging/kernel/kata_config_version` | A dedicated job enforces the bump |
| Any `.md` file | `make docs-lint` | Runs `cspell` and `editorconfig-checker` in Docker |
| A `.github/workflows/` file | `actionlint` and `zizmor` | Workflow linting and workflow security auditing |
| Any shell script | `shellcheck` at severity `style` | `shellcheck_required.yaml` |

Two notes on documentation. New project-specific vocabulary has to be added to
`tests/spellcheck/kata-dictionary.txt` or `cspell` will reject it, though
anything inside backticks is ignored. And new pages under `docs/` must be
registered in `docs/.nav.yml`; the repository ships a skill at
`.claude/skills/mkdocs-docs/SKILL.md` describing the documentation conventions.

### Rung 3: build the artefacts

Every commit must build. For a shim change that means, from the repository
root:

```bash
make shim-v2-rust-tarball     # runtime-rs
make shim-v2-go-tarball       # the Go runtime
```

Other useful targets from the same Makefile: `make agent-tarball`,
`make kernel-tarball`, `make rootfs-image-tarball`, `make genpolicy-tarball`,
and `make kata-tarball` for the complete bundle. They all build inside Docker,
so you need a working Docker daemon and enough disk.

To validate a whole series rather than just its tip:

```bash
git rebase --exec 'make shim-v2-rust-tarball' upstream/main
```

Stop there. Installing a build onto the host and running the end-to-end suites
under `tests/integration/kubernetes` need a machine you are willing to
reconfigure and a cluster to talk to. Leave both to CI unless the user asks for
them, and if they do ask, follow `tests/README.md` rather than improvising.

## Two runtimes, one behaviour

`src/runtime` (Go) and `src/runtime-rs` (Rust) are two implementations of the
same architecture. They share no business logic. They do share a configuration
file shape, an annotation namespace, an agent protocol, and a set of user
expectations.

The Go runtime is deprecated, which makes the rule asymmetric. Getting the
direction right matters:

- **New functionality goes into `runtime-rs` only.** Do not add a feature, a
  configuration option or an annotation to the Go runtime. If a request seems
  to call for that, say that the Go runtime is closed to new functionality and
  implement it in `runtime-rs` instead.
- **Bug fixes go wherever the bug is, which is usually both runtimes.** The two
  implementations were written from the same design, so a logic error, a
  missing validation or a wrong default in one is very often present in the
  other.

**So: before you consider a bug fix finished, look for the same bug in the
other runtime.** This is the single most common source of incomplete Kata
patches. If you are an agent working from a bug report, treat it as a required
step rather than a nicety.

### How to look

```bash
# Where does the same identifier, config key or log message live elsewhere?
git grep -n '<identifier>' -- src/runtime src/runtime-rs src/libs

# History of the concept, whichever tree it was touched in
git log --oneline -S'<string you changed>'

# Commits that deliberately changed both shims at once, as worked examples
git log --oneline --grep='^runtimes:'
```

Then read the mirror of the file you edited:

| Concern | Go | Rust |
| --- | --- | --- |
| Shim entry point | `src/runtime/cmd/containerd-shim-kata-v2/` | `src/runtime-rs/crates/shim/` |
| Sandbox and container lifecycle | `src/runtime/virtcontainers/sandbox.go`, `container.go` | `src/runtime-rs/crates/runtimes/virt_container/src/` |
| Hypervisor drivers | `src/runtime/virtcontainers/{qemu,clh,fc,remote}*.go` | `src/runtime-rs/crates/hypervisor/src/{qemu,ch,firecracker,remote}/` |
| Device management | `src/runtime/pkg/device/` | `src/runtime-rs/crates/hypervisor/src/device/` |
| Network endpoints | `src/runtime/virtcontainers/*_endpoint.go` | `src/runtime-rs/crates/resource/src/network/endpoint/` |
| Storage, mounts, cgroups | `src/runtime/virtcontainers/`, `src/runtime/pkg/resourcecontrol/` | `src/runtime-rs/crates/resource/` |
| Agent client | `src/runtime/virtcontainers/kata_agent.go` | `src/runtime-rs/crates/agent/src/kata/` |
| Sandbox state persistence | `src/runtime/virtcontainers/persist/` | `src/runtime-rs/crates/persist/` |
| Configuration parsing | `src/runtime/pkg/katautils/config.go` | `src/libs/kata-types/src/config/` |
| Annotations | `src/runtime/virtcontainers/pkg/annotations/annotations.go` | `src/libs/kata-types/src/annotations/mod.rs` |
| Configuration templates | `src/runtime/config/configuration-*.toml.in` | `src/runtime-rs/config/configuration-*-runtime-rs.toml.in` |

Note the last three rows: the `runtime-rs` side of configuration and
annotations does not live under `src/runtime-rs/` at all. It lives in
`src/libs/kata-types/`, which is shared. Agents routinely miss this and
conclude, wrongly, that `runtime-rs` has no equivalent.

### Configuration options and annotations

A *new* option is `runtime-rs` only, so the touch list is:

1. The templates in `src/runtime-rs/config/`, for every hypervisor flavour the
   option applies to (`qemu`, `clh`, `fc`, `remote`, `dragonball`, plus the
   confidential and NVIDIA GPU variants).
2. The parser in `src/libs/kata-types/src/config/`, including the
   per-hypervisor `validate()` and `adjust_config()` under
   `src/libs/kata-types/src/config/hypervisor/`.
3. `docs/how-to/how-to-set-sandbox-config-kata.md` if users can set it, and
   `docs/migrating-config-go-runtime-to-runtime-rs.md`, since a new
   `runtime-rs` option widens the documented gap between the two runtimes.
4. Tests under `src/libs/kata-types/tests/`.

*Fixing* how an existing option is parsed, validated or defaulted is a
different matter. That option almost certainly exists on the Go side too, so
check `src/runtime/pkg/katautils/config.go`, the struct in
`src/runtime/virtcontainers/hypervisor.go`, the templates under
`src/runtime/config/`, and `src/runtime/pkg/katautils/config_test.go`.

Annotations split the same way. A new one is a constant in
`src/libs/kata-types/src/annotations/mod.rs`, the code that applies it, a
documentation row, and an entry in `enable_annotations` in the affected
templates. A fix to an existing annotation should also be checked against
`src/runtime/virtcontainers/pkg/annotations/annotations.go`.

### What is deliberately not mirrored

Do not manufacture parity where none is intended:

- **Dragonball** is a real hypervisor only in `runtime-rs`. The Go runtime
  returns a mock for it.
- **StratoVirt** exists only in the Go runtime.
- **`kata-monitor` and the `kata-runtime` CLI** live in `src/runtime` and serve
  the Go runtime. The successor to `kata-runtime` is `kata-ctl`, a Rust rewrite
  in `src/tools/kata-ctl` that is its own component rather than part of either
  shim. `shim-ctl` in `runtime-rs` is not a CLI for users; it is a development
  tool for driving the shim without containerd.
- **VM cache and the `[factory]` machinery** are Go-only and deprecated.
- **`mem-agent`, `use_passfd_io`, and component plugin selection** are
  `runtime-rs`-only.
- **`ppc64le`** ships only the Go runtime.
- **NUMA mapping and network rate limiters** are not implemented in
  `runtime-rs` yet. Closing that gap is legitimate work, but it is a feature in
  its own right, not something to slip in alongside a bug fix.

`docs/migrating-config-go-runtime-to-runtime-rs.md` is the authoritative list
of intentional divergences. Read it before claiming a difference is a bug.

### When you genuinely cannot do both

Sometimes the counterpart change needs hardware you do not have, or is large
enough to deserve its own review. That is fine, but say so:

- Note it explicitly in the commit message or the pull request description.
- Suggest that the user open a GitHub issue for the other runtime, with the
  detail [any issue needs](#issues), and reference it with `Related: #NNN`.

## Code conventions

Read [`docs/code-pr-advice.md`](docs/code-pr-advice.md): it covers error
handling, the narrow cases where Rust `unwrap()` and `expect()` are acceptable,
Go struct construction, comments, logging and architecture-specific code. One
thing it does not say:

- **Copyright and SPDX headers** on every new file, required by the
  `--licenses` static check for everything except Markdown. State the year of
  first publication, as in `Copyright (c) 2026 Example Corporation`.

## Traps

Things that have cost real time in this repository:

- **`make -C src/runtime check` silently does nothing.** Running it proves
  nothing. Use `lint` and `test`.
- **`cargo` commands run against the root workspace.** Most crates, including
  `src/agent`, `src/libs/*`, `src/runtime-rs`, and the tools, are members of
  the workspace defined by the root `Cargo.toml`. Running `cargo clippy` inside
  a component directory still resolves upward, so `-p <crate>` is usually what
  you want.
- **The default Rust target is musl** (`LIBC=musl` in `utils.mk`), overridden
  to gnu on `ppc64le`, `riscv64`, and `s390x`. A build that works for you with
  the default host toolchain can still fail in CI. Install `musl-tools`.
- **`clippy` runs with `-D warnings`.** A warning is a build failure. This
  includes lints such as `too_many_arguments`, which will make you restructure
  a function signature rather than suppress it.
- **`Cargo.lock` is checked in and `clippy` runs with `--locked`.** Adding a
  dependency means committing the lock file update, and `cargo deny` then has
  an opinion about the licence.
- **Generated files are diffed by CI.** Protocol bindings and the generated
  configuration files must be regenerated and committed, not left for CI.
- **Configuration templates are `.toml.in`, not `.toml`.** Editing a generated
  `.toml` under a build directory changes nothing.
- **Falling behind upstream inflates the "changed files" set.** Both
  `tests/static-checks.sh` and `tools/testing/gatekeeper/skips.py` derive it
  from a diff against `origin/<branch>`, so a branch that is behind gets linted
  over files it never touched and, in CI, has gatekeeper schedule test suites
  the change does not need. Rebase on upstream `main` as you go rather than once
  at the end, and expect unrelated CI failures when you do not.

## Issues

You do not file, close or comment on issues, and you do not write the report
either; see [What the agent must not do](#what-the-agent-must-not-do). What you can
do is assemble the evidence, which is the laborious part and the part that bug
reports most often lack. An issue without these two things sits untouched until
somebody asks for them:

- **A reproducer.** The smallest set of commands or the pod YAML that triggers
  the problem, along with the Kata version, the hypervisor, the container
  manager, and the host kernel and distribution.
- **Logs captured with debug enabled.** Turn on full debug first, following
  [`docs/Developer-Guide.md`](docs/Developer-Guide.md#enable-full-debug), then
  reproduce, then collect the output of `kata-collect-data.sh`, which gathers
  the configuration and the runtime, agent and hypervisor logs in one go.

Hand those to the user and let them write the report, following the bug
[template](https://github.com/kata-containers/.github/blob/main/.github/ISSUE_TEMPLATE/bug_report.md).

## Pull requests

- Base your branch on an up-to-date `main`, rebase rather than merge, and rebase
  again when it falls behind.
- Keep unfinished work as a draft pull request. The `wip` and `do-not-merge`
  labels and a `WIP` in the title also block the merge, and CI recognises them.
- New features need documentation that says what the feature does, why it is
  useful, how to use it, and what its limitations are.
- Read [`docs/code-pr-advice.md`](docs/code-pr-advice.md) and the
  [PR review guide](https://github.com/kata-containers/community/blob/main/PR-Review-Guide.md)
  to see what a reviewer will be looking for.

## Further reading

- [`docs/Developer-Guide.md`](docs/Developer-Guide.md) — building and installing from source
- [`docs/code-pr-advice.md`](docs/code-pr-advice.md) — what reviewers expect from code
- [`docs/Unit-Test-Advice.md`](docs/Unit-Test-Advice.md) — the table-driven test style used here
- [`docs/migrating-config-go-runtime-to-runtime-rs.md`](docs/migrating-config-go-runtime-to-runtime-rs.md) — how the two runtimes differ
- [`docs/how-to/how-to-set-sandbox-config-kata.md`](docs/how-to/how-to-set-sandbox-config-kata.md) — the annotation reference
- [`docs/Documentation-Requirements.md`](docs/Documentation-Requirements.md) — documentation style rules
- [`tests/README.md`](tests/README.md) — the test suites and how to run them
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the project-wide process, patch format and review flow

# msft-main Rebase Guide

This file is a reusable guide for rebasing `msft-main` onto future upstream
releases.

Use it as an operating checklist, not as a one-time record for a specific
release.

## Rebase Setup

Before starting a rebase, record the exact upstream target and create a safety
branch.

- Working branch: `msft-main`
- Upstream target: `<upstream-tag-or-commit>`
- Safety branch: `msft-main-pre-rebase-<upstream-tag>-<timestamp>`

Suggested setup:

```bash
cd <kata-repo>
git checkout msft-main
git branch "msft-main-pre-rebase-<upstream-tag>-$(date +%Y%m%d-%H%M%S)"
```

## Behaviors That Must Survive Future Rebases

### 1. Runtime-go static resource behavior

Preserve all of the following in `src/runtime`:

- If `static_sandbox_resource_mgmt=true` and the workload does not specify limits, use the configured defaults:
  - `static_sandbox_default_workload_mem`
  - `static_sandbox_default_workload_vcpus`
- If workload limits are specified, do not add extra CPU or memory on top of those limits.
- The Azure Linux node-builder must keep passing `STATIC=no` to the `src/runtime` make.
  Upstream defaults `STATIC=yes` on x86_64, which exports `CGO_ENABLED=0`, and the Azure
  Linux Go toolchain needs `CGO_ENABLED=1` for its default `GOEXPERIMENT=systemcrypto`.

Primary files:

- `src/runtime/pkg/oci/utils.go`
- `src/runtime/pkg/katautils/config.go`
- `src/runtime/config/configuration-clh.toml.in`
- `src/runtime/Makefile`
- `tools/osbuilder/node-builder/azure-linux/package_build.sh`

### 2. Runtime-rs static resource behavior

Preserve all of the following in `src/runtime-rs`:

- If static resource management is enabled and workload resources are unset, fall back to:
  - `static_sandbox_default_workload_mem`
  - `static_sandbox_default_workload_vcpus`
- If workload limits are specified, do not add extra CPU or memory beyond those workload limits.
  Upstream sizes the sandbox as `overhead + workload`, so this is enforced by the node-builder
  build flags zeroing the shipped hypervisor's overhead knobs (`DEFOVERHEADMEMSZ_CLH`,
  `DEFOVERHEADVCPUS_CLH`), not by patching the runtime. Upstream keeps adding overhead knobs,
  and their defaults are not zero.
- Every runtime-rs hypervisor config template that enables `static_sandbox_resource_mgmt` must
  also carry `static_sandbox_default_workload_mem` and `static_sandbox_default_workload_vcpus`.
  These are fork-added keys and default to `0` when absent (`#[serde(default)]`).
- kata-v2 (snapshot/restore) CLH sandboxes must boot without a memory hotplug window: the kata-v2 template
  (`configuration-clh-azure-runtime-rs-v2.toml.in`) sets `disable_hotplug_memory = true`, which
  makes the CLH config conversion omit `hotplug_size`. CLH copy-on-write restore rejects any
  hotplug window, and removing it only in the restore config shifts the guest's ACPI device
  addresses (PCI hotplug into restored VMs stops working). Restore may only flip `memory.shared`.

Primary files:

- `src/runtime-rs/crates/resource/src/cpu_mem/initial_size.rs`
- `src/libs/kata-types/src/config/hypervisor/mod.rs`
- `src/runtime-rs/crates/hypervisor/ch-config/src/convert.rs`
- `src/runtime-rs/crates/hypervisor/src/ch/inner_hypervisor.rs`
- `src/runtime-rs/config/configuration-clh-azure-runtime-rs-v2.toml.in`
- `src/runtime-rs/config/configuration-clh-azure-runtime-rs.toml.in`
- `src/runtime-rs/config/configuration-clh-runtime-rs.toml.in`
- `src/runtime-rs/config/configuration-dragonball.toml.in`
- `src/runtime-rs/Makefile`
- `tools/osbuilder/node-builder/azure-linux/package_build.sh`

### 3. VM templating (factory) static sizing

Preserve all of the following:

- VM templates must be built from the static base size, not from the raw
  `HypervisorConfig`. `oci.StaticHypervisorConfig()` substitutes
  `static_sandbox_default_workload_mem` / `_vcpus` for `default_memory` /
  `default_vcpus` when those are `0`, and clamps `DefaultMaxVCPUs` to the result.
- Every factory `vf.Config` call site must use it. Upstream passes
  `runtimeConfig.HypervisorConfig` directly, which boots the template at a size the
  per-pod sandbox never matches, so the factory falls back to direct boot.
- The `configuration-clh-preview*.toml` configs enable `[factory]` and are generated
  by the node-builder, not shipped as templates.

Primary files:

- `src/runtime/pkg/oci/utils.go`
- `src/runtime/cmd/kata-runtime/factory.go`
- `src/runtime/pkg/katautils/create.go`
- `src/runtime/virtcontainers/factory/factory_linux.go`
- `tools/osbuilder/node-builder/azure-linux/package_build.sh`

### 4. Fork-only test and CI policy

Preserve the fork-specific CI and test exceptions unless the fork
infrastructure changes:

- `msft-main` branch targeting in GitHub workflows.
- Disabled jobs for runners the fork does not have.
- Disabled `required-tests` entries for unsupported AKS, s390x, GPU, and GHCR-dependent jobs.
- Injected sandbox memory limits in some integration tests.
- Disabled dragonball runtime-rs tests that fail with `MachineConfig(InvalidVcpuCount(0))`.

Primary files:

- `.github/workflows/ci.yaml`
- `.github/workflows/docs.yaml`
- `.github/workflows/static-checks-self-hosted.yaml`
- `tools/testing/gatekeeper/required-tests.yaml`
- `tests/integration/cri-containerd/integration-tests.sh`
- `tests/integration/nydus/nydus-sandbox.yaml`

## Changes That Often Do Not Need Replaying

Do not mechanically replay old fork commits just because they existed on the
previous branch tip. Re-evaluate them against the new upstream target.

The following categories often drop cleanly or should be rechecked before being
reapplied:

- Obsolete Cloud Hypervisor pinning to fork-only repositories.
- Changes that were already upstreamed in a newer form.
- Formatting-only commits.
- Regenerated client code if upstream already regenerated the same surface.
- Local fixes that upstream later implemented differently but with equivalent behavior.

Rule: only replay a fork commit if the behavior is still required and missing
from the new upstream base.

## Conflict Hotspots And What To Do

### `.gitignore`

Keep both:

- newer upstream ignores
- Microsoft-specific osbuilder and IGVM ignores

### `versions.yaml`

Default to upstream Cloud Hypervisor references from the new release tag.

Do not re-pin to `microsoft/cloud-hypervisor` unless the fork explicitly needs
it again.

### Workflow branch conflicts

When upstream changes workflow structure and the fork changes branch names, keep
both:

- upstream workflow structure
- fork branch target `msft-main`

### `tools/testing/gatekeeper/required-tests.yaml`

This file changes frequently upstream. Re-express the fork skips against the
current upstream job names instead of mechanically replaying old lines.

The fork currently expects these skip categories:

- unsupported runners
- unsupported k8s environments
- GHCR-dependent jobs
- low-memory test incompatibilities
- dragonball runtime-rs `InvalidVcpuCount(0)` failures

### `src/runtime/pkg/katautils/config.go`

Two common pitfalls:

- keep newer upstream fields added to the `runtime` struct
- do not reintroduce `SandboxWorkloadMemMin`

### `src/runtime-rs/Makefile`

Keep both:

- the explicit `cargo build -p runtime-rs`
- the fork's `RELEASE_CARGO_PROFILE_ENV` release-profile overrides

Also do a final manual check for stray conflict markers in this file after the
rebase completes. This file has been a repeat conflict hotspot.

### `tools/osbuilder/node-builder/azure-linux/common.sh`, `package_build.sh`, `package_install.sh`

Keep the Azure Linux node-builder shim config names aligned with the runtime
Makefiles and config directories:

- runtime-go release config: `configuration-clh.toml`
- runtime-go debug config: `configuration-clh-debug.toml`
- runtime-rs release config: `configuration-clh-azure-runtime-rs.toml`
- runtime-rs debug config: `configuration-clh-azure-runtime-rs-debug.toml`

Notes:

- `src/runtime-rs/Makefile` is the source of truth for the release config name.
- the runtime-rs debug config is created by `tools/osbuilder/node-builder/azure-linux/package_build.sh` by copying the release config and enabling debug options.

Quick verification:

```bash
cd <kata-repo>
grep -n 'CONFIG_FILE_CLH_AZURE = configuration-clh-azure-runtime-rs.toml' src/runtime-rs/Makefile
grep -n 'SHIM_CONFIG_FILE_NAME_RUNTIME_GO\|SHIM_CONFIG_FILE_NAME_RUNTIME_RS' tools/osbuilder/node-builder/azure-linux/common.sh
bash -n tools/osbuilder/node-builder/azure-linux/common.sh tools/osbuilder/node-builder/azure-linux/package_build.sh tools/osbuilder/node-builder/azure-linux/package_install.sh
```

### Static build scripts

In `tools/packaging/static-build/cloud-hypervisor/build-static-clh.sh`, keep:

- `rm -rf cloud-hypervisor`

If upstream changes the copy command, keep the newer upstream structure and only
preserve the cleanup behavior if still needed.

## Focused Validation Commands

Run these after the rebase:

```bash
cd <kata-repo>
cargo test -p resource --manifest-path src/runtime-rs/Cargo.toml --lib initial_size -- --nocapture
```

```bash
cd <kata-repo>/src/runtime
go test ./pkg/oci ./pkg/katautils
```

Useful inspection commands:

```bash
cd <kata-repo>
git log --oneline --reverse <upstream-tag>..msft-main
git grep -n 'static_sandbox_default_workload_mem\|static_sandbox_default_workload_vcpus\|InvalidVcpuCount\|sandbox_workload_mem_min' -- src/runtime src/runtime-rs tools/testing/gatekeeper/required-tests.yaml tests/integration
```

Before pushing, scan tracked files for unresolved rebase markers:

```bash
cd <kata-repo>
git grep -nE '^(<<<<<<<|=======|>>>>>>>)'
```

If the only hits are banner lines inside scripts or help text, they are safe.
Any true start-of-line conflict marker in source or config files must be
removed before committing or pushing.

## Rebase Review Checklist

Use this checklist before you push:

1. Confirm the branch still preserves the fork-specific resource-sizing behavior in runtime-go and runtime-rs.
2. Confirm CI still targets `msft-main` and still skips unsupported jobs.
3. Confirm `required-tests.yaml` skips match current upstream job names.
4. Confirm node-builder config filenames still match the runtime Makefiles.
5. Confirm there are no stray conflict markers.
6. Confirm the validation commands above pass, or document any known failures.

## Practical Rule For Future Rebases

Prefer this order of decisions:

1. Keep upstream if the fork change was already upstreamed.
2. Keep fork behavior for resource sizing in runtime-go and runtime-rs.
3. Keep fork CI and test skips when the limitation still exists.
4. Avoid replaying stale Cloud Hypervisor pinning commits.
5. Re-express `required-tests` skips against current job names instead of preserving old labels verbatim.
