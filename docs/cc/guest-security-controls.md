# Guest security controls: seccomp, AppArmor and SELinux

Kubernetes lets a workload ask for three in-guest confinement mechanisms through
`securityContext`: a seccomp profile, an AppArmor profile and SELinux options. In a
confidential sandbox none of the three is applied. This page records why, what the
consequence is, and how the stack reports it, so that the absence is a documented
position rather than something an operator discovers by instrumenting a container.

The short version: all three are configured by the **host**, and the host is the
adversary this sandbox is built to exclude. Refusing host-supplied confinement
configuration is the correct default. The cost is that the workload also loses the
confinement, and that cost was previously invisible.

## Status

| Control | Guest kernel | Guest userspace | kata-agent | Policy | Applied? |
| --- | --- | --- | --- | --- | --- |
| seccomp | `CONFIG_SECCOMP_FILTER=y` | `libseccomp` linked | `rustjail::seccomp::init_seccomp` | refuses (`is_null(i_linux.Seccomp)`) | **no** |
| AppArmor | LSM not built | no `apparmor_parser` | none | pins `Process.ApparmorProfile` | **no** |
| SELinux | `CONFIG_SECURITY_SELINUX=y` | rootfs not labelled (`SELINUX=no`) | `rustjail::selinux` | refuses (`SelinuxLabel`, `MountLabel` empty) | **no** |

The three fail for different reasons, and the difference matters when deciding what
could change.

### seccomp — capability present, deliberately not wired

The guest kernel supports seccomp filtering and the agent can install a filter. What is
missing is a trustworthy source for the profile. A profile arriving in
`CreateContainerRequest.OCI.Linux.Seccomp` is host-supplied data, and the policy refuses
it outright.

Two other layers happen to agree. The runtime strips the profile before the request is
built (`disable_guest_seccomp` defaults to `true`), and genpolicy does not model the
field. The policy check is the one that is load-bearing: it holds even if a host sets
`disable_guest_seccomp=false` to try to inject a filter.

Consequence: containers run with an unfiltered syscall surface.

Under this threat model that is a second-order loss. seccomp constrains a workload's
access to the *guest* kernel, and the guest VM is the tenant's own trust domain — a
container escaping into it does not reach the host or another tenant, which is exactly
what distinguishes a confidential sandbox from a shared node. It remains real
defence-in-depth between containers in a pod, and between a workload and the agent.

### AppArmor — cannot be applied at all

The guest kernel is built without the AppArmor LSM and the rootfs ships no
`apparmor_parser`, so no profile can be loaded no matter what is requested. `rustjail`
contains no AppArmor code.

The policy still pins `Process.ApparmorProfile`, and that is worth keeping: it costs
nothing, it is fail-closed, and it stops the host varying a field the guest would begin
honouring the moment AppArmor support were added. But pinning an inert field confines
nothing today, and describing it as enforcement would overstate the boundary.

Adding AppArmor handling to the agent would be dead code until the guest kernel gains
the LSM, `apparmor_parser` is added to the rootfs, and profiles are distributed to and
measured in the guest.

### SELinux — capability present, prerequisites absent

The guest kernel enables SELinux and `rustjail` can set process and mount labels. The
rootfs, however, is not labelled (`image_builder.sh` defaults `SELINUX=no`) and no
policy is loaded in the guest, so labelling would have nothing to enforce against.

The label is also host-derived: the runtime takes it from the host's own SELinux context
or from the `guest_selinux_label` runtime configuration. That is why the policy requires
`Process.SelinuxLabel` and `Linux.MountLabel` to be empty.

Enabling SELinux properly means building the rootfs with `SELINUX=yes`, shipping and
measuring an SELinux policy inside the guest image, and teaching genpolicy to pin the
expected label — at which point the label is committed to by the policy rather than
supplied by the host.

## Comparison with the C-ACI / hcsshim baseline

| Control | hcsshim | here |
| --- | --- | --- |
| seccomp | policy pins `sha256(json.Marshal(LinuxSeccomp))`, guest applies the profile | refused outright |
| AppArmor | not modelled; field passed through to runc unchanged | pinned in policy, inert in guest |
| SELinux | not modelled | refused outright |

hcsshim is ahead on seccomp only. Its model works because the profile is supplied by the
policy author as an explicit file (`seccomp_profile_path`) and hashed at policy-generation
time; it supports neither `RuntimeDefault` nor `Localhost` and ships no default profile.
Reproducing that here is harder than it looks, because in Kubernetes the profile is
resolved by containerd — `RuntimeDefault` expands to a Go-defined, capability-dependent
profile that varies by containerd release — so a hash pinned at generation time would
commit to a byte-exact reproduction of a moving target, and any drift would stop pods
starting.

The alternative worth considering is stronger than the baseline: have the agent apply a
profile shipped in the measured rootfs and ignore host-supplied `Linux.Seccomp` entirely,
with the policy naming a profile identifier. Then no host input is trusted at all, the
profile's integrity comes from the rootfs measurement, and there is nothing to reproduce.
That is not implemented.

On AppArmor and SELinux there is no gap to close: hcsshim models neither.

## How this is reported

A control that is silently dropped is worse than one that is refused, because the
operator is left believing a boundary exists where none does. Both halves are now
visible:

- **At policy-generation time**, genpolicy prints a warning naming the pod or container,
  the profile type requested, and the consequence. It is written straight to stderr
  rather than through `warn!`, because genpolicy initialises `env_logger` with no default
  filter and `RUST_LOG` is normally unset — a `warn!` would be discarded. `Unconfined` is
  never reported: asking for no confinement and getting none is not a surprise.
- **At request time**, if a profile or label reaches the agent anyway, the denial names
  the field rather than failing anonymously. Before this, refusing `Linux.Seccomp`
  produced a denial with no reasons at all.

Neither changes what is enforced. They change what the operator is told.
