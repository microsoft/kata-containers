// Copyright (c) 2026 Kata Containers community
//
// SPDX-License-Identifier: Apache-2.0

//! FR-11 — trusted device / CDI resolution.
//!
//! Container Device Interface (CDI) resolution applies `containerEdits` (environment
//! variables, device nodes, mounts, hooks) to the OCI spec from CDI spec files found in a
//! guest directory (e.g. `/var/run/cdi`). Those edits are applied *after* the create
//! request is authorized, and the spec files themselves may be produced by host-influenced
//! entities. A host can therefore smuggle privilege into a container by injecting a CDI
//! annotation and/or a CDI spec that the policy never authorized (the GPU instance of the
//! canonical-object gap).
//!
//! This module makes CDI resolution *trusted*: every CDI spec that contributes an injected
//! device must be **measured** — its content digest must appear in an authorized set of
//! measured manifests. Resolution is closed-door by default: if a container requests CDI
//! devices but no measured manifest authorizes them, the request is rejected rather than
//! silently applying host-arbitrary edits. Each authorized device is returned as a
//! [`VerifiedCdiDevice`] so the resolved handle can be bound to the container occurrence.

use std::collections::HashSet;
use std::fmt;

/// A CDI device requested by a container, split into its kind and device name.
/// For `nvidia.com/gpu=0` the kind is `nvidia.com/gpu` and the name is `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiDeviceRequest {
    pub kind: String,
    pub name: String,
}

impl CdiDeviceRequest {
    /// Parse a fully-qualified CDI device string (`<kind>=<name>`).
    pub fn parse(fqdn: &str) -> Option<Self> {
        let (kind, name) = fqdn.rsplit_once('=')?;
        if kind.is_empty() || name.is_empty() {
            return None;
        }
        Some(CdiDeviceRequest {
            kind: kind.to_string(),
            name: name.to_string(),
        })
    }

    fn fqdn(&self) -> String {
        format!("{}={}", self.kind, self.name)
    }
}

/// A CDI spec file available in the guest spec directory, with its measured content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredCdiSpec {
    pub path: String,
    /// The CDI `kind` declared by the spec (e.g. `nvidia.com/gpu`).
    pub kind: String,
    /// Content digest of the spec file (e.g. `sha256:...`).
    pub digest: String,
    /// Fully-qualified device names this spec declares (e.g. `nvidia.com/gpu=0`).
    ///
    /// Authorization is decided against *this*, not against [`Self::kind`]: a device must be
    /// authorized against the spec that actually provides it. Matching on `kind` alone would
    /// let one measured spec vouch for every other spec sharing its kind, which is a bypass
    /// (a host adding a spec of an already-authorized kind could inject arbitrary
    /// `containerEdits` under a device name the measured spec does not declare).
    pub devices: Vec<String>,
}

/// A CDI device whose providing spec has been verified as measured/trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCdiDevice {
    /// Fully-qualified device string (`<kind>=<name>`).
    pub device: String,
    /// Digest of the measured spec that provides the device (binds device→content).
    pub spec_digest: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CdiError {
    /// A container requested CDI devices but no measured manifest is authorized (the
    /// closed-door default): applying host-arbitrary CDI edits is refused.
    HostArbitraryCdi { device: String },
    /// A spec of the requested kind exists but its content digest is not in the
    /// authorized (measured) set — an unmeasured / tampered spec.
    UnmeasuredSpec {
        device: String,
        kind: String,
        found_digest: String,
    },
    /// No spec of the requested kind is available at all.
    UnsatisfiedRequest { device: String },
}

impl fmt::Display for CdiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CdiError::HostArbitraryCdi { device } => write!(
                f,
                "CDI device {device} requested but no measured CDI manifest is authorized \
                 (host-arbitrary CDI is refused in strict mode)"
            ),
            CdiError::UnmeasuredSpec {
                device,
                kind,
                found_digest,
            } => write!(
                f,
                "CDI device {device}: spec of kind {kind} has unmeasured digest {found_digest}"
            ),
            CdiError::UnsatisfiedRequest { device } => {
                write!(f, "CDI device {device}: no spec of its kind is available")
            }
        }
    }
}

impl std::error::Error for CdiError {}

/// Authorize a set of requested CDI devices against the measured spec files available in
/// the guest, using an authorized set of measured spec digests.
///
/// A device is authorized only if **every** spec that declares it is measured. Binding on
/// the providing specs rather than on the CDI `kind` is what makes the check sound: the
/// edits a container receives come from whichever spec declares the device, so a spec that
/// does not declare it must not be able to vouch for it. Requiring *all* of its providers
/// to be measured — rather than any one of them — avoids having to predict which spec the
/// CDI cache will pick when several declare the same device.
///
/// Returns the verified devices (device→providing-spec-digest) in request order, or the
/// first authorization failure. Resolution is closed-door: with an empty authorized set,
/// any requested CDI device is refused.
pub fn authorize_cdi(
    requested: &[CdiDeviceRequest],
    available_specs: &[MeasuredCdiSpec],
    authorized_digests: &HashSet<String>,
) -> Result<Vec<VerifiedCdiDevice>, CdiError> {
    let mut verified = Vec::with_capacity(requested.len());

    for req in requested {
        let device = req.fqdn();

        // Closed-door default: no measured manifests => refuse host-arbitrary CDI.
        if authorized_digests.is_empty() {
            return Err(CdiError::HostArbitraryCdi { device });
        }

        // The specs that actually declare the requested device.
        let providers: Vec<&MeasuredCdiSpec> = available_specs
            .iter()
            .filter(|s| s.devices.iter().any(|d| d == &device))
            .collect();
        let providing = match providers.split_first() {
            Some((first, _)) => *first,
            None => return Err(CdiError::UnsatisfiedRequest { device }),
        };

        // Every provider must be measured: an unmeasured one could be the spec the CDI
        // cache resolves the device from, and its edits would then never have been
        // authorized.
        if let Some(unmeasured) = providers
            .iter()
            .find(|s| !authorized_digests.contains(&s.digest))
        {
            return Err(CdiError::UnmeasuredSpec {
                device,
                kind: unmeasured.kind.clone(),
                found_digest: unmeasured.digest.clone(),
            });
        }

        verified.push(VerifiedCdiDevice {
            device,
            spec_digest: providing.digest.clone(),
        });
    }

    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: &str, digest: &str) -> MeasuredCdiSpec {
        spec_with(kind, digest, &["0"])
    }
    fn spec_with(kind: &str, digest: &str, devices: &[&str]) -> MeasuredCdiSpec {
        MeasuredCdiSpec {
            path: format!("/var/run/cdi/{kind}-{digest}.json"),
            kind: kind.to_string(),
            digest: digest.to_string(),
            devices: devices.iter().map(|d| format!("{kind}={d}")).collect(),
        }
    }
    fn auth(digests: &[&str]) -> HashSet<String> {
        digests.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_fqdn() {
        let r = CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap();
        assert_eq!(r.kind, "nvidia.com/gpu");
        assert_eq!(r.name, "0");
        assert!(CdiDeviceRequest::parse("no-equals").is_none());
        assert!(CdiDeviceRequest::parse("kind=").is_none());
    }

    #[test]
    fn no_cdi_requested_is_noop() {
        let v = authorize_cdi(&[], &[], &HashSet::new()).unwrap();
        assert!(v.is_empty());
    }

    /// TC4.2: an unsigned/unmeasured CDI spec is rejected.
    #[test]
    fn unmeasured_spec_is_rejected() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap()];
        let specs = vec![spec("nvidia.com/gpu", "sha256:HOSTARBITRARY")];
        let authorized = auth(&["sha256:TRUSTED"]);
        assert!(matches!(
            authorize_cdi(&req, &specs, &authorized).unwrap_err(),
            CdiError::UnmeasuredSpec { .. }
        ));
    }

    /// TC4.2: a measured/signed CDI spec is accepted; TC4.3: the resolved device carries
    /// the providing spec digest so it can be bound to the occurrence.
    #[test]
    fn measured_spec_is_accepted_and_bound() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap()];
        let specs = vec![spec("nvidia.com/gpu", "sha256:TRUSTED")];
        let authorized = auth(&["sha256:TRUSTED"]);
        let v = authorize_cdi(&req, &specs, &authorized).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].device, "nvidia.com/gpu=0");
        assert_eq!(v[0].spec_digest, "sha256:TRUSTED");
    }

    /// Closed-door default: CDI requested but no measured manifest authorized => refused.
    #[test]
    fn closed_door_refuses_host_arbitrary_cdi() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap()];
        let specs = vec![spec("nvidia.com/gpu", "sha256:WHATEVER")];
        assert!(matches!(
            authorize_cdi(&req, &specs, &HashSet::new()).unwrap_err(),
            CdiError::HostArbitraryCdi { .. }
        ));
    }

    #[test]
    fn unsatisfied_request_when_no_spec_of_kind() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap()];
        let specs = vec![spec("acme.com/nic", "sha256:TRUSTED")];
        let authorized = auth(&["sha256:TRUSTED"]);
        assert!(matches!(
            authorize_cdi(&req, &specs, &authorized).unwrap_err(),
            CdiError::UnsatisfiedRequest { .. }
        ));
    }

    /// A spec of the requested kind exists and is measured, but does not declare the
    /// requested device: nothing provides it, so the request is unsatisfied rather than
    /// being waved through on the strength of a sibling spec.
    #[test]
    fn unsatisfied_request_when_measured_spec_lacks_the_device() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=7").unwrap()];
        let specs = vec![spec_with("nvidia.com/gpu", "sha256:TRUSTED", &["0", "1"])];
        let authorized = auth(&["sha256:TRUSTED"]);
        assert!(matches!(
            authorize_cdi(&req, &specs, &authorized).unwrap_err(),
            CdiError::UnsatisfiedRequest { .. }
        ));
    }

    /// Regression, F-183: authorization must bind a device to the spec that *provides* it,
    /// not to its CDI kind.
    ///
    /// A measured spec of kind `nvidia.com/gpu` legitimately provides device `0`. A host
    /// that can write one file into the spec directory adds an unmeasured spec of the same
    /// kind declaring device `1` with arbitrary `containerEdits`. The device names do not
    /// collide, so the CDI cache's conflict handling never fires and the host's edits are
    /// injected. Matching on `kind` accepted this, because a measured spec of that kind
    /// existed -- and reported the innocent spec's digest as the binding.
    #[test]
    fn unmeasured_spec_cannot_hide_behind_a_measured_spec_of_the_same_kind() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=1").unwrap()];
        let specs = vec![
            spec_with("nvidia.com/gpu", "sha256:TRUSTED", &["0"]),
            spec_with("nvidia.com/gpu", "sha256:HOST_ARBITRARY", &["1"]),
        ];
        let authorized = auth(&["sha256:TRUSTED"]);
        match authorize_cdi(&req, &specs, &authorized).unwrap_err() {
            CdiError::UnmeasuredSpec {
                device,
                found_digest,
                ..
            } => {
                assert_eq!(device, "nvidia.com/gpu=1");
                assert_eq!(found_digest, "sha256:HOST_ARBITRARY");
            }
            other => panic!("expected UnmeasuredSpec, got {:?}", other),
        }
    }

    /// Regression, F-183: when several specs declare the same device, *every* one of them
    /// must be measured. Which one the CDI cache resolves the device from depends on spec
    /// precedence, so authorizing on the strength of the measured one would authorize edits
    /// that may never be the ones applied.
    #[test]
    fn every_spec_declaring_the_device_must_be_measured() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap()];
        let specs = vec![
            spec_with("nvidia.com/gpu", "sha256:TRUSTED", &["0"]),
            spec_with("nvidia.com/gpu", "sha256:HOST_ARBITRARY", &["0"]),
        ];
        let authorized = auth(&["sha256:TRUSTED"]);
        assert!(matches!(
            authorize_cdi(&req, &specs, &authorized).unwrap_err(),
            CdiError::UnmeasuredSpec { .. }
        ));

        // ... and it is accepted once both providers are measured.
        let authorized = auth(&["sha256:TRUSTED", "sha256:HOST_ARBITRARY"]);
        assert_eq!(authorize_cdi(&req, &specs, &authorized).unwrap().len(), 1);
    }

    /// An unmeasured spec of an authorized kind is irrelevant so long as it declares none
    /// of the requested devices: it cannot contribute edits to this container.
    #[test]
    fn unmeasured_spec_declaring_other_devices_is_ignored() {
        let req = vec![CdiDeviceRequest::parse("nvidia.com/gpu=0").unwrap()];
        let specs = vec![
            spec_with("nvidia.com/gpu", "sha256:TRUSTED", &["0"]),
            spec_with("nvidia.com/gpu", "sha256:HOST_ARBITRARY", &["3"]),
        ];
        let authorized = auth(&["sha256:TRUSTED"]);
        let v = authorize_cdi(&req, &specs, &authorized).unwrap();
        assert_eq!(v[0].spec_digest, "sha256:TRUSTED");
    }
}
