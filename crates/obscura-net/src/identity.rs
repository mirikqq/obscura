//! Binding a [`StealthProfile`] to the stack that actually goes on the wire.
//!
//! `obscura-stealth` names the emulation a profile is allowed to claim, and
//! `StealthProfile::validate` rejects a profile that claims anything else. This
//! module is the other end of that contract: it turns the name back into the
//! `wreq_util` enum the client is built from.
//!
//! The names are `wreq_util`'s own serde identifiers, so the mapping is a
//! deserialization rather than a hand-written table that would rot the moment
//! `wreq_util` adds a stack. [`every_supported_emulation_resolves`] walks the
//! whole list and fails the build if the two crates ever disagree.

use obscura_stealth::StealthProfile;

/// Resolve an emulation name into the profile `wreq` will emulate.
///
/// `None` when `wreq_util` does not know the name. The caller falls back to the
/// default stack rather than failing the request: a slightly older handshake is
/// an ordinary browser, while no request at all is a broken run.
pub fn profile_by_name(name: &str) -> Option<wreq_util::Profile> {
    serde_json::from_value(serde_json::Value::String(name.to_string())).ok()
}

/// Resolve a platform name (`"windows"`, `"macos"`, ...) into `wreq_util`'s enum.
pub fn platform_by_name(name: &str) -> Option<wreq_util::Platform> {
    serde_json::from_value(serde_json::Value::String(name.to_string())).ok()
}

/// The emulation options for a profile.
///
/// Both halves come from the profile: the stack from `tls_impersonate` (which
/// validation has already tied to the browser and version the UA names) and the
/// platform from the OS the profile claims. Taking the platform from the *host*
/// instead is the mistake this exists to prevent -- it would send
/// `sec-ch-ua-platform: "Windows"` under a macOS user agent whenever the engine
/// happened to run on Windows.
pub fn emulation_for(profile: &StealthProfile) -> wreq_util::Emulation {
    let stack = profile_by_name(&profile.tls_impersonate).unwrap_or_else(|| {
        tracing::warn!(
            stack = %profile.tls_impersonate,
            "profile names a stack this build of wreq_util does not have; \
             falling back to the default"
        );
        wreq_util::Profile::default()
    });
    let platform = platform_by_name(obscura_stealth::expected_platform(profile))
        .unwrap_or(wreq_util::Platform::Windows);
    wreq_util::Emulation::builder()
        .profile(stack)
        .platform(platform)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract between the two crates. `obscura-stealth` lists the stacks
    /// a profile may declare; every one of them has to resolve here, or a
    /// validated profile would still fall back to the wrong handshake at
    /// runtime with only a warning to show for it.
    #[test]
    fn every_supported_emulation_resolves() {
        for name in obscura_stealth::supported_emulations() {
            assert!(
                profile_by_name(&name).is_some(),
                "obscura-stealth offers '{name}', which wreq_util cannot emulate"
            );
        }
    }

    /// The platform names `expected_platform` returns must resolve too.
    #[test]
    fn every_platform_name_resolves() {
        for name in ["windows", "macos", "linux", "android", "ios"] {
            assert!(
                platform_by_name(name).is_some(),
                "wreq_util cannot emulate platform '{name}'"
            );
        }
    }

    /// A preset must reach the wire as the browser it claims to be.
    #[test]
    fn presets_resolve_to_their_own_stack() {
        for (name, profile) in obscura_stealth::presets::all() {
            assert!(
                profile_by_name(&profile.tls_impersonate).is_some(),
                "preset {name} names an unresolvable stack '{}'",
                profile.tls_impersonate
            );
        }
    }

    #[test]
    fn an_unknown_stack_does_not_resolve() {
        assert!(profile_by_name("chrome_9001").is_none());
        assert!(platform_by_name("beos").is_none());
    }
}
