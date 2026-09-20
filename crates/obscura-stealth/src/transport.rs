//! The wire identity a profile is allowed to claim.
//!
//! A profile is only coherent if the ClientHello a site sees belongs to the
//! browser the user agent names. `tls_impersonate` used to be free text that
//! nothing read, so a profile could say `firefox_135` and still hand over a
//! Chrome handshake -- the JA4-versus-UA contradiction is a stronger signal
//! than either value on its own.
//!
//! This module derives the emulation name from the fields that actually decide
//! it (browser name, major version, device class) and [`StealthProfile::validate`]
//! rejects any profile that declares something else. The names are `wreq_util`'s
//! own profile identifiers; `obscura-net` resolves them back into the enum and
//! its `every_supported_emulation_resolves` test fails the build if this list
//! and the transport ever disagree.

use crate::profile::{DeviceClass, StealthProfile};

/// Chrome desktop stacks `wreq_util` can emit, newest last.
const CHROME_STACKS: &[u32] = &[
    100, 101, 104, 105, 106, 107, 108, 109, 110, 114, 116, 117, 118, 119, 120, 123, 124, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146,
    147, 148,
];

/// Firefox stacks `wreq_util` can emit, newest last.
const FIREFOX_STACKS: &[u32] = &[
    109, 117, 128, 133, 135, 136, 139, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
];

/// Safari desktop stacks, as `wreq_util` spells them.
const SAFARI_DESKTOP_STACKS: &[(&str, u32)] = &[
    ("safari_15.3", 15),
    ("safari_16", 16),
    ("safari_17.0", 17),
    ("safari_18", 18),
    ("safari_18.2", 18),
    ("safari_18.3.1", 18),
    ("safari_18.5", 18),
    ("safari_26", 26),
    ("safari_26.4", 26),
];

/// Safari-on-iOS stacks, as `wreq_util` spells them.
const SAFARI_IOS_STACKS: &[(&str, u32)] = &[
    ("safari_ios_17.2", 17),
    ("safari_ios_18.1.1", 18),
    ("safari_ios_26", 26),
    ("safari_ios_26.2", 26),
];

/// Every emulation name a profile may legally declare.
///
/// `obscura-net` asserts each one resolves to a real `wreq_util::Profile`, so a
/// name that only exists here is a build failure rather than a runtime surprise.
pub fn supported_emulations() -> Vec<String> {
    let mut names: Vec<String> = CHROME_STACKS
        .iter()
        .map(|major| format!("chrome_{major}"))
        .collect();
    names.extend(FIREFOX_STACKS.iter().map(|major| format!("firefox_{major}")));
    names.extend(
        SAFARI_DESKTOP_STACKS
            .iter()
            .chain(SAFARI_IOS_STACKS)
            .map(|(name, _)| (*name).to_string()),
    );
    names
}

/// Pick the newest stack at or below `major`, falling back to the oldest.
///
/// A profile claiming a browser version newer than any captured stack still has
/// to put *some* real handshake on the wire. Sending the newest one we have is
/// the closest available truth; inventing parameters for the version it names
/// would produce a ClientHello no shipping browser emits, which is the one
/// outcome worse than being a few versions behind.
fn nearest(stacks: &[u32], major: u32) -> u32 {
    stacks
        .iter()
        .copied()
        .filter(|candidate| *candidate <= major)
        .next_back()
        .unwrap_or_else(|| stacks.first().copied().unwrap_or(major))
}

fn nearest_named(stacks: &[(&'static str, u32)], major: u32) -> &'static str {
    stacks
        .iter()
        .filter(|(_, candidate)| *candidate <= major)
        .next_back()
        .or_else(|| stacks.first())
        .map(|(name, _)| *name)
        .unwrap_or("safari_26")
}

/// The major version a profile's `browser_version` names.
fn major_version(profile: &StealthProfile) -> u32 {
    profile
        .browser_version
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .unwrap_or(0)
}

/// The emulation this profile's browser and device class actually emit.
///
/// This is the single source of truth: presets declare it, `validate()` checks
/// it, and `obscura-net` builds the client from it.
pub fn expected_emulation(profile: &StealthProfile) -> String {
    let major = major_version(profile);
    match profile.browser_name.as_str() {
        "Firefox" => format!("firefox_{}", nearest(FIREFOX_STACKS, major)),
        "Safari" => {
            let stacks = if profile.device_class == DeviceClass::MobileIOS {
                SAFARI_IOS_STACKS
            } else {
                SAFARI_DESKTOP_STACKS
            };
            nearest_named(stacks, major).to_string()
        }
        // Chrome, Edge and every other Chromium-derived brand share the stack.
        _ => format!("chrome_{}", nearest(CHROME_STACKS, major)),
    }
}

/// The platform `wreq_util` should claim, as its `Platform` enum spells it.
///
/// This drives the platform-dependent request headers (`sec-ch-ua-platform`
/// among them), so it has to follow the profile's OS rather than the host the
/// engine happens to run on.
pub fn expected_platform(profile: &StealthProfile) -> &'static str {
    match profile.device_class {
        DeviceClass::MobileAndroid => "android",
        DeviceClass::MobileIOS => "ios",
        DeviceClass::Desktop => match profile.os_name.as_str() {
            "macOS" => "macos",
            "Linux" => "linux",
            _ => "windows",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presets;

    #[test]
    fn every_preset_declares_the_stack_it_emits() {
        for (name, profile) in presets::all() {
            assert_eq!(
                profile.tls_impersonate,
                expected_emulation(&profile),
                "{name} declares a TLS identity it does not emit"
            );
        }
    }

    #[test]
    fn declared_names_are_all_supported() {
        let supported = supported_emulations();
        for (name, profile) in presets::all() {
            assert!(
                supported.contains(&profile.tls_impersonate),
                "{name} names '{}', which is not a stack we can emit",
                profile.tls_impersonate
            );
        }
    }

    /// A version newer than any captured stack falls back to the newest one
    /// rather than naming a handshake nothing can produce.
    #[test]
    fn unknown_future_version_falls_back_to_newest() {
        let mut profile = presets::chrome_148_windows();
        profile.browser_version = "400.0.1.2".into();
        assert_eq!(expected_emulation(&profile), "chrome_148");
    }

    #[test]
    fn platform_follows_the_profile_not_the_host() {
        assert_eq!(
            expected_platform(&presets::chrome_148_macos()),
            "macos"
        );
        assert_eq!(
            expected_platform(&presets::chrome_148_linux()),
            "linux"
        );
        assert_eq!(
            expected_platform(&presets::chrome_148_windows()),
            "windows"
        );
        assert_eq!(
            expected_platform(&presets::pixel_9_pro_chrome_148()),
            "android"
        );
        assert_eq!(
            expected_platform(&presets::iphone_15_pro_safari_18()),
            "ios"
        );
    }

    /// Firefox must not be handed the Chromium stack, and the reverse.
    #[test]
    fn browser_family_selects_the_stack_family() {
        assert!(expected_emulation(&presets::firefox_135_macos()).starts_with("firefox_"));
        assert!(expected_emulation(&presets::chrome_148_macos()).starts_with("chrome_"));
        assert!(expected_emulation(&presets::iphone_15_pro_safari_18()).starts_with("safari_ios_"));
    }
}
