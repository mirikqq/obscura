//! Coherent browser identities for Obscura.
//!
//! A fingerprint is not judged field by field. What a risk engine actually
//! checks is whether the fields agree: whether the TLS handshake belongs to the
//! browser the user agent names, whether the clock matches the address the
//! connection comes from, whether the WebGL renderer is one that ships on the
//! platform claimed. Any single value here is ordinary; the combinations are
//! what give an engine away.
//!
//! So this crate owns the identity as one object. [`StealthProfile`] holds every
//! surface -- navigator, screen, WebGL, client hints, locale, wire stack -- and
//! [`StealthProfile::validate`] rejects a profile whose fields contradict each
//! other before it reaches a site.
//!
//! Where a profile comes from
//! --------------------------
//! * [`presets`] -- fixed, hand-verified identities. Stable and offline.
//! * [`generator`] -- drawn from a Bayesian network of observed fingerprints,
//!   so field *combinations* are ones that occur in the wild rather than ones
//!   that merely look plausible.
//!
//! Either way the profile is then aligned to the connection it goes out on:
//! [`geo`] resolves the exit address against a local GeoLite2 database the way
//! Camoufox does, and [`egress`] turns that into the timezone, coordinates and
//! locale the profile reports. `obscura-net` performs the lookup, because this
//! crate deliberately opens no sockets.
//!
//! [`transport`] is the seam that keeps the two halves honest: it derives the
//! `wreq_util` stack a profile is allowed to claim, `validate()` enforces it,
//! and `obscura-net` builds the client from it.
//!
//! These are anti-fingerprinting measures: they present a normal, consistent
//! browser identity so ordinary automation traffic is not singled out. There is
//! no bot or automation-abuse payload here.

pub mod behavior;
pub mod config;
pub mod egress;
pub mod generator;
pub mod geo;
pub mod gpu;
pub mod presets;
pub mod profile;
pub mod transport;

pub use behavior::{BehaviorProfile, Handedness, MousePoint, ScrollStyle, WheelTick};
pub use config::{ConfigError, ConfigFormat};
pub use egress::{apply_country, apply_egress, known_countries, parse_egress, wants_egress, Egress};
pub use generator::{Constraints, GeneratorError};
pub use gpu::GpuProfile;
pub use presets::{default_profile, select};
pub use profile::{DeviceClass, MediaDeviceInfo, StealthProfile};
pub use transport::{expected_emulation, expected_platform, supported_emulations};
