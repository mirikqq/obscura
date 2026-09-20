//! Finding out where this engine's traffic actually comes out.
//!
//! `obscura-stealth::egress` decides what an exit address *implies* -- the
//! timezone, the coordinates, the locale -- and deliberately opens no sockets.
//! This is the half that does, because the answer has to describe the address
//! the *site* sees, which means going through the same proxy the page load
//! will use rather than asking about the machine the engine runs on.
//!
//! Two routes, in order of preference:
//!
//! 1. **Local GeoLite2.** Resolve the exit IP against a MaxMind database on
//!    disk, the way Camoufox does. One cheap request to learn the address, then
//!    an offline lookup. Nothing about the run is disclosed to a geolocation
//!    provider, and it keeps working when that provider is down or blocked --
//!    which is exactly when a proxied run is most likely to need it.
//! 2. **HTTP providers.** Three independent endpoints, tried in turn, for hosts
//!    with no database and no wish to download one.
//!
//! Best-effort throughout: when neither route answers, the profile keeps the
//! locale it already had. A confident wrong position contradicts the clock and
//! the address, which is worse than not having claimed one.

use std::net::IpAddr;
use std::time::Duration;

use obscura_stealth::{Egress, StealthProfile};

/// How long any single lookup may take before the page load stops waiting.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(6);

/// How long the GeoLite2 download may take. Generous next to a lookup: the
/// database is tens of megabytes and this happens at most once a month.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);

/// Endpoints that report the calling address, in preference order.
///
/// The first two report a full record; `api.country.is` returns only a country
/// and is the last resort. Independent operators on purpose: one being down or
/// blocked must not silently leave every profile mis-localised.
const PROVIDERS: &[&str] = &[
    "https://ipinfo.io/json",
    "https://ipapi.co/json/",
    "https://api.country.is/",
];

/// Endpoints that report only the caller's IP, for the GeoLite2 route.
const IP_PROVIDERS: &[&str] = &["https://api.ipify.org", "https://checkip.amazonaws.com"];

/// Align `profile` to the address its traffic leaves from.
///
/// Gated so it never fires on the offline test path: the lookup only earns its
/// round trip when the traffic leaves through a proxy (the exit IP then differs
/// from the host) or the caller forces it with `OBSCURA_ALIGN_EGRESS=1`. A
/// profile that is already aligned is left alone, and `OBSCURA_NO_EGRESS=1`
/// disables it outright.
///
/// Returns whether the profile changed.
pub async fn align_to_egress(profile: &mut StealthProfile) -> bool {
    let has_proxy = profile.proxy.is_some() || std::env::var_os("OBSCURA_PROXY").is_some();
    let forced = std::env::var_os("OBSCURA_ALIGN_EGRESS").is_some();
    let disabled = std::env::var_os("OBSCURA_NO_EGRESS").is_some();
    if !obscura_stealth::wants_egress(has_proxy, forced, disabled, profile.latitude.is_some()) {
        return false;
    }
    match detect_egress(profile).await {
        Some(egress) => obscura_stealth::apply_egress(profile, &egress),
        None => false,
    }
}

/// Resolve the exit address, preferring the local database.
pub async fn detect_egress(profile: &StealthProfile) -> Option<Egress> {
    if !obscura_stealth::geo::disabled() {
        if let Some(egress) = detect_via_geolite(profile).await {
            return Some(egress);
        }
    }
    detect_via_providers(profile).await
}

/// The two-letter country of the exit address, for callers that need no more.
pub async fn detect_country(profile: &StealthProfile) -> Option<String> {
    detect_egress(profile).await.map(|egress| egress.country)
}

/// Learn the exit IP, then resolve it against the local GeoLite2 database.
async fn detect_via_geolite(profile: &StealthProfile) -> Option<Egress> {
    let path = obscura_stealth::geo::mmdb_path();
    if obscura_stealth::geo::needs_refresh(&path) {
        // A refresh that fails is not fatal: an existing (stale) database still
        // answers, and a missing one falls through to the HTTP providers.
        refresh_geolite(profile).await;
    }
    let address = detect_public_ip(profile).await?;
    let egress = obscura_stealth::geo::lookup(address);
    if egress.is_some() {
        tracing::debug!(%address, "resolved the egress address from the local GeoLite2 database");
    }
    egress
}

/// Ask an endpoint for the address it sees us as.
async fn detect_public_ip(profile: &StealthProfile) -> Option<IpAddr> {
    for url in IP_PROVIDERS {
        let Some(body) = get_text(profile, url).await else {
            continue;
        };
        if let Ok(address) = body.trim().parse::<IpAddr>() {
            return Some(address);
        }
    }
    None
}

/// Download the GeoLite2 database into the cache.
///
/// Only from a source the operator named. Fetching a binary database from a
/// third-party redistribution on our own initiative is a supply-chain decision
/// that is not the engine's to make; with no source configured the lookup
/// falls through to the HTTP providers instead.
async fn refresh_geolite(profile: &StealthProfile) {
    let Some(url) = obscura_stealth::geo::mmdb_url() else {
        tracing::debug!(
            "no OBSCURA_GEOIP_URL configured; skipping the GeoLite2 download"
        );
        return;
    };
    let Some(client) = client_for(profile) else {
        return;
    };
    let request = client.get(&url).send();
    let Ok(Ok(response)) = tokio::time::timeout(DOWNLOAD_TIMEOUT, request).await else {
        tracing::debug!(%url, "GeoLite2 download did not complete; continuing without it");
        return;
    };
    if !response.status().is_success() {
        tracing::debug!(%url, status = %response.status(), "GeoLite2 download refused");
        return;
    }
    let Ok(bytes) = response.bytes().await else {
        return;
    };
    match obscura_stealth::geo::install(&bytes) {
        Ok(path) => tracing::info!(path = %path.display(), "cached the GeoLite2 database"),
        Err(error) => tracing::debug!(%error, "could not cache the GeoLite2 database"),
    }
}

/// Fall back to the geolocation providers.
async fn detect_via_providers(profile: &StealthProfile) -> Option<Egress> {
    for url in PROVIDERS {
        let Some(body) = get_text(profile, url).await else {
            continue;
        };
        if let Some(egress) = obscura_stealth::parse_egress(&body) {
            return Some(egress);
        }
    }
    None
}

/// One GET through the profile's own transport, proxy included.
async fn get_text(profile: &StealthProfile, url: &str) -> Option<String> {
    let client = client_for(profile)?;
    let request = client.get(url).send();
    let Ok(Ok(response)) = tokio::time::timeout(LOOKUP_TIMEOUT, request).await else {
        return None;
    };
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}

/// A client wearing this profile's identity, through this profile's proxy.
///
/// Built per lookup rather than shared: this runs at most a handful of times
/// per profile, and reusing the page's pooled client would put these requests
/// in the same connection pool as the page's own traffic.
fn client_for(profile: &StealthProfile) -> Option<wreq::Client> {
    let mut builder = wreq::Client::builder()
        .emulation(crate::identity::emulation_for(profile))
        .timeout(LOOKUP_TIMEOUT);
    let proxy = profile
        .proxy
        .clone()
        .or_else(|| std::env::var("OBSCURA_PROXY").ok());
    if let Some(proxy) = proxy.as_deref().filter(|proxy| !proxy.is_empty()) {
        match wreq::Proxy::all(proxy) {
            Ok(proxy) => builder = builder.proxy(proxy),
            Err(error) => {
                // Without the proxy the lookup would describe the host rather
                // than the exit, which is precisely the wrong answer -- so this
                // fails the lookup instead of silently going direct.
                tracing::warn!(%error, "egress lookup proxy is unusable; skipping alignment");
                return None;
            }
        }
    }
    builder.build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offline-suite invariant: with no proxy and no force flag, nothing
    /// here opens a socket.
    #[tokio::test]
    async fn no_proxy_and_no_force_makes_no_request() {
        std::env::remove_var("OBSCURA_PROXY");
        std::env::remove_var("OBSCURA_ALIGN_EGRESS");
        let mut profile = obscura_stealth::presets::chrome_148_windows();
        assert!(!align_to_egress(&mut profile).await);
        assert_eq!(profile.timezone, "America/New_York");
    }

    /// An already-aligned profile is not looked up again, even behind a proxy.
    #[tokio::test]
    async fn an_aligned_profile_is_left_alone() {
        let mut profile = obscura_stealth::presets::chrome_148_windows();
        profile.proxy = Some("http://127.0.0.1:1".into());
        profile.latitude = Some(59.3294);
        profile.timezone = "Europe/Stockholm".into();
        assert!(!align_to_egress(&mut profile).await);
        assert_eq!(profile.timezone, "Europe/Stockholm");
    }

    /// A profile with an unparseable proxy must not fall back to a direct
    /// lookup: that would report the host's address as the exit.
    #[test]
    fn an_unusable_proxy_yields_no_client() {
        let mut profile = obscura_stealth::presets::chrome_148_windows();
        profile.proxy = Some("not a proxy url".into());
        assert!(client_for(&profile).is_none());
    }
}

/// The identity this process uses, aligned to its egress once.
///
/// Rotating identity from one address is itself a signal, and the alignment
/// costs a round trip, so both happen exactly once per process. The result is
/// shared by every context and page.
static ALIGNED: tokio::sync::OnceCell<std::sync::Arc<StealthProfile>> =
    tokio::sync::OnceCell::const_new();

/// The process identity, aligning it to the egress on first call.
///
/// Call this from a path that can await -- the CLI does, before it opens any
/// page -- so the synchronous [`current_profile`] used while constructing a
/// page finds it already resolved.
pub async fn aligned_profile() -> std::sync::Arc<StealthProfile> {
    ALIGNED
        .get_or_init(|| async {
            let mut profile = obscura_stealth::select();
            if align_to_egress(&mut profile).await {
                tracing::info!(
                    timezone = %profile.timezone,
                    latitude = ?profile.latitude,
                    "aligned the browser identity to the egress address"
                );
            }
            if let Err(errors) = profile.validate() {
                // A profile that contradicts itself is worse than the default:
                // the contradiction is the signal. Fall back rather than ship it.
                tracing::warn!(
                    errors = ?errors,
                    "the selected profile is not internally consistent; using the default"
                );
                return std::sync::Arc::new(obscura_stealth::default_profile());
            }
            std::sync::Arc::new(profile)
        })
        .await
        .clone()
}

/// The process identity as it stands, without waiting for the alignment.
///
/// Page construction is synchronous, so it cannot await the lookup. When
/// [`aligned_profile`] has already run -- which is the normal path, because the
/// CLI awaits it at startup -- this returns the aligned profile; otherwise it
/// returns the unaligned selection, which is still internally consistent and
/// still matches the transport, just not the exit address.
pub fn current_profile() -> std::sync::Arc<StealthProfile> {
    if let Some(profile) = ALIGNED.get() {
        return profile.clone();
    }
    std::sync::Arc::new(obscura_stealth::select())
}
