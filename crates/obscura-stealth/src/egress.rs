//! Aligning the fingerprint with the connection it goes out on.
//!
//! A profile is only coherent relative to the address it is presented from. An
//! exit IP in Stockholm paired with `Europe/Paris` and `fr-FR` is not a subtle
//! inconsistency — geolocation of the peer is the cheapest signal a risk engine
//! has, and it is checked against the timezone and `Accept-Language` on nearly
//! every request. Randomising the locale independently of the egress therefore
//! makes a profile *worse* than leaving it fixed.
//!
//! So the locale is not sampled: it is resolved from wherever the traffic
//! actually leaves, through the very client that will carry the page load —
//! proxy included, since that is the address the site sees.
//!
//! This module is the policy half and stays free of any socket: what a
//! country implies, whether a lookup is worth its round trip, and how a
//! provider's answer is read. `obscura-net::egress` performs the lookup over
//! the page's own client, and `geo` resolves an address offline from a
//! GeoLite2 database the way Camoufox does.

use crate::profile::StealthProfile;

/// Country → (language tag, `navigator.languages`, IANA timezone).
///
/// One entry per country we can speak for: the primary language as the site
/// would expect it, English kept as a secondary where it is genuinely common,
/// and the timezone of the country's main population centre.
const COUNTRY_LOCALES: &[(&str, &str, &[&str], &str)] = &[
    ("US", "en-US", &["en-US", "en"], "America/New_York"),
    ("CA", "en-CA", &["en-CA", "en", "fr-CA"], "America/Toronto"),
    ("GB", "en-GB", &["en-GB", "en"], "Europe/London"),
    ("IE", "en-IE", &["en-IE", "en"], "Europe/Dublin"),
    (
        "DE",
        "de-DE",
        &["de-DE", "de", "en-US", "en"],
        "Europe/Berlin",
    ),
    ("AT", "de-AT", &["de-AT", "de", "en"], "Europe/Vienna"),
    (
        "CH",
        "de-CH",
        &["de-CH", "de", "fr-CH", "en"],
        "Europe/Zurich",
    ),
    (
        "FR",
        "fr-FR",
        &["fr-FR", "fr", "en-US", "en"],
        "Europe/Paris",
    ),
    ("ES", "es-ES", &["es-ES", "es", "en"], "Europe/Madrid"),
    ("IT", "it-IT", &["it-IT", "it", "en"], "Europe/Rome"),
    ("PT", "pt-PT", &["pt-PT", "pt", "en"], "Europe/Lisbon"),
    (
        "NL",
        "nl-NL",
        &["nl-NL", "nl", "en-US", "en"],
        "Europe/Amsterdam",
    ),
    (
        "BE",
        "nl-BE",
        &["nl-BE", "nl", "fr-BE", "en"],
        "Europe/Brussels",
    ),
    (
        "SE",
        "sv-SE",
        &["sv-SE", "sv", "en-US", "en"],
        "Europe/Stockholm",
    ),
    (
        "NO",
        "nb-NO",
        &["nb-NO", "no", "en-US", "en"],
        "Europe/Oslo",
    ),
    (
        "DK",
        "da-DK",
        &["da-DK", "da", "en-US", "en"],
        "Europe/Copenhagen",
    ),
    (
        "FI",
        "fi-FI",
        &["fi-FI", "fi", "en-US", "en"],
        "Europe/Helsinki",
    ),
    (
        "PL",
        "pl-PL",
        &["pl-PL", "pl", "en-US", "en"],
        "Europe/Warsaw",
    ),
    ("CZ", "cs-CZ", &["cs-CZ", "cs", "en"], "Europe/Prague"),
    ("RO", "ro-RO", &["ro-RO", "ro", "en"], "Europe/Bucharest"),
    ("UA", "uk-UA", &["uk-UA", "uk", "ru", "en"], "Europe/Kyiv"),
    (
        "RU",
        "ru-RU",
        &["ru-RU", "ru", "en-US", "en"],
        "Europe/Moscow",
    ),
    (
        "TR",
        "tr-TR",
        &["tr-TR", "tr", "en-US", "en"],
        "Europe/Istanbul",
    ),
    (
        "BR",
        "pt-BR",
        &["pt-BR", "pt", "en-US", "en"],
        "America/Sao_Paulo",
    ),
    ("MX", "es-MX", &["es-MX", "es", "en"], "America/Mexico_City"),
    (
        "AR",
        "es-AR",
        &["es-AR", "es", "en"],
        "America/Argentina/Buenos_Aires",
    ),
    ("IN", "en-IN", &["en-IN", "en", "hi"], "Asia/Kolkata"),
    ("JP", "ja-JP", &["ja-JP", "ja", "en-US", "en"], "Asia/Tokyo"),
    ("KR", "ko-KR", &["ko-KR", "ko", "en-US", "en"], "Asia/Seoul"),
    ("SG", "en-SG", &["en-SG", "en", "zh-CN"], "Asia/Singapore"),
    ("AU", "en-AU", &["en-AU", "en"], "Australia/Sydney"),
    ("NZ", "en-NZ", &["en-NZ", "en"], "Pacific/Auckland"),
    ("ZA", "en-ZA", &["en-ZA", "en"], "Africa/Johannesburg"),
    ("AE", "en-AE", &["en-AE", "en", "ar"], "Asia/Dubai"),
    (
        "IL",
        "he-IL",
        &["he-IL", "he", "en-US", "en"],
        "Asia/Jerusalem",
    ),
    ("HK", "zh-HK", &["zh-HK", "zh", "en"], "Asia/Hong_Kong"),
];

/// What the lookup could tell us about the address the traffic leaves from.
///
/// Country is the only field every provider returns; the rest are present when
/// the provider gives them. The city-level fields matter because a country is
/// not a timezone: an exit in Los Angeles and one in New York share `US`, and
/// resolving both to the country's main population centre puts a
/// coast-and-a-half between the address a site geolocates and the clock the
/// browser reports.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Egress {
    pub country: String,
    pub city: Option<String>,
    pub region: Option<String>,
    /// IANA zone as the provider resolved it for this address.
    pub timezone: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Align a profile with the address its traffic leaves from.
///
/// Returns `false` only when there is nothing usable — no provider timezone and
/// no table entry for the country. Better to keep the sampled locale than to
/// invent a mapping, since a wrong-but-confident pairing is exactly the
/// inconsistency this exists to avoid.
pub fn apply_egress(profile: &mut StealthProfile, egress: &Egress) -> bool {
    let cc = egress.country.trim().to_ascii_uppercase();
    let entry = COUNTRY_LOCALES.iter().find(|(c, ..)| *c == cc);

    // The provider resolved the zone for this exact address; the table only
    // knows the country's main population centre. Prefer the address.
    let tz = egress
        .timezone
        .as_deref()
        .filter(|t| t.contains('/'))
        .map(str::to_string)
        .or_else(|| entry.map(|(_, _, _, tz)| (*tz).to_string()));
    let Some(tz) = tz else {
        return false;
    };
    profile.timezone = tz;

    // Coordinates ride along so the geolocation surface agrees with the clock
    // and the address, for whatever reads it.
    profile.latitude = egress.latitude;
    profile.longitude = egress.longitude;

    // The language does not follow the address: English reads as ordinary from
    // anywhere, and a localised captcha is unreadable to whoever is driving.
    // Set `OBSCURA_MATCH_LANG=1` to take the country's language too.
    match (
        std::env::var_os("OBSCURA_MATCH_LANG").is_some(),
        entry,
    ) {
        (true, Some((_, lang, langs, _))) => {
            profile.language = (*lang).to_string();
            profile.languages = langs.iter().map(|s| (*s).to_string()).collect();
        }
        _ => {
            profile.language = "en-US".to_string();
            profile.languages = vec!["en-US".to_string(), "en".to_string()];
        }
    }
    true
}

/// Whether an egress lookup is worth making for this profile.
///
/// Pure so the network-avoidance policy is testable without a socket. The
/// lookup only earns its round trip when the traffic leaves through a proxy
/// (the exit IP then differs from the host) or the caller forces it; a
/// direct-connect run — which is every offline test — makes no network call.
pub fn wants_egress(has_proxy: bool, forced: bool, disabled: bool, already_aligned: bool) -> bool {
    !disabled && !already_aligned && (has_proxy || forced)
}

/// Back-compat shim for callers that only have a country code.
pub fn apply_country(profile: &mut StealthProfile, country: &str) -> bool {
    apply_egress(
        profile,
        &Egress {
            country: country.to_string(),
            ..Egress::default()
        },
    )
}

/// Countries this module can align a profile to.
pub fn known_countries() -> impl Iterator<Item = &'static str> {
    COUNTRY_LOCALES.iter().map(|(c, ..)| *c)
}

/// Read what the provider will tell us about the exit address.
///
/// The three providers spell things differently — ipinfo packs the coordinates
/// into one `"loc": "lat,lon"` string while ipapi.co splits them into
/// `latitude`/`longitude`, and the country arrives as either `country` or
/// `country_code`. A country is only accepted as exactly two ASCII letters,
/// which rejects a full country name arriving under the same key.
///
/// `None` when there is no country: the rest is optional detail, but without a
/// country there is nothing to align to.
pub fn parse_egress(body: &str) -> Option<Egress> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;

    let country = ["country_code", "country"]
        .iter()
        .filter_map(|k| v.get(*k).and_then(|x| x.as_str()))
        .find(|s| s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic()))?
        .to_ascii_uppercase();

    let text = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .filter(|s| !s.is_empty())
    };
    // A provider may send a number or a numeric string for the same field.
    let num = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_f64().or_else(|| x.as_str()?.parse().ok()))
    };

    let (loc_lat, loc_lon) = v
        .get("loc")
        .and_then(|x| x.as_str())
        .and_then(|s| s.split_once(','))
        .map(|(a, b)| (a.trim().parse().ok(), b.trim().parse().ok()))
        .unwrap_or((None, None));

    Some(Egress {
        country,
        city: text("city"),
        region: text("region"),
        timezone: text("timezone"),
        latitude: num("latitude").or(loc_lat),
        longitude: num("longitude").or(loc_lon),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_only_fires_when_it_earns_the_round_trip() {
        // The property that keeps the offline test suite network-free:
        // no proxy and no force flag ⇒ never look up.
        assert!(!wants_egress(false, false, false, false));
        // A proxy, or an explicit force, makes it worthwhile.
        assert!(wants_egress(true, false, false, false));
        assert!(wants_egress(false, true, false, false));
        // Disable and already-aligned both veto, whatever else is set.
        assert!(!wants_egress(true, true, true, false));
        assert!(!wants_egress(true, true, false, true));
    }

    #[test]
    fn egress_is_read_from_either_field_name() {
        let e = parse_egress(r#"{"ip":"1.2.3.4","country":"SE","city":"Stockholm"}"#).unwrap();
        assert_eq!(e.country, "SE");
        assert_eq!(e.city.as_deref(), Some("Stockholm"));
        assert_eq!(
            parse_egress(r#"{"country_code":"fr","country_name":"France"}"#)
                .unwrap()
                .country,
            "FR"
        );
        // A full name under `country` must not be mistaken for a code.
        assert!(parse_egress(r#"{"country":"Sweden"}"#).is_none());
        assert!(parse_egress("не json").is_none());
    }

    #[test]
    fn coordinates_come_from_either_shape() {
        // ipinfo packs them into one string.
        let e = parse_egress(r#"{"country":"SE","loc":"59.3294,18.0687"}"#).unwrap();
        assert_eq!(e.latitude, Some(59.3294));
        assert_eq!(e.longitude, Some(18.0687));
        // ipapi.co splits them, and may send them as numbers.
        let e =
            parse_egress(r#"{"country_code":"US","latitude":34.05,"longitude":-118.24}"#).unwrap();
        assert_eq!(e.latitude, Some(34.05));
        assert_eq!(e.longitude, Some(-118.24));
    }

    #[test]
    fn provider_timezone_beats_the_country_table() {
        // The bug this backs: every US exit used to report the table's
        // `America/New_York`, so an address a site geolocates to Los Angeles
        // came with an East-coast clock.
        let mut p = crate::presets::chrome_148_macos();
        assert!(apply_egress(
            &mut p,
            &Egress {
                country: "US".into(),
                timezone: Some("America/Los_Angeles".into()),
                latitude: Some(34.05),
                longitude: Some(-118.24),
                ..Egress::default()
            }
        ));
        assert_eq!(p.timezone, "America/Los_Angeles");
        assert_eq!(p.latitude, Some(34.05));
    }

    #[test]
    fn country_table_is_the_fallback_and_language_stays_english() {
        let mut p = crate::presets::chrome_148_macos();
        assert!(apply_country(&mut p, "se"));
        // No provider zone: the table's entry stands in.
        assert_eq!(p.timezone, "Europe/Stockholm");
        // The language does not follow the address — English is ordinary
        // from anywhere, and a localised captcha is unreadable to the driver.
        assert_eq!(p.language, "en-US");
        // Unknown country with no provider zone leaves the profile untouched.
        let before = p.timezone.clone();
        assert!(!apply_country(&mut p, "XX"));
        assert_eq!(p.timezone, before);
    }
}
