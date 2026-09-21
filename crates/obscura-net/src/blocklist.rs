
use std::collections::HashSet;
use std::sync::OnceLock;

const PGL_LIST: &str = include_str!("pgl_domains.txt");

fn blocklist() -> &'static HashSet<&'static str> {
    static BLOCKLIST: OnceLock<HashSet<&str>> = OnceLock::new();
    BLOCKLIST.get_or_init(|| {
        let mut set = HashSet::with_capacity(4000);
        for line in PGL_LIST.lines() {
            let domain = line.trim();
            if !domain.is_empty() && !domain.starts_with('#') {
                set.insert(domain);
            }
        }
        for domain in EXTRA_DOMAINS {
            set.insert(*domain);
        }
        set
    })
}

/// What a blocked request hands back.
///
/// An empty `200`, not a failure. Returning status 0 -- a network error --
/// broke two things at once. The page's own loader saw the script fail, fired
/// `onerror` and derailed whatever it was bootstrapping, which on a real site
/// takes the rest of the application down with it. And it was a fingerprint:
/// a client where exactly the tracker hosts fail, with a transport error no
/// less, is not something a browser without an extension ever looks like --
/// least of all to an origin that can watch its own beacon never arrive.
///
/// An empty body is the honest equivalent of what a content blocker achieves:
/// the resource "loads", carries nothing, and the request never leaves. Script
/// destinations get an empty script (a no-op); pixels and beacons get an empty
/// body they cannot decode, which is what being blocked looks like anyway.
pub fn blocked_response(url: &url::Url) -> crate::client::Response {
    crate::client::Response {
        status: 200,
        url: url.clone(),
        headers: std::collections::HashMap::new(),
        body: Vec::new(),
        redirected_from: Vec::new(),
    }
}

pub fn is_blocked(host: &str) -> bool {
    let bl = blocklist();

    if bl.contains(host) {
        return true;
    }

    let mut domain = host;
    while let Some(pos) = domain.find('.') {
        domain = &domain[pos + 1..];
        if bl.contains(domain) {
            return true;
        }
    }

    false
}

static EXTRA_DOMAINS: &[&str] = &[];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(is_blocked("google-analytics.com"));
        assert!(is_blocked("doubleclick.net"));
    }

    #[test]
    fn test_subdomain_match() {
        assert!(is_blocked("www.google-analytics.com"));
        assert!(is_blocked("ssl.google-analytics.com"));
    }

    #[test]
    fn test_not_blocked() {
        assert!(!is_blocked("google.com"));
        assert!(!is_blocked("example.com"));
        assert!(!is_blocked("github.com"));
    }

    #[test]
    fn test_pgl_domains() {
        assert!(is_blocked("adnxs.com"));
        assert!(is_blocked("criteo.com"));
    }

    #[test]
    fn test_blocklist_size() {
        assert!(blocklist().len() > 3500);
    }
}

#[cfg(test)]
mod blocked_response_tests {
    use super::*;

    /// The whole point of the change: a blocked script must look loaded, not
    /// failed, or the page's own loader tears the application down around it.
    #[test]
    fn a_blocked_request_reads_as_a_successful_empty_resource() {
        let url = url::Url::parse("https://tracking.epicgames.com/tracking.js").expect("url");
        let response = blocked_response(&url);
        assert!(
            (200..=299).contains(&response.status),
            "a blocked resource must be executable-but-empty, got {}",
            response.status
        );
        assert!(response.body.is_empty(), "nothing is served from a blocked host");
        assert_eq!(response.url, url);
    }

    /// The hosts from the Epic Games Store trace, so the regression is pinned
    /// to the case that exposed it: one exact entry, one parent-domain match.
    #[test]
    fn the_hosts_that_broke_the_store_are_still_matched() {
        assert!(is_blocked("tracking.epicgames.com"), "exact blocklist entry");
        assert!(
            is_blocked("static.cloudflareinsights.com"),
            "subdomain of a blocked parent"
        );
        assert!(!is_blocked("store.epicgames.com"), "the site itself is not a tracker");
        assert!(!is_blocked("components.unrealengine.com"));
    }
}
