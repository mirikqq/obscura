#![cfg(feature = "stealth")]

use std::io::{Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use obscura::Browser;

const ORDINARY_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";

fn spawn_server() -> (String, mpsc::Receiver<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = mpsc::sync_channel(1);

    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        request_tx
            .send(String::from_utf8(request).unwrap())
            .unwrap();

        let body = "<!doctype html><html><body>ok</body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body,
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    (format!("http://{}", addr), request_rx)
}

async fn navigate_user_agent(stealth: bool) -> String {
    let (url, request_rx) = spawn_server();

    let browser = Browser::builder().stealth(stealth).build().unwrap();
    let mut page = browser.new_page().await.unwrap();
    page.goto(&url).await.unwrap();

    let request = request_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    request
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("user-agent")
                .then(|| value.trim().to_string())
        })
        .expect("request should include a user-agent header")
}

#[tokio::test(flavor = "current_thread")]
async fn stealth_transport_requires_compile_time_and_runtime_opt_in() {
    std::env::set_var("OBSCURA_ALLOW_PRIVATE_NETWORK", "1");
    std::env::set_var("OBSCURA_PROFILE", "0");

    // The stealth UA is asserted against the profile rather than a literal.
    // What matters is that the wire carries the *identity the engine selected*
    // -- the same object its ClientHello was built from. Pinning a version
    // string here would only test that nobody bumped the preset.
    let profile = obscura_net::current_profile();
    assert_eq!(navigate_user_agent(true).await, profile.user_agent);
    assert_ne!(
        profile.user_agent, ORDINARY_USER_AGENT,
        "stealth must not fall back to the ordinary profile's identity"
    );
    assert_eq!(navigate_user_agent(false).await, ORDINARY_USER_AGENT);
}
