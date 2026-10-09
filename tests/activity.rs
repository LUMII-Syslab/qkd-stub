//! Activity events and the data APIs used by the GUI.
use axum::{
    Extension,
    body::Body,
    http::{Request, StatusCode},
};
use qkd_stub::{
    Config, app,
    auth::{PeerIdentity, Registry},
    events,
    keys::Psk,
    setup::{self, Command, DemoCommand, Settings},
};
use std::sync::Arc;
use tower::ServiceExt;

fn config(sender: Option<events::EventSender>) -> Config {
    Config {
        auth: Some(Arc::new(
            Registry::from_toml("[[sae]]\nid='A'\ncode=1\n[[sae]]\nid='B'\ncode=2").unwrap(),
        )),
        events: sender,
        ..Config::new(Psk::new(&[7; 32]).unwrap())
    }
}

#[tokio::test]
async fn requests_publish_events_without_query_or_secrets() {
    let (sender, mut receiver) = events::channel();
    let router = app(config(Some(sender))).layer(Extension(PeerIdentity(Some(1))));
    let status = router
        .clone()
        .oneshot(
            Request::get("/api/v1/keys/B/dec_keys?key_ID=secret-key-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status();
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.caller_sae.as_deref(), Some("A"));
    assert_eq!(event.method, "GET");
    assert_eq!(event.route, "/api/v1/keys/{sae}/dec_keys");
    assert_eq!(event.status, 400);
    assert!(!format!("{event:?}").contains("secret-key-id"));

    router
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let event = receiver.try_recv().unwrap();
    assert_eq!((event.route.as_str(), event.status), ("(unmatched)", 404));
}

#[tokio::test]
async fn unknown_or_missing_identity_has_no_caller() {
    let (sender, mut receiver) = events::channel();
    let router = app(config(Some(sender)));
    let response = router
        .oneshot(
            Request::get("/api/v1/keys/B/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let event = receiver.try_recv().unwrap();
    assert_eq!((event.caller_sae, event.status), (None, 401));
}

#[tokio::test]
async fn no_sender_means_no_overhead_or_failure() {
    let response = app(config(None))
        .layer(Extension(PeerIdentity(Some(1))))
        .oneshot(
            Request::get("/api/v1/keys/B/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn setup_data_apis_describe_a_demo() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let dir = tempfile::tempdir().unwrap();
    let demo = dir.path().join("demo");
    setup::run(
        Command::Demo {
            command: DemoCommand::Init { dir: demo.clone() },
        },
        &demo.join("unused.toml"),
    )
    .await
    .unwrap();
    let path = demo.join("a.toml");
    let settings = Settings::load(&path).unwrap().resolved(&path);

    let report = setup::check_report(&settings);
    assert_eq!(report.len(), 4);
    assert!(report.iter().all(|item| item.result.is_ok()));

    let cas = setup::trusted_cas(&settings).unwrap();
    assert_eq!(cas.len(), 1);
    assert!(cas[0].subject.contains("QKD stub demo CA"));
    assert_eq!(cas[0].sha256.len(), 64);

    let server = setup::server_certificates(&settings).unwrap();
    assert!(server[0].subject.contains("server-a"));

    let saes = setup::sae_entries(&settings).unwrap();
    assert_eq!(saes.len(), 2);
    assert_eq!((saes[0].id.as_str(), saes[0].code), ("A", 1));
    assert_eq!(saes[0].identities, ["{ subject_dn = \"CN=client-a\" }"]);

    std::fs::remove_file(&settings.psk_file).unwrap();
    let report = setup::check_report(&settings);
    assert!(report[0].result.is_err());
    assert!(report[1..].iter().all(|item| item.result.is_ok()));
}
