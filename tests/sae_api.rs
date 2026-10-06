use axum::{
    Extension,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use qkd_stub::{
    Config, app,
    auth::{PeerIdentity, Registry},
    keys::{self, AccessError, Parties},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

fn registry() -> Arc<Registry> {
    Arc::new(Registry::from_toml(
            "[[sae]]\nid='A'\ncode=1\n[[sae]]\nid='B'\ncode=2\n[[sae]]\nid='C'\ncode=3\n[[sae]]\nid='D'\ncode=4",
        ).unwrap())
}
async fn call(
    caller: Option<u16>,
    method: &str,
    path: &str,
    body: Option<Value>,
    spoof: Option<&str>,
) -> (StatusCode, Value) {
    let router = app(Config {
        auth: Some(registry()),
        ..Config::new(psk())
    });
    // The live server inserts this extension only after verifying the TLS peer.
    let router = match caller {
        Some(code) => router.layer(Extension(PeerIdentity(Some(code)))),
        None => router,
    };
    let mut request = Request::builder()
        .method(method)
        .uri(format!("/api/v1/keys/{path}"));
    if let Some(id) = spoof {
        request = request.header("Request-SAE-ID", id);
    }
    let request = request
        .header("Content-Type", "application/json")
        .body(Body::from(body.map(|v| v.to_string()).unwrap_or_default()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn authenticated_status_and_required_identity() {
    for path in ["B/status", "B/enc_keys", "B/dec_keys?key_ID=bad"] {
        assert_eq!(
            call(None, "GET", path, None, Some("A")).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(Some(99), "GET", path, None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, body) = call(Some(1), "GET", "B/status", None, Some("D")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["master_SAE_ID"], "A");
    assert_eq!(body["slave_SAE_ID"], "B");
    for method in ["status", "enc_keys"] {
        assert_eq!(
            call(Some(1), "GET", &format!("unknown/{method}"), None, None)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn independent_pairs_and_atomic_batch_authorization() {
    let mut issued = Vec::new();
    for (caller, target) in [(1, "B"), (3, "D")] {
        let (status, keys) = call(
            Some(caller),
            "POST",
            &format!("{target}/enc_keys"),
            Some(json!({"number":2,"size":512})),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        issued.push(keys);
    }
    let ids = |v: &Value| json!({"key_IDs":v["keys"].as_array().unwrap().iter().map(|k|json!({"key_ID":k["key_ID"]})).collect::<Vec<_>>()});
    for (caller, master, keys) in [(2, "A", &issued[0]), (4, "C", &issued[1])] {
        let (status, result) = call(
            Some(caller),
            "POST",
            &format!("{master}/dec_keys"),
            Some(ids(keys)),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&result, keys);
    }
    let id = issued[0]["keys"][0]["key_ID"].as_str().unwrap();
    assert_eq!(
        call(
            Some(2),
            "GET",
            &format!("A/dec_keys?key_ID={id}"),
            None,
            Some("D")
        )
        .await
        .1["keys"][0],
        issued[0]["keys"][0]
    );
    for (caller, path) in [(4, "A"), (1, "A"), (2, "C")] {
        assert_eq!(
            call(
                Some(caller),
                "GET",
                &format!("{path}/dec_keys?key_ID={id}"),
                None,
                Some("B")
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let mixed = json!({"key_IDs":[{"key_ID":issued[0]["keys"][0]["key_ID"]},{"key_ID":issued[1]["keys"][0]["key_ID"]}]});
    let (status, error) = call(Some(2), "POST", "A/dec_keys", Some(mixed), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(error.get("keys").is_none());
    // Repeat/restart semantics: each call constructs a fresh router.
    assert_eq!(
        call(Some(2), "POST", "A/dec_keys", Some(ids(&issued[0])), None)
            .await
            .1,
        issued[0]
    );
}

#[tokio::test]
async fn binding_rejects_unassigned_codes_and_opt_out_skips_authorization() {
    let old = keys::generate(256, &psk()).unwrap();
    assert_eq!(
        call(
            Some(2),
            "GET",
            &format!("A/dec_keys?key_ID={}", old.key_id),
            None,
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let bound = keys::generate_bound(
        256,
        Parties {
            master: 1,
            slave: 2,
        },
        &psk(),
    )
    .unwrap();
    assert_eq!(keys::derive(&bound.key_id, &psk()).unwrap().key, bound.key);
    assert!(matches!(
        keys::derive_bound(
            &bound.key_id,
            Parties {
                master: 1,
                slave: 3
            },
            &psk()
        ),
        Err(AccessError::Unauthorized)
    ));
}

#[test]
fn bound_ids_preserve_pair_and_sizes() {
    for size in [8, 256, 512, 65536] {
        let pair = Parties {
            master: 65535,
            slave: 2,
        };
        let k = keys::generate_bound(size, pair, &psk()).unwrap();
        assert_eq!(
            keys::derive_bound(&k.key_id, pair, &psk()).unwrap().key,
            k.key
        );
        let uuid = uuid::Uuid::parse_str(&k.key_id).unwrap();
        assert_eq!(
            u16::from_be_bytes([uuid.as_bytes()[0], uuid.as_bytes()[1]]) as u32 * 8,
            size
        );
        assert_eq!(&uuid.as_bytes()[2..4], &[255, 255]);
        assert_eq!(&uuid.as_bytes()[4..6], &[0, 2]);
    }
    assert!(
        keys::generate_bound(
            256,
            Parties {
                master: 0,
                slave: 2
            },
            &psk()
        )
        .is_err()
    );
    let k = keys::derive_bound(
        "00200001-0002-8678-9abc-def0123456b4",
        Parties {
            master: 1,
            slave: 2,
        },
        &psk(),
    )
    .unwrap();
    assert_eq!(k.key, "JT3926nJlkFON+iD/HgZVKA4ft8nPE+YrJSH8zvYSgw=");
}

fn psk() -> keys::Psk {
    keys::Psk::new(&[7; 32]).unwrap()
}
