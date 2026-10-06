use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use qkd_stub::{Config, app, keys};
use serde_json::{Value, json};
use tower::ServiceExt;

async fn request(
    method: &str,
    uri: &str,
    body: Option<String>,
    header: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(value) = header {
        req = req.header("Request-SAE-ID", value);
    }
    if body.is_some() {
        req = req.header("Content-Type", "application/json");
    }
    let res = app(Config::new(psk()))
        .oneshot(req.body(Body::from(body.unwrap_or_default())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    assert_eq!(res.headers()["content-type"], "application/json");
    assert_eq!(res.headers()["cache-control"], "no-store");
    let body = to_bytes(res.into_body(), 2 * 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
const ENC: &str = "/api/v1/keys/B/enc_keys";
const DEC: &str = "/api/v1/keys/A/dec_keys";
const VECTOR: &str = "00200000-0000-8678-9abc-def012345679";

#[test]
fn fixed_vector_and_uuid_validation() {
    let key = keys::derive(VECTOR, &psk()).unwrap();
    assert_eq!(key.key, "nVsQbynRkkSHxR590PcH9EjAZfPx6vgYbS2iigrJgLE=");
    assert_eq!(
        keys::derive(&VECTOR.to_uppercase(), &psk()).unwrap().key,
        key.key
    );
    for id in [
        "",
        "invalid",
        "514b0020123486789abcdef012345678",
        "514b0020-1234-4678-9abc-def012345678",
        "514b0020-1234-8678-1abc-def012345678",
        "004b0020-1234-8678-9abc-def012345678",
        "514b0000-1234-8678-9abc-def012345678",
        "514b2001-1234-8678-9abc-def012345678",
    ] {
        assert!(keys::derive(id, &psk()).is_err(), "{id}");
    }
}

#[test]
fn roundtrip_sizes_and_fresh_ids() {
    let mut ids = std::collections::HashSet::new();
    for size in [8, 16, 128, 256, 512, 1024, 65_536] {
        for _ in 0..20 {
            let key = keys::generate(size, &psk()).unwrap();
            assert!(ids.insert(key.key_id.clone()));
            assert_eq!(STANDARD.decode(&key.key).unwrap().len(), size as usize / 8);
            assert_eq!(keys::derive(&key.key_id, &psk()).unwrap().key, key.key);
            let uuid = uuid::Uuid::parse_str(&key.key_id).unwrap();
            assert_eq!(uuid.as_bytes()[6] >> 4, 8);
            assert_eq!(uuid.as_bytes()[8] >> 6, 2);
            assert_eq!(
                u16::from_be_bytes([uuid.as_bytes()[0], uuid.as_bytes()[1]]) as u32 * 8,
                size
            );
        }
    }
}

#[tokio::test]
async fn status_fields_and_identity() {
    for header in [None, Some("caller-A")] {
        let (code, value) = request("GET", "/api/v1/keys/peer%20B/status", None, header).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(
            value,
            json!({
                "source_KME_ID":"kme-local", "target_KME_ID":"kme-peer",
                "master_SAE_ID":header.unwrap_or("sae-local"), "slave_SAE_ID":"peer B",
                "key_size":256, "stored_key_count":1024, "max_key_count":1024,
                "max_key_per_request":128, "max_key_size":65536, "min_key_size":8, "max_SAE_ID_count":0
            })
        );
    }
}

#[tokio::test]
async fn get_post_interoperate_across_independent_routers() {
    for (method, uri, body) in [
        ("GET", ENC.to_owned(), None),
        ("POST", ENC.to_owned(), Some("{}".into())),
        ("GET", format!("{ENC}?number=3&size=512"), None),
        (
            "POST",
            ENC.to_owned(),
            Some(json!({"number":3,"size":512}).to_string()),
        ),
        ("GET", format!("{ENC}?number=128&size=8"), None),
        ("GET", format!("{ENC}?size=65536"), None),
    ] {
        let (code, issued) = request(method, &uri, body, None).await;
        assert_eq!(code, StatusCode::OK);
        let keys = issued["keys"].as_array().unwrap();
        let ids: Vec<_> = keys.iter().map(|k| json!({"key_ID":k["key_ID"]})).collect();
        let (code, retrieved) =
            request("POST", DEC, Some(json!({"key_IDs":ids}).to_string()), None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(issued, retrieved);
        // Repeated GETs on newly constructed routers need no issuance history.
        for _ in 0..2 {
            let (code, retrieved) = request(
                "GET",
                &format!("{DEC}?key_ID={}", keys[0]["key_ID"].as_str().unwrap()),
                None,
                None,
            )
            .await;
            assert_eq!(code, StatusCode::OK);
            assert_eq!(retrieved["keys"][0], keys[0]);
        }
    }
}

#[tokio::test]
async fn reject_bad_counts_and_sizes_in_both_methods() {
    for field in ["number", "size"] {
        let values = if field == "number" {
            vec!["0", "-1", "129", "1.5", "4294967296", "null", "\"x\""]
        } else {
            vec!["0", "-8", "7", "257", "65544", "1.5", "4294967296", "\"x\""]
        };
        for val in values {
            for (method, uri, body) in [
                (
                    "GET",
                    format!("{ENC}?{field}={}", val.replace('"', "%22")),
                    None,
                ),
                (
                    "POST",
                    ENC.to_owned(),
                    Some(format!("{{\"{field}\":{val}}}")),
                ),
            ] {
                let (code, error) = request(method, &uri, body, None).await;
                assert_eq!(
                    code,
                    StatusCode::BAD_REQUEST,
                    "{method} {field}={val}: {error}"
                );
                assert!(error["message"].is_string());
            }
        }
    }
    let (_, error) = request("GET", &format!("{ENC}?size=9"), None, None).await;
    assert_eq!(error["message"], "size shall be a multiple of 8");
}

#[tokio::test]
async fn extensions_and_invalid_bodies() {
    for body in [
        "{",
        "[]",
        "[1,256,[],[],[]]",
        "null",
        "{\"extension_optional\":42}",
        "{\"additional_slave_SAE_IDs\":[\"C\"]}",
    ] {
        assert_eq!(
            request("POST", ENC, Some(body.into()), None).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (code, value) = request(
        "POST",
        ENC,
        Some(json!({"extension_mandatory":[{"vendor_x":true}]}).to_string()),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(
        value["message"],
        "not all extension_mandatory parameters are supported"
    );
    assert_eq!(request("POST", ENC, Some(json!({"extension_optional":[{"vendor_x":{"anything":true}}], "extension_mandatory":[], "additional_slave_SAE_IDs":[]}).to_string()), None).await.0, StatusCode::OK);
    let (code, error) = request(
        "POST",
        ENC,
        Some(json!({"padding":"x".repeat(65536)}).to_string()),
        None,
    )
    .await;
    assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(error["message"].is_string());
}

#[tokio::test]
async fn invalid_dec_requests_are_atomic() {
    for body in [
        "{}".to_owned(),
        "{\"key_IDs\":[]}".into(),
        "{\"key_IDs\":[{}]}".into(),
        "{\"key_IDs\":[{\"key_ID\":null}]}".into(),
        json!({"key_IDs":[{"key_ID":VECTOR},{"key_ID":"bad"}]}).to_string(),
        json!({"key_IDs":vec![json!({"key_ID":VECTOR});129]}).to_string(),
    ] {
        let (code, error) = request("POST", DEC, Some(body), None).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(error.get("keys").is_none());
        assert!(error["message"].is_string());
    }
    let body = json!({"key_IDs":[[VECTOR]]}).to_string();
    assert_eq!(
        request("POST", DEC, Some(body), None).await.0,
        StatusCode::BAD_REQUEST
    );
    for suffix in [
        "",
        "?key_ID=",
        "?key_ID=bad",
        "?key_ID=514b2001-1234-8678-9abc-def012345678",
    ] {
        assert_eq!(
            request("GET", &format!("{DEC}{suffix}"), None, None)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn concurrent_issuance_and_retrieval() {
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..64 {
        tasks.spawn(async {
            let (status, issued) = request("GET", ENC, None, None).await;
            assert_eq!(status, StatusCode::OK);
            let id = issued["keys"][0]["key_ID"].as_str().unwrap();
            let (status, retrieved) =
                request("GET", &format!("{DEC}?key_ID={id}"), None, None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(issued, retrieved);
            id.to_owned()
        });
    }
    let mut ids = std::collections::HashSet::new();
    while let Some(result) = tasks.join_next().await {
        assert!(ids.insert(result.unwrap()));
    }
}

#[tokio::test]
async fn routing_errors_are_json() {
    assert_eq!(
        request("GET", "/api/v1/keys/%FF/status", None, None)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request("GET", "/unknown", None, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request("DELETE", ENC, None, None).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

fn psk() -> keys::Psk {
    keys::Psk::new(&[7; 32]).unwrap()
}
