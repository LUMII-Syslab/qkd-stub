pub mod keys;

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use keys::{Key, MAX_BITS, MAX_COUNT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone)]
pub struct Config {
    pub sae_id: String,
    pub kme_id: String,
    pub peer_kme_id: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            sae_id: "sae-local".into(),
            kme_id: "kme-local".into(),
            peer_kme_id: "kme-peer".into(),
        }
    }
}

pub fn app(config: Config) -> Router {
    Router::new()
        .route("/api/v1/keys/{sae}/status", get(status))
        .route("/api/v1/keys/{sae}/enc_keys", get(enc_get).post(enc_post))
        .route("/api/v1/keys/{sae}/dec_keys", get(dec_get).post(dec_post))
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, "not found".into()) })
        .method_not_allowed_fallback(|| async {
            ApiError(StatusCode::METHOD_NOT_ALLOWED, "method not allowed".into())
        })
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::map_response(
            |mut response: Response| async move {
                response
                    .headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                response
            },
        ))
        .with_state(config)
}

struct ApiError(StatusCode, String);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"message": self.1}))).into_response()
    }
}
fn bad(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}
fn json_error(e: JsonRejection) -> ApiError {
    ApiError(
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            e.status()
        } else {
            StatusCode::BAD_REQUEST
        },
        e.body_text(),
    )
}
fn query_error(e: QueryRejection) -> ApiError {
    bad(e.body_text())
}

async fn status(
    State(c): State<Config>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let Path(sae) = path.map_err(|e| bad(e.body_text()))?;
    let master = match headers.get("Request-SAE-ID") {
        Some(value) => value
            .to_str()
            .map_err(|_| bad("invalid Request-SAE-ID header"))?,
        None => &c.sae_id,
    };
    Ok(Json(json!({
        "source_KME_ID": c.kme_id, "target_KME_ID": c.peer_kme_id,
        "master_SAE_ID": master, "slave_SAE_ID": sae,
        "key_size": 256, "stored_key_count": 1024, "max_key_count": 1024,
        "max_key_per_request": MAX_COUNT, "max_key_size": MAX_BITS,
        "min_key_size": 8, "max_SAE_ID_count": 0
    })))
}

#[derive(Default, Deserialize)]
struct EncQuery {
    number: Option<u32>,
    size: Option<u32>,
}
#[derive(Default, Deserialize)]
struct KeyRequest {
    number: Option<u32>,
    size: Option<u32>,
    #[serde(default, rename = "additional_slave_SAE_IDs")]
    additional: Vec<String>,
    #[serde(default)]
    extension_mandatory: Vec<serde_json::Map<String, Value>>,
    #[serde(default, rename = "extension_optional")]
    _optional: Vec<serde_json::Map<String, Value>>,
}
#[derive(Serialize)]
struct Container {
    keys: Vec<Key>,
}

fn issue(request: KeyRequest) -> Result<Json<Container>, ApiError> {
    let number = request.number.unwrap_or(1) as usize;
    let size = request.size.unwrap_or(256);
    if !(1..=MAX_COUNT).contains(&number) {
        return Err(bad("number must be between 1 and 128"));
    }
    if !size.is_multiple_of(8) {
        return Err(bad("size shall be a multiple of 8"));
    }
    if !(8..=MAX_BITS).contains(&size) {
        return Err(bad("size must be between 8 and 65536 bits"));
    }
    if !request.extension_mandatory.is_empty() {
        return Err(bad("not all extension_mandatory parameters are supported"));
    }
    if !request.additional.is_empty() {
        return Err(bad("additional_slave_SAE_IDs are not supported"));
    }
    let keys = (0..number)
        .map(|_| keys::generate(size))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            ApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "key generation unavailable".into(),
            )
        })?;
    Ok(Json(Container { keys }))
}
async fn enc_get(
    query: Result<Query<EncQuery>, QueryRejection>,
) -> Result<Json<Container>, ApiError> {
    let Query(q) = query.map_err(query_error)?;
    issue(KeyRequest {
        number: q.number,
        size: q.size,
        ..Default::default()
    })
}
async fn enc_post(body: Result<Json<Value>, JsonRejection>) -> Result<Json<Container>, ApiError> {
    let value = body.map_err(json_error)?.0;
    for field in ["number", "size"] {
        if value.get(field).is_some_and(Value::is_null) {
            return Err(bad(format!("{field} must be an integer")));
        }
    }
    issue(object_body(value)?)
}
fn object_body<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ApiError> {
    if !value.is_object() {
        return Err(bad("request body must be a JSON object"));
    }
    serde_json::from_value(value).map_err(|e| bad(e.to_string()))
}
#[derive(Deserialize)]
struct KeyId {
    #[serde(rename = "key_ID")]
    key_id: String,
}
#[derive(Deserialize)]
struct KeyIds {
    #[serde(rename = "key_IDs")]
    key_ids: Vec<KeyId>,
}
fn retrieve(ids: Vec<KeyId>) -> Result<Json<Container>, ApiError> {
    if !(1..=MAX_COUNT).contains(&ids.len()) {
        return Err(bad("key_IDs must contain between 1 and 128 IDs"));
    }
    let keys = ids
        .iter()
        .map(|id| keys::derive(&id.key_id))
        .collect::<Result<Vec<_>, _>>()
        .map_err(bad)?;
    Ok(Json(Container { keys }))
}
async fn dec_get(query: Result<Query<KeyId>, QueryRejection>) -> Result<Json<Container>, ApiError> {
    retrieve(vec![query.map_err(query_error)?.0])
}
async fn dec_post(body: Result<Json<Value>, JsonRejection>) -> Result<Json<Container>, ApiError> {
    let value = body.map_err(json_error)?.0;
    if let Some(ids) = value.get("key_IDs").and_then(Value::as_array)
        && ids.iter().any(|id| !id.is_object())
    {
        return Err(bad("each key_IDs entry must be a JSON object"));
    }
    retrieve(object_body::<KeyIds>(value)?.key_ids)
}
