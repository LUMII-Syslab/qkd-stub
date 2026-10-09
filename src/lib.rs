pub mod auth;
pub mod events;
pub mod keys;
pub mod server;
pub mod setup;
pub mod tls;

use auth::{PeerIdentity, Registry};
use keys::{AccessError, Parties, Psk};
use std::{sync::Arc, time::Instant};

use axum::{
    Json, Router,
    extract::{
        DefaultBodyLimit, FromRequestParts, MatchedPath, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header::CACHE_CONTROL, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use keys::{Key, MAX_BITS, MAX_COUNT};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone)]
pub struct Config {
    pub psk: Arc<Psk>,
    pub auth: Option<Arc<Registry>>,
    pub sae_id: String,
    pub kme_id: String,
    pub peer_kme_id: String,
    /// Receives one event per handled request when set.
    pub events: Option<events::EventSender>,
}
impl Config {
    pub fn new(psk: Psk) -> Self {
        Self {
            auth: None,
            psk: Arc::new(psk),
            sae_id: "sae-local".into(),
            kme_id: "kme-local".into(),
            peer_kme_id: "kme-peer".into(),
            events: None,
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
        .layer(middleware::from_fn_with_state(config.clone(), record))
        .with_state(config)
}

/// Publish one event per request. Never reads the query string or body.
async fn record(State(c): State<Config>, request: Request, next: Next) -> Response {
    let Some(events) = c.events.clone() else {
        return next.run(request).await;
    };
    let started = Instant::now();
    let method = request.method().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or("(unmatched)", MatchedPath::as_str)
        .to_owned();
    let caller_sae = c
        .auth
        .as_ref()
        .zip(request.extensions().get::<PeerIdentity>().and_then(|p| p.0))
        .and_then(|(registry, code)| registry.id(code).map(str::to_owned));
    let response = next.run(request).await;
    // A send error only means that nobody is listening.
    let _ = events.send(events::Event {
        time: time::OffsetDateTime::now_utc(),
        caller_sae,
        method,
        route,
        status: response.status().as_u16(),
        duration_ms: started.elapsed().as_millis() as u64,
    });
    response
}

pub struct ApiError(StatusCode, String);
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

struct SaeRequest {
    peer_id: String,
    pair: Option<Parties>,
}
impl FromRequestParts<Config> for SaeRequest {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Config,
    ) -> Result<Self, Self::Rejection> {
        let Path(peer_id) = Path::<String>::from_request_parts(parts, state)
            .await
            .map_err(|e| bad(e.body_text()))?;
        let pair = if let Some(registry) = &state.auth {
            let caller = parts
                .extensions
                .get::<PeerIdentity>()
                .and_then(|p| p.0)
                .filter(|code| registry.id(*code).is_some())
                .ok_or_else(unauthorized)?;
            let peer = registry.code(&peer_id).ok_or_else(unauthorized)?;
            Some(Parties {
                master: caller,
                slave: peer,
            })
        } else {
            None
        };
        Ok(Self { peer_id, pair })
    }
}
fn unauthorized() -> ApiError {
    ApiError(
        StatusCode::UNAUTHORIZED,
        "SAE is not authorized for this request".into(),
    )
}

async fn status(
    State(c): State<Config>,
    sae: SaeRequest,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let master = if let (Some(registry), Some(pair)) = (&c.auth, sae.pair) {
        registry.id(pair.master).ok_or_else(unauthorized)?
    } else {
        match headers.get("Request-SAE-ID") {
            Some(value) => value
                .to_str()
                .map_err(|_| bad("invalid Request-SAE-ID header"))?,
            None => &c.sae_id,
        }
    };
    Ok(Json(json!({
        "source_KME_ID": c.kme_id, "target_KME_ID": c.peer_kme_id,
        "master_SAE_ID": master, "slave_SAE_ID": sae.peer_id,
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

fn issue(
    request: KeyRequest,
    parties: Option<Parties>,
    psk: &Psk,
) -> Result<Json<Container>, ApiError> {
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
        .map(|_| match parties {
            Some(p) => keys::generate_bound(size, p, psk),
            None => keys::generate(size, psk),
        })
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
    State(c): State<Config>,
    sae: SaeRequest,
    query: Result<Query<EncQuery>, QueryRejection>,
) -> Result<Json<Container>, ApiError> {
    let Query(q) = query.map_err(query_error)?;
    issue(
        KeyRequest {
            number: q.number,
            size: q.size,
            ..Default::default()
        },
        sae.pair,
        &c.psk,
    )
}
async fn enc_post(
    State(c): State<Config>,
    sae: SaeRequest,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Container>, ApiError> {
    let value = body.map_err(json_error)?.0;
    for field in ["number", "size"] {
        if value.get(field).is_some_and(Value::is_null) {
            return Err(bad(format!("{field} must be an integer")));
        }
    }
    issue(object_body(value)?, sae.pair, &c.psk)
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
fn retrieve(
    ids: Vec<KeyId>,
    parties: Option<Parties>,
    psk: &Psk,
) -> Result<Json<Container>, ApiError> {
    if !(1..=MAX_COUNT).contains(&ids.len()) {
        return Err(bad("key_IDs must contain between 1 and 128 IDs"));
    }
    let keys = ids
        .iter()
        .map(|id| match parties {
            Some(pair) => keys::derive_bound(
                &id.key_id,
                Parties {
                    master: pair.slave,
                    slave: pair.master,
                },
                psk,
            )
            .map_err(|e| match e {
                AccessError::Invalid(message) => bad(message),
                AccessError::Unauthorized => unauthorized(),
            }),
            None => keys::derive(&id.key_id, psk).map_err(bad),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Container { keys }))
}
async fn dec_get(
    State(c): State<Config>,
    sae: SaeRequest,
    query: Result<Query<KeyId>, QueryRejection>,
) -> Result<Json<Container>, ApiError> {
    retrieve(vec![query.map_err(query_error)?.0], sae.pair, &c.psk)
}
async fn dec_post(
    State(c): State<Config>,
    sae: SaeRequest,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Container>, ApiError> {
    let value = body.map_err(json_error)?.0;
    if let Some(ids) = value.get("key_IDs").and_then(Value::as_array)
        && ids.iter().any(|id| !id.is_object())
    {
        return Err(bad("each key_IDs entry must be a JSON object"));
    }
    retrieve(object_body::<KeyIds>(value)?.key_ids, sae.pair, &c.psk)
}
