//! The upstream node's JSON-RPC surface over a [`Capture`], served a prefix at a time.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

use crate::capture::{hex, Capture, ChainScope, EventRow, EventType};
use crate::json::{write_string, Json};
use crate::{ReplayError, Result};
use raven_railgun_core::hex::decode_hex;

const POI_EVENTS: &str = "ppoi_poi_events";
const NODE_STATUS: &str = "ppoi_node_status";
const VALIDATE_POI_MERKLEROOTS: &str = "ppoi_validate_poi_merkleroots";
const SUBMIT_TRANSACT_PROOF: &str = "ppoi_submit_transact_proof";
const SUBMIT_LEGACY_TRANSACT_PROOFS: &str = "ppoi_submit_legacy_transact_proofs";

/// Upstream `QueryLimits.MAX_EVENT_QUERY_RANGE_LENGTH`: `endIndex - startIndex` may be 500, so a
/// page holds at most 501 rows.
pub const MAX_EVENT_QUERY_RANGE_LENGTH: u32 = 500;

/// Upstream `express.json({ limit: '5mb' })`.
const BODY_LIMIT_BYTES: usize = 5 * 1024 * 1024;

/// A capture being served, `served_rows()` of it visible.
#[derive(Debug)]
pub struct Replay {
    capture: Capture,
    scope: ChainScope,
    list_key_hex: String,
    node_status: Json,
    served: AtomicUsize,
    /// Canonical root bytes to the first row that published them, sorted by root.
    root_index: Vec<([u8; 32], u32)>,
}

/// One HTTP answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Response body, JSON.
    pub body: String,
}

impl Replay {
    /// `node_status_response` is a recorded `ppoi_node_status` response body. Its `result` is
    /// served as recorded apart from this list's `poiEventLengths`,
    /// `historicalMerklerootsLength` and `latestHistoricalMerkleroot`, which follow the served
    /// prefix.
    ///
    /// # Errors
    ///
    /// [`ReplayError::NodeStatus`] if the body has no status object for this network and list,
    /// [`ReplayError::Rows`] if `served` exceeds the capture.
    pub fn new(
        capture: Capture,
        scope: ChainScope,
        node_status_response: &[u8],
        served: usize,
    ) -> Result<Self> {
        let list_key_hex = hex(capture.list_key());
        let node_status = Json::parse(node_status_response)
            .map_err(|e| ReplayError::NodeStatus(format!("not JSON: {e}")))?
            .get("result")
            .cloned()
            .ok_or_else(|| ReplayError::NodeStatus("the body has no result".to_owned()))?;
        let has_list_status = node_status
            .get("forNetwork")
            .and_then(|n| n.get(&scope.network))
            .and_then(|n| n.get("listStatuses"))
            .and_then(|s| s.get(&list_key_hex))
            .is_some_and(Json::is_object);
        if !has_list_status {
            return Err(ReplayError::NodeStatus(format!(
                "result.forNetwork.{}.listStatuses.{list_key_hex} is not an object",
                scope.network
            )));
        }
        let mut root_index: Vec<([u8; 32], u32)> = capture
            .rows()
            .iter()
            .filter(|row| capture.root_wire(row) == hex(&row.validated_merkleroot))
            .map(|row| (row.validated_merkleroot, row.index))
            .collect();
        root_index.sort_unstable();
        root_index.dedup_by_key(|(root, _)| *root);
        let replay = Self {
            capture,
            scope,
            list_key_hex,
            node_status,
            served: AtomicUsize::new(0),
            root_index,
        };
        replay.grow_to(served)?;
        Ok(replay)
    }

    /// Rows currently served, from index 0.
    #[must_use]
    pub fn served_rows(&self) -> usize {
        self.served.load(Ordering::Acquire)
    }

    /// Rows in the capture.
    #[must_use]
    pub fn total_rows(&self) -> usize {
        self.capture.rows().len()
    }

    fn served(&self) -> &[EventRow] {
        let rows = self.capture.rows();
        rows.get(..self.served_rows()).unwrap_or(rows)
    }

    /// Upstream's inclusive `$gte`/`$lte` over the served rows, which are sorted by index.
    fn rows_between(&self, start: f64, end: f64) -> &[EventRow] {
        let served = self.served();
        let lo = served.partition_point(|row| f64::from(row.index) < start);
        let hi = served.partition_point(|row| f64::from(row.index) <= end);
        served.get(lo..hi.max(lo)).unwrap_or_default()
    }

    /// Serves `rows` rows from now on. Upstream's list only grows, so neither does this.
    ///
    /// # Errors
    ///
    /// [`ReplayError::Rows`] if `rows` is past the capture or below what is already served.
    pub fn grow_to(&self, rows: usize) -> Result<()> {
        let total = self.total_rows();
        if rows > total {
            return Err(ReplayError::Rows(format!(
                "asked to serve {rows} rows, the capture holds {total}"
            )));
        }
        let before = self.served.fetch_max(rows, Ordering::AcqRel);
        if rows < before {
            return Err(ReplayError::Rows(format!(
                "asked to serve {rows} rows, {before} are already served and a list never shrinks"
            )));
        }
        Ok(())
    }

    /// Answers one `POST /` body as the upstream node does. `json_body` is whether the request
    /// declared `application/json`; upstream reads any other body as `{}`.
    #[must_use]
    pub fn answer(&self, body: &[u8], json_body: bool) -> Reply {
        let request = if json_body {
            match Json::parse(body) {
                Ok(request) => request,
                Err(e) => {
                    let message = format!("Parse error: {e}");
                    return rpc_error(400, -32700, &message, None, None);
                }
            }
        } else {
            Json::Object(Vec::new())
        };
        let id = request.get("id");
        let method = request.get("method").and_then(Json::as_str).filter(|m| {
            [
                POI_EVENTS,
                NODE_STATUS,
                VALIDATE_POI_MERKLEROOTS,
                SUBMIT_TRANSACT_PROOF,
                SUBMIT_LEGACY_TRANSACT_PROOFS,
            ]
            .contains(m)
        });
        let Some(method) = method else {
            return rpc_error(404, -32601, "Method not found", None, id);
        };
        let Some(params) = request.get("params").filter(|p| !matches!(p, Json::Null)) else {
            return rpc_error(
                400,
                -32602,
                "Invalid params",
                Some("\"params is missing\""),
                id,
            );
        };
        // Upstream's `listKeys.includes(listKey)`: strict equality, so only this exact string.
        let list_key = params.get("listKey");
        if list_key.is_some_and(Json::is_truthy)
            && list_key.and_then(Json::as_str) != Some(self.list_key_hex.as_str())
        {
            return rpc_error(
                400,
                -32602,
                "Invalid params",
                Some("\"Invalid listKey\""),
                id,
            );
        }
        let outcome = match method {
            POI_EVENTS => self.poi_events(params),
            NODE_STATUS => Ok(self.node_status(params)),
            VALIDATE_POI_MERKLEROOTS => self.validate_poi_merkleroots(params),
            _ => Err(Refusal::Logic(
                "ppoi replay is read-only: it serves a recorded list and accepts no submissions",
            )),
        };
        match outcome {
            Ok(Ok(result)) => {
                let mut body = String::with_capacity(result.len() + 48);
                body.push_str("{\"jsonrpc\":\"2.0\",\"result\":");
                body.push_str(&result);
                push_id(&mut body, id);
                Reply { status: 200, body }
            }
            Ok(Err(message)) | Err(Refusal::Logic(message)) => {
                rpc_error(500, -32603, message, None, id)
            }
            Err(Refusal::Schema(errors)) => {
                rpc_error(400, -32602, "Invalid params", Some(&errors), id)
            }
        }
    }

    fn poi_events(&self, params: &Json) -> Outcome {
        check_schema(
            params,
            &[
                ("txidVersion", Kind::String),
                ("startIndex", Kind::Number),
                ("endIndex", Kind::Number),
                ("listKey", Kind::String),
            ],
            &["txidVersion", "startIndex", "endIndex", "listKey"],
        )?;
        if !self.is_scope_chain(params) {
            return Ok(Err("No network info available."));
        }
        let start = params
            .get("startIndex")
            .and_then(Json::as_f64)
            .unwrap_or(0.0);
        let end = params.get("endIndex").and_then(Json::as_f64).unwrap_or(0.0);
        if end - start > f64::from(MAX_EVENT_QUERY_RANGE_LENGTH) {
            return Ok(Err("Max event query range length is 500"));
        }
        if end - start < 0.0 {
            return Ok(Err("Invalid query range"));
        }
        let mut out = String::from("[");
        if self.is_scope_list(params) {
            for (i, row) in self.rows_between(start, end).iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                self.write_event(row, &mut out);
            }
        }
        out.push(']');
        Ok(Ok(out))
    }

    /// Upstream's `JSON.stringify` of a `POISyncedListEvent`: this member order, no spaces.
    fn write_event(&self, row: &EventRow, out: &mut String) {
        out.push_str("{\"signedPOIEvent\":{\"index\":");
        out.push_str(&row.index.to_string());
        out.push_str(",\"blindedCommitment\":");
        if let Some(wire) = self.capture.wire_override(row.index) {
            write_string(&wire.blinded_commitment, out);
            out.push_str(",\"signature\":");
            write_string(&wire.signature, out);
            out.push_str(",\"type\":");
            write_string(&wire.event_type, out);
            out.push_str("},\"validatedMerkleroot\":");
            write_string(&wire.validated_merkleroot, out);
        } else {
            out.push_str("\"0x");
            out.push_str(&hex(&row.blinded_commitment));
            out.push_str("\",\"signature\":\"");
            out.push_str(&hex(&row.signature));
            out.push_str("\",\"type\":\"");
            out.push_str(row.event_type.wire_name());
            out.push_str("\"},\"validatedMerkleroot\":\"");
            out.push_str(&hex(&row.validated_merkleroot));
            out.push('"');
        }
        out.push('}');
    }

    fn node_status(&self, params: &Json) -> Result<String, &'static str> {
        // Upstream forwards a listed key to that list's own node; a replay has no such node.
        if params
            .get("listKey")
            .is_some_and(|k| !matches!(k, Json::Null))
        {
            return Err("Cannot connect to listKey");
        }
        let served = self.served();
        let mut counts = [0u64; 4];
        for row in served {
            if let Some(count) = counts.get_mut(usize::from(row.event_type.code())) {
                *count += 1;
            }
        }
        let mut status = self.node_status.clone();
        if let Some(list_status) = status
            .get_mut("forNetwork")
            .and_then(|n| n.get_mut(&self.scope.network))
            .and_then(|n| n.get_mut("listStatuses"))
            .and_then(|s| s.get_mut(&self.list_key_hex))
        {
            let mut lengths = list_status
                .get("poiEventLengths")
                .filter(|l| l.is_object())
                .cloned()
                .unwrap_or(Json::Object(Vec::new()));
            for (event_type, count) in EventType::ALL.into_iter().zip(counts) {
                lengths.set(event_type.wire_name(), Json::from_u64(count));
            }
            list_status.set("poiEventLengths", lengths);
            list_status.set(
                "historicalMerklerootsLength",
                Json::from_u64(u64::try_from(served.len()).unwrap_or(u64::MAX)),
            );
            list_status.set(
                "latestHistoricalMerkleroot",
                Json::String(served.last().map_or_else(
                    || "No merkleroot found".to_owned(),
                    |row| self.capture.root_wire(row),
                )),
            );
        }
        let mut out = String::new();
        status.write(&mut out);
        Ok(out)
    }

    fn validate_poi_merkleroots(&self, params: &Json) -> Outcome {
        check_schema(
            params,
            &[
                ("txidVersion", Kind::String),
                ("poiMerkleroots", Kind::Strings),
            ],
            &["txidVersion", "poiMerkleroots"],
        )?;
        if !self.is_scope_chain(params) {
            return Ok(Err("No network info available."));
        }
        let roots = match params.get("poiMerkleroots") {
            Some(Json::Array(roots)) => roots.as_slice(),
            _ => &[],
        };
        let all_exist = if self.is_scope_list(params) {
            roots
                .iter()
                .all(|root| root.as_str().is_some_and(|r| self.root_is_served(r)))
        } else {
            roots.is_empty()
        };
        Ok(Ok(all_exist.to_string()))
    }

    /// Upstream looks the string up as stored, so only the exact served spelling exists.
    fn root_is_served(&self, root: &str) -> bool {
        let served = self.served_rows();
        let canonical = root.len() == 64
            && root
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let in_index = canonical
            && decode_hex::<32>(root).is_some_and(|bytes| {
                self.root_index
                    .binary_search_by_key(&bytes, |(r, _)| *r)
                    .ok()
                    .and_then(|i| self.root_index.get(i))
                    .is_some_and(|(_, index)| usize::try_from(*index).is_ok_and(|i| i < served))
            });
        in_index
            || self.capture.overrides().any(|(index, wire)| {
                usize::try_from(*index).is_ok_and(|i| i < served)
                    && wire.validated_merkleroot == root
            })
    }

    fn is_scope_chain(&self, params: &Json) -> bool {
        let as_number = |key: &str| params.get(key).and_then(js_number);
        as_number("chainType") == Some(f64::from(self.scope.chain_type))
            && as_number("chainID") == Some(f64::from(self.scope.chain_id))
    }

    /// Any other list or txid version is a store with no rows in it.
    fn is_scope_list(&self, params: &Json) -> bool {
        params.get("listKey").and_then(Json::as_str) == Some(self.list_key_hex.as_str())
            && params.get("txidVersion").and_then(Json::as_str)
                == Some(self.scope.txid_version.as_str())
    }
}

/// A logic function's value, or the message of the error it threw.
type Outcome = Result<Result<String, &'static str>, Refusal>;

enum Refusal {
    Schema(String),
    Logic(&'static str),
}

#[derive(Clone, Copy)]
enum Kind {
    String,
    Number,
    Strings,
}

/// The subset of ajv (`allErrors`) upstream's flat schemas exercise: object type, then every
/// missing required property, then each present property's type.
fn check_schema(
    params: &Json,
    properties: &[(&str, Kind)],
    required: &[&str],
) -> Result<(), Refusal> {
    let mut errors = SchemaErrors(Vec::new());
    if !params.is_object() {
        errors.wrong_type("", "#/type", "object");
    }
    for name in required
        .iter()
        .filter(|name| params.is_object() && params.get(name).is_none())
    {
        errors.push(
            "",
            "#/required",
            "required",
            &format!("{{\"missingProperty\":\"{name}\"}}"),
            &format!("must have required property '{name}'"),
        );
    }
    for (name, kind) in properties {
        let Some(value) = params.get(name) else {
            continue;
        };
        let schema_path = format!("#/properties/{name}/type");
        match (kind, value) {
            (Kind::String, Json::String(_)) | (Kind::Number, Json::Number(_)) => {}
            (Kind::Strings, Json::Array(items)) => {
                for (i, _) in items
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| v.as_str().is_none())
                {
                    errors.wrong_type(
                        &format!("/{name}/{i}"),
                        &format!("#/properties/{name}/items/type"),
                        "string",
                    );
                }
            }
            (Kind::String, _) => errors.wrong_type(&format!("/{name}"), &schema_path, "string"),
            (Kind::Number, _) => errors.wrong_type(&format!("/{name}"), &schema_path, "number"),
            (Kind::Strings, _) => errors.wrong_type(&format!("/{name}"), &schema_path, "array"),
        }
    }
    if errors.0.is_empty() {
        Ok(())
    } else {
        Err(Refusal::Schema(format!("[{}]", errors.0.join(","))))
    }
}

/// ajv error objects, each already serialized.
struct SchemaErrors(Vec<String>);

impl SchemaErrors {
    fn push(&mut self, path: &str, schema_path: &str, keyword: &str, params: &str, message: &str) {
        let mut e = String::from("{\"instancePath\":");
        write_string(path, &mut e);
        e.push_str(",\"schemaPath\":");
        write_string(schema_path, &mut e);
        e.push_str(",\"keyword\":");
        write_string(keyword, &mut e);
        e.push_str(",\"params\":");
        e.push_str(params);
        e.push_str(",\"message\":");
        write_string(message, &mut e);
        e.push('}');
        self.0.push(e);
    }

    fn wrong_type(&mut self, path: &str, schema_path: &str, want: &str) {
        self.push(
            path,
            schema_path,
            "type",
            &format!("{{\"type\":\"{want}\"}}"),
            &format!("must be {want}"),
        );
    }
}

/// JavaScript `Number(v)` for the values a chain id arrives as.
fn js_number(value: &Json) -> Option<f64> {
    match value {
        Json::Number(n) => n.as_f64(),
        Json::Bool(b) => Some(f64::from(u8::from(*b))),
        Json::Null => Some(0.0),
        Json::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                Some(0.0)
            } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok().map(f64::from)
            } else {
                s.parse::<f64>().ok().filter(|v| v.is_finite())
            }
        }
        Json::Array(_) | Json::Object(_) => None,
    }
}

/// Upstream's `{ jsonrpc, error, id }`; `id` is left out when the request had none, as
/// `JSON.stringify` drops `undefined`.
fn rpc_error(
    status: u16,
    code: i32,
    message: &str,
    data: Option<&str>,
    id: Option<&Json>,
) -> Reply {
    let mut body = format!("{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":{code},\"message\":");
    write_string(message, &mut body);
    if let Some(data) = data {
        body.push_str(",\"data\":");
        body.push_str(data);
    }
    body.push('}');
    push_id(&mut body, id);
    Reply { status, body }
}

fn push_id(body: &mut String, id: Option<&Json>) {
    if let Some(id) = id {
        body.push_str(",\"id\":");
        id.write(body);
    }
    body.push('}');
}

/// The router: `POST /` only, which is the one route Raven's clients call.
pub fn router(replay: Arc<Replay>) -> Router {
    Router::new()
        .route("/", post(answer_http))
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .with_state(replay)
}

async fn answer_http(
    State(replay): State<Arc<Replay>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let json_body = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"));
    let reply = replay.answer(&body, json_body);
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        reply.body,
    )
        .into_response()
}

/// Binds `addr`; port 0 takes an OS-chosen port, returned beside the listener.
///
/// # Errors
///
/// [`ReplayError::Bind`] naming the address.
pub async fn bind(addr: SocketAddr) -> Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ReplayError::Bind(format!("bind {addr}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| ReplayError::Bind(format!("local address of {addr}: {e}")))?;
    Ok((listener, local))
}

/// Serves `replay` on `listener` until the accept loop fails.
///
/// # Errors
///
/// [`ReplayError::Bind`] if it does.
pub async fn serve(listener: tokio::net::TcpListener, replay: Arc<Replay>) -> Result<()> {
    axum::serve(listener, router(replay))
        .await
        .map_err(|e| ReplayError::Bind(format!("serve: {e}")))
}
