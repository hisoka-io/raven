//! Client-declared shapes checked against the served parameters at admission, so a malformed
//! body costs one decode instead of a permit wait and a blocking worker. Each check mirrors a
//! refusal the respond or registration path makes later.

use axum::http::StatusCode;
use raven_inspire::inspiring::ClientPackingKeys;
use raven_inspire::math::Poly;
use raven_inspire::SeededClientQuery;
use raven_railgun_core::InstanceId;
use raven_railgun_engine::inspire::InspireServerState;

/// 400 for a shape this instance cannot answer; `slot` is the query's place in its batch.
pub(crate) fn refuse_malformed_shape(
    instance_id: &InstanceId,
    slot: usize,
    shape: Result<(), String>,
) -> Result<(), StatusCode> {
    shape.map_err(|reason| {
        tracing::warn!(%instance_id, slot, %reason, "refused at admission: malformed shape");
        StatusCode::BAD_REQUEST
    })
}

pub(crate) fn check_query_shape(
    state: &InspireServerState,
    query: &SeededClientQuery,
) -> Result<(), String> {
    let params = &state.crs.params;
    let rgsw = &query.rgsw_ciphertext;
    let gadget = &rgsw.gadget;
    if gadget.len != 1 || gadget.base != params.gadget_base || gadget.q != params.q {
        return Err(format!(
            "RGSW gadget len={} base={} q={}, the served CRS uses len=1 base={} q={}",
            gadget.len, gadget.base, gadget.q, params.gadget_base, params.q
        ));
    }
    if rgsw.rows.len() != 1 {
        return Err(format!(
            "RGSW carries {} rows, the served gadget has 1",
            rgsw.rows.len()
        ));
    }
    for (index, row) in rgsw.rows.iter().enumerate() {
        check_poly(
            "RGSW row b",
            index,
            &row.b,
            params.ring_dim,
            params.moduli(),
        )?;
    }
    let num_shards = state.encoded_db.config.num_shards();
    if u64::from(query.shard_id) >= num_shards {
        return Err(format!(
            "shard {} is past the {num_shards} shards this instance serves",
            query.shard_id
        ));
    }
    match (&query.inspiring_packing_keys, query.session_handle) {
        (Some(keys), None) => check_packing_key_shape(state, keys),
        (None, Some(_)) => Ok(()),
        (Some(_), Some(_)) => {
            Err("query carries both inline packing keys and a session handle".to_owned())
        }
        (None, None) => {
            Err("query carries neither inline packing keys nor a session handle".to_owned())
        }
    }
}

pub(crate) fn check_packing_key_shape(
    state: &InspireServerState,
    keys: &ClientPackingKeys,
) -> Result<(), String> {
    let pack = state.cache.pack_params();
    if keys.y_body.len() != pack.key_rows() {
        return Err(format!(
            "packing key has {} y_body rows, the served gadget needs {}",
            keys.y_body.len(),
            pack.key_rows()
        ));
    }
    if keys.num_to_pack != pack.num_to_pack {
        return Err(format!(
            "packing key declares gamma {}, the server packs {}",
            keys.num_to_pack, pack.num_to_pack
        ));
    }
    for (body, polys) in [("y_body", &keys.y_body), ("z_body", &keys.z_body)] {
        for (index, poly) in polys.iter().enumerate() {
            check_poly(body, index, poly, pack.ring_dim, &pack.moduli)?;
        }
    }
    Ok(())
}

fn check_poly(
    what: &str,
    index: usize,
    poly: &Poly,
    ring_dim: usize,
    moduli: &[u64],
) -> Result<(), String> {
    if poly.dimension() != ring_dim {
        return Err(format!(
            "{what}[{index}] has dimension {}, the served ring has {ring_dim}",
            poly.dimension()
        ));
    }
    if poly.moduli() != moduli {
        return Err(format!(
            "{what}[{index}] declares moduli {:?}, the served ring uses {moduli:?}",
            poly.moduli()
        ));
    }
    if poly.is_ntt() {
        return Err(format!(
            "{what}[{index}] is in the NTT domain; the server expects coefficients"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{header, Method, Request, StatusCode};
    use raven_inspire::inspiring::ClientPackingKeys;
    use raven_inspire::math::{GaussianSampler, Poly};
    use raven_inspire::params::{InspireParams, InspireVariant, ParamsLabel};
    use raven_inspire::rgsw::GadgetVector;
    use raven_inspire::{query_seeded, SeededClientQuery, ServerSessionHandle};
    use raven_railgun_core::InstanceId;
    use raven_railgun_engine::inspire::{setup_state, RavenInspireScheme};
    use raven_railgun_engine::{Engine, InstanceRole, PirInstance};
    use tower::ServiceExt;

    use crate::config::HttpConfig;
    use crate::state::AppState;
    use crate::versioned::{read_versioned, wire_schema_for, write_versioned, write_versioned_as};

    const INSTANCE: &str = "shape-admission";
    const ENTRY_BYTES: usize = 32;
    /// Well above a decode of these toy bodies, far below any permit wait or worker run.
    const ADMISSION_BUDGET: Duration = Duration::from_millis(50);
    /// Long enough that a body which queues for a permit cannot pass the budget.
    const PERMIT_WAIT_MS: u64 = 2_000;

    fn params() -> InspireParams {
        InspireParams {
            ring_dim: 256,
            q: 1_152_921_504_606_830_593,
            crt_moduli: vec![1_152_921_504_606_830_593],
            p: 65_537,
            sigma: 6.4,
            gadget_base: 1 << 20,
            query_gadget_len: 3,
            packing_gadget_len: 3,
            approximate_packing_gadget: false,
            params_label: ParamsLabel::Primary,
        }
    }

    struct Fixture {
        app: AppState<RavenInspireScheme>,
        /// An honest query with its packing keys inline.
        query: SeededClientQuery,
        /// An honest session upload.
        keys: ClientPackingKeys,
    }

    fn fixture() -> Fixture {
        fixture_with(params())
    }

    fn fixture_with(params: InspireParams) -> Fixture {
        let db = raven_railgun_testkit::toy_db(256, ENTRY_BYTES);
        let (state, secret_key) =
            setup_state(&params, &db, ENTRY_BYTES, InspireVariant::TwoPacking).expect("toy state");
        let mut sampler = GaussianSampler::with_seed(params.sigma, 0x51);
        let (_, query) = query_seeded(
            &state.crs,
            0,
            state.shard_config(),
            &secret_key,
            &mut sampler,
        )
        .expect("seeded query");
        assert!(query.inspiring_packing_keys.is_some() && query.session_handle.is_none());
        let keys = ClientPackingKeys::generate(
            &secret_key,
            &state.crs.params,
            state.crs.inspiring_num_columns,
            state.crs.inspiring_w_seed,
            &mut sampler,
        )
        .expect("packing keys");
        let engine: Engine<RavenInspireScheme> = Engine::new();
        engine
            .add_live(Arc::new(PirInstance::new(
                InstanceId::new(INSTANCE),
                InstanceRole::Live,
                state,
            )))
            .expect("register instance");
        let mut config = HttpConfig::demo("shape-admission-token-0123456789ab");
        config.respond_permit_wait_ms = PERMIT_WAIT_MS;
        Fixture {
            app: AppState::new(engine, config).expect("app state"),
            query,
            keys,
        }
    }

    async fn post(app: &AppState<RavenInspireScheme>, route: &str, body: Vec<u8>) -> StatusCode {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/instance/{INSTANCE}/{route}"))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header("x-raven-client-id", "33333333333333333333333333333333")
            .body(Body::from(body))
            .expect("request");
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            23_456,
        )));
        crate::inspire_router(app.clone())
            .expect("router")
            .oneshot(request)
            .await
            .expect("dispatch")
            .status()
    }

    fn batch_of(query: &SeededClientQuery) -> Vec<u8> {
        write_versioned(&vec![query.clone()]).expect("versioned batch")
    }

    /// The gadget mainnet answered 500 after 4.1-7.7 s on 2026-10-28, with its row over q = 2
    /// so the body passes the wire decode and only an admission check can refuse it early.
    fn mainnet_gadget(query: &SeededClientQuery) -> SeededClientQuery {
        let mut forged = query.clone();
        forged.rgsw_ciphertext.gadget = GadgetVector {
            base: 2,
            len: 1,
            q: 2,
        };
        forged.rgsw_ciphertext.rows[0].b = Poly::zero_moduli(params().ring_dim, &[2]);
        forged
    }

    /// With every respond and handshake permit held, the mainnet body is refused 400 within the
    /// admission budget on both read routes: it never queues for a permit or reaches a worker.
    #[tokio::test]
    async fn the_mainnet_gadget_body_is_refused_400_at_admission() {
        let fixture = fixture();
        let app = &fixture.app;
        let respond = u32::try_from(app.semaphore.available_permits()).expect("u32");
        let _respond_held = Arc::clone(&app.semaphore)
            .acquire_many_owned(respond)
            .await
            .expect("hold every respond permit");
        let forged = mainnet_gadget(&fixture.query);
        for (route, body) in [
            ("batch", batch_of(&forged)),
            ("query", write_versioned(&forged).expect("versioned query")),
        ] {
            let decoded = if route == "batch" {
                read_versioned::<Vec<SeededClientQuery>>(&body).map(|_| ())
            } else {
                read_versioned::<SeededClientQuery>(&body).map(|_| ())
            };
            assert!(decoded.is_ok(), "{route}: the forged body must decode");
            let started = Instant::now();
            let status = tokio::time::timeout(
                Duration::from_millis(PERMIT_WAIT_MS * 3),
                post(app, route, body),
            )
            .await
            .expect("answered");
            let took = started.elapsed();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{route}");
            assert!(took < ADMISSION_BUDGET, "{route} took {took:?}");
        }
    }

    /// Every client-declared shape the respond path would refuse is refused 400 up front, and
    /// the honest query the forgeries start from is served, so the 400s are the shape check's.
    #[tokio::test]
    async fn every_malformed_query_shape_is_refused_400() {
        let fixture = fixture();
        let app = &fixture.app;
        let honest = &fixture.query;
        let params = params();
        assert_eq!(post(app, "batch", batch_of(honest)).await, StatusCode::OK);

        let mut cases: Vec<(&str, SeededClientQuery)> =
            vec![("mainnet gadget", mainnet_gadget(honest))];
        let mut forged = honest.clone();
        forged.rgsw_ciphertext.gadget.base = 1 << 10;
        cases.push(("gadget base", forged));
        let mut forged = honest.clone();
        forged.rgsw_ciphertext.gadget.q = 65_537;
        cases.push(("gadget q", forged));
        let mut forged = honest.clone();
        forged.rgsw_ciphertext.gadget.len = 2;
        let row = forged.rgsw_ciphertext.rows[0].clone();
        forged.rgsw_ciphertext.rows.push(row);
        cases.push(("gadget length", forged));
        let mut forged = honest.clone();
        forged.rgsw_ciphertext.rows[0].b = Poly::zero_moduli(128, params.moduli());
        cases.push(("ring dimension", forged));
        let mut forged = honest.clone();
        forged.rgsw_ciphertext.rows[0].b = Poly::zero_moduli(params.ring_dim, &[65_537]);
        cases.push(("moduli", forged));
        let mut forged = honest.clone();
        forged.shard_id = 1;
        cases.push(("shard past the table", forged));
        let mut forged = honest.clone();
        forged.inspiring_packing_keys = None;
        cases.push(("no key source", forged));
        let mut forged = honest.clone();
        forged.session_handle = Some(ServerSessionHandle(7));
        cases.push(("two key sources", forged));
        let mut forged = honest.clone();
        if let Some(keys) = forged.inspiring_packing_keys.as_mut() {
            keys.y_body.pop();
        }
        cases.push(("inline key rows", forged));
        let mut forged = honest.clone();
        if let Some(keys) = forged.inspiring_packing_keys.as_mut() {
            keys.num_to_pack += 1;
        }
        cases.push(("inline key gamma", forged));

        for (case, query) in &cases {
            assert_eq!(
                post(app, "batch", batch_of(query)).await,
                StatusCode::BAD_REQUEST,
                "{case}"
            );
        }
    }

    /// A session upload whose key cannot seat is refused 400 while every handshake permit is
    /// held, instead of queueing for one and failing inside registration.
    #[tokio::test]
    async fn a_malformed_session_upload_is_refused_400_at_admission() {
        let fixture = fixture();
        let app = &fixture.app;
        let mut short = fixture.keys.clone();
        short.y_body.pop();
        let mut wrong_gamma = fixture.keys.clone();
        wrong_gamma.num_to_pack += 1;
        let handshakes = u32::try_from(app.handshake_permits.available_permits()).expect("u32");
        let held = Arc::clone(&app.handshake_permits)
            .acquire_many_owned(handshakes)
            .await
            .expect("hold every handshake permit");
        for (case, keys) in [("key rows", &short), ("gamma", &wrong_gamma)] {
            let started = Instant::now();
            let status = post(app, "session", write_versioned(keys).expect("upload")).await;
            let took = started.elapsed();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case}");
            assert!(took < ADMISSION_BUDGET, "{case} took {took:?}");
        }
        drop(held);
        let honest = write_versioned(&fixture.keys).expect("upload");
        assert_eq!(post(app, "session", honest).await, StatusCode::OK);
    }

    /// The approximate packing gadget seats one key row fewer; its honest query and upload are
    /// admitted, so the admission check follows the served set rather than the exact one.
    #[tokio::test]
    async fn the_approximate_gadget_set_is_admitted() {
        let params = InspireParams {
            approximate_packing_gadget: true,
            ..params()
        };
        let schema = wire_schema_for(&params);
        let fixture = fixture_with(params);
        let app = &fixture.app;
        assert_eq!(fixture.keys.y_body.len(), 2);
        let batch = write_versioned_as(&vec![fixture.query.clone()], schema).expect("batch");
        assert_eq!(post(app, "batch", batch).await, StatusCode::OK);
        let upload = write_versioned_as(&fixture.keys, schema).expect("upload");
        assert_eq!(post(app, "session", upload).await, StatusCode::OK);
    }
}
