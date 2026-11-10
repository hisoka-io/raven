//! Each target's decode path, as the node's route runs it, against serving shapes built once. A
//! target feeds it hostile bytes; `examples/seeds.rs` proves every honest seed reaches its end.

use std::sync::LazyLock;

use howl_node::engine::{Batch, Pir};
use howl_wire::{Answer, RequestPrefix, PARAM_SET_D2048_CELL256, PARAM_SET_D2048_CELL256_P16};
use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::math::NttContext;
use raven_inspire::params::{InspireParams, ShardConfig};
use raven_inspire::{PackingKeySeat, SeededClientQuery, ServerCrs};
use raven_inspire_session::SessionStoreLimits;
use raven_railgun_http::versioned::{
    read_versioned_as, WIRE_SCHEMA_VERSION, WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET,
};
use raven_railgun_http::InstanceParams;

/// How far a body got: `Ok` when every step of its route's decoding accepted it.
pub type Reached = Result<(), String>;

fn reached<T, E: std::fmt::Debug>(step: &str, result: Result<T, E>) -> Result<T, String> {
    result.map_err(|e| format!("{step}: {e:?}"))
}

/// The Railgun cell a packing key is seated for.
pub const RAILGUN_ENTRY_BYTES: usize = 512;

/// A Railgun instance's packing shape: what a session upload is seated against.
pub struct PackingShape {
    pub schema: u16,
    pub pack: PackParams,
    pub ntt: NttContext,
}

fn packing_shape(params: InspireParams) -> PackingShape {
    let schema = raven_railgun_http::versioned::wire_schema_for(&params);
    let pack = PackParams::try_new(&params, raven_inspire::num_columns(RAILGUN_ENTRY_BYTES))
        .expect("the shipped parameter sets pack this cell");
    PackingShape {
        schema,
        ntt: params.ntt_context(),
        pack,
    }
}

/// Both shipped Railgun parameter sets, one per wire schema.
pub static RAILGUN_SHAPES: LazyLock<[PackingShape; 2]> = LazyLock::new(|| {
    let shapes = [
        packing_shape(InspireParams::d2048()),
        packing_shape(InspireParams::d2048_approximate_gadget()),
    ];
    assert_eq!(shapes[0].schema, WIRE_SCHEMA_VERSION);
    assert_eq!(shapes[1].schema, WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET);
    shapes
});

/// Every schema a Railgun node accepts a body under.
pub const RAILGUN_SCHEMAS: [u16; 2] = [WIRE_SCHEMA_VERSION, WIRE_SCHEMA_VERSION_APPROXIMATE_GADGET];

fn howl_pir(set: u16) -> Pir {
    // set 1 keeps its key material on disk, one directory per process; a fixed seed so a crash
    // replays against the same material
    let dir = std::env::temp_dir().join(format!("raven-fuzz-howl-set{set}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory for set 1's key material");
    Pir::open(&dir, set, SessionStoreLimits::default(), Some([7; 32]), 1)
        .expect("both parameter sets open")
}

/// A Howl node per parameter set it can serve.
pub static HOWL_PIRS: LazyLock<[Pir; 2]> = LazyLock::new(|| {
    [
        howl_pir(PARAM_SET_D2048_CELL256),
        howl_pir(PARAM_SET_D2048_CELL256_P16),
    ]
});

/// The node's per-batch query allowance (howl-node http.rs).
const HOWL_QUERY_BYTES_LIMIT: usize = 1 << 20;

/// The node a Howl request body is addressed to, and the payload after its prefix: what the
/// node's routes do before decoding the payload.
fn howl_payload(body: &[u8]) -> Result<(&'static Pir, &[u8]), String> {
    let (prefix, rest) = reached("request prefix", RequestPrefix::decode(body))?;
    HOWL_PIRS
        .iter()
        .find(|pir| pir.param_set() == prefix.param_set)
        .map(|pir| (pir, rest))
        .ok_or_else(|| format!("no node serves set {}", prefix.param_set))
}

/// `POST /v1/instance/{id}/session`: the packing-key upload, decoded and seated as the node does,
/// under every shape a node can serve.
pub fn railgun_session_body(body: &[u8]) -> Reached {
    let mut last = String::from("no shape");
    for shape in RAILGUN_SHAPES.iter() {
        let seated = reached(
            "decode",
            read_versioned_as::<ClientPackingKeys>(body, shape.schema),
        )
        .and_then(|keys| {
            reached(
                "seat",
                PackingKeySeat::from_wire(keys, &shape.pack, &shape.ntt),
            )
        });
        match seated {
            Ok(_) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// `POST .../query` and `POST .../batch`: one seeded query, or a batch of them.
pub fn railgun_batch_body(body: &[u8]) -> Reached {
    let mut accepted = false;
    for schema in RAILGUN_SCHEMAS {
        accepted |= read_versioned_as::<SeededClientQuery>(body, schema).is_ok();
        accepted |= read_versioned_as::<Vec<SeededClientQuery>>(body, schema).is_ok();
    }
    accepted
        .then_some(())
        .ok_or_else(|| "no schema decodes it".to_owned())
}

/// `GET .../params` as a wallet reads it: the envelope, then each blob it carries.
pub fn railgun_params_blob(blob: &[u8]) -> Reached {
    let mut last = String::from("no schema");
    for schema in RAILGUN_SCHEMAS {
        let read = || -> Reached {
            let instance = reached(
                "envelope",
                read_versioned_as::<InstanceParams>(blob, schema),
            )?;
            reached(
                "crs",
                ServerCrs::from_versioned_bytes(&instance.crs_bincode),
            )?;
            let params = reached(
                "params",
                bincode::deserialize::<InspireParams>(&instance.inspire_params_bincode),
            )?;
            reached("params", params.validate())?;
            let shards = reached(
                "shards",
                bincode::deserialize::<ShardConfig>(&instance.shard_config_bincode),
            )?;
            reached("shards", shards.validate_for_params(&params))
        };
        match read() {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The versioned CRS a wallet decodes from a node, below the envelope so every input reaches the
/// CRS decoder and its validation.
pub fn inspire_crs_blob(blob: &[u8]) -> Reached {
    reached("crs", ServerCrs::from_versioned_bytes(blob)).map(drop)
}

/// `POST /howl/v1/session`: a packing key under either parameter set.
pub fn howl_session_body(body: &[u8]) -> Reached {
    let (pir, payload) = howl_payload(body)?;
    pir.decode_key(payload).map(drop)
}

/// `POST /howl/v1/notes`: a batch of private reads under either parameter set.
pub fn howl_notes_body(body: &[u8]) -> Reached {
    let (pir, payload) = howl_payload(body)?;
    if let Batch::Single(batch) = pir.decode_batch(payload, HOWL_QUERY_BYTES_LIMIT)? {
        // set 2's layout is fixed-width, so a payload it accepts is the only encoding of its batch
        assert_eq!(batch.encode(), payload);
    }
    Ok(())
}

/// Every answer a Howl node sends, as a wallet decodes it.
pub fn howl_answer(bytes: &[u8]) -> Reached {
    let answer = reached("answer", Answer::decode(bytes))?;
    assert_eq!(Answer::decode(&answer.encode()), Ok(answer));
    Ok(())
}
