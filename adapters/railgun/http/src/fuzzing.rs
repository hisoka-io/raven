//! The admission shape checks the query, batch and session routes run after the wire decode,
//! callable over the served parameters alone so a fuzz harness reaches them without an instance.

use raven_inspire::inspiring::{ClientPackingKeys, PackParams};
use raven_inspire::params::InspireParams;
use raven_inspire::SeededClientQuery;

/// The check `POST .../query` and `POST .../batch` run on each decoded query: `params` is the
/// served CRS's parameter set, `pack` its packing parameters, `num_shards` the table's shards.
pub fn check_query_shape(
    params: &InspireParams,
    pack: &PackParams,
    num_shards: u64,
    query: &SeededClientQuery,
) -> Result<(), String> {
    crate::shape::query_shape(params, pack, num_shards, query)
}

/// The check `POST .../session` runs on a decoded packing-key upload.
pub fn check_packing_key_shape(pack: &PackParams, keys: &ClientPackingKeys) -> Result<(), String> {
    crate::shape::packing_key_shape(pack, keys)
}
