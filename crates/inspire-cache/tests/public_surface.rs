use raven_inspire_cache::{CellShape, OfflinePackingKeysCache};

#[test]
fn public_cache_path_is_stable() {
    let cache = OfflinePackingKeysCache::new("state");
    assert_eq!(
        cache.path(),
        std::path::Path::new("state/cache/offline_packing_keys.bin")
    );
    let shape = CellShape {
        scheme_tag: b"scheme".to_vec(),
        entries: 1,
        entry_bytes: 32,
        packing_param_id: b"params".to_vec(),
    };
    assert_ne!(shape.fingerprint(), [0; 32]);
}
