#![allow(clippy::expect_used, clippy::panic)]
//! Spelling gate over the two bounded selections, not a timing proof. It pins
//! their scan-and-select form so secret-indexed access cannot return quietly.

const QUERY_SRC: &str = include_str!("../src/query.rs");
const EXTRACT_SRC: &str = include_str!("../src/extract.rs");

fn item_source(source: &'static str, header: &str) -> &'static str {
    let start = source
        .find(header)
        .unwrap_or_else(|| panic!("`{header}` must be present"));
    let rest = &source[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 2);
    &rest[..end]
}

#[test]
fn query_delta_placement_scans_every_slot() {
    let query = item_source(QUERY_SRC, "pub fn query");
    assert!(!query.contains("get_mut(col)"), "{query}");
    assert!(!query.contains("query_vec[col]"), "{query}");
    assert!(query.contains("add_delta_by_scan("), "{query}");

    let scan = item_source(QUERY_SRC, "fn add_delta_by_scan");
    assert!(scan.contains("query_vec.iter_mut().enumerate()"), "{scan}");
    assert!(scan.contains("u32::conditional_select"), "{scan}");
    assert!(scan.contains(".ct_eq(&selected_col)"), "{scan}");
}

#[test]
fn extract_answer_selection_scans_every_row() {
    let extract = item_source(EXTRACT_SRC, "pub fn extract");
    assert!(!extract.contains("answer.get(state.row)"), "{extract}");
    assert!(!extract.contains("answer[state.row]"), "{extract}");
    assert!(extract.contains("select_answer_by_scan("), "{extract}");

    let scan = item_source(EXTRACT_SRC, "fn select_answer_by_scan");
    assert!(scan.contains("answer.iter().enumerate()"), "{scan}");
    assert!(scan.contains("u32::conditional_select"), "{scan}");
    assert!(scan.contains(".ct_eq(&selected_row)"), "{scan}");
}

#[test]
fn extract_documents_the_direct_hint_row_tradeoff() {
    assert!(EXTRACT_SRC.contains("The hint-row read remains"));
    assert!(EXTRACT_SRC.contains("constant-time would cost a scan of all `L*n`"));
    assert!(EXTRACT_SRC.contains("which is an accepted tradeoff"));
}
