// was env!("CARGO_BIN_EXE_child") before the in-process rewrite
fn reap(child: &mut std::process::Child) {
    child.kill().unwrap();
}
