// child.kill() once the sentinel appears
/* nested /* child.kill() */ still a comment: child.kill() */
fn spawn() {
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_child"))
        .spawn()
        .unwrap();
    let _ = ("child.kill()", r#"child.kill() "quoted""#, child);
}
