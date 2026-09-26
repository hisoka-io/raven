use std::process::Command;

fn kill_mid_write() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_writer_child"))
        .spawn()
        .unwrap();
    child.kill().unwrap();
}
