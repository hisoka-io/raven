mod kill_helper;

fn spawn() -> std::process::Child {
    std::process::Command::new(env!("CARGO_BIN_EXE_worker"))
        .spawn()
        .unwrap()
}
