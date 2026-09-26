fn reap() {
    let mut sleeper = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    sleeper.kill().unwrap();
}
