#[path = "nested/signal.rs"]
mod signal;

fn respawn() {
    let _ = std::process::Command::new(std::env::current_exe().unwrap()).status();
}
