pub fn stop(child: &mut std::process::Child) {
    child.kill().unwrap();
}
