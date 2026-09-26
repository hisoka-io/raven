use std::process::{Child, Command};

struct Guard<T>(Child, T);

impl<T> Drop for Guard<T>
where
    T: Sized,
{
    fn drop(&mut self) {
        let open = '{';
        let _ = (open, "{{ {");
        let _ = self.0.kill();
    }
}

fn kill_at_checkpoint() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chaos_child"))
        .spawn()
        .unwrap();
    child.kill().unwrap();
}
