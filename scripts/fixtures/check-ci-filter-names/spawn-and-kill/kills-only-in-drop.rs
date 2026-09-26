use std::process::{Child, Command};

struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let close = '}';
        let _ = (close, "}}");
        let _ = self.child.kill();
    }
}

fn boot() -> Server {
    Server {
        child: Command::new(env!("CARGO_BIN_EXE_server")).spawn().unwrap(),
    }
}
