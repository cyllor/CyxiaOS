//! Inspect an artifact with the same bounded parser used by the guest loader.
fn main() {
    let mut failed = false;
    for path in std::env::args().skip(1) {
        match std::fs::read(&path) {
            Ok(bytes) => match cyxia_posix::executable::parse(&bytes) {
                Ok(plan) => println!(
                    "{path}: entry={:#x} pages={} TLS={:?}",
                    plan.entry,
                    plan.pages().count(),
                    plan.tls()
                ),
                Err(error) => {
                    eprintln!("{path}: {error:?}");
                    failed = true;
                }
            },
            Err(error) => {
                eprintln!("{path}: {error}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
