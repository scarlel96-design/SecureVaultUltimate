fn main() {
    if std::env::args().any(|arg| arg == "--secure-uninstall-wipe") {
        if let Err(error) = secure_vault_ultimate_lib::run_secure_uninstall_wipe() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    secure_vault_ultimate_lib::run();
}
