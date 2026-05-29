#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().any(|arg| {
        matches!(
            arg.as_str(),
            "--secure-uninstall-wipe" | "--uninstall-purge"
        )
    }) {
        if let Err(error) = secure_vault_ultimate_lib::run_secure_uninstall_wipe() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    secure_vault_ultimate_lib::run();
}
