//! Build script to ensure migrations are re-run when they change

fn main() {
    println!("cargo:rerun-if-changed=migrations/postgres");
    println!("cargo:rerun-if-changed=migrations/mysql");
    println!("cargo:rerun-if-changed=migrations/sqlite");
}
