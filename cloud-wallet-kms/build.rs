//! Build script to ensure migrations are re-run when they change

fn main() {
    println!("cargo:rerun-if-changed=src/storage/migrations");
}
