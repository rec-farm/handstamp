// Embeds the SQL migrations in migrations/. The table and advisory lock are the ones the Node server used, so an
// existing database keeps its history.
use std::{env, fs, path::PathBuf};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("migrations");
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".sql"))
        .collect();
    names.sort();
    let entries: String = names
        .iter()
        .map(|name| {
            let path = dir.join(name).canonicalize().unwrap();
            format!("    ({name:?}, include_str!({:?})),\n", path.display().to_string())
        })
        .collect();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("migrations.rs");
    fs::write(
        out,
        format!("pub const MIGRATIONS: &[(&str, &str)] = &[\n{entries}];\n"),
    )
    .unwrap();
}
