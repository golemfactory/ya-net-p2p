use std::env;

fn main() {
    println!(
        "cargo:warning=Generating code into {}",
        env::var("OUT_DIR").unwrap()
    );
    let mut config = prost_build::Config::new();
    config.type_attribute(".", "#[derive(serde::Deserialize, serde::Serialize)]");
    config
        .compile_protos(&["proto/kad.proto"], &["proto/"])
        .unwrap();
}
