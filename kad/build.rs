use std::env;

fn main() {
    println!(
        "cargo:warning=Generating code into {}",
        env::var("OUT_DIR").unwrap()
    );
    prost_build::compile_protos(&["proto/kad.proto"], &["proto/"]).unwrap();
}
