fn main() {
    hbb_common::gen_version();
    compile_license_proto();
    embed_vendor_public_key();
}

fn compile_license_proto() {
    println!("cargo:rerun-if-changed=src/license.proto");
    let out_dir = format!("{}/license-proto", std::env::var("OUT_DIR").unwrap());
    std::fs::create_dir_all(&out_dir).unwrap();
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(out_dir)
        .input("src/license.proto")
        .include("src")
        .run()
        .expect("License proto codegen failed.");
    std::fs::write(
        format!("{}/license-proto/mod.rs", std::env::var("OUT_DIR").unwrap()),
        "pub mod license;",
    )
    .expect("License proto module file generation failed.");
}

fn embed_vendor_public_key() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = std::path::Path::new(&out_dir).join("vendor_pubkey.rs");

    println!("cargo:rerun-if-env-changed=VENDOR_PUBKEY_PATH");
    let pubkey_path = std::env::var("VENDOR_PUBKEY_PATH").unwrap_or_default();

    if pubkey_path.is_empty() {
        std::fs::write(&dest, "pub const VENDOR_PUBKEY: [u8; 32] = [0u8; 32];").unwrap();
        return;
    }

    println!("cargo:rerun-if-changed={}", pubkey_path);
    let path = std::path::Path::new(&pubkey_path);
    if !path.exists() {
        panic!("VENDOR_PUBKEY_PATH set but file not found: {}", pubkey_path);
    }

    let pubkey_bytes = std::fs::read(path).expect("Failed to read VENDOR_PUBKEY_PATH file");
    assert_eq!(
        pubkey_bytes.len(),
        32,
        "VENDOR_PUBKEY must be exactly 32 bytes (Ed25519 public key)"
    );
    std::fs::write(
        &dest,
        format!(
            "pub const VENDOR_PUBKEY: [u8; 32] = {:?};",
            pubkey_bytes.as_slice()
        ),
    )
    .unwrap();
}
