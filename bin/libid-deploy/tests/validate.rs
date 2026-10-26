//! `libid-deploy validate` over the committed network files, as CI and a
//! developer run it.

use std::{
    path::{
        Path,
        PathBuf,
    },
    process::{
        Command,
        Output,
    },
};

/// The committed `networks/*.toml`, in name order.
fn committed_network_files() -> Vec<PathBuf> {
    let networks = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&networks)
        .expect("networks/ is readable")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    files
}

/// `libid-deploy validate --network <file> <args>`.
fn validate(file: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_libid-deploy"))
        .arg("validate")
        .arg("--network")
        .arg(file)
        .args(args)
        .output()
        .expect("libid-deploy runs")
}

/// `validate` contacts no chain without `--check-rpc`, so every committed
/// file passes with no `--rpc-url`: a real network's names no endpoint.
#[test]
fn every_committed_network_file_validates_offline() {
    let files = committed_network_files();
    assert!(
        files.iter().any(|file| file.ends_with("sepolia.toml")),
        "{files:?}"
    );

    for file in files {
        let output = validate(&file, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{}\n{stdout}\n{stderr}",
            file.display()
        );
        assert!(stdout.contains("parses and validates"), "{stdout}");
    }
}

/// `--check-rpc` contacts the chain, so a file that names no endpoint needs
/// `--rpc-url` with it, and says so.
#[test]
fn check_rpc_needs_an_endpoint() {
    let sepolia =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks/sepolia.toml");

    let output = validate(&sepolia, &["--check-rpc"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("no endpoint for 'sepolia'"), "{stderr}");
}

/// A Safe declared anywhere but the address its name and the deployer
/// predict fails `validate`, naming the predicted address.
#[test]
fn a_safe_off_its_predicted_address_fails_validation() {
    let sepolia =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../networks/sepolia.toml");
    let notary_fees = "0x50c5fb6d2861c8b29df8880a13ce8d9e949f3c34";
    let registry_fees = "0x19bcbc5cf49025a8330e4fc32b4192bd08783096";
    let text = std::fs::read_to_string(&sepolia).expect("sepolia.toml is readable");
    let declared = format!("address = \"{notary_fees}\"");
    assert!(
        text.contains(&declared),
        "sepolia declares notary_fees at {notary_fees}"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let swapped = dir.path().join("sepolia.toml");
    std::fs::write(
        &swapped,
        text.replace(&declared, &format!("address = \"{registry_fees}\"")),
    )
    .expect("write the swapped file");

    let output = validate(&swapped, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("safes.notary_fees.address"), "{stderr}");
    assert!(stderr.contains(notary_fees), "{stderr}");
}
