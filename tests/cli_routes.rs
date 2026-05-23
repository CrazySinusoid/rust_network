use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_rust_network")
}

#[test]
fn version_command_prints_package_version() {
    let output = Command::new(binary()).arg("--version").output().unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("rust_network {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn routes_client_prints_full_tunnel_commands() {
    let output = Command::new(binary())
        .args([
            "routes",
            "client",
            "--server-ip",
            "203.0.113.10",
            "--old-gateway",
            "192.168.1.1",
            "--tun-name",
            "tun0",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "\
sudo ip route add 203.0.113.10/32 via 192.168.1.1
sudo ip route add 0.0.0.0/1 dev tun0
sudo ip route add 128.0.0.0/1 dev tun0
"
    );
}

#[test]
fn routes_client_apply_requires_gateway() {
    let output = Command::new(binary())
        .args(["routes", "client", "--server-ip", "203.0.113.10"])
        .output()
        .unwrap();

    assert!(!output.status.success());
}
