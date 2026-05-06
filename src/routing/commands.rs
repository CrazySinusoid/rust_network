pub fn server_nat_commands(vpn_subnet: &str, tun_name: &str, out_iface: &str) -> Vec<String> {
    vec![
        "sudo sysctl -w net.ipv4.ip_forward=1".to_owned(),
        format!(
            "sudo iptables -t nat -A POSTROUTING -s {vpn_subnet} -o {out_iface} -j MASQUERADE"
        ),
        format!("sudo iptables -A FORWARD -i {tun_name} -o {out_iface} -j ACCEPT"),
        format!(
            "sudo iptables -A FORWARD -i {out_iface} -o {tun_name} -m state --state RELATED,ESTABLISHED -j ACCEPT"
        ),
    ]
}
