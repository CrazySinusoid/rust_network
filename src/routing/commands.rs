use crate::routing::linux::{FULL_TUNNEL_ROUTE_HIGH, FULL_TUNNEL_ROUTE_LOW};

pub fn server_nat_commands(vpn_subnet: &str, tun_name: &str, out_iface: &str) -> Vec<String> {
    server_gateway_commands(vpn_subnet, tun_name, out_iface)
}

pub fn server_gateway_commands(vpn_subnet: &str, tun_name: &str, out_iface: &str) -> Vec<String> {
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

pub fn server_gateway_rollback_commands(
    vpn_subnet: &str,
    tun_name: &str,
    out_iface: &str,
) -> Vec<String> {
    vec![
        format!(
            "sudo iptables -t nat -D POSTROUTING -s {vpn_subnet} -o {out_iface} -j MASQUERADE"
        ),
        format!("sudo iptables -D FORWARD -i {tun_name} -o {out_iface} -j ACCEPT"),
        format!(
            "sudo iptables -D FORWARD -i {out_iface} -o {tun_name} -m state --state RELATED,ESTABLISHED -j ACCEPT"
        ),
        "sudo sysctl -w net.ipv4.ip_forward=0".to_owned(),
    ]
}

pub fn client_full_tunnel_commands(
    server_public_ip: &str,
    old_gateway: &str,
    tun_name: &str,
) -> Vec<String> {
    vec![
        format!("sudo ip route add {server_public_ip}/32 via {old_gateway}"),
        format!("sudo ip route add {FULL_TUNNEL_ROUTE_LOW} dev {tun_name}"),
        format!("sudo ip route add {FULL_TUNNEL_ROUTE_HIGH} dev {tun_name}"),
    ]
}

pub fn client_full_tunnel_rollback_commands(server_public_ip: &str, tun_name: &str) -> Vec<String> {
    vec![
        format!("sudo ip route del {FULL_TUNNEL_ROUTE_HIGH} dev {tun_name}"),
        format!("sudo ip route del {FULL_TUNNEL_ROUTE_LOW} dev {tun_name}"),
        format!("sudo ip route del {server_public_ip}/32"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_gateway_commands_match_mvp_docs() {
        assert_eq!(
            server_gateway_commands("10.8.0.0/24", "tun0", "eth0"),
            vec![
                "sudo sysctl -w net.ipv4.ip_forward=1",
                "sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
                "sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT",
                "sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
            ]
        );
    }

    #[test]
    fn server_rollback_deletes_rules_before_disabling_forwarding() {
        assert_eq!(
            server_gateway_rollback_commands("10.8.0.0/24", "tun0", "eth0"),
            vec![
                "sudo iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
                "sudo iptables -D FORWARD -i tun0 -o eth0 -j ACCEPT",
                "sudo iptables -D FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
                "sudo sysctl -w net.ipv4.ip_forward=0",
            ]
        );
    }

    #[test]
    fn client_full_tunnel_routes_preserve_server_path() {
        assert_eq!(
            client_full_tunnel_commands("203.0.113.10", "192.168.1.1", "tun0"),
            vec![
                "sudo ip route add 203.0.113.10/32 via 192.168.1.1",
                "sudo ip route add 0.0.0.0/1 dev tun0",
                "sudo ip route add 128.0.0.0/1 dev tun0",
            ]
        );
    }

    #[test]
    fn client_rollback_removes_broad_routes_first() {
        assert_eq!(
            client_full_tunnel_rollback_commands("203.0.113.10", "tun0"),
            vec![
                "sudo ip route del 128.0.0.0/1 dev tun0",
                "sudo ip route del 0.0.0.0/1 dev tun0",
                "sudo ip route del 203.0.113.10/32",
            ]
        );
    }
}
