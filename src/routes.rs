use anyhow::{bail, Result};

use crate::cli::RoutesCommand;
use crate::routing;

pub fn commands(command: RoutesCommand) -> Result<Vec<String>> {
    match command {
        RoutesCommand::Server(args) => {
            if args.rollback {
                Ok(routing::commands::server_gateway_rollback_commands(
                    &args.vpn_subnet,
                    &args.tun_name,
                    &args.out_iface,
                ))
            } else {
                Ok(routing::commands::server_gateway_commands(
                    &args.vpn_subnet,
                    &args.tun_name,
                    &args.out_iface,
                ))
            }
        }
        RoutesCommand::Client(args) => {
            if args.rollback {
                Ok(routing::commands::client_full_tunnel_rollback_commands(
                    &args.server_ip,
                    &args.tun_name,
                ))
            } else {
                let Some(old_gateway) = args.old_gateway else {
                    bail!("--old-gateway is required unless --rollback is set");
                };

                Ok(routing::commands::client_full_tunnel_commands(
                    &args.server_ip,
                    &old_gateway,
                    &args.tun_name,
                ))
            }
        }
    }
}

pub fn print(command: RoutesCommand) -> Result<()> {
    for command in commands(command)? {
        println!("{command}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{ClientRoutesArgs, ServerRoutesArgs};

    #[test]
    fn renders_server_apply_commands() {
        let output = commands(RoutesCommand::Server(ServerRoutesArgs {
            vpn_subnet: "10.8.0.0/24".to_owned(),
            tun_name: "tun0".to_owned(),
            out_iface: "eth0".to_owned(),
            rollback: false,
        }))
        .unwrap();

        assert_eq!(
            output,
            vec![
                "sudo sysctl -w net.ipv4.ip_forward=1",
                "sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE",
                "sudo iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT",
                "sudo iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT",
            ]
        );
    }

    #[test]
    fn renders_client_rollback_commands_without_gateway() {
        let output = commands(RoutesCommand::Client(ClientRoutesArgs {
            server_ip: "203.0.113.10".to_owned(),
            old_gateway: None,
            tun_name: "tun0".to_owned(),
            rollback: true,
        }))
        .unwrap();

        assert_eq!(
            output,
            vec![
                "sudo ip route del 128.0.0.0/1 dev tun0",
                "sudo ip route del 0.0.0.0/1 dev tun0",
                "sudo ip route del 203.0.113.10/32",
            ]
        );
    }

    #[test]
    fn rejects_client_apply_without_gateway() {
        let result = commands(RoutesCommand::Client(ClientRoutesArgs {
            server_ip: "203.0.113.10".to_owned(),
            old_gateway: None,
            tun_name: "tun0".to_owned(),
            rollback: false,
        }));

        assert!(result.is_err());
    }
}
