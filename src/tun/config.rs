#[derive(Debug, Clone)]
pub struct TunRuntimeConfig {
    pub name: String,
    pub ip_cidr: String,
    pub mtu: u16,
}
