use anyhow::Result;

pub struct TunDevice {
    name: String,
}

impl TunDevice {
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub async fn create(name: &str, _ip_cidr: &str, _mtu: u16) -> Result<TunDevice> {
    Ok(TunDevice {
        name: name.to_owned(),
    })
}
