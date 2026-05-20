use anyhow::Result;

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CStr;
    use std::fs::OpenOptions;
    use std::io;
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::process::Command;

    use anyhow::{bail, Context, Result};
    use tokio::fs::File;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use libc::{ifreq, ioctl, IFF_NO_PI, IFF_TUN, TUNSETIFF};

    pub struct TunDevice {
        name: String,
        file: File,
    }

    impl TunDevice {
        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
            Ok(self.file.read(buf).await?)
        }

        pub async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
            self.file.write_all(packet).await?;
            Ok(())
        }
    }

    pub async fn create(name: &str, ip_cidr: &str, mtu: u16) -> Result<TunDevice> {
        let device = open_tun(name).context("failed to create TUN device")?;
        configure_interface(device.name(), ip_cidr, mtu)
            .context("failed to configure TUN device")?;
        tracing::info!(
            tun = device.name(),
            ip = %ip_cidr,
            mtu,
            "TUN device configured"
        );
        Ok(device)
    }

    fn open_tun(name: &str) -> Result<TunDevice> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("failed to open /dev/net/tun")?;

        let fd = file.as_raw_fd();
        let mut ifr: ifreq = unsafe { mem::zeroed() };

        let name_bytes = name.as_bytes();
        if name_bytes.len() >= libc::IFNAMSIZ {
            bail!("TUN interface name is too long: {name}");
        }

        for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes.iter()) {
            *dst = *src as libc::c_char;
        }

        unsafe {
            ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;

            if ioctl(fd, TUNSETIFF, &ifr) < 0 {
                return Err(io::Error::last_os_error()).context("TUNSETIFF ioctl failed");
            }
        }

        let actual_name = unsafe {
            CStr::from_ptr(ifr.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned()
        };

        Ok(TunDevice {
            name: actual_name,
            file: File::from_std(file),
        })
    }

    fn configure_interface(name: &str, ip_cidr: &str, mtu: u16) -> Result<()> {
        run_ip(["addr", "replace", ip_cidr, "dev", name])?;
        run_ip(["link", "set", "dev", name, "mtu", &mtu.to_string()])?;
        run_ip(["link", "set", "dev", name, "up"])?;
        Ok(())
    }

    fn run_ip<const N: usize>(args: [&str; N]) -> Result<()> {
        tracing::debug!(args = ?args, "running ip command");
        let status = Command::new("ip")
            .args(args)
            .status()
            .context("failed to run ip command")?;

        if !status.success() {
            bail!("ip command failed with status {status}");
        }

        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use anyhow::{bail, Result};

    pub struct TunDevice {
        name: String,
    }

    impl TunDevice {
        pub fn name(&self) -> &str {
            &self.name
        }

        pub async fn read_packet(&mut self, _buf: &mut [u8]) -> Result<usize> {
            bail!("Linux TUN devices are only supported on Linux")
        }

        pub async fn write_packet(&mut self, _packet: &[u8]) -> Result<()> {
            bail!("Linux TUN devices are only supported on Linux")
        }
    }

    pub async fn create(_name: &str, _ip_cidr: &str, _mtu: u16) -> Result<TunDevice> {
        bail!("Linux TUN devices are only supported on Linux")
    }
}

pub use imp::TunDevice;

pub async fn create(name: &str, ip_cidr: &str, mtu: u16) -> Result<TunDevice> {
    imp::create(name, ip_cidr, mtu).await
}
