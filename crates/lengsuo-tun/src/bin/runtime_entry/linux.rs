//! Linux 上的真实 TUN 设备：经 `/dev/net/tun` 的 `TUNSETIFF` ioctl 挂载。
//!
//! 裸 FFI 绑定与 `struct ifreq` 布局在 [`super::linux_ffi`]；本模块只做**流程编排**
//! （挂载 → 置非阻塞 → 设 MTU → 置 UP → 收发），对外暴露的 `LinuxTunDevice` 及其
//! 方法是**安全**的。
//!
//! # 与参考实现的对照
//!
//! Xray `proxy/tun/tun_linux.go` 的 `open()` 走：`unix.Open("/dev/net/tun", O_RDWR)`
//! → `unix.NewIfreq(name)` → `IFF_TUN | IFF_NO_PI` → `unix.IoctlIfreq(fd, TUNSETIFF, ifr)`
//! → `unix.SetNonblock(fd, true)`。本模块逐步对齐，差别有三处：
//! 1. Xray 用 netlink 设 MTU / 置 UP，本模块用 `SIOCSIFMTU` / `SIOCSIFFLAGS`
//!    ioctl（同样能力，少一个依赖）。
//! 2. Xray 的 TUN 是交给 gVisor 的 `fdbased` 端点读写的，本模块自己读。
//! 3. Xray 不做 MTU 之外的接口配置，本模块额外用控制套接字读回状态供断言。
//!    逐条差异见分文档的「偏离清单」。
//!
//! # unsafe 边界
//!
//! `unsafe` 全部落在 [`super::linux_ffi`] 的裸绑定里；本模块只在明确知道
//! 「描述符有效、缓冲区长度已知」的地方调用它们。

use std::time::Duration;

use lengsuo_tun::ingress::{PacketSource, Receipt};

use super::device::{DeviceError, TunDevice};
use super::linux_ffi::{self as ffi, IfReq, PollFd};

/// 设备节点的路径。
const TUN_DEVICE: &str = "/dev/net/tun";
/// 单个 IP 报文的最大字节数（IPv4 总长字段的上界）。
const MAX_PACKET: usize = u16::MAX as usize;

/// 打开并挂载一个 Linux TUN 接口。
///
/// 流程与 Xray `proxy/tun/tun_linux.go` 的 `open()` + `setup()` 对齐：
/// 打开 `/dev/net/tun` → `TUNSETIFF`（`IFF_TUN | IFF_NO_PI`）→ 置非阻塞 →
/// 设 MTU → 置接口 UP。任何一步失败都返回类型化的 [`DeviceError`]，不留半成品
/// （失败的描述符会被关闭，不泄漏）。
pub fn open(name: &str, mtu: u16) -> Result<LinuxTunDevice, DeviceError> {
    if name.is_empty() || name.len() >= ffi::IFNAMSIZ {
        return Err(DeviceError::Io {
            detail: format!("设备名 {name:?} 长度非法（上限 {}）", ffi::IFNAMSIZ - 1),
        });
    }
    let fd = ffi::open_read_write(TUN_DEVICE).ok_or_else(|| syscall_error("打开 TUN 设备"))?;
    // 后续任何失败都必须关掉 fd，否则会泄漏描述符。
    LinuxTunDevice::attach(fd, name, mtu)
}

/// Linux 上的真实 TUN 设备。
#[derive(Debug)]
pub struct LinuxTunDevice {
    /// `/dev/net/tun` 的文件描述符（收包/写包走它）。
    fd: ffi::CInt,
    /// 控制套接字：接口级 ioctl（`SIOCSIFMTU` / `SIOCSIFFLAGS`）**只认套接字**，
    /// 拿 TUN 的 fd 去调会返回 `EINVAL`。内核的 `dev_ifsioc` 走 `sock->file`，
    /// 不是 `file->private_data`。
    control: ffi::CInt,
    /// 实际生效的设备名（内核可能改写名字，例如以 `tun` 开头）。
    name: String,
    /// 生效的 MTU。
    mtu: u16,
}

impl LinuxTunDevice {
    /// 挂载接口：设置 `TUNSETIFF`、非阻塞、MTU、UP。
    ///
    /// 失败时**必须**已经关闭 `fd` 与 `control`——本函数是唯一持有裸描述符的地方。
    fn attach(fd: ffi::CInt, name: &str, mtu: u16) -> Result<Self, DeviceError> {
        // 控制套接字：接口级 ioctl 必须在套接字上做。
        let control = ffi::control_socket().ok_or_else(|| syscall_error("建立控制套接字"))?;
        match Self::configure(fd, control, name, mtu) {
            Ok((actual_name, actual_mtu)) => Ok(Self {
                fd,
                control,
                name: actual_name,
                mtu: actual_mtu,
            }),
            Err(error) => {
                // 关闭失败时不改变主错误：挂载失败才是调用方要看到的那件事。
                unsafe {
                    ffi::close_fd(control);
                    ffi::close_fd(fd);
                }
                Err(error)
            }
        }
    }

    /// 真正的挂载序列。任一步失败即返回错误。
    fn configure(
        fd: ffi::CInt,
        control: ffi::CInt,
        name: &str,
        mtu: u16,
    ) -> Result<(String, u16), DeviceError> {
        // ① `TUNSETIFF`：挂载接口。内核会把实际设备名写回 `ifr_name`。
        let mut request = IfReq::new(name);
        request.set_flags(ffi::IFF_TUN | ffi::IFF_NO_PI);
        ioctl(fd, ffi::TUNSETIFF, &mut request, "挂载 TUN 接口")?;
        let actual_name = request.name();

        // ② 置非阻塞：读超时由 `poll` 实现（Xray 同样置非阻塞）。
        let flags = unsafe { ffi::get_flags(fd) }.ok_or_else(|| syscall_error("读取设备标志"))?;
        unsafe { ffi::set_flags(fd, flags | ffi::O_NONBLOCK) }
            .ok_or_else(|| syscall_error("设置非阻塞"))?;

        // ③ 设 MTU（Xray 用 netlink `LinkSetMTU`，此处用等价的 `SIOCSIFMTU`）。
        let mut mtu_request = IfReq::new(&actual_name);
        mtu_request.set_mtu(mtu);
        ioctl(control, ffi::SIOCSIFMTU, &mut mtu_request, "设置接口 MTU")?;

        // ④ 置接口 UP（Xray 的 `Start()` 走 netlink `LinkSetUp`）。
        let mut flags_request = IfReq::new(&actual_name);
        ioctl(
            control,
            ffi::SIOCGIFFLAGS,
            &mut flags_request,
            "读取接口标志",
        )?;
        let mut flags = flags_request.flags();
        flags |= ffi::IFF_UP;
        flags_request.set_flags(flags);
        ioctl(control, ffi::SIOCSIFFLAGS, &mut flags_request, "置接口 UP")?;

        Ok((actual_name, mtu))
    }

    /// 实际生效的设备名。
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 实际生效的 MTU。
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// 从内核读回接口的当前状态（MTU + 标志）。
    ///
    /// 这是**读回**而不是复述本地字段：只有内核认账的值才算生效。接口级 ioctl
    /// 必须走控制套接字（`SIOCGIFMTU` / `SIOCGIFFLAGS`）。
    pub fn query_state(&self) -> Result<InterfaceState, DeviceError> {
        let mut mtu_request = IfReq::new(&self.name);
        ioctl(
            self.control,
            ffi::SIOCGIFMTU,
            &mut mtu_request,
            "读取接口 MTU",
        )?;
        let mut flags_request = IfReq::new(&self.name);
        ioctl(
            self.control,
            ffi::SIOCGIFFLAGS,
            &mut flags_request,
            "读取接口标志",
        )?;
        Ok(InterfaceState {
            mtu: mtu_request.mtu(),
            up: flags_request.flags() & ffi::IFF_UP != 0,
        })
    }
}

/// 接口的当前内核状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceState {
    /// 内核认账的 MTU。
    pub mtu: u16,
    /// 接口是否已置 UP。
    pub up: bool,
}

impl TunDevice for LinuxTunDevice {
    fn send(&mut self, packet: &[u8]) -> Result<(), DeviceError> {
        if packet.is_empty() || packet.len() > MAX_PACKET {
            return Err(DeviceError::Io {
                detail: format!("待写回报文长度 {} 非法", packet.len()),
            });
        }
        // 单次 `write`：TUN 设备一次写一个完整 IP 报文。
        // 短写视为失败：IP 报文不可拆分（分片由上层决定，本层不重组）。
        let written = unsafe { ffi::write_bytes(self.fd, packet) }.ok_or_else(|| {
            syscall_error("写回报文")
        })?;
        if written != packet.len() {
            return Err(DeviceError::Io {
                detail: format!("短写：期望 {} 字节，实际 {written}", packet.len()),
            });
        }
        Ok(())
    }
}

impl PacketSource for LinuxTunDevice {
    type Error = DeviceError;

    fn receive(&mut self, timeout: Duration) -> Result<Receipt, Self::Error> {
        let millis = ffi::CInt::try_from(timeout.as_millis()).unwrap_or(ffi::CInt::MAX);
        let mut fds = PollFd {
            fd: self.fd,
            events: ffi::POLLIN,
            revents: 0,
        };
        // `poll` 返回 0 表示超时（正常空闲），不是错误。
        let ready = unsafe { ffi::wait_readable(&mut fds, 1, millis) }
            .ok_or_else(|| syscall_error("等待报文"))?;
        if ready == 0 {
            return Ok(Receipt::Timeout);
        }
        if fds.revents & (ffi::POLLIN | ffi::POLL_ERROR) == 0 {
            return Ok(Receipt::Timeout);
        }
        let mut buffer = vec![0u8; MAX_PACKET];
        let read = match unsafe { ffi::read_bytes(self.fd, &mut buffer) } {
            Some(read) => read,
            None => {
                let errno = ffi::errno();
                if errno == ffi::EINTR || errno == ffi::EAGAIN {
                    return Ok(Receipt::Timeout);
                }
                return Err(syscall_error("读取报文"));
            }
        };
        if read == 0 {
            // 读到 0 字节：设备被对端关闭，不当作一个空包。
            return Err(DeviceError::Closed);
        }
        buffer.truncate(read);
        Ok(Receipt::Packet(buffer))
    }
}

impl Drop for LinuxTunDevice {
    fn drop(&mut self) {
        unsafe {
            ffi::close_fd(self.control);
            ffi::close_fd(self.fd);
        }
    }
}

/// 发起一个带 `struct ifreq` 的 ioctl。失败时把 errno 包成 [`DeviceError::Syscall`]。
fn ioctl(
    fd: ffi::CInt,
    request: ffi::CULong,
    ifreq: &mut IfReq,
    op: &'static str,
) -> Result<(), DeviceError> {
    let done = unsafe { ffi::ioctl_ifreq(fd, request, ifreq.as_bytes_mut()) };
    if done.is_none() {
        return Err(syscall_error(op));
    }
    Ok(())
}

/// 构造一个 errno 错误。
fn syscall_error(op: &'static str) -> DeviceError {
    DeviceError::Syscall {
        op,
        code: ffi::errno(),
    }
}
