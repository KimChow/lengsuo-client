//! Linux TUN 所需的**裸 FFI 绑定**与 `struct ifreq` 视图。
//!
//! 本模块是本卡 `unsafe` 的**唯一**落点：`linux.rs` 只做流程编排，所有裸符号
//! 调用与内存布局假设都收敛在这里。
//!
//! # 为什么用裸 `extern "C"` 而不是 `libc` crate
//!
//! `lengsuo-tun` 的依赖里没有 `libc`，而本卡**不许改 `Cargo.toml`**（共享区由基建卡
//! 独占）。glibc 的这些符号（`open` / `close` / `ioctl` / `fcntl` / `poll` / `read` /
//! `write` / `socket`）由 `std` 必定链接进来，因此直接声明即可，无需新增依赖。
//!
//! # unsafe 纪律
//!
//! - 每个裸函数都包一层**安全**的 helper，helper 负责把 errno 包成类型化错误。
//! - 指针参数全部指向调用方持有的、长度已知的缓冲区；`read`/`write` 的长度是
//!   字节数，不是元素数。
//! - `struct ifreq` 用**定长字节数组**表达，绝不 transmute 成 C 的联合体：
//!   联合体的对齐/填充在 ABI 上不可移植，字节数组 + 显式偏移没有这个风险。

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_ulong, c_void};

/// C 的 `int`。
pub type CInt = c_int;
/// C 的 `unsigned long`（x86_64 上为 64 位）。
pub type CULong = c_ulong;

/// `IFNAMSIZ`：设备名缓冲区长度（含结尾 NUL）。
pub const IFNAMSIZ: usize = 16;
/// `struct ifreq` 的缓冲区尺寸：内核侧 `sizeof(struct ifreq)` 为 40 字节
/// （16 字节名字 + 24 字节联合体，内核按 32 字节对齐到 40）。这里取 40 字节，
/// 与内核一致：内核的 `copy_from_user` 只读 `sizeof(struct ifreq)` 字节，
/// 缓冲区更小会被拒，更大则无害。
pub const IFREQ_SIZE: usize = 40;
/// `struct ifreq` 中 `ifr_name` 的偏移。
const IFR_NAME_OFFSET: usize = 0;
/// `struct ifreq` 中联合体（`ifr_flags` / `ifr_mtu`）的偏移。
const IFR_UNION_OFFSET: usize = IFNAMSIZ;

/// `open` 的 `O_RDWR`。
pub const O_RDWR: CInt = 0o2;
/// `socket` 的 `AF_INET`。
pub const AF_INET: CInt = 2;
/// `socket` 的 `SOCK_DGRAM`。
pub const SOCK_DGRAM: CInt = 2;
/// `fcntl` 的 `F_GETFL`。
pub const F_GETFL: CInt = 3;
/// `fcntl` 的 `F_SETFL`。
pub const F_SETFL: CInt = 4;
/// `fcntl` 的 `O_NONBLOCK`。
pub const O_NONBLOCK: CInt = 0o4000;

/// `TUNSETIFF` = `_IOW('T', 202, int)`。
pub const TUNSETIFF: CULong = 0x4004_54ca;
/// `SIOCSIFMTU`：设置接口 MTU。
pub const SIOCSIFMTU: CULong = 0x8922;
/// `SIOCGIFMTU`：读取接口 MTU。
pub const SIOCGIFMTU: CULong = 0x8921;
/// `SIOCGIFFLAGS`：读接口标志。
pub const SIOCGIFFLAGS: CULong = 0x8913;
/// `SIOCSIFFLAGS`：写接口标志。
pub const SIOCSIFFLAGS: CULong = 0x8914;

/// `IFF_TUN`：三层隧道设备。
pub const IFF_TUN: u16 = 0x0001;
/// `IFF_NO_PI`：不在包前附加 `struct tun_pi` 头部（本入口按裸 IP 报文处理）。
pub const IFF_NO_PI: u16 = 0x1000;
/// `IFF_UP`：置起接口。
pub const IFF_UP: u16 = 0x0001;

/// `poll` 的 `POLLIN`。
pub const POLLIN: i16 = 0x001;
/// `poll` 的 `POLLERR` / `POLLHUP` / `POLLNVAL`：设备出错。
pub const POLL_ERROR: i16 = 0x008 | 0x010 | 0x020;

/// `EINTR`：被信号打断。
pub const EINTR: i32 = 4;
/// `EAGAIN`：非阻塞读暂时无数据。
pub const EAGAIN: i32 = 11;

extern "C" {
    /// 打开文件（glibc `open`，变参的 mode 只在带 `O_CREAT` 时有意义）。
    ///
    /// Rust 侧改名成 `c_open` 是为了不和调用方的 `open` 函数撞名；`link_name`
    /// 把它绑回真正的 glibc 符号 `open`。
    #[link_name = "open"]
    fn c_open(path: *const c_char, flags: CInt, ...) -> CInt;
    /// 关闭文件描述符。
    fn close(fd: CInt) -> CInt;
    /// 设备控制。
    fn ioctl(fd: CInt, request: CULong, ...) -> CInt;
    /// 文件控制。
    fn fcntl(fd: CInt, cmd: CInt, ...) -> CInt;
    /// 等待文件描述符上的事件。
    fn poll(fds: *mut PollFd, nfds: CULong, timeout: CInt) -> CInt;
    /// 从文件描述符读字节。
    fn read(fd: CInt, buffer: *mut c_void, count: usize) -> isize;
    /// 向文件描述符写字节。
    fn write(fd: CInt, buffer: *const c_void, count: usize) -> isize;
    /// 建立一个套接字（用于接口级 ioctl）。
    fn socket(domain: CInt, ty: CInt, protocol: CInt) -> CInt;
}

/// `struct pollfd`：fd、事件掩码、返回的事件掩码。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    /// 要等待的描述符。
    pub fd: CInt,
    /// 关心的事件掩码。
    pub events: i16,
    /// 返回的事件掩码。
    pub revents: i16,
}

/// 打开一个文件（`O_RDWR`）。失败返回 `None`。
///
/// # Safety
///
/// `path` 必须是合法的 NUL 结尾 C 字符串。本函数只做只读打开，不写任何内存。
pub fn open_read_write(path: &str) -> Option<CInt> {
    let path = CString::new(path).ok()?;
    let fd = unsafe { c_open(path.as_ptr(), O_RDWR) };
    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

/// 关闭描述符。返回值忽略（关闭失败无可挽回）。
///
/// # Safety
///
/// `fd` 必须是当前打开着的、且本进程拥有的描述符。
pub unsafe fn close_fd(fd: CInt) {
    close(fd);
}

/// 建立一个 `AF_INET`/`SOCK_DGRAM` 套接字。失败返回 `None`。
pub fn control_socket() -> Option<CInt> {
    let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

/// 读描述符的标志位。失败返回 `None`。
///
/// # Safety
///
/// `fd` 必须是当前打开着的描述符。
pub unsafe fn get_flags(fd: CInt) -> Option<CInt> {
    let flags = fcntl(fd, F_GETFL);
    if flags < 0 {
        None
    } else {
        Some(flags)
    }
}

/// 设置描述符的标志位。失败返回 `None`。
///
/// # Safety
///
/// `fd` 必须是当前打开着的描述符。
pub unsafe fn set_flags(fd: CInt, flags: CInt) -> Option<()> {
    if fcntl(fd, F_SETFL, flags) < 0 {
        None
    } else {
        Some(())
    }
}

/// 等待描述符上的事件。返回 `Some(就绪数)`；`None` 表示失败。
///
/// # Safety
///
/// `fds` 必须指向至少 `nfds` 个有效的 `PollFd`，且其中的 `fd` 必须是打开着的。
pub unsafe fn wait_readable(fds: *mut PollFd, nfds: CULong, timeout_ms: CInt) -> Option<CInt> {
    let ready = poll(fds, nfds, timeout_ms);
    if ready < 0 {
        None
    } else {
        Some(ready)
    }
}

/// 从描述符读字节。返回读到的字节数；`None` 表示失败。
///
/// # Safety
///
/// `buffer` 必须指向至少 `len` 字节的可写内存。
pub unsafe fn read_bytes(fd: CInt, buffer: &mut [u8]) -> Option<usize> {
    let read = read(fd, buffer.as_mut_ptr().cast::<c_void>(), buffer.len());
    if read < 0 {
        None
    } else {
        Some(read as usize)
    }
}

/// 向描述符写字节。返回写出的字节数；`None` 表示失败。
///
/// # Safety
///
/// `buffer` 必须指向至少 `len` 字节的可读内存。
pub unsafe fn write_bytes(fd: CInt, buffer: &[u8]) -> Option<usize> {
    let written = write(fd, buffer.as_ptr().cast::<c_void>(), buffer.len());
    if written < 0 {
        None
    } else {
        Some(written as usize)
    }
}

/// 发起一个带 `struct ifreq` 的 ioctl。失败返回 `None`。
///
/// # Safety
///
/// `request` 必须指向至少 [`IFREQ_SIZE`] 字节的有效内存。
pub unsafe fn ioctl_ifreq(fd: CInt, request: CULong, ifreq: &mut [u8]) -> Option<()> {
    let result = ioctl(fd, request, ifreq.as_mut_ptr().cast::<c_void>());
    if result < 0 {
        None
    } else {
        Some(())
    }
}

/// 取当前 errno。
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `struct ifreq` 的最小视图：名字 + 联合体。
///
/// 联合体在 Linux 上 `ifr_flags`（`short`）与 `ifr_mtu`（`int`）同偏移，
/// 与内核一致；缓冲区按 [`IFREQ_SIZE`] 与内核等长。
pub struct IfReq {
    bytes: [u8; IFREQ_SIZE],
}

impl IfReq {
    /// 建立一个清零的请求，并把设备名写进 `ifr_name`。
    pub fn new(name: &str) -> Self {
        let mut request = Self {
            bytes: [0u8; IFREQ_SIZE],
        };
        let name_bytes = name.as_bytes();
        // 名字由调用方校验过长度（`< IFNAMSIZ`）；这里仍做防御性截断。
        let len = name_bytes.len().min(IFNAMSIZ - 1);
        request.bytes[IFR_NAME_OFFSET..IFR_NAME_OFFSET + len].copy_from_slice(&name_bytes[..len]);
        request
    }

    /// 读取 `ifr_name`（去掉结尾 NUL）。
    pub fn name(&self) -> String {
        let raw = &self.bytes[IFR_NAME_OFFSET..IFR_NAME_OFFSET + IFNAMSIZ];
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    /// 读取 `ifr_flags`。
    pub fn flags(&self) -> u16 {
        let raw = &self.bytes[IFR_UNION_OFFSET..IFR_UNION_OFFSET + 2];
        u16::from_ne_bytes([raw[0], raw[1]])
    }

    /// 写 `ifr_flags`。
    pub fn set_flags(&mut self, flags: u16) {
        let raw = &mut self.bytes[IFR_UNION_OFFSET..IFR_UNION_OFFSET + 2];
        raw.copy_from_slice(&flags.to_ne_bytes());
    }

    /// 写 `ifr_mtu`。
    ///
    /// 内核的 `struct ifreq` 里 `ifr_mtu` 是 `int`（**4 字节**），与 `ifr_flags`
    /// （`short`，2 字节）同偏移。写 2 字节会留下半个字的高位垃圾，内核按 4 字节
    /// 读出来就是个乱值。
    pub fn set_mtu(&mut self, mtu: u16) {
        let raw = &mut self.bytes[IFR_UNION_OFFSET..IFR_UNION_OFFSET + 4];
        raw.copy_from_slice(&i32::from(mtu).to_ne_bytes());
    }

    /// 读 `ifr_mtu`（内核写回的是 `int`，本层只取其低 16 位）。
    pub fn mtu(&self) -> u16 {
        let raw = &self.bytes[IFR_UNION_OFFSET..IFR_UNION_OFFSET + 4];
        u16::try_from(i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]])).unwrap_or(0)
    }

    /// 交出底层字节缓冲，供 ioctl 使用。
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}
