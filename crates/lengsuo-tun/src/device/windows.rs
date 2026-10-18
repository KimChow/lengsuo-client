//! Windows 侧 wintun 设备实现：只在 `#[cfg(windows)]` 下编译。
//!
//! 全部调用都走 wintun 0.5.1 的**安全** API；本文件不含任何 `unsafe`，因此动态库加载
//! 由宿主完成（wintun 的 `load` / `load_from_path` / `load_from_library` 都是 `unsafe fn`），
//! 加载结果通过 [`Library::from_handle`] 注入本层。
//!
//! 接收用 `try_receive` + 短休眠轮询实现超时：等待 wintun 的读事件需要
//! `WaitForSingleObject`（unsafe），本层禁用，所以采用轮询。
//!
//! 状态机：`create`/`open`（只有适配器）→ `start_session`（适配器 + 会话）→
//! `end_session` / `close` / `Drop`（会话结束）。关闭后的任何操作返回 [`Error::Closed`]，
//! 不会二次关闭。适配器句柄在 `Device` 析构时由 wintun 绑定释放。

use super::{
    DeviceConfig, Error, Result, LIBRARY_ENV, LIBRARY_FILE, MAX_PACKET_BYTES, POLL_INTERVAL,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wintun::{Adapter, Session, Wintun};

/// 与 wintun.h 注释一致的系统错误码，用于把绑定错误分类成本层的类型化错误。
/// 数值取自 windows-sys 的 `WIN32_ERROR` 常量，只在本机做整数比较。
const ERROR_INVALID_DATA: i32 = 13;
const ERROR_HANDLE_EOF: i32 = 38;
const ERROR_BUFFER_OVERFLOW: i32 = 111;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const ERROR_ADAPTER_OFF: i32 = 1246;

/// 已加载的 wintun 库句柄。克隆只增加引用计数（绑定的 `Wintun` 本身就是 `Arc`）。
#[derive(Clone)]
pub struct Library {
    wintun: Wintun,
}

impl std::fmt::Debug for Library {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Library")
            .field("path", &super::library_path())
            .finish_non_exhaustive()
    }
}

impl Library {
    /// 注入宿主已经加载好的 wintun 句柄。本层不加载 dll：那需要 `unsafe`。
    pub fn from_handle(wintun: Wintun) -> Result<Self> {
        Ok(Self { wintun })
    }

    /// 本层期望 dll 就位的路径（环境变量 [`LIBRARY_ENV`] 的绝对路径优先，
    /// 其次可执行文件同目录的 [`LIBRARY_FILE`]）。
    #[must_use]
    pub fn expected_path() -> std::path::PathBuf {
        super::library_path()
    }

    /// dll 已就位则返回其路径，否则返回带放置提示的 [`Error::LibraryMissing`]。
    /// 只检查存在性，不加载、不复制、不写入系统目录。
    pub fn locate() -> Result<std::path::PathBuf> {
        super::ensure_library()
    }

    /// 给宿主/操作者的加载提示文案。
    #[must_use]
    pub fn load_hint() -> String {
        format!(
            "请在宿主 crate 内以 unsafe {{ wintun::load_from_path(path) }} 加载 {}，\
             path 取环境变量 {LIBRARY_ENV} 或可执行文件同目录的 {LIBRARY_FILE}，\
             再把返回的 Wintun 句柄传给 Library::from_handle（本 crate 禁止 unsafe，不代为加载）",
            Self::expected_path().display()
        )
    }

    fn handle(&self) -> &Wintun {
        &self.wintun
    }
}

/// Windows TUN 设备：一个 wintun 适配器，外加可选的活动会话。
pub struct Device {
    config: DeviceConfig,
    adapter: Arc<Adapter>,
    session: Option<Arc<Session>>,
    closed: bool,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Device")
            .field("adapter_name", &self.config.adapter_name)
            .field("ring_capacity", &self.config.ring_capacity)
            .field("mtu", &self.config.mtu)
            .field("session", &self.session.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// 创建新的 wintun 适配器（不开会话）。需要管理员权限：这会在系统里注册网络接口。
    /// 测试请用 [`DeviceConfig::for_test`] 生成专用名与随机 GUID。
    pub fn create(library: &Library, config: DeviceConfig) -> Result<Self> {
        config.validate()?;
        let adapter = Adapter::create(
            library.handle(),
            &config.adapter_name,
            &config.tunnel_type,
            config.guid,
        )
        .map_err(map_error)?;
        Ok(Self {
            config,
            adapter,
            session: None,
            closed: false,
        })
    }

    /// 打开系统中已存在的同名 wintun 适配器，并从系统状态同步 MTU 与 GUID。
    pub fn open(library: &Library, mut config: DeviceConfig) -> Result<Self> {
        config.validate()?;
        let adapter = Adapter::open(library.handle(), &config.adapter_name).map_err(map_error)?;
        config.guid = Some(adapter.get_guid());
        let mut device = Self {
            config,
            adapter,
            session: None,
            closed: false,
        };
        // 系统侧 MTU 才是事实来源；读取失败时保留配置值，由调用方显式 set_mtu 纠正。
        if let Ok(mtu) = device.mtu() {
            device.config.mtu = mtu;
        }
        Ok(device)
    }

    /// 开启会话。`capacity` 是驱动内部环形缓冲字节数：必须是
    /// [`DeviceConfig::MIN_RING_CAPACITY`]..=[`DeviceConfig::MAX_RING_CAPACITY`] 的 2 的幂。
    /// 已有会话时先结束旧会话，保证一个设备只有一个活动会话（防重入）。
    pub fn start_session(&mut self, capacity: u32) -> Result<()> {
        self.ensure_open()?;
        self.config.validate_ring_capacity(capacity)?;
        self.end_session()?;
        let session = self.adapter.start_session(capacity).map_err(map_error)?;
        self.session = Some(Arc::new(session));
        self.config.ring_capacity = capacity;
        Ok(())
    }

    /// 结束当前会话；没有会话时是空操作。唤醒可能阻塞在其他线程上的接收。
    pub fn end_session(&mut self) -> Result<()> {
        self.ensure_open()?;
        let Some(session) = self.session.take() else {
            return Ok(());
        };
        // shutdown 只是置位停止事件；失败不影响随后的会话释放，交由绑定处理。
        let _ = session.shutdown();
        drop(session);
        Ok(())
    }

    /// 会话是否活动。
    #[must_use]
    pub fn has_session(&self) -> bool {
        !self.closed && self.session.is_some()
    }

    /// 设备是否已关闭。
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// 当前生效配置（`set_mtu` 与 `start_session` 会同步更新）。
    #[must_use]
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// 适配器 GUID。
    pub fn guid(&self) -> Result<u128> {
        self.ensure_open()?;
        Ok(self.adapter.get_guid())
    }

    /// Windows 接口索引，供按接口指定 `netsh` 等命令。
    pub fn interface_index(&self) -> Result<u32> {
        self.ensure_open()?;
        wrap(self.adapter.get_adapter_index())
    }

    /// 设置 MTU。wintun 内部通过 `netsh` 修改接口，属于系统状态变更，
    /// 只在调用方显式请求时执行；成功后同步进配置。
    pub fn set_mtu(&mut self, mtu: u16) -> Result<()> {
        self.ensure_open()?;
        self.config.validate_mtu(mtu)?;
        wrap(self.adapter.set_mtu(usize::from(mtu)))?;
        self.config.mtu = mtu;
        Ok(())
    }

    /// 读取系统侧当前 MTU。
    pub fn mtu(&self) -> Result<u16> {
        self.ensure_open()?;
        let mtu = wrap(self.adapter.get_mtu())?;
        u16::try_from(mtu).map_err(|_| Error::Device {
            reason: format!("系统 MTU {mtu} 超出 16 位单包上限 {MAX_PACKET_BYTES}"),
        })
    }

    /// 在 `timeout` 内接收一个原始 IP 报文（返回堆拷贝，不借用驱动内存）。
    ///
    /// 无报文返回 [`Error::Timeout`]；适配器被移除或驱动撤回返回 [`Error::SessionEnded`]；
    /// 已关闭返回 [`Error::Closed`]；未开会话返回 [`Error::Device`]。
    pub fn receive(&self, timeout: Duration) -> Result<Vec<u8>> {
        self.ensure_open()?;
        let session = self.session_arc()?;
        let deadline = Instant::now() + timeout;
        loop {
            match session.try_receive().map_err(map_error)? {
                Some(packet) => {
                    let len = packet.bytes().len();
                    if len == 0 || len > MAX_PACKET_BYTES {
                        return Err(Error::InvalidPacket {
                            value: len,
                            max: MAX_PACKET_BYTES,
                        });
                    }
                    return Ok(packet.bytes().to_vec());
                }
                None => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(Error::Timeout { waited: timeout });
                    }
                    std::thread::sleep(POLL_INTERVAL.min(deadline - now));
                }
            }
        }
    }

    /// 发送一个原始 IP 报文。空报文或超过 MTU 的报文返回 [`Error::InvalidPacket`]；
    /// 发送环形缓冲无空闲空间返回 [`Error::BufferInsufficient`]。
    pub fn send(&self, packet: &[u8]) -> Result<()> {
        self.ensure_open()?;
        self.config.validate_packet_len(packet.len())?;
        let session = self.session_arc()?;
        let size = u16::try_from(packet.len()).map_err(|_| Error::InvalidPacket {
            value: packet.len(),
            max: MAX_PACKET_BYTES,
        })?;
        // wintun 要求每个分配的包都被发送，否则发送队列会永久卡住。
        // 分配长度与写入长度同为 packet.len()，copy_from_slice 不会失败，
        // 因此本函数不存在「已分配未发送」的返回路径。
        let mut buffer = session.allocate_send_packet(size).map_err(map_error)?;
        buffer.bytes_mut().copy_from_slice(packet);
        session.send_packet(buffer);
        Ok(())
    }

    /// 显式关闭：结束会话并标记句柄失效。可重复调用（防重入）；
    /// 关闭后所有操作返回 [`Error::Closed`]。适配器句柄在 `Device` 析构时由绑定释放。
    pub fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if let Some(session) = self.session.take() {
            let _ = session.shutdown();
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    fn session_arc(&self) -> Result<Arc<Session>> {
        self.session.clone().ok_or_else(|| Error::Device {
            reason: "会话未开启：先调用 Device::start_session".to_string(),
        })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        // 幂等：显式 close() 之后再到这里不会二次关闭。
        let _ = self.close();
    }
}

/// 把 wintun 绑定的结果统一换成本层错误类型。
fn wrap<T>(result: std::result::Result<T, wintun::Error>) -> Result<T> {
    result.map_err(map_error)
}

/// 错误分类。wintun::Error 是 `#[non_exhaustive]`，所以必须有兜底分支；
/// 兜底保留原始文案，绝不把失败说成成功。
fn map_error(error: wintun::Error) -> Error {
    match error {
        wintun::Error::ShuttingDown => Error::SessionEnded,
        wintun::Error::CapacityOutOfRange(data) => Error::RingCapacity {
            value: data.value,
            min: *data.range.start(),
            max: *data.range.end(),
        },
        wintun::Error::CapacityNotPowerOfTwo(value) => Error::RingCapacity {
            value,
            min: DeviceConfig::MIN_RING_CAPACITY,
            max: DeviceConfig::MAX_RING_CAPACITY,
        },
        wintun::Error::Io(io) => map_io_error(io),
        other => Error::Device {
            reason: format!("{other}"),
        },
    }
}

/// IO 错误按 Win32 错误码分类；取不到错误码时保留文案与 dll 提示。
fn map_io_error(io: std::io::Error) -> Error {
    match io.raw_os_error() {
        // 这三类都表示 ring/适配器侧已经终止，重试无意义。
        Some(ERROR_NO_MORE_ITEMS)
        | Some(ERROR_HANDLE_EOF)
        | Some(ERROR_INVALID_DATA)
        | Some(ERROR_ADAPTER_OFF) => Error::SessionEnded,
        Some(ERROR_BUFFER_OVERFLOW) => Error::BufferInsufficient,
        _ => Error::Device {
            reason: format!(
                "{io}（提示：{}；确认 {LIBRARY_ENV} 指向的 dll 与已装驱动版本一致）",
                Library::load_hint()
            ),
        },
    }
}
