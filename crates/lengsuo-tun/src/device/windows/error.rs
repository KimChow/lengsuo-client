//! wintun 绑定的错误分类：把绑定错误换成本层的类型化错误。

use super::{DeviceConfig, Error, Result, LIBRARY_ENV};

/// 与 wintun.h 注释一致的系统错误码，用于把绑定错误分类成本层的类型化错误。
/// 数值取自 windows-sys 的 `WIN32_ERROR` 常量，只在本机做整数比较。
const ERROR_INVALID_DATA: i32 = 13;
const ERROR_HANDLE_EOF: i32 = 38;
const ERROR_BUFFER_OVERFLOW: i32 = 111;
const ERROR_NO_MORE_ITEMS: i32 = 259;
const ERROR_ADAPTER_OFF: i32 = 1246;

/// 把 wintun 绑定的结果统一换成本层错误类型。
pub(super) fn wrap<T>(result: std::result::Result<T, wintun::Error>) -> Result<T> {
    result.map_err(map_error)
}

/// 错误分类。wintun::Error 是 `#[non_exhaustive]`，所以必须有兜底分支；
/// 兜底保留原始文案，绝不把失败说成成功。
pub(super) fn map_error(error: wintun::Error) -> Error {
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
                super::Library::load_hint()
            ),
        },
    }
}
