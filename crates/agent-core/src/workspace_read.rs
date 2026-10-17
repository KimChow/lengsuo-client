//! 授权工作区内的有界文本读取（PC06 §2 / R06-1）。
//!
//! 只提供一个能力：在宿主传入的 `root` 之内读取单个文本文件，且最多 `max_bytes` 字节。
//! 不含写入、删除、批量编辑、目录遍历或全盘扫描；不依赖任何额外 crate；不使用 `unsafe`。
//!
//! ## 信任边界与已知限制
//!
//! 路径判断是**静态 canonical 检查**，不是完整沙箱：
//! - `root` 与目标路径各自 `canonicalize()` 后做前缀比较，可拦住 `../`、root 外的
//!   绝对路径、以及指向外部的 symlink（因为解析后的真实路径落在 root 之外）。
//! - 检查与 `read()` 之间存在 **TOCTOU** 窗口：调用后若 root 内容被改动（文件被替换成
//!   指向外部的 symlink、目录被重排等），本次读取可能越过检查时的判断。彻底关闭需要
//!   `openat2(O_NOFOLLOW|RESOLVE_* | `O_PATH` 逐级句柄校验，本卡不引入该复杂度。
//! - root 本身若是 symlink 也接受（canonical 后是真实目录），但仍要求目标在其内。
//! - 本模块**尚未**暴露为模型可调用工具；后续由执行器的权限门（PermissionGate）接线后
//!   才进入工具面，届时授权判定仍以运行时权限检查为准。

use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::path::Path;

/// 读取 `root` 内的文本文件，最多 `max_bytes` 字节。
///
/// - `root`：宿主提供的授权工作区根目录（不存在则报 `NotFound`）。
/// - `path`：相对 root 或绝对路径；空路径、含 `NUL`/内部 `..` 分量的路径直接拒绝。
/// - `max_bytes`：上限，必须 `> 0`；实际读取 `max_bytes + 1` 字节探测超限。
///
/// 错误语义：
/// - `InvalidInput`：`max_bytes == 0`、路径为空或含内部 `..` 分量、超出大小上限。
/// - `PermissionDenied`：canonical 解析后路径不在 canonical root 内。
/// - `NotFound`：root 或目标文件不存在。
/// - `InvalidData`：内容不是有效 UTF-8，或目标不是普通文件。
/// - 其它 `ErrorKind`：底层 IO 错误（权限、IO 故障等）原样向上传递。
///
/// 超限与无效 UTF-8 都是**整体失败**，不返回部分内容。
pub fn read_workspace_file<P: AsRef<Path>, Q: AsRef<Path>>(
    root: P,
    path: Q,
    max_bytes: usize,
) -> Result<String> {
    let root = root.as_ref();
    let path = path.as_ref();
    if max_bytes == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "max_bytes must be greater than 0",
        ));
    }

    let canonical_root = root.canonicalize()?;
    let target = resolve_candidate(&canonical_root, path)?;
    let canonical_target = target.canonicalize()?;

    if !canonical_target.starts_with(&canonical_root) {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "path escapes the authorized workspace root: {}",
                path.display()
            ),
        ));
    }

    let mut file = File::open(&canonical_target)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("not a regular file: {}", canonical_target.display()),
        ));
    }
    if meta.len() as usize > max_bytes {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "file too large: {} bytes exceeds max_bytes {max_bytes}",
                meta.len()
            ),
        ));
    }

    // 探测读取：即使 metadata 谎报，也只多读 1 字节即判定超限，不返回部分内容。
    let mut buf = Vec::with_capacity(max_bytes.min(1 << 20) + 1);
    file.by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "file larger than max_bytes {max_bytes} (read {}+ bytes)",
                max_bytes + 1
            ),
        ));
    }

    String::from_utf8(buf).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            format!("file is not valid UTF-8: {}", canonical_target.display()),
        )
    })
}

/// 把调用方路径折成 root 内的候选绝对路径；拒绝空路径与含 `NUL` 的分量。
///
/// 绝对路径允许（宿主可能传入已规范化的绝对路径），但 canonical 后仍必须落在 root 内。
/// `..` 不在此处做词法拒绝：交给 `canonicalize()` 按真实文件系统语义解析，
/// 逃逸由调用点的 `starts_with` 守卫判定为 `PermissionDenied`。
fn resolve_candidate(canonical_root: &Path, path: &Path) -> Result<std::path::PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "empty path"));
    }
    if path.components().next().is_none() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unresolvable path: {}", path.display()),
        ));
    }
    if path.as_os_str().to_string_lossy().contains('\0') {
        return Err(Error::new(ErrorKind::InvalidInput, "path contains NUL"));
    }

    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    // 相对路径直接拼到 root 后；`..` 保留给 canonicalize() 按真实文件系统语义解析。
    Ok(canonical_root.join(path))
}
