//! 跨进程重启的 UDP 重放保护：把每个会话已见的 packet id 持久化到调用方指定的路径。
//!
//! 语义（fail-closed）：
//! - 进程重启后从磁盘加载已见 packet id 上下界；同一 `(session_id)` 且
//!   `packet_id` 已见（或落在一个已跨越的区间内）时拒绝。
//! - 落盘采用「已见区间集合 + 各区间上下界」的紧凑表示：UDP 发送方按
//!   packet id 单调递增发包，因此连续区间能覆盖绝大多数字节；乱序包插入
//!   新区间。区间数超过上限时合并为 `[min, max]` 单区间，只会更保守
//!   （宁可多拒不可漏拒），不会削弱保护。
//! - 写入使用「临时文件 + 原子 rename」，保证重启时读到的是完整快照。
//! - 并发安全：本类型不内部加锁，调用方必须以 `Mutex`（或等价物）串行化；
//!   本模块只在 `&mut self` 方法上修改状态。
//!
//! 记录格式（文件头 + 变长会话表，全部大端）：
//! ```text
//! magic:       8 字节 b"SS22RP01"
//! version:     u32 = 1
//! session_cnt: u32
//! 每个会话：
//!   session_id: [u8; 8]
//!   range_cnt:  u32
//!   每个区间：
//!     lo: u64  已见的最小 packet id（含）
//!     hi: u64  已见的最大 packet id（含）
//! ```
//! 磁盘上不写入任何 PSK、salt 或载荷内容；`session_id` 是每会话随机 8 字节，
//! 不含凭据。文件权限由调用方创建的目录决定，本模块不额外收紧。
use crate::Error;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// 单个会话保留的最大区间数；超出后合并为单区间（更保守）。
const MAX_RANGES_PER_SESSION: usize = 64;
const MAGIC: &[u8; 8] = b"SS22RP01";
const VERSION: u32 = 1;

/// 已见 packet id 的闭区间集合，按 `lo` 升序且互不重叠（相邻合并）。
#[derive(Clone, Default)]
struct Ranges {
    ranges: Vec<(u64, u64)>,
}

impl Ranges {
    /// 是否已包含 `id`（二分查找）。
    fn contains(&self, id: u64) -> bool {
        match self.ranges.binary_search_by(|(lo, _)| lo.cmp(&id)) {
            Ok(_) => true,
            Err(0) => false,
            Err(index) => {
                let (_, hi) = self.ranges[index - 1];
                id <= hi
            }
        }
    }
    /// 标记 `id` 已见；与相邻区间合并，必要时按上限收敛。
    fn insert(&mut self, id: u64) {
        // 找到按 `lo` 升序的插入点；已包含则无事可做（调用方应先 contains）。
        let index = match self.ranges.binary_search_by(|(lo, _)| lo.cmp(&id)) {
            Ok(_) => return,
            Err(index) => index,
        };
        // 新区间初值；与前一区间相接（含相邻）则左并。
        let (mut lo, mut hi) = (id, id);
        let mut start = index;
        if index > 0 {
            let (previous_lo, previous_hi) = self.ranges[index - 1];
            if id <= previous_hi.saturating_add(1) {
                lo = lo.min(previous_lo);
                hi = hi.max(previous_hi);
                start = index - 1;
            }
        }
        // 依次右并所有相接的后续区间。
        let mut end = index;
        while end < self.ranges.len() {
            let (next_lo, next_hi) = self.ranges[end];
            if next_lo > hi.saturating_add(1) {
                break;
            }
            hi = hi.max(next_hi);
            end += 1;
        }
        self.ranges.splice(start..end, [(lo, hi)]);
        self.shrink();
    }
    /// 区间过多时合并为单区间 `[min, max]`，只会更保守。
    fn shrink(&mut self) {
        if self.ranges.len() > MAX_RANGES_PER_SESSION {
            let lo = self.ranges[0].0;
            let hi = self.ranges[self.ranges.len() - 1].1;
            self.ranges = vec![(lo, hi)];
        }
    }
}

/// 可持久化的重放窗口，落盘到调用方指定的路径。
pub struct ReplayStore {
    path: PathBuf,
    sessions: BTreeMap<[u8; 8], Ranges>,
}

impl ReplayStore {
    /// 从 `path` 加载已有状态；文件不存在视为空状态。格式损坏时 fail-closed 报错。
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let sessions = match std::fs::read(&path) {
            Ok(bytes) => decode(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(Error::Io(error)),
        };
        Ok(Self { path, sessions })
    }
    /// 判定并记录：`true` 表示首次到达（可转发）；重复则返回 `false` 且不改状态。
    pub fn accept(&mut self, session_id: [u8; 8], packet_id: u64) -> bool {
        let ranges = self.sessions.entry(session_id).or_default();
        if ranges.contains(packet_id) {
            return false;
        }
        ranges.insert(packet_id);
        true
    }
    /// 落地当前快照（临时文件 + 原子 rename）；无变化也安全重入。
    pub fn flush(&self) -> Result<(), Error> {
        let bytes = encode(&self.sessions);
        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, &bytes)?;
        std::fs::rename(&temporary, &self.path)?;
        Ok(())
    }
    /// 是否已记录该 `(session_id, packet_id)`，不修改状态。
    pub fn contains(&self, session_id: [u8; 8], packet_id: u64) -> bool {
        self.sessions
            .get(&session_id)
            .is_some_and(|ranges| ranges.contains(packet_id))
    }
    /// 已记录的会话数（诊断用，不导出 id）。
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
    /// 落盘路径。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn encode(sessions: &BTreeMap<[u8; 8], Ranges>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
    for (session_id, ranges) in sessions {
        out.extend_from_slice(session_id);
        out.extend_from_slice(&(ranges.ranges.len() as u32).to_be_bytes());
        for (lo, hi) in &ranges.ranges {
            out.extend_from_slice(&lo.to_be_bytes());
            out.extend_from_slice(&hi.to_be_bytes());
        }
    }
    out
}

fn decode(bytes: &[u8]) -> Result<BTreeMap<[u8; 8], Ranges>, Error> {
    let mut cursor = Slice { bytes, offset: 0 };
    if cursor.take(8)? != MAGIC {
        return Err(Error::ReplayStore);
    }
    if u32::from_be_bytes(cursor.take(4)?.try_into().expect("固定长度")) != VERSION {
        return Err(Error::ReplayStore);
    }
    let count = u32::from_be_bytes(cursor.take(4)?.try_into().expect("固定长度"));
    let mut sessions = BTreeMap::new();
    for _ in 0..count {
        let session_id: [u8; 8] = cursor.take(8)?.try_into().expect("固定长度");
        let range_count = u32::from_be_bytes(cursor.take(4)?.try_into().expect("固定长度"));
        let mut ranges = Ranges::default();
        let mut previous_hi: Option<u64> = None;
        for _ in 0..range_count {
            let lo = u64::from_be_bytes(cursor.take(8)?.try_into().expect("固定长度"));
            let hi = u64::from_be_bytes(cursor.take(8)?.try_into().expect("固定长度"));
            // 拒绝乱序或自相交的区间：损坏快照必须 fail-closed。
            if lo > hi || previous_hi.is_some_and(|previous| lo <= previous) {
                return Err(Error::ReplayStore);
            }
            previous_hi = Some(hi);
            ranges.ranges.push((lo, hi));
        }
        sessions.insert(session_id, ranges);
    }
    if cursor.offset != bytes.len() {
        return Err(Error::ReplayStore);
    }
    Ok(sessions)
}

struct Slice<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Slice<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(length).ok_or(Error::ReplayStore)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::ReplayStore)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "lengsuo-ss2022-replay-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory.join("replay.bin")
    }

    #[test]
    fn unrecorded_id_is_accepted_then_rejected() {
        let path = temp_path("basic");
        let _ = std::fs::remove_file(&path);
        let mut store = ReplayStore::load(&path).unwrap();
        let session = [0x11; 8];
        assert!(store.accept(session, 7));
        assert!(!store.accept(session, 7));
        assert!(store.accept(session, 8));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn state_survives_reload() {
        let path = temp_path("reload");
        let _ = std::fs::remove_file(&path);
        let session = [0x22; 8];
        {
            let mut store = ReplayStore::load(&path).unwrap();
            assert!(store.accept(session, 0));
            assert!(store.accept(session, 1));
            assert!(store.accept(session, 5));
            store.flush().unwrap();
        }
        let mut reloaded = ReplayStore::load(&path).unwrap();
        // 重启后同一 (session, packet id) 必须拒绝。
        assert!(!reloaded.accept(session, 0));
        assert!(!reloaded.accept(session, 1));
        assert!(!reloaded.accept(session, 5));
        // 递增的新 id 仍然接受。
        assert!(reloaded.accept(session, 6));
        // 其它会话不受影响。
        assert!(reloaded.accept([0x33; 8], 0));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gap_ids_are_not_falsely_rejected() {
        let path = temp_path("gaps");
        let _ = std::fs::remove_file(&path);
        let mut store = ReplayStore::load(&path).unwrap();
        let session = [0x44; 8];
        for id in [0u64, 2, 4, 6] {
            assert!(store.accept(session, id), "id {id} 应首次接受");
        }
        for id in [0u64, 2, 4, 6] {
            assert!(!store.accept(session, id), "id {id} 应重放拒绝");
        }
        // 空洞中的 id 也应首次接受。
        for id in [1u64, 3, 5] {
            assert!(store.accept(session, id), "空洞 id {id} 应首次接受");
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_file_fails_closed() {
        let path = temp_path("corrupt");
        std::fs::write(&path, b"not a snapshot").unwrap();
        assert!(matches!(ReplayStore::load(&path), Err(Error::ReplayStore)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_file_fails_closed() {
        let path = temp_path("truncated");
        let _ = std::fs::remove_file(&path);
        {
            let mut store = ReplayStore::load(&path).unwrap();
            store.accept([0x55; 8], 1);
            store.flush().unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 3]).unwrap();
        assert!(matches!(ReplayStore::load(&path), Err(Error::ReplayStore)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn overlapping_ranges_are_rejected() {
        let mut sessions = BTreeMap::new();
        sessions.insert(
            [0x66; 8],
            Ranges {
                ranges: vec![(5, 9), (7, 12)],
            },
        );
        assert!(matches!(
            decode(&encode(&sessions)),
            Err(Error::ReplayStore)
        ));
    }

    #[test]
    fn large_jump_collapses_but_stays_conservative() {
        let path = temp_path("jump");
        let _ = std::fs::remove_file(&path);
        let mut store = ReplayStore::load(&path).unwrap();
        let session = [0x77; 8];
        for id in 0..(MAX_RANGES_PER_SESSION as u64 * 2) {
            assert!(store.accept(session, id * 2));
        }
        // 收敛为单区间后，区间内任何值都视为已见（更保守）。
        assert!(!store.accept(session, 3));
        assert!(!store.accept(session, 2));
        // 区间外的新 id 仍接受。
        assert!(store.accept(session, u64::MAX));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn flush_is_atomic_and_reentrant() {
        let path = temp_path("atomic");
        let _ = std::fs::remove_file(&path);
        let mut store = ReplayStore::load(&path).unwrap();
        store.accept([0x88; 8], 1);
        store.flush().unwrap();
        store.flush().unwrap();
        assert!(!store.path().with_extension("tmp").exists());
        let reloaded = ReplayStore::load(&path).unwrap();
        assert!(reloaded.contains([0x88; 8], 1));
        assert_eq!(reloaded.session_count(), 1);
        let _ = std::fs::remove_file(&path);
    }
}
