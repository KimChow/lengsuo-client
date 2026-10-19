//! 会话内 UDP 关联登记表。
//!
//! 参考 anytls-go fd6167a 把 UDP 关联直接落在普通 anytls 流上：客户端多开一条
//! 流，目的地址填魔法域；服务端在 `inbound_tcp.go` 的 `onNewStream` 里读走
//! 目的地址与 `uot.ReadRequest` 后即转入 UoT 通道，不再需要额外的流编号语义。
//! 本表只补一层「流编号 ↔ 关联」的记账，供调用方判断某编号是否已建立关联、
//! 以及在流关闭时一并清理；它不改变任何线格式。
use crate::stream::{Association, StreamError};
use std::collections::HashMap;

/// 流编号 -> 关联。每个编号最多一条关联，编号为零一律拒绝。
#[derive(Debug, Default)]
pub struct UdpAssociations {
    associations: HashMap<u32, Association>,
}

impl UdpAssociations {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.associations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.associations.is_empty()
    }

    pub fn get(&self, stream_id: u32) -> Option<&Association> {
        self.associations.get(&stream_id)
    }

    /// 登记关联；流编号为零或重复登记均失败。
    pub fn insert(&mut self, stream_id: u32, association: Association) -> Result<(), StreamError> {
        if stream_id == 0 {
            return Err(StreamError::InvalidId("UDP 关联流编号为零"));
        }
        if self.associations.contains_key(&stream_id) {
            return Err(StreamError::DuplicateAssociation(stream_id));
        }
        self.associations.insert(stream_id, association);
        Ok(())
    }

    pub fn remove(&mut self, stream_id: u32) -> Result<Association, StreamError> {
        self.associations
            .remove(&stream_id)
            .ok_or(StreamError::UnknownAssociation(stream_id))
    }

    pub fn clear(&mut self) {
        self.associations.clear();
    }
}
