//! allowedIPs 路由表：按最长前缀匹配的二叉树（对照 wireguard-go
//! `device/allowedips.go`，commit 2631ce99）。
//!
//! 参考用 `unsafe` 指针对 parent 反向链接（`parentIndirection`），本 crate
//! `#![forbid(unsafe_code)]`，改用「父节点数组下标 + 槽位」表示同一条反向链接：
//! 语义完全一致，只是把裸指针换成 `(Option<usize>, usize)`。索引为 `None`
//! 表示挂在 `AllowedIps` 的根槽上。所有删除操作都在节点顺序扫描中完成，
//! 不做地址运算，因此下标始终有效。
//!
//! `remove` 中的「折叠父节点」分支（参考用 `unsafe.Offsetof` 反推父节点）
//! 改为直接用保存的父下标取父节点，等价且无需指针算术。
//!
//! 本文件只放 `Node`/`Trie` 的状态与节点管理（建节点、取槽位、下行定位、
//! 摘除与折叠、双栈表 `AllowedIps` 的增删查）；前缀树插入/查询这两段最长的
//! 路径算法放在子模块 [`place`] 中，作为同一 `impl` 的续写。这样单文件都
//! 落在 400 行软目标内，同时不改变任何跨模块可见性（`Node`/`Trie` 仍为
//! 模块私有，仅 `place` 可见）。

/// 父反向链接：`(父节点下标, 槽位)`；父下标 `None` 表示直接挂在根上。
type ParentLink = (Option<usize>, usize);

pub(super) struct Node {
    /// 归属 peer；`None` 表示该节点只是路径中间节点。
    peer: Option<usize>,
    children: [Option<usize>; 2],
    parent: ParentLink,
    cidr: u8,
    /// 该前缀在前缀串中的字节下标（`cidr / 8`）。
    bit_at_byte: usize,
    /// 该前缀在 `bit_at_byte` 字节内的位移（`7 - cidr % 8`）。
    bit_at_shift: u8,
    /// 掩码后的前缀字节。
    bits: Vec<u8>,
}

impl Node {
    pub(super) fn choose(&self, ip: &[u8]) -> usize {
        ((ip[self.bit_at_byte] >> self.bit_at_shift) & 1) as usize
    }

    /// 对照 `maskSelf`：把前缀里超出 `cidr` 的位清零。
    pub(super) fn mask_self(&mut self) {
        let bit_len = self.bits.len() * 8;
        for (index, byte) in self.bits.iter_mut().enumerate() {
            let remaining = bit_len.saturating_sub(index * 8);
            let kept = remaining.min(self.cidr as usize);
            let mask = if kept >= 8 {
                0xff
            } else {
                (0xffu16 << (8 - kept)) as u8
            };
            *byte &= mask;
        }
    }
}

/// 两个前缀共同的前导位数（对照 `commonBits`）。长度必须一致（同族）。
fn common_bits(a: &[u8], b: &[u8]) -> u8 {
    let size = a.len();
    debug_assert_eq!(size, b.len());
    let mut count: u8 = 0;
    for index in 0..size {
        let x = a[index] ^ b[index];
        if x == 0 {
            count += 8;
            continue;
        }
        return count + x.leading_zeros() as u8;
    }
    count
}

/// 单族（v4 或 v6）前缀树。
pub(super) struct Trie {
    pub(super) nodes: Vec<Node>,
    /// 根槽位（对照参考里 `&table.IPv4` / `&table.IPv6` 作为 `trie.parentBit`）。
    pub(super) root: Option<usize>,
}

impl Trie {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            root: None,
        }
    }

    pub(super) fn slot(&mut self, link: ParentLink) -> &mut Option<usize> {
        match link.0 {
            None => &mut self.root,
            Some(parent) => &mut self.nodes[parent].children[link.1],
        }
    }

    pub(super) fn slot_get(&self, link: ParentLink) -> Option<usize> {
        match link.0 {
            None => self.root,
            Some(parent) => self.nodes[parent].children[link.1],
        }
    }

    /// 对照 `nodePlacement`：沿树下行直到不再满足包含关系。
    pub(super) fn node_placement(&self, ip: &[u8], cidr: u8) -> (Option<usize>, bool) {
        let mut node = self.root;
        let mut parent = None;
        while let Some(index) = node {
            let current = &self.nodes[index];
            if current.cidr > cidr || common_bits(&current.bits, ip) < current.cidr {
                break;
            }
            parent = Some(index);
            if current.cidr == cidr {
                return (parent, true);
            }
            node = current.children[current.choose(ip)];
        }
        (parent, false)
    }

    pub(super) fn new_node(&mut self, ip: &[u8], cidr: u8, peer: Option<usize>) -> usize {
        let mut node = Node {
            peer,
            children: [None, None],
            parent: (None, 2),
            cidr,
            bit_at_byte: (cidr / 8) as usize,
            bit_at_shift: 7 - (cidr % 8),
            bits: ip.to_vec(),
        };
        node.mask_self();
        self.nodes.push(node);
        self.nodes.len() - 1
    }

    /// 对照 `trieEntry.remove`：摘除该节点，必要时折叠其单子父节点。
    pub(super) fn remove(&mut self, index: usize) {
        self.nodes[index].peer = None;
        if self.nodes[index].children[0].is_some() && self.nodes[index].children[1].is_some() {
            return;
        }
        let bit = if self.nodes[index].children[0].is_none() {
            1
        } else {
            0
        };
        let child = self.nodes[index].children[bit];
        if let Some(child_index) = child {
            self.nodes[child_index].parent = self.nodes[index].parent;
        }
        let link = self.nodes[index].parent;
        *self.slot(link) = child;

        let has_children = child.is_some();
        let link_slot = link.1;
        if has_children || link_slot > 1 {
            self.zeroize(index);
            return;
        }

        // 父节点只剩下另一个孩子：把它上提到祖父位置（对照参考的折叠分支）。
        let parent_index = match link.0 {
            Some(parent) => parent,
            None => {
                self.zeroize(index);
                return;
            }
        };
        if self.nodes[parent_index].peer.is_some() {
            self.zeroize(index);
            return;
        }
        let sibling = self.nodes[parent_index].children[link_slot ^ 1];
        if let Some(sibling_index) = sibling {
            self.nodes[sibling_index].parent = self.nodes[parent_index].parent;
        }
        let parent_link = self.nodes[parent_index].parent;
        *self.slot(parent_link) = sibling;
        self.zeroize(index);
        self.zeroize(parent_index);
    }

    pub(super) fn zeroize(&mut self, index: usize) {
        self.nodes[index].peer = None;
        self.nodes[index].children = [None, None];
        self.nodes[index].parent = (None, 2);
        self.nodes[index].bits.clear();
    }

    /// 把新节点挂到 `parent`（`None` 表示挂根）。对照参考 `insert` 结尾：
    /// `bit := parent.choose(newNode.bits)`——分支位取自**新节点自身的（已掩码）
    /// 前缀**，而不是原始 `ip`；两者在掩码后可能不同，用错会挂到姊妹槽位。
    pub(super) fn attach_to_parent(&mut self, index: usize, parent: Option<usize>) {
        match parent {
            None => {
                self.nodes[index].parent = (None, 2);
                self.root = Some(index);
            }
            Some(parent_index) => {
                let bits = self.nodes[index].bits.clone();
                let bit = self.nodes[parent_index].choose(&bits);
                self.nodes[index].parent = (Some(parent_index), bit);
                self.nodes[parent_index].children[bit] = Some(index);
            }
        }
    }
}

mod place;

/// 双栈 allowedIPs 表。
pub struct AllowedIps {
    v4: Trie,
    v6: Trie,
}

impl Default for AllowedIps {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowedIps {
    #[must_use]
    pub fn new() -> Self {
        Self {
            v4: Trie::new(),
            v6: Trie::new(),
        }
    }

    /// 插入 `prefix` 归属 `peer`。`ip` 长度必须为 4 或 16，`cidr` 不超过位宽；
    /// 否则返回 `false` 且不改变表（fail-closed）。
    pub fn insert(&mut self, peer: usize, ip: &[u8], cidr: u8) -> bool {
        let trie = match ip.len() {
            4 if cidr <= 32 => &mut self.v4,
            16 if cidr <= 128 => &mut self.v6,
            _ => return false,
        };
        // 对齐参考：先按 cidr 掩码前缀，避免带主机位的地址进入树。
        let masked = mask_prefix(ip, cidr);
        trie.insert(&masked, cidr, peer);
        true
    }

    /// 最长前缀匹配。`ip` 长度必须为 4 或 16。
    #[must_use]
    pub fn lookup(&self, ip: &[u8]) -> Option<usize> {
        match ip.len() {
            4 => self.v4.lookup(ip),
            16 => self.v6.lookup(ip),
            _ => None,
        }
    }

    /// 删除恰好等于 `(ip, cidr)` 且归属 `peer` 的条目；不匹配则不动。
    pub fn remove(&mut self, peer: usize, ip: &[u8], cidr: u8) -> bool {
        let trie = match ip.len() {
            4 if cidr <= 32 => &mut self.v4,
            16 if cidr <= 128 => &mut self.v6,
            _ => return false,
        };
        let masked = mask_prefix(ip, cidr);
        let (node, exact) = trie.node_placement(&masked, cidr);
        match node {
            Some(index) if exact && trie.nodes[index].peer == Some(peer) => {
                trie.remove(index);
                true
            }
            _ => false,
        }
    }

    /// 删除某 peer 的全部条目。
    pub fn remove_by_peer(&mut self, peer: usize) {
        for trie in [&mut self.v4, &mut self.v6] {
            let owned: Vec<usize> = trie
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| node.peer == Some(peer))
                .map(|(index, _)| index)
                .collect();
            for index in owned {
                if trie.nodes[index].peer == Some(peer) {
                    trie.remove(index);
                }
            }
        }
    }
}

/// 把 `ip` 里超出 `cidr` 的位清零（对照参考在 `Insert` 前对前缀做掩码）。
fn mask_prefix(ip: &[u8], cidr: u8) -> Vec<u8> {
    let bit_len = ip.len() * 8;
    let mut masked = ip.to_vec();
    for (index, byte) in masked.iter_mut().enumerate() {
        let remaining = bit_len.saturating_sub(index * 8);
        let kept = remaining.min(cidr as usize);
        let mask = if kept >= 8 {
            0xff
        } else {
            (0xffu16 << (8 - kept)) as u8
        };
        *byte &= mask;
    }
    masked
}
