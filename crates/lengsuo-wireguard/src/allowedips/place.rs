//! `Trie` 的前缀放置与查询：`insert`（对照 `parentIndirection.insert`）与
//! `lookup`（最长前缀匹配）。这两个函数是整棵树里最长的路径算法，单独成
//! 文件以守住 400 行软目标；它们与父模块是同一条 `impl Trie` 的续写，
//! 不改变任何可见性（`Trie` 及其字段仍为 `pub(super)`，仅本模块可见）。

use super::Trie;

impl Trie {
    /// 对照 `parentIndirection.insert`。
    pub(super) fn insert(&mut self, ip: &[u8], cidr: u8, peer: usize) {
        let root_link: super::ParentLink = (None, 2);
        if self.slot_get(root_link).is_none() {
            let index = self.new_node(ip, cidr, Some(peer));
            self.nodes[index].parent = root_link;
            *self.slot(root_link) = Some(index);
            return;
        }

        let base = self.root.expect("已判定非空");
        let (node, exact) = self.node_placement(ip, cidr);
        if exact {
            let index = node.expect("exact 必伴随 parent");
            self.nodes[index].peer = Some(peer);
            return;
        }

        let new_index = self.new_node(ip, cidr, Some(peer));

        let down = match node {
            None => Some(base),
            Some(index) => {
                let bit = self.nodes[index].choose(ip);
                match self.nodes[index].children[bit] {
                    Some(child) => Some(child),
                    None => {
                        self.nodes[new_index].parent = (Some(index), bit);
                        self.nodes[index].children[bit] = Some(new_index);
                        return;
                    }
                }
            }
        };

        let down_index = down.expect("非空树必有下行节点");
        let mut cidr = cidr;
        let common = super::common_bits(&self.nodes[down_index].bits, ip);
        if common < cidr {
            cidr = common;
        }
        let parent = node;

        // 对照参考：`newNode.cidr` **保持构造时的原始 cidr**（不因 common 收缩而改写），
        // `newNode.bits` 也只在构造时掩码一次；下面用收缩后的 `cidr` 与它比较。
        // 若在此把 newNode.cidr 改成收缩值，等于分支判定即被破坏。
        if self.nodes[new_index].cidr == cidr {
            // newNode 与 down 同前缀长：newNode 成为 down 的父节点。
            let bit = self.nodes[new_index].choose(&self.nodes[down_index].bits);
            self.nodes[down_index].parent = (Some(new_index), bit);
            self.nodes[new_index].children[bit] = Some(down_index);
            self.attach_to_parent(new_index, parent);
            return;
        }

        // 需要插入中间节点：以 (newNode.bits, 收缩后的 cidr) 生成路径节点。
        let mid_bits = self.nodes[new_index].bits.clone();
        let mid_index = self.new_node(&mid_bits, cidr, None);
        let down_bit = self.nodes[mid_index].choose(&self.nodes[down_index].bits);
        self.nodes[down_index].parent = (Some(mid_index), down_bit);
        self.nodes[mid_index].children[down_bit] = Some(down_index);
        let new_bit = self.nodes[mid_index].choose(&self.nodes[new_index].bits);
        self.nodes[new_index].parent = (Some(mid_index), new_bit);
        self.nodes[mid_index].children[new_bit] = Some(new_index);
        self.attach_to_parent(mid_index, parent);
    }

    /// 对照 `lookup`：最长前缀匹配。
    pub(super) fn lookup(&self, ip: &[u8]) -> Option<usize> {
        let mut found = None;
        let mut node = self.root;
        while let Some(index) = node {
            let current = &self.nodes[index];
            if super::common_bits(&current.bits, ip) < current.cidr {
                break;
            }
            if let Some(peer) = current.peer {
                found = Some(peer);
            }
            // 对照 `lookup`：节点前缀已用满整串（bitAtByte == size）时不再下行，
            // 否则 `choose` 会越界读取 ip。这正是 /32、/128 精确匹配的终止条件。
            if current.bit_at_byte == ip.len() {
                break;
            }
            let child = current.children[current.choose(ip)];
            node = child;
        }
        found
    }
}
