#!/usr/bin/env python3
"""派卡规则：路径边界、冲突判定、越界验收、合入校验。

本文件是 lengsuo-network（网络数据面）版本，与 lengsuo-agent 的同名脚本规则一致，
只有两处差异：**派卡根目录**与 **lane 划分**（网络仓的 crate 名是 `lengsuo-*`）。

核心三条：
1. 冲突判定按**路径段**（`lengsuo-vless` 与 `lengsuo-vless-xel` 是两个目录）；
2. 验收用**单向包含**（声明 `a/b` 时改 `a/other` 属越界）；
3. 任何 git 失败都抛错，不返回空串——否则无效基线会被当成"0 文件"通过。
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

from card_ledger import Ledger, LedgerError

# 允许用环境变量指向别的派卡根（回归测试隔离用；平时不必设置）
ROOT = Path(os.environ.get("LENGSUO_DEV_ROOT") or (Path.home() / "lengsuo-network-dev"))
REPO = ROOT / "repo"

SHARED_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".github",
    "scripts",
)

# 网络仓按「协议 / 数据面 / 浏览器」三条线划 lane；lane 只用于展示与冲突提示，
# 真正的互斥靠 touches 路径段。独立仓里每个 crate 是独立目录，天然不重叠。
LANES = {
    "proto": [
        "lengsuo-vless",
        "lengsuo-vmess",
        "lengsuo-trojan",
        "lengsuo-shadowsocks",
        "lengsuo-ss2022",
        "lengsuo-hysteria",
        "lengsuo-wireguard",
        "lengsuo-anytls",
    ],
    "datapath": ["lengsuo-tun", "lengsuo-environment", "lengsuo-node"],
    "browser": [
        "lengsuo-browser-state",
        "lengsuo-browser-installer",
        "lengsuo-browser-profile",
        "lengsuo-browser-signature",
        "lengsuo-browser-package",
        "lengsuo-browser-lifecycle",
    ],
    "core": ["ss-core", "ss-client", "ss-cli", "lengsuo-tls"],
    # 跨端链路：link-core 是无 IO 的协议核心（可编移动端静态库）；
    # tunnel 是有 IO 的隧道运行时（只在 PC 端）；ipc 是本地网关客户端。
    "link": ["lengsuo-link-core", "lengsuo-tunnel", "lengsuo-ipc"],
}

# merging 也算占用：否则进入合流后别的卡能立刻占进来，合流就不再独占。
BUSY = ("claimed", "running", "verifying", "merging")


def normalize(path: str) -> str:
    """规范化路径；拒绝绝对路径与 `..`（否则能用别名绕开边界）。

    必须先判原始串再 strip 前导斜杠：先 strip 会让 `/etc` 变成 `etc`，
    绝对路径检查永远不命中（回归测试抓到过）。
    """
    raw = path.strip().replace("\\", "/")
    if not raw:
        return ""
    if raw.startswith("/") or Path(raw).is_absolute():
        raise ValueError(f"touches 必须是仓库内相对路径：{path}")
    if len(raw) > 1 and raw[1] == ":":
        raise ValueError(f"touches 不允许盘符路径：{path}")
    p = raw.strip("/")
    if any(seg == ".." for seg in p.split("/")):
        raise ValueError(f"touches 不允许包含 `..`：{path}")
    return str(Path(p).as_posix())


def overlaps(a: str, b: str) -> bool:
    """两卡是否冲突（双向）：任一方向包含即冲突。"""
    if not a or not b:
        return False
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def within(path: str, scope: str) -> bool:
    """改动是否落在授权范围内（单向）。

    单向是关键：声明 `a/b` 时改 `a/other.rs` 属越界；双向会把父目录下
    所有兄弟路径算合法，等于放宽了边界。
    """
    if not path or not scope:
        return False
    return path == scope or path.startswith(scope + "/")


def git(cwd: Path, *args: str) -> str:
    """执行 git；失败一律抛错，绝不返回空串。"""
    r = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise LedgerError(f"git {' '.join(args)} 失败：{r.stderr.strip()[:300]}")
    return r.stdout


def scope_of(spec: dict) -> list[str]:
    return [t for t in (normalize(x) for x in spec.get("touches", [])) if t]


def commit_in_main(sha: str) -> bool:
    """提交是否已在 origin/main 历史里（合入校验的硬依据）。"""
    r = subprocess.run(
        ["git", "-C", str(REPO), "merge-base", "--is-ancestor", sha, "origin/main"],
        capture_output=True,
    )
    return r.returncode == 0


def worktree_fingerprint(wt: Path, head: str) -> str:
    """工作区指纹：HEAD + 状态 + 未提交 diff + 未跟踪文件内容。

    只记 HEAD 不够：验完再改未提交内容时 HEAD 不变，仍能蒙混合流。
    """
    h = hashlib.sha256()
    h.update(head.encode())
    h.update(git(wt, "status", "--porcelain").encode())
    h.update(git(wt, "diff", "HEAD").encode())
    for rel in git(wt, "ls-files", "--others", "--exclude-standard").splitlines():
        if not rel.strip():
            continue
        f = wt / rel
        h.update(rel.encode())
        if f.is_file():
            h.update(hashlib.sha256(f.read_bytes()).hexdigest().encode())
    return h.hexdigest()


def collect_errors(task: str, spec: dict, led: Ledger) -> list[str]:
    """纯检查：返回所有阻止派卡的理由（空列表 = 可以开）。"""
    errs: list[str] = []
    tasks, states = led.tasks(), led.states()

    lane, wt = spec.get("lane"), spec.get("worktree")
    try:
        scope = scope_of(spec)
    except ValueError as e:
        return [str(e)]

    if not lane:
        errs.append("缺少 lane")
    if not scope:
        errs.append("缺少 touches（不写等于没边界）")
    if not wt:
        errs.append("缺少 worktree")

    # 共享区必须独占，唯一例外是 Cargo.lock：它只是 crate manifest 变化的派生物，
    # 不允许随 crate 走就会把「加依赖」这件事人为切成两张卡。
    # 并发安全仍然成立——两张卡同时声明 Cargo.lock 会被上面的路径重叠判定拦住。
    hits = [t for t in scope for s in SHARED_PATHS if overlaps(t, s)]
    lock_only = bool(hits) and all(overlaps(h, "Cargo.lock") for h in hits)
    if hits and len(scope) > len(hits) and not lock_only:
        errs.append(f"共享路径必须独占：{hits}；改 Cargo.toml/scripts 请单开基建卡")

    # worktree 不得复用
    for name, other in tasks.items():
        if name != task and other.get("worktree") == wt:
            errs.append(f"worktree 与 {name} 相同，每卡必须独立")

    # 与在跑的卡路径冲突
    for name, other in tasks.items():
        if name == task or states.get(name, {}).get("state") not in BUSY:
            continue
        try:
            other_scope = scope_of(other)
        except ValueError:
            continue
        for a in scope:
            for b in other_scope:
                if overlaps(a, b):
                    errs.append(f"与在跑的 {name}（lane={other.get('lane')}）冲突：{a} ⟷ {b}")

    # 依赖必须真正合进 main
    for dep in spec.get("depends_on", []):
        if dep not in tasks:
            errs.append(f"依赖 {dep} 没有任务单")
            continue
        if states.get(dep, {}).get("state") != "merged":
            errs.append(
                f"依赖 {dep} 尚未 merged（当前={states.get(dep, {}).get('state') or '未派卡'}）"
            )
            continue
        dep_head = states[dep].get("head")
        if dep_head and not commit_in_main(dep_head):
            errs.append(f"依赖 {dep} 标了 merged，但其提交 {dep_head[:8]} 不在 main 历史里")

    return errs
