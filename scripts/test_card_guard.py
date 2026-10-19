#!/usr/bin/env python3
"""card_guard 回归测试：在隔离的临时目录里跑，不碰真实派卡数据。

    python3 scripts/test_card_guard.py

覆盖的失败模式（每条都对应一个曾经的真实缺陷）：
1. 五张互不重叠的卡可同时认领（多窗口并行）
2. 路径重叠必须拒绝（含父子目录）
3. `..` 与绝对路径必须拒绝（防用别名绕开边界）
4. 越界改动 → state=failed，且**不残留 verifying**
5. 验收后又改代码 → 拒绝合流（SHA 绑定）
6. 两张待合卡不互相阻塞（互锁回归）
7. 提交不在 main 里 → 不允许标记 merged
8. 台账 JSON 损坏 → 报错而非当作未占用
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

GUARD = Path(__file__).resolve().parent / "card_guard.py"
PASS, FAILED = [], []


def run(root: Path, *args: str) -> tuple[int, str]:
    env = dict(os.environ, LENGSUO_DEV_ROOT=str(root))
    r = subprocess.run(
        [sys.executable, str(GUARD), *args], capture_output=True, text=True, env=env
    )
    return r.returncode, (r.stdout + r.stderr)


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASS.append(name)
        print(f"  ✓ {name}")
    else:
        FAILED.append(f"{name}: {detail}")
        print(f"  ✗ {name}  {detail}")


def make_card(root: Path, name: str, touches: list[str], lane: str = "core", deps=None):
    spec = {
        "worktree": str(root / "worktrees" / name),
        "base": "origin/main",
        "slot": 0,
        "lane": lane,
        "touches": touches,
        "depends_on": deps or [],
    }
    (root / "tasks").mkdir(parents=True, exist_ok=True)
    (root / "tasks" / f"{name}.json").write_text(json.dumps(spec))


def state_of(root: Path, name: str) -> str | None:
    p = root / "state" / f"{name}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text()).get("state")
    except ValueError:
        return "<bad-json>"


def build_repo(root: Path) -> None:
    """造一个最小仓库，含 origin/main 引用，供 commit_in_main 使用。"""
    repo = root / "repo"
    repo.mkdir(parents=True)
    g = lambda *a: subprocess.run(  # noqa: E731
        ["git", "-C", str(repo), *a], capture_output=True, check=True
    )
    g("init", "-b", "main")
    g("config", "user.email", "t@t")
    g("config", "user.name", "t")
    (repo / "README.md").write_text("x\n")
    g("add", ".")
    g("commit", "-m", "init")
    g("update-ref", "refs/remotes/origin/main", "HEAD")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="cg-test-"))
    root = tmp
    try:
        build_repo(root)
        print("\n[1] 五张互不重叠的卡可同时认领")
        for i, p in enumerate(
            ["loop", "permission", "bus", "schema", "config"], start=1
        ):
            make_card(root, f"w{i}", [f"crates/lengsuo-tun/src/{p}"], lane=f"l{i}")
            rc, out = run(root, "claim", f"w{i}")
            check(f"w{i} 认领", rc == 0, out.strip())

        print("\n[2] 路径重叠必须拒绝")
        make_card(root, "dup", ["crates/lengsuo-tun/src/loop/sub"], lane="lx")
        rc, out = run(root, "claim", "dup")
        check("父目录重叠被拒", rc != 0, out.strip())

        print("\n[3] `..` 与绝对路径必须拒绝")
        make_card(root, "escape1", ["crates/../etc"], lane="ly")
        rc, out = run(root, "claim", "escape1")
        check("`..` 被拒", rc != 0, out.strip())
        make_card(root, "escape2", ["/etc/passwd"], lane="lz")
        rc, out = run(root, "claim", "escape2")
        check("绝对路径被拒", rc != 0, out.strip())

        print("\n[4] 越界改动 → failed，且不残留 verifying")
        wt = root / "worktrees" / "w1"
        wt.mkdir(parents=True)
        subprocess.run(["git", "-C", str(root / "repo"), "worktree", "add",
                        str(wt), "-b", "t/w1"], capture_output=True, check=False)
        (wt / "crates" / "lengsuo-tun" / "src" / "loop").mkdir(parents=True, exist_ok=True)
        (wt / "crates" / "lengsuo-tun" / "src" / "loop" / "ok.rs").write_text("ok\n")
        (wt / "OUTSIDE.txt").write_text("bad\n")
        rc, out = run(root, "verify", "w1")
        check("越界被拦", rc != 0, out.strip())
        check("状态为 failed", state_of(root, "w1") == "failed", str(state_of(root, "w1")))

        print("\n[5] 验收后又改代码 → 拒绝合流")
        (wt / "OUTSIDE.txt").unlink()
        rc, _ = run(root, "verify", "w1")
        check("清理后 verify 通过", rc == 0)
        before = state_of(root, "w1")
        (wt / "crates" / "lengsuo-tun" / "src" / "loop" / "ok.rs").write_text("changed\n")
        subprocess.run(["git", "-C", str(wt), "add", "-A"], capture_output=True)
        rc, out = run(root, "merge", "w1")
        check("验后又改被拒", rc != 0, out.strip())
        check("verify 后状态是 verifying", before == "verifying", str(before))

        print("\n[6] 两张待合卡不互相阻塞")
        make_card(root, "w2b", ["crates/lengsuo-tun/src/zzz"], lane="lzz")
        run(root, "claim", "w2b")
        wt2 = root / "worktrees" / "w2b"
        wt2.mkdir(parents=True)
        subprocess.run(["git", "-C", str(root / "repo"), "worktree", "add",
                        str(wt2), "-b", "t/w2b"], capture_output=True, check=False)
        run(root, "verify", "w2b")
        check("w2b 到 verifying", state_of(root, "w2b") == "verifying", str(state_of(root, "w2b")))
        # w1 仍因 SHA 不符被拒，但错误不应是"其他卡在合流"
        rc, out = run(root, "merge", "w1")
        check("不是互锁导致", "已有卡在合流" not in out, out.strip())

        print("\n[7] 提交不在 main → 不允许标记 merged")
        # 必须造一个真实提交：worktree 的 HEAD 若等于 main，本来就"已在 main"，
        # 那样测的是测试自身的错，不是产品行为。
        (wt2 / "crates" / "lengsuo-tun" / "src" / "zzz").mkdir(parents=True, exist_ok=True)
        (wt2 / "crates" / "lengsuo-tun" / "src" / "zzz" / "new.rs").write_text("x\n")
        subprocess.run(["git", "-C", str(wt2), "add", "-A"], capture_output=True)
        subprocess.run(
            ["git", "-C", str(wt2), "-c", "user.email=t@t", "-c", "user.name=t",
             "commit", "-m", "w2b change"],
            capture_output=True,
        )
        rc, out = run(root, "merged", "w2b")
        check("未合入被拒", rc != 0, out.strip())

        print("\n[8] 台账损坏 → 报错而非当未占用")
        bad = root / "state" / "broken.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("{not json")
        make_card(root, "broken", ["crates/agent-only/x"], lane="lb")
        rc, out = run(root, "claim", "broken")
        check("坏台账使 claim 失败", rc != 0, out.strip())

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'=' * 50}\n通过 {len(PASS)}，失败 {len(FAILED)}")
    for f in FAILED:
        print(f"  ✗ {f}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    sys.exit(main())
