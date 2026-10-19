#!/usr/bin/env python3
"""派卡守卫：让多条开发线并行而不抢同一块代码。

（lengsuo-network 版本，规则与 lengsuo-agent 同源；派卡根 `~/lengsuo-network-dev`。）

调度模型：一个「窗口」= 一条 lane。窗口之间并行，窗口内可挂多张卡，
只要 `touches` 互不重叠。防冲突靠**路径边界 + 原子认领**，不靠限制并发数。

任务单 `tasks/<task>.json`：

    {
      "worktree": "/abs/path/worktrees/<task>",
      "base": "origin/main",
      "slot": 0,
      "lane": "proto",
      "touches": ["crates/lengsuo-vmess"],
      "depends_on": ["other-task"]
    }

状态机：

    pending → claimed → running → verifying → merging → merged
                         ↓          ↓
                       failed    failed（越界/验后又改）

命令：lanes | status | check | claim | release | verify | merge | merged
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from card_ledger import Ledger, LedgerError  # noqa: E402
from card_merge import integrate  # noqa: E402
from card_rules import (  # noqa: E402
    BUSY,
    LANES,
    REPO,
    ROOT,
    SHARED_PATHS,
    collect_errors,
    commit_in_main,
    git,
    normalize,
    overlaps,
    scope_of,
    within,
    worktree_fingerprint,
)


# ---------------- 命令实现 ----------------


def fail(msg: str, details: list[str] | None = None) -> int:
    print(f"✗ {msg}")
    for line in details or []:
        print(f"    {line}")
    return 1


def spec_of(led: Ledger, task: str) -> dict | None:
    return led.tasks().get(task)


def cmd_check(task: str) -> int:
    led = Ledger(ROOT)
    spec = spec_of(led, task)
    if spec is None:
        return fail(f"找不到任务单 tasks/{task}.json")
    errs = collect_errors(task, spec, led)
    if errs:
        return fail(f"{task} 不能派卡：", errs)
    print(f"✓ {task} 可以派卡（lane={spec.get('lane')}）")
    return 0


def cmd_claim(task: str) -> int:
    led = Ledger(ROOT)
    with led.lock():
        spec = spec_of(led, task)
        if spec is None:
            return fail(f"找不到任务单 tasks/{task}.json")

        st = led.state_of(task)
        if st in BUSY:
            return fail(f"{task} 已被占用（state={st}）")

        errs = collect_errors(task, spec, led)
        if errs:
            return fail(f"{task} 不能派卡：", errs)

        led.update(task, state="claimed", lane=spec.get("lane"), claimed_at=time.time())
    print(f"✓ {task} 已认领（lane={spec.get('lane')}）")
    return 0


def cmd_release(task: str, force: bool = False) -> int:
    led = Ledger(ROOT)
    with led.lock():
        if spec_of(led, task) is None:
            return fail(f"找不到任务单 tasks/{task}.json")
        st = led.state_of(task)
        if st == "merging" and not force:
            return fail(f"{task} 正在合流，拒绝释放（确需放弃请加 --force）")
        led.update(task, state="pending")
    print(f"✓ {task} 已释放")
    return 0


def cmd_verify(task: str) -> int:
    """校验改动是否越界。任何 git 失败都按失败处理。"""
    led = Ledger(ROOT)
    spec = spec_of(led, task)
    if spec is None:
        return fail(f"找不到任务单 tasks/{task}.json")

    wt = Path(spec.get("worktree", ""))
    base = spec.get("base", "origin/main")
    if not wt.is_dir():
        return fail(f"worktree 不存在：{wt}")

    try:
        scope = scope_of(spec)
        head = git(wt, "rev-parse", "HEAD").strip()
        changed: set[str] = set()
        for line in git(wt, "diff", "--name-only", f"{base}...").splitlines():
            if line.strip():
                changed.add(normalize(line))
        for line in git(wt, "diff", "--name-only", "HEAD").splitlines():
            if line.strip():
                changed.add(normalize(line))
        for line in git(wt, "ls-files", "--others", "--exclude-standard").splitlines():
            if line.strip():
                changed.add(normalize(line))
    except (LedgerError, ValueError) as e:
        with led.lock():
            led.update(task, state="failed", reason=f"verify 出错：{e}")
        return fail(f"{task} 验收无法完成（按失败处理）：{e}")

    fp = worktree_fingerprint(wt, head)
    outside = sorted(p for p in changed if not any(within(p, t) for t in scope))
    if outside:
        with led.lock():
            # 必须显式置 failed，否则旧的 verifying 会残留，越界产物仍可合流
            led.update(task, state="failed", reason="touches 越界")
        return fail(f"{task} 越界改动 {len(outside)}/{len(changed)} 个文件：", outside[:20])

    with led.lock():
        led.update(task, state="verifying", verified_sha=head, verified_fp=fp, verified_at=time.time())
    print(f"✓ {task} 改动在范围内（{len(changed)} 文件，绑定 {head[:8]}）")
    return 0


def cmd_merge(task: str) -> int:
    """串行集成：候选合并 + 门禁 + 快进 main。

    真正的合并在 `card_merge.integrate` 里做（独立集成锁覆盖全流程，
    失败保留候选 worktree 与日志，占用不释放，等人工处理）。
    """
    led = Ledger(ROOT)
    if spec_of(led, task) is None:
        return fail(f"找不到任务单 tasks/{task}.json")

    result = integrate(led, task)
    for line in result.get("gate_evidence", []):
        print(f"    {line}")
    if result.get("ok"):
        print(f"✓ {task} 已合入 main（{str(result.get('merge_sha'))[:8]}）")
        return 0
    return fail(
        f"{task} 集成失败（state={result.get('state')}，占用保留）：{result.get('reason')}"
    )


def cmd_mark_merged(task: str) -> int:
    """已手工合并时使用：校验提交确实在 main 历史里，再标记 merged。"""
    led = Ledger(ROOT)
    with led.lock():
        spec = spec_of(led, task)
        if spec is None:
            return fail(f"找不到任务单 tasks/{task}.json")
        wt = Path(spec.get("worktree", ""))
        try:
            head = git(wt, "rev-parse", "HEAD").strip()
        except LedgerError as e:
            return fail(f"{task} 读取 HEAD 失败：{e}")
        if not commit_in_main(head):
            return fail(f"{task} 的提交 {head[:8]} 不在 main 历史里，不能标记为已合入")
        led.update(task, state="merged", head=head)
    print(f"✓ {task} 标记为已合入（{head[:8]} 已在 main）")
    return 0


def cmd_status() -> int:
    led = Ledger(ROOT)
    tasks, states = led.tasks(strict=False), led.states(strict=False)
    if not tasks:
        print("（暂无任务单）")
        return 0

    by_lane: dict[str, list[str]] = {}
    for name, spec in tasks.items():
        by_lane.setdefault(spec.get("lane", "<无 lane>"), []).append(name)

    mark = {
        "claimed": "◐ 已认领",
        "running": "▶ 跑",
        "verifying": "… 待合",
        "merging": "⇄ 合流中",
        "merged": "✓ 已合入",
        "failed": "✗ 失败",
    }
    print(f"{'lane':<9} {'卡':<22} {'状态':<10} touches")
    print("-" * 92)
    for lane in sorted(by_lane):
        for name in sorted(by_lane[lane]):
            st = states.get(name, {}).get("state", "pending")
            touches = ",".join(tasks[name].get("touches", []))[:38]
            print(f"{lane:<9} {name:<22} {mark.get(st, '· 待跑'):<10} {touches}")

    busy = [n for n, s in states.items() if s.get("state") in BUSY]
    print(f"\n占用 {len(busy)} 张：{', '.join(busy) if busy else '无'}")
    print(f"共 {len(tasks)} 张卡，{len(by_lane)} 条 lane")
    return 0


def cmd_lanes() -> int:
    print("建议 lane 划分：\n")
    for lane, crates in LANES.items():
        print(f"  {lane:<8} {', '.join(crates)}")
    print("\n共享禁区（普通卡不得改，需单开基建卡独占）：")
    for p in SHARED_PATHS:
        print(f"  {p}")
    print("\n同一 crate 并行多卡时，touches 请精确到子目录，")
    print("例如 crates/lengsuo-tun/src/dns 与 crates/lengsuo-tun/src/tcp。")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 0
    cmd = sys.argv[1]
    if cmd == "status":
        return cmd_status()
    if cmd == "lanes":
        return cmd_lanes()

    handlers = {
        "check": cmd_check,
        "claim": cmd_claim,
        "release": cmd_release,
        "verify": cmd_verify,
        "merge": cmd_merge,
        "merged": cmd_mark_merged,
    }
    if cmd not in handlers:
        return fail(f"未知命令：{cmd}")
    if len(sys.argv) < 3:
        return fail(f"用法：card_guard.py {cmd} <task>")
    if cmd == "release" and "--force" in sys.argv:
        return cmd_release(sys.argv[2], force=True)
    return handlers[cmd](sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
