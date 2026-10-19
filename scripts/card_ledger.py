#!/usr/bin/env python3
"""派卡台账：状态存储、跨进程锁、原子读写。

被 `card_guard.py` 使用，单独拆出是为了让"状态是否可靠"这件事只有一处实现。

三条硬要求：
1. **原子写**：先写临时文件再 `os.replace`，避免进程被杀时留下半截 JSON。
2. **严格读**：JSON 损坏一律抛错，不能"跳过当未占用"——那会让冲突卡溜进来。
3. **跨平台锁**：Linux 用 flock；Windows 没有 fcntl，退化为 `O_EXCL` 目录锁。
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


class LedgerError(RuntimeError):
    """台账读写出错：必须让调用方 fail-closed，不能静默继续。"""


def atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
    os.replace(tmp, path)


def read_json_strict(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise LedgerError(f"台账文件损坏或不可读：{path}（{e}）") from e


class _DirLock:
    """Windows 退化锁：独占创建目录，天然原子。"""

    def __init__(self, path: Path, timeout: float = 30.0):
        self.path = path
        self.timeout = timeout

    def __enter__(self):
        deadline = time.time() + self.timeout
        while True:
            try:
                self.path.mkdir()
                return self
            except FileExistsError:
                if time.time() > deadline:
                    raise LedgerError(f"等待台账锁超时：{self.path}")
                time.sleep(0.05)

    def __exit__(self, *exc):
        try:
            self.path.rmdir()
        except OSError:
            pass
        return False


class _FlockLock:
    """POSIX 锁：flock 在进程被杀死时由内核自动释放，不会留死锁。"""

    def __init__(self, path: Path):
        self.path = path

    def __enter__(self):
        import fcntl

        self._fh = open(self.path, "w")
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        import fcntl

        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()
        return False


def acquire_lock(root: Path):
    """返回可用的跨进程排他锁。"""
    if os.name == "nt":
        return _DirLock(root / ".guard.lock.d")
    return _FlockLock(root / ".guard.lock")


class Ledger:
    def __init__(self, root: Path):
        self.root = root
        self.tasks_dir = root / "tasks"
        self.state_dir = root / "state"

    # ---- 读 ----

    def _scan(self, directory: Path, *, strict: bool) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if not directory.is_dir():
            return out
        for f in sorted(directory.glob("*.json")):
            if f.stem.endswith("-settings"):
                continue
            try:
                out[f.stem] = read_json_strict(f)
            except LedgerError:
                # 派卡目录里的坏文件必须让人看见；strict=False 时只用于展示类命令。
                if strict:
                    raise
                print(f"⚠ 跳过损坏台账：{f}")
        return out

    def tasks(self, *, strict: bool = True) -> dict[str, dict]:
        return self._scan(self.tasks_dir, strict=strict)

    def states(self, *, strict: bool = True) -> dict[str, dict]:
        return self._scan(self.state_dir, strict=strict)

    def state_of(self, task: str) -> str | None:
        p = self.state_dir / f"{task}.json"
        if not p.is_file():
            return None
        return read_json_strict(p).get("state")

    # ---- 写 ----

    def update(self, task: str, **fields) -> None:
        p = self.state_dir / f"{task}.json"
        cur: dict = {}
        if p.is_file():
            cur = read_json_strict(p)
        cur.update(fields)
        cur["updated_at"] = time.time()
        atomic_write(p, cur)

    def lock(self):
        return acquire_lock(self.root)
