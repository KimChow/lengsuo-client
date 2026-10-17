#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最小 MCP 测试夹具服务端（agent-mcp 集成测试专用，不是产品代码）。

用法：python3 mcp_fixture_server.py [line|lsp]

- line：行分隔 JSON（一行一个 JSON-RPC 消息）
- lsp ：Content-Length: N\r\n\r\n{body} 分帧

每个请求在独立线程里处理，所以响应可以乱序返回，用于验证客户端的 id 关联。
`initialize` 与退出类方法在主线程内联处理，其余派发到线程。
stdin EOF 时进程退出（避免遗留睡眠进程）。

内置测试钩子方法（仅用于驱动异常路径，产品代码不会调用）：
  test/slow                params {"ms": n}      延迟 n 毫秒后正常响应
  test/hang                永不响应               触发客户端超时
  test/hang_then_respond   延迟 300ms 后响应       触发超时后的迟到响应
  test/bad_message_then_ok 先吐合法 JSON 但非 JSON-RPC 形状的消息与空行，
                                                  再正常响应（不得 poison）
  test/bad_frame           吐 JSON 语法错误 / 非法头
                                                  （帧级损坏，必须 poison）
  test/notify              连发 3 条服务端通知后响应
  test/server_request      发一条服务端→客户端请求后响应
  test/exit                不响应直接退出进程（意外退出路径）
  test/truncated           只写半行就退出（EOF 截断帧）
  test/echo_index          按 (10 - index) 反向延迟，回显 index（并发不串测试）
"""

import json
import os
import sys
import threading
import time

# Test-only lifecycle evidence; never reads production data.
if os.environ.get("LENGSUO_TEST_PID_FILE"):
    with open(os.environ["LENGSUO_TEST_PID_FILE"], "w", encoding="ascii") as pid_file:
        pid_file.write(str(os.getpid()))

FRAMING = (sys.argv[1] if len(sys.argv) > 1 else "line").lower()
SUPPORTED_PROTOCOLS = ["2025-06-18", "2024-11-05"]

STDIN_FD = 0
STDOUT_FD = 1
OUT_LOCK = threading.Lock()
STOP = threading.Event()

INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INTERNAL_ERROR = -32603

TOOLS = [
    {
        "name": "echo",
        "description": "回显输入文本",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "add",
        "description": "两数求和",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
            "required": ["a", "b"],
        },
    },
    {
        "name": "boom",
        "description": "总是返回 JSON-RPC 错误",
        "inputSchema": {"type": "object"},
    },
]


def write_raw(raw):
    """整帧一次写入（持锁），避免多线程把一帧字节拆开交叉。"""
    with OUT_LOCK:
        if STOP.is_set():
            return
        try:
            os.write(STDOUT_FD, raw)
        except OSError:
            STOP.set()


def encode(obj):
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if FRAMING == "lsp":
        return b"Content-Length: " + str(len(data)).encode("ascii") + b"\r\n\r\n" + data
    return data + b"\n"


def send(obj):
    write_raw(encode(obj))


def respond(msg_id, result=None, error=None):
    if error is not None:
        send({"jsonrpc": "2.0", "id": msg_id, "error": error})
    else:
        send({"jsonrpc": "2.0", "id": msg_id, "result": {} if result is None else result})


def error_obj(code, message, data=None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return err


def handle_initialize(msg_id, params):
    requested = (params or {}).get("protocolVersion", "")
    negotiated = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
    echo_capabilities = (params or {}).get("capabilities") or {}
    respond(
        msg_id,
        {
            "protocolVersion": negotiated,
            "capabilities": {
                "tools": {"listChanged": True},
                "experimental": {"lengsuo.test/echo": echo_capabilities},
            },
            "serverInfo": {"name": "agent-mcp-fixture", "version": "0.1.0", "vendor": "lengsuo"},
            "instructions": "测试夹具，仅用于协议验证。",
        },
    )


def handle_tools_call(msg_id, params):
    name = (params or {}).get("name")
    args = (params or {}).get("arguments") or {}
    if name == "echo":
        respond(msg_id, {"content": [{"type": "text", "text": str(args.get("text", ""))}], "isError": False})
    elif name == "add":
        respond(msg_id, {"content": [{"type": "text", "text": str(int(args["a"]) + int(args["b"]))}], "isError": False})
    elif name == "boom":
        respond(msg_id, error=error_obj(INTERNAL_ERROR, "tool execution failed", {"tool": name}))
    else:
        # MCP 语义：工具自身失败放在 result.isError，而不是 JSON-RPC error。
        respond(msg_id, {"content": [{"type": "text", "text": "unknown tool: %s" % name}], "isError": True})


def handle_hook(msg_id, method, params):
    if method == "test/oversized":
        write_raw(encode({"jsonrpc": "2.0", "id": msg_id, "result": "x" * 4096}))
    elif method == "test/slow":
        ms = (params or {}).get("ms", 50)
        time.sleep(float(ms) / 1000.0)
        respond(msg_id, {"ms": ms})
    elif method == "test/hang":
        time.sleep(3600)
    elif method == "test/hang_then_respond":
        time.sleep(0.3)
        respond(msg_id, {"late": True})
    elif method == "test/bad_message_then_ok":
        # JSON 合法但不是 JSON-RPC 2.0 消息：客户端应忽略并继续，不 poison。
        write_raw(b'{"hello":"world"}\n')
        write_raw(b"[]\n")
        write_raw(b"null\n")
        write_raw(b'{"jsonrpc":"2.0"}\n')
        write_raw(b'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}\n')
        write_raw(b"\n")
        write_raw(b"   \n")
        respond(msg_id, {"ok": True})
    elif method == "test/bad_frame":
        if FRAMING == "lsp":
            write_raw(b"Content-Length: not-a-number\r\n\r\n")
        else:
            write_raw(b"{not-json}\n")
        time.sleep(3600)
    elif method == "test/notify":
        for i in range(3):
            send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/message",
                    "params": {"level": "info", "seq": i, "logger": "fixture"},
                }
            )
        respond(msg_id, {"notifications": 3})
    elif method == "test/server_request":
        send({"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": {"messages": []}})
        respond(msg_id, {"sent_server_request": True})
    elif method == "test/exit":
        # 意外退出：不写任何响应。
        STOP.set()
        os._exit(0)
    elif method == "test/truncated":
        write_raw(b'{"jsonrpc":"2.0","id":7,"result":{"trunc":')
        STOP.set()
        os._exit(0)
    elif method == "test/echo_index":
        index = int((params or {}).get("index", 0))
        # 反向延迟：后发先至，检验 id 关联而不是顺序假设。
        time.sleep(0.02 * (10 - index))
        respond(msg_id, {"index": index, "echo": (params or {}).get("token")})
    else:
        respond(msg_id, error=error_obj(METHOD_NOT_FOUND, "unknown hook: %s" % method))


def handle(msg):
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        if isinstance(msg, dict) and msg.get("id") is not None:
            respond(msg.get("id"), error=error_obj(INVALID_REQUEST, "missing jsonrpc 2.0"))
        return
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params")
    if msg_id is None:
        # 通知：按规范不响应。
        if method in ("exit",):
            STOP.set()
            os._exit(0)
        return
    if method == "initialize":
        handle_initialize(msg_id, params)
    elif method == "ping":
        respond(msg_id, {})
    elif method == "shutdown":
        respond(msg_id, {})
        STOP.set()
        os._exit(0)
    elif method == "tools/list":
        cursor = (params or {}).get("cursor")
        payload = {"tools": TOOLS}
        if cursor is None:
            payload["nextCursor"] = "page2"
        respond(msg_id, payload)
    elif method == "tools/call":
        handle_tools_call(msg_id, params)
    elif isinstance(method, str) and method.startswith("test/"):
        handle_hook(msg_id, method, params)
    else:
        respond(msg_id, error=error_obj(METHOD_NOT_FOUND, "method not found: %s" % method))


def dispatch(msg):
    method = msg.get("method") if isinstance(msg, dict) else None
    main_thread = method == "initialize" or (
        isinstance(method, str) and method in ("test/exit", "test/truncated", "shutdown")
    )
    if main_thread:
        handle(msg)
        return
    threading.Thread(target=handle, args=(msg,), daemon=True).start()


def read_lsp(fd):
    """按 Content-Length 头分帧读取；返回 (kind, value)。"""
    buf = b""
    while not STOP.is_set():
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk
        while True:
            sep = buf.find(b"\r\n\r\n")
            if sep < 0:
                break
            header = buf[:sep].decode("latin-1")
            length = None
            malformed = False
            for line in header.split("\r\n"):
                if not line:
                    continue
                if ":" not in line:
                    malformed = True
                    continue
                key, value = line.split(":", 1)
                if key.strip().lower() == "content-length":
                    try:
                        length = int(value.strip())
                    except ValueError:
                        malformed = True
            if malformed or length is None:
                # 夹具自身不产生非法头；出现即视为同步丢失，退出。
                STOP.set()
                return
            if len(buf) < sep + 4 + length:
                break
            body = buf[sep + 4 : sep + 4 + length]
            buf = buf[sep + 4 + length :]
            try:
                yield ("msg", json.loads(body.decode("utf-8")))
            except Exception:
                yield ("garbage", body)


def read_line(fd):
    """按行分帧读取。"""
    buf = b""
    while not STOP.is_set():
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return
        if not chunk:
            return
        buf += chunk
        while True:
            idx = buf.find(b"\n")
            if idx < 0:
                break
            line = buf[:idx]
            buf = buf[idx + 1 :]
            line = line.strip()
            if not line:
                continue
            try:
                yield ("msg", json.loads(line.decode("utf-8")))
            except Exception:
                yield ("garbage", line)


def main():
    reader = read_lsp(STDIN_FD) if FRAMING == "lsp" else read_line(STDIN_FD)
    for kind, value in reader:
        if STOP.is_set():
            return
        if kind == "garbage":
            continue
        dispatch(value)
    # stdin EOF：结束读取并退出。EOF 前所有响应都已逐帧 flush，不丢数据。
    STOP.set()


if __name__ == "__main__":
    main()
