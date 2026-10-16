// Windows wintun 设备回环验证（需要管理员权限运行）。
// 用法: 先以 unsafe { wintun::load_from_path(dll) } 拿到 Library，再创建适配器
// 并做 send/receive 回环。此处为手动驱动脚本说明，实机验证步骤：
// 1. 管理员 PowerShell: cargo test -p lengsuo-tun --locked --test device_windows -- --ignored --nocapture
// 2. 需 LENGSUO_WINTUN_DLL 指向 wintun/bin/amd64/wintun.dll
fn main() {
    println!("see tests/device_windows.rs");
}
