//! 宿主进程 bin 入口（**极薄**）：取真实 stdio 锁 → [`entry`] 逻辑 → 退出码。
//!
//! # IO 纪律
//!
//! - **stdout 是协议通道**：除主循环写的管道帧之外一个字节都不能写
//!   （`println!` / `dbg!` 到 stdout 全禁）；
//! - 诊断一律走 stderr（[`eprintln!`]），且⛔不打印任何载荷字节
//!   （[`LoopError`] 的 Display 保证不含载荷）；
//! - 失败绝不映射成退出码 0（退出码表见 [`HostError::exit_code`]）。
//!
//! [`entry`]: lengsuo_native_host::entry
//! [`LoopError`]: lengsuo_native_host::LoopError
//! [`HostError::exit_code`]: lengsuo_native_host::HostError::exit_code

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let outcome = lengsuo_native_host::entry::parse_launch_args(std::env::args_os())
        .and_then(|origin| lengsuo_native_host::entry::run_host(&origin, &mut input, &mut output));
    match outcome {
        Ok(closed) => {
            let _ = closed; // LoopOutcome::Closed：帧边界正常关闭 ⇒ 0。
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("lengsuo-native-host: {error}");
            ExitCode::from(error.exit_code())
        }
    }
}
