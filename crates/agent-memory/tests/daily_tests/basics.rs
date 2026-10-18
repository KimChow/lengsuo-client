//! daily 基础语义：追加、尾部读取、清理、自动建链、性能锚（规格 §5.4 / §3 / §5.7 / §5.9）。

use std::path::Path;
use std::time::Instant;

use agent_memory::{append_daily, clear_daily};

use crate::{TempDir, OTHER_DAY, TODAY, TOMORROW};

/// §5.4：自动建目录/文件、追加不覆盖、两次追加顺序保持（append 自动补换行）。
#[test]
fn append_daily_creates_dirs_and_appends_in_order() {
    let tmp = TempDir::new("append-order");
    assert!(!tmp.daily_file(TODAY).exists(), "前置：当日文件不存在");

    append_daily(&tmp.paths(), TODAY, "第一行摘要").expect("首次追加应成功");
    assert!(
        tmp.memory_dir().is_dir(),
        "应自动创建 <workspace>/.lengsuo/memory"
    );
    assert_eq!(tmp.raw(TODAY), "第一行摘要\n");

    append_daily(&tmp.paths(), TODAY, "第二行摘要").expect("二次追加应成功");
    let content = tmp.raw(TODAY);
    assert_eq!(content, "第一行摘要\n第二行摘要\n", "追加不得覆盖既有内容");
    assert_eq!(
        content.lines().collect::<Vec<_>>(),
        ["第一行摘要", "第二行摘要"],
        "顺序须与写入顺序一致"
    );
}

/// §5.4：日期隔离——不同 date 落不同文件；未写的日期读为 None（只读「当日」文件）。
#[test]
fn append_daily_isolates_by_date() {
    let tmp = TempDir::new("append-date");

    append_daily(&tmp.paths(), TODAY, "今天的日志").unwrap();
    append_daily(&tmp.paths(), TOMORROW, "明天的日志").unwrap();

    assert_eq!(tmp.raw(TODAY), "今天的日志\n");
    assert_eq!(tmp.raw(TOMORROW), "明天的日志\n");
    assert_eq!(tmp.tail(TODAY, 10).unwrap(), "今天的日志");
    assert_eq!(tmp.tail(TOMORROW, 10).unwrap(), "明天的日志");
    assert_eq!(tmp.tail(OTHER_DAY, 10), None, "未写过的日期 ⇒ None");
}

/// §3：read_daily_tail 只取尾部 ≤max_lines 行并保持原行序。
#[test]
fn read_daily_tail_returns_last_lines_in_order() {
    let tmp = TempDir::new("tail-order");
    for i in 1..=5 {
        append_daily(&tmp.paths(), TODAY, &format!("行 {i}")).unwrap();
    }

    assert_eq!(tmp.tail(TODAY, 2).unwrap(), "行 4\n行 5");
    assert_eq!(
        tmp.tail(TODAY, 99).unwrap(),
        "行 1\n行 2\n行 3\n行 4\n行 5",
        "max_lines 超行数 ⇒ 全文"
    );
    assert_eq!(tmp.tail(TODAY, 0).unwrap(), "", "max_lines=0 ⇒ 空文本");

    // 用户可直接改文件（规格 §1）：无结尾换行时仍取满尾部行。
    tmp.write_raw(TODAY, "a\nb\nc");
    assert_eq!(tmp.tail(TODAY, 2).unwrap(), "b\nc");
}

/// §3 边界：CRLF 行的行终止符按 `lines()` 语义处理；存在但为空的文件 ⇒ Some("")（非 None）。
#[test]
fn read_daily_tail_handles_crlf_and_empty_file() {
    let tmp = TempDir::new("tail-edge");
    tmp.write_raw(TODAY, "甲\r\n乙\r\n丙\r\n");
    assert_eq!(
        tmp.tail(TODAY, 2).unwrap().lines().collect::<Vec<_>>(),
        ["乙", "丙"],
        "CRLF 仍按两行尾部读取"
    );

    // 空文件 ≠ 缺失文件：路径存在即返回 Some（缺失才是 None，规格 §3）。
    tmp.write_raw(TODAY, "");
    assert_eq!(tmp.tail(TODAY, 200), Some(String::new()));
}

/// §5.7：clear_daily 删除后读取变 None；不存在视为成功（幂等）；不误删其他日期。
#[test]
fn clear_daily_makes_tail_none_and_is_idempotent() {
    let tmp = TempDir::new("clear");
    append_daily(&tmp.paths(), TODAY, "待清除").unwrap();
    append_daily(&tmp.paths(), TOMORROW, "另一天").unwrap();
    assert!(tmp.tail(TODAY, 10).is_some());

    clear_daily(&tmp.paths(), TODAY).expect("删除应成功");
    assert!(!tmp.daily_file(TODAY).exists());
    assert_eq!(tmp.tail(TODAY, 10), None, "§5.7：删除后对应层为 None");
    assert!(tmp.tail(TOMORROW, 10).is_some(), "其他日期不受影响");

    clear_daily(&tmp.paths(), TODAY).expect("文件不存在视为成功");
    clear_daily(&tmp.paths(), OTHER_DAY).expect("目录也不存在时同样视为已清空");
}

/// workspace 尚未创建（合法路径、无逃逸）⇒ 自动补齐整条目录链。
#[test]
fn append_creates_missing_workspace_chain() {
    let tmp = TempDir::new("missing-ws");
    let paths = tmp.paths();
    assert!(!Path::new(&paths.workspace).exists());
    append_daily(&paths, TODAY, "首次会话写入").expect("应自动补齐 workspace 链");
    assert!(tmp.daily_file(TODAY).exists());
}

/// §5.9 性能锚：1000 行日志取尾部 200 行 < 10ms。
///
/// 规格明写「标注不强制 CI」：测量与打印始终执行，阈值断言只在非 CI 下生效，
/// 避免慢盘/负载抖动把基线卡成随机红。
#[test]
fn perf_anchor_tail_of_1000_lines_under_10ms() {
    let tmp = TempDir::new("perf");
    let mut blob = String::with_capacity(110 * 1000);
    for i in 1..=1000 {
        blob.push_str(&format!("第 {i} 行日志摘要内容\n"));
    }
    tmp.write_raw(TODAY, &blob);

    let mut best = u128::MAX;
    for _ in 0..5 {
        let started = Instant::now();
        let tail = tmp.tail(TODAY, 200).unwrap();
        best = best.min(started.elapsed().as_micros());
        assert_eq!(tail.lines().count(), 200, "必须正好取到尾部 200 行");
        assert_eq!(tail.lines().next().unwrap(), "第 801 行日志摘要内容");
        assert_eq!(tail.lines().last().unwrap(), "第 1000 行日志摘要内容");
    }
    let budget = std::time::Duration::from_millis(10).as_micros();
    println!("1000 行日志 tail(200) 最快一次: {best} µs（预算 {budget} µs）");
    if std::env::var_os("CI").is_none() {
        assert!(best < budget, "§5.9 性能锚：{best} µs 超过 10ms 预算");
    } else {
        println!("CI 环境：性能锚仅打印不断言（规格 §5.9）");
    }
}
