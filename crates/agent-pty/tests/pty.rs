//! 波次 1 卡 4 验收测试（Linux 真伪终端）。
//!
//! 规格要求的用例：`bash -c echo` 输出断言、交互式写入回显、resize 不 panic、
//! kill 后 alive=false、replay 含历史、两会话独立、写已死会话 NotFound/AlreadyDead。
//! 所有异步等待都带超时（AGENTS.md §4）。

use std::time::Duration;

use agent_pty::{PtyConfig, PtyError, PtyManager};

/// 测试用等待上限；真 PTY 在研究机上远快于此值。
const WAIT: Duration = Duration::from_secs(20);

fn cfg(line: &str) -> PtyConfig {
    PtyConfig {
        shell: format!("bash --norc --noprofile -c {line:?}"),
        ..Default::default()
    }
}

/// 读取输出流直到累计出现 `needle`（或流关闭/超时）。
async fn read_until(
    rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    needle: &[u8],
) -> Result<Vec<u8>, ()> {
    let mut acc = Vec::new();
    loop {
        if acc.windows(needle.len()).any(|w| w == needle) {
            return Ok(acc);
        }
        let next = tokio::time::timeout(WAIT, rx.recv())
            .await
            .map_err(|_| ())?;
        match next {
            Some(chunk) => {
                acc.extend(chunk);
                assert!(acc.len() < 4_000_000, "输出无界增长");
            }
            // 流关闭后已有内容仍可能匹配；统一交给上层断言判断。
            None => return Ok(acc),
        }
    }
}

/// 收集到流关闭（子进程退出 + reader EOF）为止的全部输出。
async fn drain_until_closed(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    let mut acc = Vec::new();
    loop {
        match tokio::time::timeout(WAIT, rx.recv()).await {
            Ok(Some(chunk)) => acc.extend(chunk),
            Ok(None) => return acc,
            Err(_) => panic!("等待输出超时，输出流未正常关闭"),
        }
    }
}

/// 读 PTY 输出直到出现 `needle`，用于交互式回话（不关闭流）。
async fn pump_until(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>, needle: &[u8]) -> Vec<u8> {
    match tokio::time::timeout(WAIT, read_until(rx, needle)).await {
        Ok(Ok(acc)) => acc,
        Ok(Err(_)) => panic!("等待输出关闭超时"),
        Err(_) => panic!("等待标记 {needle:?} 超时"),
    }
}

// ---- T1：bash -c echo 的输出能从输出流读到，且流随进程退出而关闭 ----

#[tokio::test]
async fn echo_output_then_stream_closes() {
    let mut mgr = PtyManager::new();
    let id = mgr.create(cfg("echo w1-pty-hello")).await.unwrap();
    let mut rx = mgr.take_output(id).await.expect("输出流可取回");
    let out = drain_until_closed(&mut rx).await;
    assert!(
        out.windows(b"w1-pty-hello".len())
            .any(|w| w == b"w1-pty-hello"),
        "输出未含标记，实际={out:?}"
    );
    // 二次取回已被取走的流 ⇒ None（每会话仅一条输出流）。
    assert!(mgr.take_output(id).await.is_none(), "输出流不得重复取回");
}

#[tokio::test]
async fn take_output_unknown_session_is_none() {
    let mut mgr = PtyManager::new();
    assert!(mgr.take_output(9999).await.is_none());
}

// ---- T2：交互式写入后由 shell 执行并回显（先 stty -echo，排除 tty 回显干扰） ----

#[tokio::test]
async fn interactive_write_executed_by_shell() {
    let mut mgr = PtyManager::new();
    // 交互 bash（stdin 是 tty）；先关掉 tty 回显，之后写入的字符串不会被原样回显。
    let cfgp = PtyConfig {
        shell: "bash --norc --noprofile".to_string(),
        ..PtyConfig::default()
    };
    let id = mgr.create(cfgp).await.unwrap();
    let mut rx = mgr.take_output(id).await.expect("输出流可取回");

    mgr.write(id, b"stty -echo; read x; echo got:$x\r")
        .await
        .unwrap();
    // 等 bash 真正走到 read（提示符/命令回显之后）再喂输入。
    pump_until(&mut rx, b"stty -echo").await;

    mgr.write(id, b"w1-value-777\r").await.unwrap();
    let out = pump_until(&mut rx, b"got:w1-value-777").await;
    assert!(
        out.windows(b"got:w1-value-777".len())
            .any(|w| w == b"got:w1-value-777"),
        "未见执行结果，实际={out:?}"
    );
    mgr.kill(id).await.unwrap();
}

// ---- T3：resize 不 panic，且对未知/已死会话返回约定错误 ----

#[tokio::test]
async fn resize_many_calls_do_not_panic() {
    let mut mgr = PtyManager::new();
    let id = mgr.create(cfg("sleep 30")).await.unwrap();
    for (cols, rows) in [(10u16, 5u16), (200, 50), (1, 1), (80, 24)] {
        let res = tokio::time::timeout(WAIT, mgr.resize(id, cols, rows)).await;
        assert!(res.is_ok_and(|r| r.is_ok()), "resize({cols},{rows}) 失败");
    }
    assert!(matches!(
        tokio::time::timeout(WAIT, mgr.resize(4242, 80, 24))
            .await
            .unwrap(),
        Err(PtyError::NotFound(4242))
    ));
    mgr.kill(id).await.unwrap();
}

// ---- T4：kill 后会话仍在列表中且 alive=false，pid/started_at 可用 ----

#[tokio::test]
async fn kill_marks_session_not_alive() {
    let mut mgr = PtyManager::new();
    let id = mgr.create(cfg("sleep 60")).await.unwrap();
    let before = mgr.list();
    assert_eq!(before.len(), 1);
    assert!(before[0].alive, "刚创建应为活动");
    assert!(before[0].pid.is_some(), "应报告子进程 pid");
    assert!(before[0].started_at_ms > 0);

    tokio::time::timeout(WAIT, mgr.kill(id))
        .await
        .unwrap()
        .expect("kill 应成功");
    let after = mgr.list();
    assert_eq!(after.len(), 1, "kill 只终止进程，保留会话记录供回放");
    assert!(!after[0].alive, "kill 后 alive 必须为 false");

    // 幂等性：再次 kill 同一已死会话 ⇒ AlreadyDead。
    assert!(matches!(
        tokio::time::timeout(WAIT, mgr.kill(id)).await.unwrap(),
        Err(PtyError::AlreadyDead(_))
    ));
    assert!(matches!(
        tokio::time::timeout(WAIT, mgr.kill(777)).await.unwrap(),
        Err(PtyError::NotFound(777))
    ));
}

// ---- T5：replay 含历史，供重开 UI 回放 ----

#[tokio::test]
async fn replay_contains_history() {
    let mut mgr = PtyManager::new();
    let id = mgr.create(cfg("echo REPLAY-ME-42")).await.unwrap();
    let mut rx = mgr.take_output(id).await.expect("输出流可取回");
    drain_until_closed(&mut rx).await;

    let hist = mgr.replay(id);
    assert!(
        hist.windows(b"REPLAY-ME-42".len())
            .any(|w| w == b"REPLAY-ME-42"),
        "replay 未含历史，实际={hist:?}"
    );
    assert!(mgr.replay(9999).is_empty(), "未知会话 replay 为空");
}

// ---- T6：两个会话彼此独立（输出流与历史互不串台） ----

#[tokio::test]
async fn two_sessions_are_isolated() {
    let mut mgr = PtyManager::new();
    let a = mgr.create(cfg("echo AAA-ONLY")).await.unwrap();
    let b = mgr.create(cfg("echo BBB-ONLY")).await.unwrap();
    assert_ne!(a, b, "会话 id 必须唯一");
    let mut rxa = mgr.take_output(a).await.expect("a 输出流");
    let mut rxb = mgr.take_output(b).await.expect("b 输出流");
    let oa = drain_until_closed(&mut rxa).await;
    let ob = drain_until_closed(&mut rxb).await;

    assert!(oa.windows(8).any(|w| w == b"AAA-ONLY"), "a 缺自身输出");
    assert!(ob.windows(8).any(|w| w == b"BBB-ONLY"), "b 缺自身输出");
    assert!(
        !oa.windows(8).any(|w| w == b"BBB-ONLY"),
        "a 不得含 b 的输出"
    );
    assert!(
        !ob.windows(8).any(|w| w == b"AAA-ONLY"),
        "b 不得含 a 的输出"
    );
    assert!(
        mgr.replay(a).windows(8).any(|w| w == b"AAA-ONLY")
            && !mgr.replay(a).windows(8).any(|w| w == b"BBB-ONLY"),
        "a 历史串台"
    );
    assert_eq!(mgr.list().len(), 2);
}

// ---- T7：写/resize 已死会话与未知会话的错误码 ----

#[tokio::test]
async fn write_dead_session_errors() {
    let mut mgr = PtyManager::new();
    assert!(matches!(
        tokio::time::timeout(WAIT, mgr.write(5150, b"ls\r"))
            .await
            .unwrap(),
        Err(PtyError::NotFound(5150))
    ));

    let id = mgr.create(cfg("echo bye")).await.unwrap();
    let mut rx = mgr.take_output(id).await.expect("输出流");
    drain_until_closed(&mut rx).await;
    // 等会话状态被 reader EOF 落定为非活动。
    let deadline = tokio::time::Instant::now() + WAIT;
    while mgr.list().iter().all(|s| s.alive) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        mgr.list().iter().all(|s| !s.alive),
        "进程退出后 alive 应变为 false"
    );
    assert!(matches!(
        tokio::time::timeout(WAIT, mgr.write(id, b"ls\r"))
            .await
            .unwrap(),
        Err(PtyError::AlreadyDead(_))
    ));
    assert!(matches!(
        tokio::time::timeout(WAIT, mgr.resize(id, 80, 24))
            .await
            .unwrap(),
        Err(PtyError::AlreadyDead(_))
    ));
}

// ---- 配置与会话信息 ----

#[tokio::test]
async fn default_config_resolves_shell() {
    let d = PtyConfig::default();
    assert!(!d.shell.is_empty(), "默认 shell 必须非空");
    assert_eq!(d.cols, 80);
    assert_eq!(d.rows, 24);
    assert!(d.cwd.is_none());
    assert!(d.env.is_empty());

    let mut mgr = PtyManager::new();
    let mut c = cfg("sh -c 'echo $W1_PROBE_VAR:$(pwd)'");
    c.env.insert("W1_PROBE_VAR".into(), "probe-9".into());
    c.cwd = Some(std::env::temp_dir());
    let id = mgr.create(c).await.unwrap();
    let info = mgr
        .list()
        .into_iter()
        .find(|s| s.id == id)
        .expect("会话在列");
    assert_eq!(info.cwd, Some(std::env::temp_dir()));
    let mut rx = mgr.take_output(id).await.expect("输出流");
    let out = drain_until_closed(&mut rx).await;
    assert!(
        out.windows(b"probe-9".len()).any(|w| w == b"probe-9"),
        "自定义 env 未生效，实际={out:?}"
    );
}

#[tokio::test]
async fn missing_cwd_fails_closed() {
    let mut mgr = PtyManager::new();
    let mut c = cfg("pwd");
    c.cwd = Some(std::path::PathBuf::from("/definitely/not/a/dir/w1-pty"));
    let res = tokio::time::timeout(WAIT, mgr.create(c)).await.unwrap();
    assert!(
        matches!(res, Err(PtyError::Io(_))),
        "无效 cwd 必须 fail-closed，实际={res:?}"
    );
    assert!(mgr.list().is_empty(), "失败的 create 不得留下会话");
}

#[tokio::test]
async fn empty_shell_config_is_rejected() {
    let mut mgr = PtyManager::new();
    let res = tokio::time::timeout(
        WAIT,
        mgr.create(PtyConfig {
            shell: String::new(),
            ..Default::default()
        }),
    )
    .await
    .unwrap();
    assert!(matches!(res, Err(PtyError::Io(_))), "实际={res:?}");
}

/// 管理器必须能安全移入其它任务（网关侧单属主持有）。
#[tokio::test]
async fn manager_is_send() {
    fn assert_send<T: Send>() {}
    assert_send::<PtyManager>();
    assert_send::<PtyConfig>();
    assert_send::<PtyError>();
}
