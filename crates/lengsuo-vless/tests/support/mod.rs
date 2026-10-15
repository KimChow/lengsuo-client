use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Child, Command as Process, Stdio},
    time::Duration,
};
use tokio::{net::TcpStream, time::Instant};
pub const WAIT: Duration = Duration::from_secs(8);
pub const ID: &str = "11111111-1111-1111-1111-111111111111";
pub const KEY: [u8; 16] = [0x11; 16];
pub struct Reference {
    child: Child,
    directory: PathBuf,
}
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub async fn launch(config: Value, port: u16) -> Reference {
    let binary = std::env::var("LENGSUO_XRAY").expect("必须显式指定固定版本 Xray");
    let version = Process::new(&binary).arg("version").output().unwrap();
    let version = String::from_utf8(version.stdout).unwrap();
    assert!(
        version.contains("26.3.27") && version.contains("d2758a0"),
        "基线不匹配：{version}"
    );
    let directory =
        std::env::temp_dir().join(format!("lengsuo-vless-{}-{port}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(directory.join("xray.log")).unwrap();
    let child = Process::new(binary)
        .args(["run", "-config"])
        .arg(path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut reference = Reference { child, directory };
    let end = Instant::now() + WAIT;
    loop {
        if let Some(status) = reference.child.try_wait().unwrap() {
            panic!(
                "参考进程提前退出 {status}：{}",
                std::fs::read_to_string(reference.directory.join("xray.log")).unwrap()
            );
        }
        if TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < end, "参考服务启动超时");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let inbound = config["inbounds"][0]["protocol"].as_str().unwrap_or("未知");
    let security = config["inbounds"][0]["streamSettings"]["security"]
        .as_str()
        .unwrap_or("none");
    println!("基线 {version}测试端口 {port}，入站 {inbound}，安全层 {security}");
    reference
}
