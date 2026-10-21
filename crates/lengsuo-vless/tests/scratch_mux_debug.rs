//! scratch debug
use lengsuo_vless::header::{self, Command, Request};
use lengsuo_vless::mux::frame::{decode_from_async, read_data_async, TargetNetwork};
use lengsuo_vless::mux::worker::{SessionWriter, Strategy};
use lengsuo_vless::mux_wire::MuxWire;
use serde_json::json;
use ss_core::target::TargetAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

mod support;

const WAIT: Duration = Duration::from_secs(8);

#[tokio::test]
#[ignore]
async fn debug_mux_bytes() {
    use support::{free_port, launch, ID, KEY};
    let port = free_port();
    let reference = launch(
        json!({
            "log":{"loglevel":"debug"},
            "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless",
                "settings":{"clients":[{"id":ID}],"decryption":"none"}}],
            "outbounds":[{"protocol":"freedom"}]
        }),
        port,
    )
    .await;
    let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    let request = Request {
        command: Command::Mux,
        target: TargetAddr::Domain("v1.mux.cool".to_string(), 0),
    };
    let bytes = header::encode(&request, &KEY).unwrap();
    println!("VLESS header bytes ({}): {:02x?}", bytes.len(), bytes);
    // write header + first mux frame in ONE write (like the reference client does)
    let mut wire = bytes.clone();
    let mut w = SessionWriter::request(
        1,
        (TargetAddr::V4([127, 0, 0, 1], 1), TargetNetwork::Tcp),
        TargetNetwork::Tcp,
    );
    w.write_data(&mut wire, b"hello").unwrap();
    println!("wire ({}): {:02x?}", wire.len(), wire);
    stream.write_all(&wire).await.unwrap();
    stream.flush().await.unwrap();
    // read response header (2 bytes) then mux frames
    let mut hdr = [0u8; 2];
    timeout(WAIT, stream.read_exact(&mut hdr))
        .await
        .unwrap()
        .unwrap();
    println!("resp header: {:02x?}", hdr);
    // read mux frames
    loop {
        let r = timeout(
            Duration::from_secs(3),
            decode_from_async(&mut stream, false),
        )
        .await;
        match r {
            Ok(Ok(meta)) => {
                println!(
                    "frame: id={} status={:?} option={} target={:?}",
                    meta.session_id, meta.status, meta.option, meta.target
                );
                if meta.has_data() {
                    let d = read_data_async(&mut stream, true).await.unwrap();
                    println!("  data ({}): {:?}", d.len(), String::from_utf8_lossy(&d));
                }
            }
            Ok(Err(e)) => {
                println!("decode err: {e}");
                break;
            }
            Err(_) => {
                println!("timeout waiting for frame");
                break;
            }
        }
    }
    drop(reference);
}
