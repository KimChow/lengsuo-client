# VMess ChaCha 档参考向量生成器

独立 Go 程序，复算固定参考 Xray（commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`）
的 VMess ChaCha20-Poly1305 档请求体封包，产出期望值供
`crates/lengsuo-vmess/tests/chacha_vectors.rs` 逐字节比对。

## 为什么本目录不是自洽模块

`go.mod` 依赖 `github.com/xtls/xray-core`，而**仓库不 vendor 参考源码**
（体积与许可原因）。要复算，机器上必须有该 commit 的只读检出。

## 怎么跑（需 Go 工具链 + 参考检出）

参考检出默认放在 `~/ref/xray`（可用环境变量 `LENGSUO_XRAY_REF` 覆盖）。
先写一份带正确 `replace` 的 modfile，再跑：

```bash
cd tools/reference/vmess_vectors
REF="${LENGSUO_XRAY_REF:-$HOME/ref/xray}"
sed "s|=> ./xray-core-checkout|=> $REF|" go.mod > go.local.mod
cp go.sum go.local.sum
go run -modfile=go.local.mod . > /tmp/vmess_chacha_vectors.json
```

`go.local.mod` / `go.local.sum` 是**本地生成物，不要提交**。

## 日常构建不需要它

生成的期望值已**写死**进 `crates/lengsuo-vmess/tests/chacha_vectors.rs`
的期望表 ⇒ 日常 `cargo test` / `cargo build` **不需要 Go 工具链，
也不需要参考检出**。本目录只在你需要重新复算期望值时才用到。
