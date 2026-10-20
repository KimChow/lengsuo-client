// 独立向量生成器的 Go 模块。
//
// `replace` 指向本机的**只读参考检出**（固定 commit d2758a02），因此本目录
// 不是一个自洽的独立模块：它需要参考源码在场才能跑。仓库不 vendor 参考源码
// （体积与许可原因），复算步骤见同目录 README.md。
//
// 生成的期望值已**写死**进 `crates/lengsuo-vmess/tests/chacha_vectors.rs`
// 的期望表，因此日常构建/测试不需要 Go 工具链，也不需要参考检出。
module vmessvectors

go 1.26

require (
	github.com/xtls/xray-core v0.0.0
	golang.org/x/crypto v0.49.0
)

require (
	golang.org/x/sys v0.42.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/xtls/xray-core => /home/ubuntu/ref/xray
