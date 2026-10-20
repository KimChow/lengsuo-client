// 独立向量生成器：用**参考 Xray 源码本身**（固定 commit d2758a02）产出
// VMess 多安全档黄金向量。本程序只调用参考的公开函数，不复制任何密码学实现。
//
// 用法（见同目录 README.md）：
//   cd tools/reference/vmess_vectors
//   go run . > vectors.json
//
// 产出：JSON，键为向量名，值为十六进制字符串或字符串数组。
// 本仓的 tests/chacha_vectors.rs 消费该 JSON 的**写死副本**（见该测试文件
// 顶部的 EXPECTED 常量表）；本程序是那些期望值的来源与可复算入口。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vmess/aead"
	"github.com/xtls/xray-core/proxy/vmess/encoding"
	"golang.org/x/crypto/chacha20poly1305"
)

// 固定假值（与本仓测试里用的常量一一对应；都是测试假凭据，不是真密钥）。
var (
	cmdKey    = []byte("b831381d-6324-4d")
	bodyKey   = []byte("request-body-key")
	bodyIV    = []byte("request-body-iv!")
	payload   = []byte("vmess body payload")
	plainHead = []byte("version+iv+key+seed+options+security+cmd+address+padding+fnv")
)

func hx(b []byte) string { return hex.EncodeToString(b) }

// chunkNonce 复制参考 `GenerateChunkNonce` 的语义：计数器大端写进 nonce 前 2 字节。
func chunkNonce(iv []byte, count uint16) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	nonce[0] = byte(count >> 8)
	nonce[1] = byte(count)
	return nonce[:12]
}

// bodyAEAD 用参考的套件分派（client.go `EncodeRequestBody`）封一帧载荷。
func bodyAEAD(security protocol.SecurityType, baseKey []byte, iv []byte, count uint16, plain []byte) ([]byte, error) {
	var key []byte
	switch security {
	case protocol.SecurityType_AES128_GCM:
		key = baseKey
	case protocol.SecurityType_CHACHA20_POLY1305:
		key = encoding.GenerateChacha20Poly1305Key(baseKey)
	default:
		return nil, fmt.Errorf("unsupported security %v", security)
	}
	return sealWithSuite(security, key, chunkNonce(iv, count), plain)
}

// sealWithSuite 按档位选择 AEAD 实现（与参考 client.go/server.go 的 switch 等价）。
func sealWithSuite(security protocol.SecurityType, key []byte, nonce []byte, plain []byte) ([]byte, error) {
	switch security {
	case protocol.SecurityType_AES128_GCM:
		a := crypto.NewAesGcm(key)
		return a.Seal(nil, nonce, plain, nil), nil
	case protocol.SecurityType_CHACHA20_POLY1305:
		a, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		return a.Seal(nil, nonce, plain, nil), nil
	default:
		return nil, fmt.Errorf("unsupported security %v", security)
	}
}

// authLenSegment 复现参考 `AEADChunkSizeParser.Encode`：
// 线上 = Seal(BE16(总长 - overhead))，密钥 = KDF16(requestBodyKey, "auth_len")。
//
// 参考的 `AuthenticationWriter.seal` 把 `encryptedSize + paddingSize`（即
// 明文长 + tag + padding）交给解析器，解析器再减去 `Overhead()` 才写进
// AEAD 明文——因此这里的明文是「明文长 + padding」，解码端再加回 overhead。
func authLenSegment(security protocol.SecurityType, requestBodyKey []byte, iv []byte, count uint16, total int) ([]byte, error) {
	base := aead.KDF16(requestBodyKey, "auth_len")
	var key []byte
	switch security {
	case protocol.SecurityType_AES128_GCM:
		key = base
	case protocol.SecurityType_CHACHA20_POLY1305:
		key = encoding.GenerateChacha20Poly1305Key(base)
	default:
		return nil, fmt.Errorf("unsupported security %v", security)
	}
	const overhead = 16 // AES-128-GCM 与 ChaCha20-Poly1305 的 tag 都是 16 字节
	plain := []byte{byte((total - overhead) >> 8), byte(total - overhead)}
	return sealWithSuite(security, key, chunkNonce(iv, count), plain)
}

func main() {
	out := map[string]any{}

	// 1) ChaCha20-Poly1305 的 MD5 链扩展密钥（参考 auth.go 的 GenerateChacha20Poly1305Key）。
	out["chacha_key_expansion"] = hx(encoding.GenerateChacha20Poly1305Key(bodyKey))

	// 2) 认证长度段的派生密钥（参考 KDF16(requestBodyKey, "auth_len")）。
	out["auth_len_kdf16"] = hx(aead.KDF16(bodyKey, "auth_len"))

	// 3) 各档的数据段载荷密文（nonce = chunkNonce(iv, 0)，无 AAD）。
	for _, sec := range []protocol.SecurityType{
		protocol.SecurityType_AES128_GCM,
		protocol.SecurityType_CHACHA20_POLY1305,
	} {
		ct, err := bodyAEAD(sec, bodyKey, bodyIV, 0, payload)
		if err != nil {
			fatal(err)
		}
		out[fmt.Sprintf("body_payload_ct_%s", sec.String())] = hx(ct)
	}

	// 4) 各档的认证长度段密文（18 字节 = 2B 明文 + 16B tag）。
	for _, sec := range []protocol.SecurityType{
		protocol.SecurityType_AES128_GCM,
		protocol.SecurityType_CHACHA20_POLY1305,
	} {
		seg, err := authLenSegment(sec, bodyKey, bodyIV, 0, len(payload)+16)
		if err != nil {
			fatal(err)
		}
		out[fmt.Sprintf("auth_len_segment_%s", sec.String())] = hx(seg)
	}

	// 5) Shake 掩码长度段（参考 ShakeSizeParser）：掩码流读 2 字节 BE16。
	shake := encoding.NewShakeSizeParser(bodyIV)
	masked := make([]byte, 2)
	shake.Encode(uint16(len(payload)+16), masked)
	out["masked_size_segment"] = hx(masked)

	// 6) 参考头部 AEAD（恒 AES-128-GCM）：SealVMessAEADHeader 的确定性形态。
	//    这里直接调参考实现，AuthID 用调用方注入的固定值。
	authID := [16]byte{0x5A, 0x21, 0x43, 0x65, 0x87, 0x09, 0xBA, 0xDC, 0xFE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	connNonce := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	headerWire := sealHeader(cmdKey, authID, connNonce, plainHead)
	out["header_wire"] = hx(headerWire)

	// 7) 参考的 BodyKey/BodyIV 派生（响应方向）：SHA256(requestBodyKey)[:16]。
	out["response_body_key"] = hx(sha256Prefix(bodyKey))
	out["response_body_iv"] = hx(sha256Prefix(bodyIV))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal(err)
	}
}

// sealHeader 用参考 `proxy/vmess/aead` 的派生 + AES-128-GCM 复现
// `SealVMessAEADHeader` 的确定性形态（AuthID 与连接 nonce 注入）。
// 这里刻意**不**调 `SealVMessAEADHeader`（它内部生成随机 AuthID/时间戳，
// 不可复现），而是逐字照抄它的 KDF 路径与 AAD 组装。
func sealHeader(cmdKey []byte, authID [16]byte, connNonce []byte, data []byte) []byte {
	lengthKey := aead.KDF16(cmdKey, aead.KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(authID[:]), string(connNonce))
	lengthNonce := aead.KDF(cmdKey, aead.KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(authID[:]), string(connNonce))[:12]
	lengthAEAD := crypto.NewAesGcm(lengthKey)
	lenBuf := new(bytes.Buffer)
	lenBuf.WriteByte(byte(len(data) >> 8))
	lenBuf.WriteByte(byte(len(data)))
	lengthCT := lengthAEAD.Seal(nil, lengthNonce, lenBuf.Bytes(), authID[:])

	payloadKey := aead.KDF16(cmdKey, aead.KDFSaltConstVMessHeaderPayloadAEADKey, string(authID[:]), string(connNonce))
	payloadNonce := aead.KDF(cmdKey, aead.KDFSaltConstVMessHeaderPayloadAEADIV, string(authID[:]), string(connNonce))[:12]
	payloadAEAD := crypto.NewAesGcm(payloadKey)
	payloadCT := payloadAEAD.Seal(nil, payloadNonce, data, authID[:])

	out := new(bytes.Buffer)
	out.Write(authID[:])
	out.Write(lengthCT)
	out.Write(connNonce)
	out.Write(payloadCT)
	return out.Bytes()
}

func sha256Prefix(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:16]
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "generator error:", err)
	os.Exit(1)
}
