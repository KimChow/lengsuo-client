# Independent Ed25519 package vectors

Generated with the OpenSSL CLI, not the production ring signer/verifier:

- Synthetic PKCS8 DER: hex `302e020100300506032b657004220420` followed by
  byte `0b` repeated 32 times. This is public test material, never a release key.
- Public key: `66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a`.
- Signed message: ASCII `Lengsuo/KernelManifestEnvelope/v1` + NUL,
  u16 big-endian key-id UTF8 byte count, key-id `release-a`, u32 big-endian
  payload UTF8 byte count, then the exact unescaped UTF8 payload string.
- Command: `openssl pkeyutl -sign -inkey key.der -keyform DER -rawin -in message -out signature`.
- Envelopes preserve exact payload text and lowercase hexadecimal signatures.
  Editing formatting within payload invalidates the signature.

Claims use sequence 7, issued_at 90, expires_at 150. Tests verify at trusted time
100. The valid manifest's artifact SHA256 is independently Python-hashlib-derived
for the deterministic 64-byte LCG payload in fixture.rs. Other vectors have valid
signatures but deliberately invalid manifest version, unknown key, or duplicate
sha256 key. They prove authentication does not bypass manifest validation.
