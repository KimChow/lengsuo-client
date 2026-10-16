# Browser release authentication

Authenticates a release envelope with Ed25519 using application-controlled public
trust roots. This is separate from Windows Authenticode and artifact integrity.
No production key, publisher certificate, or default trusted test key is shipped.

The envelope schema is `{schema_version:1,key_id,payload,signature_hex}`. Signature
hex is 128 lowercase hex characters. The exact signing bytes are:

```text
"Lengsuo/KernelManifestEnvelope/v1\0" || u16be(key_id byte length) || key_id
    || u32be(payload byte length) || raw UTF-8 payload
```

Payload JSON has exactly `schema_version:1`, `sequence`, `issued_at_unix`,
`expires_at_unix`, and `manifest_json`. The embedded manifest must be a JSON
object; its complete business schema is checked separately by the package parser.
Unknown/duplicate envelope or claims fields fail closed. The envelope is bounded
to 1 MiB, payload to 256 KiB, embedded manifest to 64 KiB.

`TrustStore::verify_json` checks the pinned key, signature, positive sequence,
validity interval, policy lifetime bound, expiry and optional installed release
floor. Equal sequences require the same authenticated content, while identical
release reinstall is permitted. Root rotation is an application-configured set;
revoked keys are removed from that set. Nothing trusts keys supplied in a download.

The caller must obtain trusted time, persist the floor atomically **after** the
complete installation transaction, and recheck authorization and key revocation.
Use `VerifiedPayload::assert_current` immediately before the installation commit
to reject download delays and backwards time within the proof lifetime. A proof
does not establish OS compatibility, successful installation or network safety.

Tests use synthetic keys only. A fixed OpenSSL-generated signature and message
digest independently check the wire boundary; remaining tests cover tampering,
key replacement/revocation, rotation, rollback, conflicting sequences, malformed
JSON, byte limits and validity boundaries. No real customer account is involved.

The direct `ring` dependency reuses the existing locked 0.17.14 package. Its
declared license is `Apache-2.0 AND ISC`; upstream license and embedded once_cell
notices are retained in `LICENSES/ring-0.17.14` at repository root. This is a
dependency-specific review, not a claim that license compliance is CI-enforced.
