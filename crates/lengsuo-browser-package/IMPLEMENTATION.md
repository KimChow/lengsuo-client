# Package integrity implementation evidence

This crate validates package metadata and checks artifact length/SHA256. It does
not authenticate publishers, fetch, extract, install, or launch a browser.
Signature authentication is performed by the signature component; AuthenticatedManifest binds its VerifiedPayload to fully validated metadata.

## API boundary

- `from_json_str`: exact top-level keys, JSON types, duplicate rejection, schema
  version, and a 1 MiB input bound. Success is parsed input, not a validated or
  authenticated manifest.
- `validate`: version/revision/digest/basename grammars, positive size <=16 GiB,
  bounded nonempty profile/pool sets, supported profile schema, capability tokens.
- `assert_compatible`: validates first, then checks host OS/CPU, profile, pool,
  and required host capabilities.
- `verify_reader`: validates first; at most 8192 bytes buffered; consumes at
  most declared length +1; distinguishes truncation, excess bytes, digest
  mismatch, and IO failure with byte offset. The blocking Read caller remains
  responsible for its transport timeout.
- `AuthenticatedManifest` only consumes a real VerifiedPayload, parses its exact
  manifest_json, and validates before constructing private immutable state.
  It retains proof for assert_current and release_floor, and verifies artifact
  bytes against proof-bound metadata. No raw-manifest or mutable constructor
  exists; legacy Never/PublisherVerified/always-refuse placeholders are removed.

## Red evidence and oracle corrections

Initial offline locked test command genuinely failed to compile (SSH wrapper
exit 1): unresolved MIN_ARTIFACT_BYTES, invalid anonymous lifetime, String Copy,
missing serde error mapping, incompatible error fields, and test expressions.
All four production todo bodies were unimplemented at that point.

After implementation, strict tests ran 15 passed/2 failed, field validation
25 passed/1 failed. Inspection established three oracle defects, reported to
and accepted by the coordinating agent before correction:

1. A duplicated array value was inserted inside quotes without escaping its
   inner quotes, creating invalid JSON rather than a duplicate-key document.
   The helper now JSON-encodes the string and preserves DuplicateKey assertion.
2. 4294967296 was incorrectly classified as an invalid size type although it
   fits u64 and lies below the established 16 GiB limit. A positive acceptance
   test replaces that erroneous case; actual overflow and upper-bound tests stay.
3. Patchset and artifact digests describe different objects, but that does not
   mathematically require different digest strings. Equal strings now pass
   grammar validation; real mismatching bytes still fail streaming verification.

Test source compilation errors were also repaired without weakening assertions.
Large tests were split by responsibility, keeping every source file <400 lines.

## Final checks on research host 192.168.1.47

Workspace: /home/ubuntu/lengsuo-browser-dev/client-worktree
Package: crates/lengsuo-browser-package
Target: /home/ubuntu/lengsuo-browser-dev/targets/package-finish
CARGO_BUILD_JOBS=2; executable /home/ubuntu/.cargo/bin/cargo.

- `cargo test -p lengsuo-browser-package --offline --locked`: exit 0,
  65 tests passed (4 unit +61 integration) and 2 compile-fail doctests passed,
  0 failed, 0 ignored.
- `cargo clippy -p lengsuo-browser-package --all-targets --offline --locked -- -D warnings`:
  exit 0, no warnings.
- `cargo fmt -p lengsuo-browser-package -- --check`: exit 0.

One intermediate clippy --fix invocation accidentally omitted CARGO_TARGET_DIR
and used workspace default target. It naturally completed, did not run
concurrently with another package command, and only fixed this crate's test
borrows. Final checks above used the designated isolated target.

No root Cargo.toml or other crate changes. The sole Cargo.lock change for this
phase adds package -> lengsuo-browser-signature in the existing package entry;
no dependency versions change. This existing signature crate is the new path
dependency, without a second cryptographic implementation. No
no commit/push, no process termination, and no deployment in this task.
These checks establish this crate's local schema/compatibility/integrity behavior,
not a completed browser, authenticated installer, or Windows runtime acceptance.


## Real signature integration red and green

The new authenticated_manifest integration test first genuinely failed with
unresolved AuthenticatedManifest (SSH wrapper exit 1) before implementation was
uploaded. It then passed against four fixed independently OpenSSL-generated
Ed25519 envelopes. See tests/vectors/README.md for wire format and provenance.

Six boundary tests cover valid signature+manifest+artifact, genuine signature
with invalid grammar/unknown/duplicate manifest fields, metadata replacement
without proof reuse, preinstall expiry and backwards time, persisted release
floor rollback, and exact signed payload tampering. Two compile-fail doctests
prove external callers cannot construct private fields or mutate the authenticated
manifest through its getter. These replace three vacuous legacy token tests.

Before the one-entry remote lock edit, process inspection showed no cargo/rustc
process. Final offline locked commands needed no lock updates. Local root lock
was deliberately not overwritten; the coordinating agent must merge this exact
package dependency edge into its current lock if that entry is not present.
