//! Character-level grammars for every string in a manifest, plus the strict
//! JSON entry point that keeps duplicate and unknown keys from being absorbed
//! silently.
//!
//! These checks are deliberately *lexical*. They ask "could any honest
//! publisher have written this?" and reject everything else; they never repair,
//! trim, case-fold or pad an input into something acceptable.
//!
//! The two halves live in the `shapes` and `strict_json` submodules and are
//! re-exported here, so every `crate::grammar::X` path stays exactly where it
//! was.

mod shapes;
mod strict_json;

pub(crate) use shapes::*;
pub(crate) use strict_json::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_shape() {
        assert!(version_shape_ok("155.0.8059.85"));
        assert!(version_shape_ok("0.0.0.0"));
        assert!(!version_shape_ok("155.0.8059"));
        assert!(!version_shape_ok("155.0.8059.85.1"));
        assert!(!version_shape_ok("155.0..85"));
        assert!(!version_shape_ok("155.0.8059.085"));
        assert!(!version_shape_ok(" 155.0.8059.85"));
        assert!(!version_shape_ok("155.0.8059.85 "));
        assert!(!version_shape_ok("155.0.8059.x"));
    }

    #[test]
    fn hex_shape() {
        assert!(hex_lowercase_of_len(&"0".repeat(40), 40));
        assert!(!hex_lowercase_of_len(&"0".repeat(39), 40));
        assert!(!hex_lowercase_of_len(&"f".repeat(41), 40));
        assert!(!hex_lowercase_of_len(&("A".repeat(39) + "f"), 40));
        assert!(!hex_lowercase_of_len(&("0".repeat(39) + "g"), 40));
        assert!(!hex_lowercase_of_len(&("0".repeat(39) + " "), 40));
    }

    #[test]
    fn artifact_name_shape() {
        assert!(artifact_name_ok("chrome-linux64.zip"));
        assert!(artifact_name_ok("chrome+x86_64.tar.zst"));
        for hostile in [
            "",
            ".",
            "..",
            "../evil",
            "a/../b",
            "/etc/passwd",
            "C:\\windows",
            "sub/dir.zip",
            "chrome\r\n.dll",
            "nul",
            "CON",
            "COM1",
            "LPT9.",
            "aux.txt",
            "-x",
            ".hidden",
            "chrome .dll",
            "chrome.dll ",
            "\u{7}zip",
            "ünïcode.zip",
            "a:b",
        ] {
            assert!(!artifact_name_ok(hostile), "accepted {hostile:?}");
        }
        assert!(!artifact_name_ok(&"a".repeat(MAX_ARTIFACT_NAME_LEN + 1)));
    }

    #[test]
    fn token_shape() {
        assert!(capability_ok("webauthn-proxy"));
        assert!(capability_ok("vaapi"));
        assert!(!capability_ok("vaApi"));
        assert!(!capability_ok("2026"));
        assert!(!capability_ok("_x"));
        assert!(pool_version_ok("2026.10"));
        assert!(pool_version_ok("pool-2026-10"));
        assert!(!pool_version_ok(""));
        assert!(!pool_version_ok(".."));
        assert!(!pool_version_ok("../etc"));
        assert!(!pool_version_ok(&"p".repeat(MAX_TOKEN_LEN + 1)));
    }

    #[test]
    fn extension_dir_name_shape() {
        assert!(extension_dir_name_ok("lengsuo-credential"));
        assert!(extension_dir_name_ok("credential"));
        assert!(extension_dir_name_ok("cred_2026.10"));
        for hostile in [
            "",
            ".",
            "..",
            "../evil",
            "a/b",
            "sub\\dir",
            "/absolute",
            "C:\\windows",
            ".hidden",
            "-flag",
            "trailing.",
            "trailing-",
            "with space",
            "nul",
            "CON",
            "COM1",
            "aux.txt",
            "ünïcode",
        ] {
            assert!(!extension_dir_name_ok(hostile), "accepted {hostile:?}");
        }
        assert!(!extension_dir_name_ok(
            &"a".repeat(MAX_EXTENSION_DIR_NAME_LEN + 1)
        ));
        assert!(extension_dir_name_ok(
            &"a".repeat(MAX_EXTENSION_DIR_NAME_LEN)
        ));
    }
}
