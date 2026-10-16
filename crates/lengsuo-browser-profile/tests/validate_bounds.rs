//! Contract validation: slot coverage, numeric bounds, locale syntax and
//! platform/touch consistency.

use lengsuo_browser_profile::{Platform, ProfileError, DIMENSIONS};

mod support;
use support::{mobile_spec, spec};

fn rejected(spec: &lengsuo_browser_profile::ProfileSpecV1) -> ProfileError {
    match spec.validate() {
        Ok(()) => panic!("profile must be rejected: {spec:?}"),
        Err(err) => err,
    }
}

#[test]
fn slot_dimensions_must_be_exact() {
    // Schema 1 covers exactly seven dimensions.
    assert_eq!(
        DIMENSIONS,
        [
            "canvas",
            "webgl",
            "audio",
            "fonts",
            "client_rects",
            "gpu",
            "ua"
        ]
    );

    // Every single supported dimension missing is refused, named specifically.
    for dim in DIMENSIONS {
        let mut s = spec();
        s.slots.remove(dim);
        assert_eq!(
            rejected(&s),
            ProfileError::MissingDimension(dim.to_string()),
            "missing {dim} accepted"
        );
    }

    // An empty slot map is refused too.
    let mut s = spec();
    s.slots.clear();
    assert!(matches!(rejected(&s), ProfileError::MissingDimension(_)));

    // Unknown / extra dimensions are refused, including near-miss spellings.
    // `webgpu` is deliberately in this list: schema 1 does not define a WebGPU
    // slot yet, so a profile carrying one must be rejected rather than
    // silently dropped.
    for extra in [
        "webgpu",
        "Canvas",
        "canvas ",
        " canvas",
        "client-rects",
        "clientRects",
        "ua_ch",
        "fonts2",
        "webrtc",
        "timezone",
        "",
    ] {
        let mut s = spec();
        s.slots.insert(extra.to_string(), 1);
        assert_eq!(
            rejected(&s),
            ProfileError::UnknownDimension(extra.to_string()),
            "extra {extra:?} accepted"
        );
    }

    // A swap (drop one, add one) must still fail closed on one of the two.
    let mut s = spec();
    s.slots.remove("gpu");
    s.slots.insert("webgpu".to_string(), 1);
    assert!(matches!(
        rejected(&s),
        ProfileError::UnknownDimension(_) | ProfileError::MissingDimension(_)
    ));
}

#[test]
fn slot_tier_ids_must_be_within_range() {
    for id in [0, lengsuo_browser_profile::MAX_SLOT_ID + 1, u32::MAX] {
        for dim in DIMENSIONS {
            let mut s = spec();
            s.slots.insert(dim.to_string(), id);
            match rejected(&s) {
                ProfileError::SlotIdOutOfRange {
                    dimension,
                    value,
                    max,
                } => {
                    assert_eq!(dimension, dim.to_string());
                    assert_eq!(value, id);
                    assert_eq!(max, lengsuo_browser_profile::MAX_SLOT_ID);
                }
                other => panic!("slot id {id} for {dim} produced {other}"),
            }
        }
    }

    // The declared maximum is still representable and accepted.
    let mut s = spec();
    for dim in DIMENSIONS {
        s.slots
            .insert(dim.to_string(), lengsuo_browser_profile::MAX_SLOT_ID);
    }
    s.validate().unwrap();
}

#[test]
fn screen_bounds_and_area_are_enforced() {
    for value in [
        0,
        lengsuo_browser_profile::MAX_SCREEN_DIMENSION + 1,
        u32::MAX,
    ] {
        let mut s = spec();
        s.screen.width = value;
        assert!(
            matches!(rejected(&s), ProfileError::ScreenOutOfRange { .. }),
            "width {value} accepted"
        );
        let mut s = spec();
        s.screen.height = value;
        assert!(
            matches!(rejected(&s), ProfileError::ScreenOutOfRange { .. }),
            "height {value} accepted"
        );
    }

    // 16384 * 16384 fits u32 only by wrapping; the area check runs in u64 and
    // must reject it rather than silently wrapping.
    let mut s = spec();
    s.screen.width = lengsuo_browser_profile::MAX_SCREEN_DIMENSION;
    s.screen.height = lengsuo_browser_profile::MAX_SCREEN_DIMENSION;
    match rejected(&s) {
        ProfileError::ScreenAreaTooLarge { value, max } => {
            assert_eq!(max, lengsuo_browser_profile::MAX_SCREEN_AREA);
            assert_eq!(value, 16384u64 * 16384u64);
            assert!(value > u32::MAX as u64 - 1 || value > max, "{value}");
        }
        other => panic!("oversized area accepted: {other}"),
    }

    let mut s = spec();
    s.screen.width = 7680;
    s.screen.height = 4320;
    s.validate().unwrap(); // 33.1 MP, under the cap

    for depth in [0u8, 1, 12, 32, 48, 64, 255] {
        let mut s = spec();
        s.screen.color_depth = depth;
        assert!(
            matches!(rejected(&s), ProfileError::ColorDepth(_)),
            "color depth {depth} accepted"
        );
    }
    for depth in [8u8, 16, 24, 30] {
        let mut s = spec();
        s.screen.color_depth = depth;
        s.validate()
            .unwrap_or_else(|e| panic!("depth {depth}: {e}"));
    }

    for dpr in [0u32, 99, 10_001, u32::MAX] {
        let mut s = spec();
        s.screen.dpr_milli = dpr;
        assert!(
            matches!(rejected(&s), ProfileError::ScreenOutOfRange { .. }),
            "dpr_milli {dpr} accepted"
        );
    }
    for dpr in [100u32, 1000, 2000, 10_000] {
        let mut s = spec();
        s.screen.dpr_milli = dpr;
        s.validate().unwrap_or_else(|e| panic!("dpr {dpr}: {e}"));
    }
}

#[test]
fn hardware_bounds_are_enforced() {
    for cores in [0u16, 1025, u16::MAX] {
        let mut s = spec();
        s.hardware.cpu_cores = cores;
        assert!(
            matches!(rejected(&s), ProfileError::HardwareOutOfRange { .. }),
            "cpu_cores {cores} accepted"
        );
    }
    for memory in [
        0u32,
        127,
        lengsuo_browser_profile::MAX_MEMORY_MIB + 1,
        u32::MAX,
    ] {
        let mut s = spec();
        s.hardware.memory_mib = memory;
        assert!(
            matches!(rejected(&s), ProfileError::HardwareOutOfRange { .. }),
            "memory_mib {memory} accepted"
        );
    }
    let mut s = spec();
    s.hardware.cpu_cores = 1;
    s.hardware.memory_mib = lengsuo_browser_profile::MIN_MEMORY_MIB;
    s.validate().unwrap();
}

#[test]
fn mobile_touch_consistency() {
    // Mobile without touch capability is a contradiction.
    for platform in [Platform::Android, Platform::Ios] {
        let mut s = mobile_spec();
        s.platform = platform;
        s.hardware.max_touch_points = 0;
        assert_eq!(
            rejected(&s),
            ProfileError::MobileTouchPoints(0),
            "{platform:?} with 0 touch points accepted"
        );

        let mut s = mobile_spec();
        s.platform = platform;
        s.hardware.max_touch_points = lengsuo_browser_profile::MAX_TOUCH_POINTS + 1;
        assert!(
            matches!(rejected(&s), ProfileError::MobileTouchPoints(_)),
            "{platform:?} with 11 touch points accepted"
        );

        let mut s = mobile_spec();
        s.platform = platform;
        s.hardware.max_touch_points = lengsuo_browser_profile::MAX_TOUCH_POINTS;
        s.validate().unwrap();
    }

    // Desktop claiming touch points is a contradiction.
    for platform in [Platform::Windows, Platform::Linux, Platform::Macos] {
        let mut s = spec();
        s.platform = platform;
        s.hardware.max_touch_points = 1;
        assert_eq!(
            rejected(&s),
            ProfileError::DesktopTouchPoints(1),
            "{platform:?} claiming touch accepted"
        );
        s.hardware.max_touch_points = u8::MAX;
        assert!(matches!(rejected(&s), ProfileError::DesktopTouchPoints(_)));
    }
}

#[test]
fn language_syntax_is_checked_without_claiming_a_subtag_database() {
    let good = [
        "en",
        "en-US",
        "zh-Hans-CN",
        "sr-Latn-RS",
        "pt-BR",
        "de-DE",
        "de",
    ];
    for language in good {
        let mut s = spec();
        s.locale.language = language.to_string();
        s.validate()
            .unwrap_or_else(|e| panic!("language {language:?}: {e}"));
    }

    let bad: Vec<String> = vec![
        String::new(),
        "-".to_string(),
        "e".to_string(),
        "en-".to_string(),
        "en-US-".to_string(),
        "en--US".to_string(),
        "1en-US".to_string(),
        "en..US".to_string(),
        "en_US".to_string(),
        "en US".to_string(),
        "en-US;evil".to_string(),
        "en-US\x00".to_string(),
        "é".to_string(),
        "ＥＮ".to_string(),
        "e".to_string() + &"n".repeat(9), // 10-char primary subtag
        format!("{}-US", "a".repeat(30)), // over the 35-char limit
        "en-US-A-B-C-D-E-F-G-H-I".to_string(), // too many subtags
    ];
    for language in bad {
        let mut s = spec();
        s.locale.language = language.clone();
        assert!(
            matches!(rejected(&s), ProfileError::LanguageSyntax),
            "language accepted: {language:?}"
        );
    }

    // Syntactically well-formed but not a registered language: this contract
    // only checks syntax and must be described as doing exactly that.
    let mut s = spec();
    s.locale.language = "zz-ZZ".to_string();
    s.validate().expect("syntax-only acceptance");
}

#[test]
fn timezone_syntax_is_checked_without_an_iana_database() {
    let good = [
        "UTC",
        "GMT",
        "Europe/Berlin",
        "America/Los_Angeles",
        "America/Argentina/Buenos_Aires",
        "Etc/GMT+8",
        "Etc/GMT-10",
        "Australia/Sydney",
        "Asia/Shanghai",
    ];
    for zone in good {
        let mut s = spec();
        s.locale.timezone = zone.to_string();
        s.validate()
            .unwrap_or_else(|e| panic!("timezone {zone:?}: {e}"));
    }

    let slash = "/";
    let dot = ".";
    let bad: Vec<String> = vec![
        String::new(),
        slash.to_string(),
        format!("{slash}{slash}"),
        format!("UTC{slash}"),
        format!("{slash}UTC"),
        format!("Europe{slash}{slash}Berlin"),
        format!("{dot}{dot}"),
        format!("{dot}{dot}{slash}{dot}{dot}{slash}etc{slash}localtime"),
        format!("Europe{slash}{dot}{dot}{slash}Berlin"),
        "UTC ".to_string(),
        "UTC\n".to_string(),
        "UTC\t".to_string(),
        "utc+08:00".to_string(),
        "+08:00".to_string(),
        format!("Europe{slash}Berlin?x=1"),
        format!("Europe{slash}Berlin#f"),
        "éurope".to_string(),
        format!("Etc{slash}Zone With Space"),
        format!("Etc{slash}1234"), // numeric-only subname
        "a".repeat(65) + slash,
    ];
    for zone in bad {
        let mut s = spec();
        s.locale.timezone = zone.clone();
        assert!(
            matches!(rejected(&s), ProfileError::TimezoneSyntax),
            "timezone accepted: {zone:?}"
        );
    }

    // Well-formed but fictional: syntax only, so accepted. Recorded as a gap.
    let mut s = spec();
    s.locale.timezone = "Mars/Olympus_Mons".to_string();
    s.validate().expect("syntax-only acceptance");
}
