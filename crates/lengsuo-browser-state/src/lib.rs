//! Bounded untrusted recovery metadata. Never grants running/authority/lease.
#![forbid(unsafe_code)]

/// Magic bytes, version, and layout constants for the LBST codec.
const MAGIC: [u8; 4] = *b"LBST";
const VERSION: u8 = 1;
/// 4 magic + 1 version + 1 env-len + 8 generation + 1 running, with env at max 64.
const MAX_BYTES: usize = 4 + 1 + 1 + 64 + 8 + 1;
const MIN_ENV_LEN: usize = 1;
const MAX_ENV_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub environment: String,
    pub generation: u64,
    pub was_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    Invalid,
    WrongEnvironment,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    NeedsReconciliation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub snapshot: Snapshot,
    pub action: RecoveryAction,
}

// LBST, u8 version1, u8 env-length, ASCII env, u64 BE generation, u8 running0/1.
// Env 1..64 ASCII alnum/-/_, generation>0. Exact length; never grants authority.

fn env_char_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn validate_env(env: &str) -> Result<(), StateError> {
    if !(MIN_ENV_LEN..=MAX_ENV_LEN).contains(&env.len()) {
        return Err(StateError::Invalid);
    }
    if !env.as_bytes().iter().all(|&c| env_char_ok(c)) {
        return Err(StateError::Invalid);
    }
    Ok(())
}

pub fn encode(snapshot: &Snapshot) -> Result<Vec<u8>, StateError> {
    validate_env(&snapshot.environment)?;
    if snapshot.generation == 0 {
        return Err(StateError::Invalid);
    }
    let mut out = Vec::with_capacity(MAX_BYTES);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(snapshot.environment.len() as u8);
    out.extend_from_slice(snapshot.environment.as_bytes());
    out.extend_from_slice(&snapshot.generation.to_be_bytes());
    out.push(u8::from(snapshot.was_running));
    debug_assert!(out.len() <= MAX_BYTES);
    Ok(out)
}

pub fn decode(
    bytes: &[u8],
    environment: &str,
    minimum_generation: u64,
) -> Result<Recovery, StateError> {
    // Validate shape before any slicing: header, exact length, then fields.
    if bytes.len() < MAGIC.len() + 2 || bytes.len() > MAX_BYTES {
        return Err(StateError::Invalid);
    }
    if bytes[..MAGIC.len()] != MAGIC {
        return Err(StateError::Invalid);
    }
    if bytes[MAGIC.len()] != VERSION {
        return Err(StateError::Invalid);
    }
    let env_len = usize::from(bytes[MAGIC.len() + 1]);
    if !(MIN_ENV_LEN..=MAX_ENV_LEN).contains(&env_len) {
        return Err(StateError::Invalid);
    }
    let expected_len = MAGIC.len() + 2 + env_len + 8 + 1;
    if bytes.len() != expected_len {
        return Err(StateError::Invalid);
    }
    let env_bytes = &bytes[MAGIC.len() + 2..MAGIC.len() + 2 + env_len];
    if !env_bytes.iter().all(|&c| env_char_ok(c)) {
        return Err(StateError::Invalid);
    }
    if env_bytes != environment.as_bytes() {
        return Err(StateError::WrongEnvironment);
    }
    let gen_start = MAGIC.len() + 2 + env_len;
    let generation = u64::from_be_bytes(
        bytes[gen_start..gen_start + 8]
            .try_into()
            .map_err(|_| StateError::Invalid)?,
    );
    if generation == 0 {
        return Err(StateError::Invalid);
    }
    let running = match bytes[gen_start + 8] {
        0 => false,
        1 => true,
        _ => return Err(StateError::Invalid),
    };
    if generation < minimum_generation {
        return Err(StateError::Stale);
    }
    let snapshot = Snapshot {
        environment: environment.to_string(),
        generation,
        was_running: running,
    };
    Ok(Recovery {
        snapshot,
        action: RecoveryAction::NeedsReconciliation,
    })
}
