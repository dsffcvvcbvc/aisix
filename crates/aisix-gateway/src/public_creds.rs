//! Public upstream client identifiers.
//!
//! Mirrors `open-sse/utils/publicCreds.ts` (and its mandatory pattern in
//! `docs/security/PUBLIC_CREDS.md`): some upstream CLIs ship OAuth client
//! ids inside their public binaries. For installed/native apps using PKCE
//! those values are public by design —
//! <https://developers.google.com/identity/protocols/oauth2/native-app> —
//! and embedding them keeps the OAuth flow working for operators who never
//! set the env override.
//!
//! Scanner-shaped values (anything a secret scanner would match) are stored
//! as XOR-masked byte sequences and decoded at runtime. This is
//! obfuscation, not encryption: anyone reading the source can recover the
//! value, which is fine because the value is public by design. The only
//! goal is to keep scanner patterns out of the source text. Short,
//! non-secret ids that match no scanner pattern live as plain literals at
//! their call sites instead.
//!
//! Resolution order (same as the TS `resolvePublicCred`): the first
//! non-empty env var wins (raw literal passed through untouched, so
//! existing overrides keep working with zero migration); otherwise the
//! embedded masked default is decoded.

/// XOR mask shared with the TS side (`open-sse/utils/publicCreds.ts`).
/// Kept identical so masked sequences can be copied between the two
/// codebases without re-encoding.
const PUBLIC_CRED_MASK: &[u8] = b"omniroute-public-v1";

/// Decode one embedded masked byte sequence to its plaintext value.
pub fn decode_public_cred_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ PUBLIC_CRED_MASK[i % PUBLIC_CRED_MASK.len()])
        .collect::<Vec<u8>>()
        .into_iter()
        .map(char::from)
        .collect()
}

/// Resolve a public client identifier: the first non-empty env var in
/// `env_names` wins (trimmed, passed through verbatim); otherwise the
/// embedded `masked_default` is decoded. Returns `""` when neither is set,
/// so callers keep their existing fail-closed shape.
pub fn resolve_public_cred(masked_default: &[u8], env_names: &[&str]) -> String {
    resolve_public_cred_with_lookup(masked_default, env_names, |name| std::env::var(name).ok())
}

/// [`resolve_public_cred`] with an injectable env lookup, so unit tests
/// can pin the environment without touching the process globals.
fn resolve_public_cred_with_lookup(
    masked_default: &[u8],
    env_names: &[&str],
    lookup: impl Fn(&str) -> Option<String>,
) -> String {
    for name in env_names {
        if let Some(raw) = lookup(name) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if masked_default.is_empty() {
        return String::new();
    }
    decode_public_cred_bytes(masked_default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masked_round_trip_is_stable() {
        // Mask is an involution: decoding twice-encoded bytes must give
        // the input back. Exercises the real path without embedding any
        // scanner-visible literal.
        let plain = b"smoke-check-value-123";
        let masked: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ PUBLIC_CRED_MASK[i % PUBLIC_CRED_MASK.len()])
            .collect();
        assert_eq!(decode_public_cred_bytes(&masked), "smoke-check-value-123");
    }

    #[test]
    fn env_override_wins_over_embedded_default() {
        let masked: Vec<u8> = b"x"
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ PUBLIC_CRED_MASK[i % PUBLIC_CRED_MASK.len()])
            .collect();
        let resolved =
            resolve_public_cred_with_lookup(&masked, &["EV_A", "EV_B"], |name| match name {
                "EV_A" => Some("   ".to_string()),
                "EV_B" => Some("  raw-override  ".to_string()),
                _ => None,
            });
        assert_eq!(resolved, "raw-override");
    }

    #[test]
    fn empty_env_falls_back_to_embedded_default() {
        let plain = b"fallback-id";
        let masked: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ PUBLIC_CRED_MASK[i % PUBLIC_CRED_MASK.len()])
            .collect();
        assert_eq!(
            resolve_public_cred_with_lookup(&masked, &["EV_MISSING"], |_| None),
            "fallback-id"
        );
    }

    #[test]
    fn no_default_and_no_env_resolves_empty_fail_closed() {
        assert_eq!(
            resolve_public_cred_with_lookup(&[], &["EV_MISSING"], |_| None),
            ""
        );
    }
}
