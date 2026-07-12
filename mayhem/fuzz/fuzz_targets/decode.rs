//! Ported from the pre-two-branch integration (archive/original-master:
//! fuzz/fuzz_targets/decode.rs). Same target name and code path (decode a
//! hostile token). The old harness built `DecodingKey`/`Validation` via
//! `Arbitrary` derives that upstream no longer ships (the fork patched
//! upstream `src/` to add an `arbitrary` feature — not additive), so this
//! harness derives them from the raw input instead: first NUL-separated
//! chunk = HMAC secret, rest = token. Also exercises `decode_header`,
//! `dangerous::insecure_decode` and JWK parsing on the same bytes.
#![no_main]

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let (secret, token) = match data.iter().position(|&b| b == 0) {
        Some(pos) => (&data[..pos], &data[pos + 1..]),
        None => (&b"fuzz-secret"[..], data),
    };

    // Header parsing (base64 + serde) on the raw token bytes.
    let _ = decode_header(token);

    // Full decode path: header, claims, signature verification (HMAC family).
    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let mut validation = Validation::new(alg);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let _: Result<TokenData<Value>, _> =
            decode(token, &DecodingKey::from_secret(secret), &validation);
    }

    // Signature-less decode (dangerous API): exercises the claims
    // deserialization path even when the signature can never match.
    let _: Result<TokenData<Value>, _> = jsonwebtoken::dangerous::insecure_decode(token);

    // JWK parsing on the same bytes.
    if let Ok(s) = std::str::from_utf8(token) {
        if let Ok(jwk) = serde_json::from_str::<jsonwebtoken::jwk::Jwk>(s) {
            let _ = DecodingKey::from_jwk(&jwk);
        }
    }
});
