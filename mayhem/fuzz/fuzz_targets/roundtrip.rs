//! Ported from the pre-two-branch integration (archive/original-master:
//! fuzz/fuzz_targets/roundtrip.rs). Same target name and property: whatever
//! claims we encode must decode back identically with the same key. The old
//! harness used `Arbitrary` derives the fork patched into upstream `src/`
//! (not additive); this one derives the secret / algorithm / claims from the
//! raw fuzz input instead and keeps the same assert-equality oracle.
#![no_main]

use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct Claims {
    sub: String,
    data: Vec<u8>,
    exp: u64,
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let alg = match data[0] % 3 {
        0 => Algorithm::HS256,
        1 => Algorithm::HS384,
        _ => Algorithm::HS512,
    };
    let split = 1 + (data[1] as usize % (data.len() - 1));
    let (secret, rest) = data.split_at(split);

    let claims = Claims {
        sub: String::from_utf8_lossy(rest).into_owned(),
        data: rest.to_vec(),
        exp: jsonwebtoken::get_current_timestamp() + 3600,
    };

    let token = encode(&Header::new(alg), &claims, &EncodingKey::from_secret(secret))
        .expect("HMAC encode of serializable claims must succeed");

    let mut validation = Validation::new(alg);
    let decoded = decode::<Claims>(&token, &DecodingKey::from_secret(secret), &validation)
        .expect("decode of a freshly encoded token with the same key must succeed");
    assert_eq!(decoded.claims, claims);

    // The same token must NOT verify under a different secret (unless the
    // secret happens to be identical bytes).
    let mut other = secret.to_vec();
    other.push(0x5a);
    validation.validate_exp = true;
    let bad = decode::<Claims>(&token, &DecodingKey::from_secret(&other), &validation);
    assert!(bad.is_err(), "token verified under a different key");
});
