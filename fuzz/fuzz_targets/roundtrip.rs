#![no_main]
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (Header, &[u8], EncodingKey, DecodingKey, Validation)| {
    if let Ok(encoded) = encode(&data.0, &data.1, &data.2) {
        let token_result: Result<TokenData<Vec<u8>>, _> = decode(&encoded, &data.3, &data.4);
        if let Ok(token) = token_result {
            assert_eq!(token.claims, data.1);
        }
    }
});
