#![no_main]
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, DecodingKey, Validation)| {
    let _: Result<TokenData<Vec<u8>>, _> = decode(&data.0, &data.1, &data.2);
});
