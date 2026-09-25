use anchor_lang::prelude::*;

#[error_code]
pub enum ShieldedError {
    #[msg("Denomination must be greater than zero")]
    InvalidDenomination,
    #[msg("The Merkle tree is full")]
    TreeFull,
    #[msg("The provided Merkle root is unknown or expired")]
    UnknownRoot,
    #[msg("The zero-knowledge proof is invalid")]
    InvalidProof,
    #[msg("Fee must be less than the denomination")]
    FeeTooHigh,
    #[msg("Malformed verifying key or proof encoding")]
    MalformedInput,
    #[msg("alt_bn128 pairing/curve operation failed")]
    CurveOperationFailed,
}
