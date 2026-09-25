use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    alt_bn128::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing},
    keccak,
};
use crate::errors::ShieldedError;

/// Number of public inputs the withdrawal circuit exposes:
/// [ root, nullifier_hash, recipient, fee ] each encoded as one BN254 field element.
pub const NUM_PUBLIC_INPUTS: usize = 4;

/// A Groth16 proof over the BN254 (alt_bn128) curve.
/// - `a`: G1 point (64 bytes)
/// - `b`: G2 point (128 bytes)
/// - `c`: G1 point (64 bytes)
/// All points are big-endian, uncompressed, matching Solana's alt_bn128 syscall layout.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

/// Input form of the verifying key passed at initialization. `ic` has one G1 point per
/// public input plus one (NUM_PUBLIC_INPUTS + 1 total).
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VerifyingKeyInput {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

/// Stored verifying key (fixed-size `ic` so it fits an Anchor account layout).
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: [[u8; 64]; NUM_PUBLIC_INPUTS + 1],
}

impl VerifyingKey {
    pub const SIZE: usize = 64 + 128 + 128 + 128 + (64 * (NUM_PUBLIC_INPUTS + 1));

    pub fn from_input(input: VerifyingKeyInput) -> Result<Self> {
        require!(
            input.ic.len() == NUM_PUBLIC_INPUTS + 1,
            ShieldedError::MalformedInput
        );
        let mut ic = [[0u8; 64]; NUM_PUBLIC_INPUTS + 1];
        for (i, point) in input.ic.iter().enumerate() {
            ic[i] = *point;
        }
        Ok(Self {
            alpha_g1: input.alpha_g1,
            beta_g2: input.beta_g2,
            gamma_g2: input.gamma_g2,
            delta_g2: input.delta_g2,
            ic,
        })
    }

    /// Groth16 verification using Solana's alt_bn128 syscalls.
    ///
    /// Computes vk_x = IC[0] + sum_i (public_i * IC[i+1]), then checks the pairing:
    ///   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    pub fn verify(&self, proof: &Proof, public_inputs: &[[u8; 32]; NUM_PUBLIC_INPUTS]) -> Result<bool> {
        // vk_x starts at IC[0].
        let mut vk_x = self.ic[0];

        for i in 0..NUM_PUBLIC_INPUTS {
            // term = public_i * IC[i+1]  (G1 scalar mul: input is 64-byte point || 32-byte scalar)
            let mut mul_input = [0u8; 96];
            mul_input[..64].copy_from_slice(&self.ic[i + 1]);
            mul_input[64..].copy_from_slice(&public_inputs[i]);
            let term = alt_bn128_multiplication(&mul_input)
                .map_err(|_| error!(ShieldedError::CurveOperationFailed))?;

            // vk_x = vk_x + term  (G1 addition: two 64-byte points)
            let mut add_input = [0u8; 128];
            add_input[..64].copy_from_slice(&vk_x);
            add_input[64..].copy_from_slice(&term);
            let sum = alt_bn128_addition(&add_input)
                .map_err(|_| error!(ShieldedError::CurveOperationFailed))?;
            vk_x.copy_from_slice(&sum);
        }

        // Negate A for the pairing check (e(-A,B) * ... == 1).
        let neg_a = negate_g1(&proof.a);

        // Pairing input is a sequence of (G1 (64) || G2 (128)) = 192-byte chunks.
        let mut pairing_input = Vec::with_capacity(192 * 4);
        pairing_input.extend_from_slice(&neg_a);
        pairing_input.extend_from_slice(&proof.b);
        pairing_input.extend_from_slice(&self.alpha_g1);
        pairing_input.extend_from_slice(&self.beta_g2);
        pairing_input.extend_from_slice(&vk_x);
        pairing_input.extend_from_slice(&self.gamma_g2);
        pairing_input.extend_from_slice(&proof.c);
        pairing_input.extend_from_slice(&self.delta_g2);

        let result = alt_bn128_pairing(&pairing_input)
            .map_err(|_| error!(ShieldedError::CurveOperationFailed))?;

        // The syscall returns a 32-byte big-endian 1 when the pairing product is identity.
        Ok(result.last() == Some(&1u8) && result[..31].iter().all(|&b| b == 0))
    }
}

/// The BN254 base field prime p. G1 negation is (x, p - y).
const BN254_FIELD_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// Negate a G1 point encoded as x(32) || y(32), big-endian.
fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    let mut out = *point;
    let y = &point[32..64];
    // If y == 0 the point is either infinity or invalid; leave as-is.
    if y.iter().all(|&b| b == 0) {
        return out;
    }
    let neg_y = big_endian_sub(&BN254_FIELD_MODULUS, y);
    out[32..64].copy_from_slice(&neg_y);
    out
}

/// Compute a - b for 32-byte big-endian values, assuming a >= b.
fn big_endian_sub(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let av = a[i] as i16;
        let bv = b[i] as i16;
        let mut diff = av - bv - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[i] = diff as u8;
    }
    result
}

/// Assemble the ordered public-input field elements the circuit is expected to expose.
///
/// Each element must be a canonical BN254 field element (< field modulus). Hash-derived
/// values (recipient, fee) are keccak-reduced by masking the top byte; your circuit must
/// apply the exact same reduction so the public signals line up.
pub fn build_public_inputs(
    root: &[u8; 32],
    nullifier_hash: &[u8; 32],
    recipient: &Pubkey,
    fee: u64,
) -> [[u8; 32]; NUM_PUBLIC_INPUTS] {
    let mut recipient_field = keccak::hash(recipient.as_ref()).to_bytes();
    // Mask the top 3 bits so the value is comfortably below the BN254 field modulus.
    recipient_field[0] &= 0x1f;

    let mut fee_field = [0u8; 32];
    fee_field[24..].copy_from_slice(&fee.to_be_bytes());

    [*root, *nullifier_hash, recipient_field, fee_field]
}
