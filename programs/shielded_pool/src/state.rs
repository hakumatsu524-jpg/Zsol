use anchor_lang::prelude::*;
use crate::verifier::VerifyingKey;

/// Number of recent Merkle roots retained so that proofs generated against a
/// slightly stale tree still verify (deposits may land between proof gen and submit).
pub const ROOT_HISTORY_SIZE: usize = 32;

#[account]
pub struct Pool {
    pub authority: Pubkey,
    /// Fixed deposit/withdraw amount in lamports. Fixed denomination is what gives
    /// the pool its anonymity set (all notes look identical).
    pub denomination: u64,
    /// Next leaf index to be written (also the count of inserted commitments).
    pub next_leaf_index: u32,
    /// Ring-buffer cursor into `roots`.
    pub root_index: u8,
    /// Most recently computed root (mirror of roots[root_index]).
    pub current_root: [u8; 32],
    /// Ring buffer of recent roots.
    pub roots: [[u8; 32]; ROOT_HISTORY_SIZE],
    /// Groth16 verifying key for withdrawal proofs.
    pub verifying_key: VerifyingKey,
    pub vault_bump: u8,
    pub bump: u8,
}

impl Pool {
    pub const SIZE: usize = 32
        + 8
        + 4
        + 1
        + 32
        + (32 * ROOT_HISTORY_SIZE)
        + VerifyingKey::SIZE
        + 1
        + 1;

    /// Push a freshly computed root into the ring buffer.
    pub fn push_root(&mut self, root: [u8; 32]) {
        self.root_index = ((self.root_index as usize + 1) % ROOT_HISTORY_SIZE) as u8;
        self.roots[self.root_index as usize] = root;
        self.current_root = root;
    }

    /// Was `root` one of the recent roots we still accept proofs against?
    pub fn is_known_root(&self, root: &[u8; 32]) -> bool {
        if *root == [0u8; 32] {
            return false;
        }
        self.roots.iter().any(|r| r == root)
    }
}

/// A spent-note marker. Its mere existence (as a PDA keyed by the nullifier hash)
/// proves the note was already withdrawn, so `init` on a duplicate fails.
#[account]
pub struct Nullifier {
    pub hash: [u8; 32],
    pub spent: bool,
}

impl Nullifier {
    pub const SIZE: usize = 32 + 1;
}
