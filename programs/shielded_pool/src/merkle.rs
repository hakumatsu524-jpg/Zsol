use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use crate::errors::ShieldedError;

/// Tree depth. 20 levels => up to 2^20 (~1,048,576) shielded notes.
pub const TREE_DEPTH: usize = 20;
pub const MAX_LEAVES: u64 = 1u64 << (TREE_DEPTH as u64);

/// An incremental (append-only) Merkle tree.
///
/// We store only the `filled_subtrees` (the left sibling needed at each level to
/// append the next leaf) rather than every node, so insertion is O(depth) in both
/// compute and storage. This is the standard Tornado/Semaphore fixed-depth design.
///
/// NOTE ON HASHING: this uses keccak256 for the node hash so the program compiles and
/// runs with only Solana's built-in syscalls. A production Zcash-style pool should use
/// a SNARK-friendly hash (Poseidon) so the same hash is cheap to prove inside the
/// circuit. If you switch to Poseidon here, the circuit's Merkle hash must match.
#[account]
pub struct MerkleTree {
    pub next_index: u32,
    pub filled_subtrees: [[u8; 32]; TREE_DEPTH],
    pub zeros: [[u8; 32]; TREE_DEPTH],
    pub root: [u8; 32],
}

impl MerkleTree {
    pub const SIZE: usize = 4 + (32 * TREE_DEPTH) + (32 * TREE_DEPTH) + 32;

    /// Precompute the "zero" hash at each level (hash of two zero children, etc.)
    /// and seed the filled subtrees with them.
    pub fn init(&mut self) {
        let mut current = zero_leaf();
        for level in 0..TREE_DEPTH {
            self.zeros[level] = current;
            self.filled_subtrees[level] = current;
            current = hash_pair(&current, &current);
        }
        self.next_index = 0;
        self.root = current;
    }

    pub fn current_root(&self) -> [u8; 32] {
        self.root
    }

    /// Append a leaf, updating filled subtrees and the root. Returns the leaf index.
    pub fn insert(&mut self, leaf: [u8; 32]) -> Result<u64> {
        let index = self.next_index;
        require!((index as u64) < MAX_LEAVES, ShieldedError::TreeFull);

        let mut current_index = index;
        let mut current_hash = leaf;
        let mut left;
        let mut right;

        for level in 0..TREE_DEPTH {
            if current_index % 2 == 0 {
                // We're a left child: our right sibling is still the zero subtree.
                left = current_hash;
                right = self.zeros[level];
                self.filled_subtrees[level] = current_hash;
            } else {
                // We're a right child: our left sibling was stored earlier.
                left = self.filled_subtrees[level];
                right = current_hash;
            }
            current_hash = hash_pair(&left, &right);
            current_index /= 2;
        }

        self.root = current_hash;
        self.next_index += 1;
        Ok(index as u64)
    }
}

/// The value of an empty leaf. keccak256("shielded_pool:zero") truncated to a field-ish
/// 32 bytes. (For Poseidon over BN254 you'd reduce this modulo the field prime.)
pub fn zero_leaf() -> [u8; 32] {
    keccak::hash(b"shielded_pool:zero").to_bytes()
}

pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    keccak::hash(&buf).to_bytes()
}
