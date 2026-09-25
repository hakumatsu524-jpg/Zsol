use anchor_lang::prelude::*;
use anchor_lang::system_program;

pub mod merkle;
pub mod verifier;
pub mod state;
pub mod errors;

use merkle::*;
use state::*;
use errors::ShieldedError;

declare_id!("ZcaShP111111111111111111111111111111111111");

/// A Zcash-style shielded pool on Solana.
///
/// Model:
/// - Users *shield* (deposit) native SOL of a fixed denomination. Doing so inserts a
///   note *commitment* into an on-chain incremental Merkle tree. The commitment hides
///   the note's secret and nullifier.
/// - Users *unshield* (withdraw) by submitting a Groth16 zk-SNARK proving they know a
///   note whose commitment is in the tree, without revealing which one. The proof also
///   reveals a *nullifier* which is recorded to prevent double-spends.
///
/// The zk circuit (commitment = Hash(secret, nullifier), Merkle membership, nullifier
/// derivation) lives off-chain. This program stores the verifying key and enforces the
/// proof on-chain using Solana's alt_bn128 syscalls (see `verifier.rs`).
#[program]
pub mod shielded_pool {
    use super::*;

    /// One-time initialization of the pool: sets the fixed denomination, the empty
    /// Merkle tree, and stores the Groth16 verifying key used to check withdrawals.
    pub fn initialize(
        ctx: Context<Initialize>,
        denomination: u64,
        verifying_key: verifier::VerifyingKeyInput,
    ) -> Result<()> {
        require!(denomination > 0, ShieldedError::InvalidDenomination);

        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.denomination = denomination;
        pool.next_leaf_index = 0;
        pool.root_index = 0;
        pool.vault_bump = ctx.bumps.vault;
        pool.bump = ctx.bumps.pool;

        // Initialize the incremental Merkle tree with zero-value subtree roots.
        let tree = &mut ctx.accounts.tree;
        tree.init();
        pool.current_root = tree.current_root();
        pool.roots[0] = pool.current_root;

        // Persist the verifying key for withdrawal proof verification.
        pool.verifying_key = verifier::VerifyingKey::from_input(verifying_key)?;

        Ok(())
    }

    /// Shield (deposit): transfer `denomination` lamports into the pool vault and
    /// insert `commitment` as a new leaf in the Merkle tree.
    ///
    /// `commitment` must equal Hash(secret, nullifier) computed by the depositor
    /// off-chain. The program never sees `secret` or `nullifier`.
    pub fn shield(ctx: Context<Shield>, commitment: [u8; 32]) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let tree = &mut ctx.accounts.tree;

        require!(
            (tree.next_index as u64) < MAX_LEAVES,
            ShieldedError::TreeFull
        );

        // Move funds from depositor into the pool's vault PDA.
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.depositor.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            pool.denomination,
        )?;

        // Insert the commitment; this recomputes the tree root.
        let leaf_index = tree.insert(commitment)?;
        let new_root = tree.current_root();

        // Record the new root in the ring buffer of recent roots.
        pool.push_root(new_root);
        pool.next_leaf_index = tree.next_index;

        emit!(ShieldEvent {
            commitment,
            leaf_index,
            new_root,
        });

        Ok(())
    }

    /// Unshield (withdraw): verify a Groth16 proof that the caller owns a note in the
    /// tree, then pay `denomination` lamports to `recipient` and burn the nullifier.
    ///
    /// Public inputs bound by the proof:
    /// - `root`: a Merkle root that must match one of the recent roots we retain.
    /// - `nullifier_hash`: revealed to prevent double-spends; recorded on success.
    /// - `recipient` + `fee`: bound into the proof so a relayer cannot redirect funds.
    pub fn unshield(
        ctx: Context<Unshield>,
        proof: verifier::Proof,
        root: [u8; 32],
        nullifier_hash: [u8; 32],
        fee: u64,
    ) -> Result<()> {
        let pool = &ctx.accounts.pool;

        require!(fee < pool.denomination, ShieldedError::FeeTooHigh);
        require!(pool.is_known_root(&root), ShieldedError::UnknownRoot);

        // The nullifier PDA is created here; if it already exists, init fails and the
        // note is rejected as already spent.
        let nullifier_record = &mut ctx.accounts.nullifier;
        nullifier_record.hash = nullifier_hash;
        nullifier_record.spent = true;

        // Build the ordered public-input vector the circuit commits to and verify.
        let public_inputs = verifier::build_public_inputs(
            &root,
            &nullifier_hash,
            &ctx.accounts.recipient.key(),
            fee,
        );
        require!(
            pool.verifying_key.verify(&proof, &public_inputs)?,
            ShieldedError::InvalidProof
        );

        // Pay out from the vault PDA: recipient gets denomination - fee, relayer gets fee.
        let payout = pool
            .denomination
            .checked_sub(fee)
            .ok_or(ShieldedError::FeeTooHigh)?;

        let seeds: &[&[u8]] = &[b"vault", pool.to_account_info().key.as_ref(), &[pool.vault_bump]];
        let signer: &[&[&[u8]]] = &[seeds];

        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                },
                signer,
            ),
            payout,
        )?;

        if fee > 0 {
            system_program::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.system_program.to_account_info(),
                    system_program::Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.relayer.to_account_info(),
                    },
                    signer,
                ),
                fee,
            )?;
        }

        emit!(UnshieldEvent {
            nullifier_hash,
            recipient: ctx.accounts.recipient.key(),
            fee,
        });

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = 8 + Pool::SIZE,
        seeds = [b"pool"],
        bump
    )]
    pub pool: Account<'info, Pool>,

    #[account(
        init,
        payer = authority,
        space = 8 + MerkleTree::SIZE,
        seeds = [b"tree", pool.key().as_ref()],
        bump
    )]
    pub tree: Account<'info, MerkleTree>,

    /// CHECK: PDA that only holds lamports; no data. Validated by seeds.
    #[account(
        seeds = [b"vault", pool.key().as_ref()],
        bump
    )]
    pub vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Shield<'info> {
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(mut, seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,

    #[account(mut, seeds = [b"tree", pool.key().as_ref()], bump)]
    pub tree: Account<'info, MerkleTree>,

    /// CHECK: vault PDA holding pooled lamports.
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump = pool.vault_bump)]
    pub vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proof: verifier::Proof, root: [u8; 32], nullifier_hash: [u8; 32])]
pub struct Unshield<'info> {
    /// Anyone can submit (self-withdraw or a relayer). Pays account rent for the nullifier.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(seeds = [b"pool"], bump = pool.bump)]
    pub pool: Account<'info, Pool>,

    /// CHECK: vault PDA holding pooled lamports.
    #[account(mut, seeds = [b"vault", pool.key().as_ref()], bump = pool.vault_bump)]
    pub vault: UncheckedAccount<'info>,

    /// The nullifier record. `init` fails if this note was already spent.
    #[account(
        init,
        payer = payer,
        space = 8 + Nullifier::SIZE,
        seeds = [b"nullifier", nullifier_hash.as_ref()],
        bump
    )]
    pub nullifier: Account<'info, Nullifier>,

    /// CHECK: recipient is bound into the zk proof's public inputs.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    /// CHECK: relayer receives the fee; may equal payer.
    #[account(mut)]
    pub relayer: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[event]
pub struct ShieldEvent {
    pub commitment: [u8; 32],
    pub leaf_index: u64,
    pub new_root: [u8; 32],
}

#[event]
pub struct UnshieldEvent {
    pub nullifier_hash: [u8; 32],
    pub recipient: Pubkey,
    pub fee: u64,
}
