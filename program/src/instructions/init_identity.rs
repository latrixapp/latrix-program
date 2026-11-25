//! `init_identity`: register a Falcon-512 public key.
//!
//! Accounts: 0 payer [signer, writable], 1 identity [writable], 2 system program.
//! Data:     identity_bump u8, vault_bump u8, agent_bump u8, falcon_pubkey [u8; 897].
//!
//! The identity address is derived from the key, so a key has exactly one identity and nobody can
//! register a different key at it. The key is stored prepared (NTT form) so every later verify is
//! cheaper. The transaction is ~1,150 bytes of 1,232: the 897-byte key leaves no room for a proof
//! of possession, and none is needed - an identity whose key you do not hold is useless to you.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, ProgramResult,
};
use solana_falcon512::{Falcon512Pubkey, FALCON_512_PUBKEY_LEN};

use super::{create_pda, derive_canonical, take, take_u8};
use crate::{auth, error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [payer, identity, _system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !payer.is_writable() || !identity.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut off = 0;
    let identity_bump = take_u8(data, &mut off)?;
    let vault_bump = take_u8(data, &mut off)?;
    let agent_bump = take_u8(data, &mut off)?;
    let pubkey_bytes = take::<FALCON_512_PUBKEY_LEN>(data, &mut off)?;
    if off != data.len() {
        return Err(LatrixError::InvalidInstructionData.into());
    }

    // The key must decode: a malformed key is rejected here, not on its first spend.
    let pubkey = Falcon512Pubkey::<false>::try_from_slice(pubkey_bytes)
        .map_err(|_| LatrixError::InvalidFalconPubkey)?;
    let prepared = pubkey
        .try_prepare_pubkey()
        .map_err(|_| LatrixError::InvalidFalconPubkey)?;

    let pk_hash = auth::pubkey_hash(pubkey_bytes);
    let expected = derive_canonical(&[state::IDENTITY_SEED, &pk_hash], identity_bump)?;
    if identity.address() != &expected {
        return Err(LatrixError::IdentityMismatch.into());
    }
    // Both bumps must be the canonical ones (the addresses every client derives), so execute_call can
    // trust the stored bumps and nobody can register a key with vault / agent PDAs its owner never uses.
    derive_canonical(&[state::VAULT_SEED, identity.address().as_ref()], vault_bump)?;
    derive_canonical(&[state::AGENT_SEED, identity.address().as_ref()], agent_bump)?;

    let bump = [identity_bump];
    let seeds = [
        Seed::from(state::IDENTITY_SEED),
        Seed::from(&pk_hash[..]),
        Seed::from(&bump[..]),
    ];
    create_pda(payer, identity, state::IDENTITY_LEN, &[Signer::from(&seeds)])?;

    let mut d = identity.try_borrow_mut()?;
    d[state::identity::DISC] = state::IDENTITY_DISCRIMINATOR;
    d[state::identity::BUMP] = identity_bump;
    d[state::identity::VAULT_BUMP] = vault_bump;
    d[state::identity::AGENT_BUMP] = agent_bump;
    d[state::identity::NONCE].copy_from_slice(&0u64.to_le_bytes());
    d[state::identity::PK_HASH].copy_from_slice(&pk_hash);
    d[state::identity::PREPARED].copy_from_slice(prepared.as_bytes());
    Ok(())
}
