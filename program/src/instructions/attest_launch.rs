//! `attest_launch`: put Latrix ON the launch transaction and record which identity launched the coin.
//!
//! Accounts: 0 funder [signer, writable] (the one-time launch wallet: pays the record's rent),
//!           1 rent_payer [writable] (funded the approval: gets its rent back),
//!           2 identity, 3 pending [writable], 4 mint, 5 pool,
//!           6 launch record [writable] (PDA `["launch", mint]`), 7 system program.
//! Data:     nonce u64, launch_bump u8, dev_share_bps u16 (0..=10000).
//!
//! Sits at the TOP LEVEL of the launch transaction, next to Meteora's pool creation and first swap,
//! so explorers list "Interact with program Latrix" and DBC still sees its own top-level creation
//! (which the minimum-fee dev buy requires). It consumes a Falcon approval of
//! `auth::launch_digest(mint, pool)` - a launch cannot be attributed to an identity whose key did not
//! sign for that exact mint and pool - and writes a permanent record any site or tracker can read.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use super::{create_pda, check_owned, close_to, derive_canonical, take_u64, take_u8};
use crate::{auth, error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [funder, rent_payer, identity, pending, mint, pool, record, _system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !funder.is_signer() || !funder.is_writable() || !record.is_writable() || !pending.is_writable() || !rent_payer.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // The coin's mint keypair must sign: only whoever creates the coin (in this same transaction) can
    // attest it, so nobody can copy the instruction out of a pending launch and consume its approval.
    if !mint.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    check_owned(identity, state::IDENTITY_DISCRIMINATOR, state::IDENTITY_LEN)?;
    check_owned(pending, state::PENDING_DISCRIMINATOR, state::PENDING_LEN)?;

    let mut off = 0;
    let nonce = take_u64(data, &mut off)?;
    let launch_bump = take_u8(data, &mut off)?;
    let dev_share_bps = u16::from_le_bytes(*super::take::<2>(data, &mut off)?);
    if dev_share_bps > 10_000 {
        return Err(LatrixError::InvalidFeeSplit.into());
    }
    if off != data.len() {
        return Err(LatrixError::InvalidInstructionData.into());
    }

    let identity_addr = *identity.address();
    let mint_addr = *mint.address();
    let pool_addr = *pool.address();
    let slot = Clock::get()?.slot;
    {
        let p = pending.try_borrow()?;
        if state::read_32(&p, state::pending::IDENTITY) != *identity_addr.as_array() {
            return Err(LatrixError::InvalidAccount.into());
        }
        if state::read_u64(&p, state::pending::NONCE) != nonce {
            return Err(LatrixError::InvalidNonce.into());
        }
        if slot > state::read_u64(&p, state::pending::VALID_UNTIL) {
            return Err(LatrixError::Expired.into());
        }
        if state::read_32(&p, state::pending::RENT_PAYER) != *rent_payer.address().as_array() {
            return Err(LatrixError::RentPayerMismatch.into());
        }
        if state::read_32(&p, state::pending::DIGEST) != auth::launch_digest(mint_addr.as_ref(), pool_addr.as_ref(), dev_share_bps) {
            return Err(LatrixError::LaunchMismatch.into());
        }
    }

    // The fee vault (the pool's creator after launch) - its bump is stored so later claims are cheap.
    let (_, fee_vault_bump) = pinocchio::Address::find_program_address(&[state::FEE_VAULT_SEED, mint_addr.as_ref()], &crate::ID);

    // One record per mint, at its CANONICAL address only; creating it twice fails, so a coin can be attested once.
    let expected = derive_canonical(&[state::LAUNCH_SEED, mint_addr.as_ref()], launch_bump)?;
    if record.address() != &expected {
        return Err(LatrixError::InvalidBump.into());
    }
    let bump = [launch_bump];
    let seeds = [Seed::from(state::LAUNCH_SEED), Seed::from(mint_addr.as_ref()), Seed::from(&bump[..])];
    create_pda(funder, record, state::LAUNCH_LEN, &[Signer::from(&seeds)])?;
    {
        let mut d = record.try_borrow_mut()?;
        d[state::launch::DISC] = state::LAUNCH_DISCRIMINATOR;
        d[state::launch::BUMP] = launch_bump;
        d[state::launch::DEV_SHARE_BPS].copy_from_slice(&dev_share_bps.to_le_bytes());
        d[state::launch::FEE_VAULT_BUMP] = fee_vault_bump;
        d[state::launch::SLOT].copy_from_slice(&slot.to_le_bytes());
        d[state::launch::IDENTITY].copy_from_slice(identity_addr.as_ref());
        d[state::launch::MINT].copy_from_slice(mint_addr.as_ref());
        d[state::launch::POOL].copy_from_slice(pool_addr.as_ref());
    }

    // Single use.
    close_to(pending, rent_payer)
}
