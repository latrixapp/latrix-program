//! `authorize_call`: the Falcon key approves one exact instruction (see `auth::call_digest`).
//!
//! Accounts: 0 payer [signer, writable], 1 identity [writable], 2 pending [writable],
//!           3 system program.
//! Data:     nonce u64, valid_until_slot u64, call_digest [u8; 32], pending_bump u8,
//!           signature [u8; 666].
//!
//! Verifies the Falcon signature over `auth::call_message`, consumes the nonce and records a
//! `Pending` approval for `call_digest`. The payer only pays (and gets the rent back later): it
//! has no say over what is approved.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use solana_falcon512::{Falcon512PreparedPubkey, Falcon512Signature, FALCON_512_SIGNATURE_LEN};

use super::{create_pda, check_owned, derive_canonical, take, take_u64, take_u8};
use crate::{auth, error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [payer, identity, pending, _system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !payer.is_writable() || !identity.is_writable() || !pending.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    check_owned(identity, state::IDENTITY_DISCRIMINATOR, state::IDENTITY_LEN)?;

    let mut off = 0;
    let nonce = take_u64(data, &mut off)?;
    let valid_until_slot = take_u64(data, &mut off)?;
    let call_digest = *take::<32>(data, &mut off)?;
    let pending_bump = take_u8(data, &mut off)?;
    let signature = take::<FALCON_512_SIGNATURE_LEN>(data, &mut off)?;
    if off != data.len() {
        return Err(LatrixError::InvalidInstructionData.into());
    }

    if Clock::get()?.slot > valid_until_slot {
        return Err(LatrixError::Expired.into());
    }

    let identity_addr = *identity.address();
    {
        let d = identity.try_borrow()?;
        if state::read_u64(&d, state::identity::NONCE) != nonce {
            return Err(LatrixError::InvalidNonce.into());
        }
        let message = auth::call_message(&crate::ID, &identity_addr, &call_digest, nonce, valid_until_slot);
        let prepared = Falcon512PreparedPubkey::<false>::try_from_slice(&d[state::identity::PREPARED])
            .map_err(|_| LatrixError::InvalidAccount)?;
        let sig = Falcon512Signature::from_ref(signature);
        if !sig.verify_with_prepared(&message, prepared) {
            return Err(LatrixError::InvalidSignature.into());
        }
    }
    {
        let mut d = identity.try_borrow_mut()?;
        let next = nonce.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;
        d[state::identity::NONCE].copy_from_slice(&next.to_le_bytes());
    }

    let nonce_le = nonce.to_le_bytes();
    let expected = derive_canonical(&[state::PENDING_SEED, identity_addr.as_ref(), &nonce_le], pending_bump)?;
    if pending.address() != &expected {
        return Err(LatrixError::InvalidBump.into());
    }
    let bump = [pending_bump];
    let seeds = [
        Seed::from(state::PENDING_SEED),
        Seed::from(identity_addr.as_ref()),
        Seed::from(&nonce_le[..]),
        Seed::from(&bump[..]),
    ];
    create_pda(payer, pending, state::PENDING_LEN, &[Signer::from(&seeds)])?;

    let payer_addr = *payer.address();
    let mut d = pending.try_borrow_mut()?;
    d[state::pending::DISC] = state::PENDING_DISCRIMINATOR;
    d[state::pending::BUMP] = pending_bump;
    d[state::pending::VALID_UNTIL].copy_from_slice(&valid_until_slot.to_le_bytes());
    d[state::pending::NONCE].copy_from_slice(&nonce_le);
    d[state::pending::IDENTITY].copy_from_slice(identity_addr.as_ref());
    d[state::pending::DIGEST].copy_from_slice(&call_digest);
    d[state::pending::RENT_PAYER].copy_from_slice(payer_addr.as_ref());
    Ok(())
}
