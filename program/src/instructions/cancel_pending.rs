//! `cancel_pending`: close an EXPIRED approval and return its rent to whoever funded it.
//!
//! Accounts: 0 rent_payer [writable], 1 pending [writable].
//! Data:     none.
//!
//! Permissionless: after expiry the approval can never be used, so closing it only tidies up.

use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use super::{check_owned, close_to};
use crate::{error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(LatrixError::InvalidInstructionData.into());
    }
    let [rent_payer, pending, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_owned(pending, state::PENDING_DISCRIMINATOR, state::PENDING_LEN)?;
    if !pending.is_writable() || !rent_payer.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    {
        let p = pending.try_borrow()?;
        if Clock::get()?.slot <= state::read_u64(&p, state::pending::VALID_UNTIL) {
            return Err(LatrixError::NotExpired.into());
        }
        if state::read_32(&p, state::pending::RENT_PAYER) != *rent_payer.address().as_array() {
            return Err(LatrixError::RentPayerMismatch.into());
        }
    }
    close_to(pending, rent_payer)
}
