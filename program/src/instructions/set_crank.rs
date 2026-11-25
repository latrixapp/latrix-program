//! `set_crank`: the program's upgrade authority sets (or rotates) the crank, the only key allowed to run
//! buybacks. Creates the Latrix config PDA `["config"]` on first use.
//!
//! Accounts: 0 upgrade authority [signer, writable] (pays the config's rent the first time),
//!           1 config [writable], 2 this program's ProgramData account, 3 system program.
//! Data:     crank [u8; 32].
//!
//! The authority is read from the ProgramData account the loader keeps (upgradeable loader state
//! `ProgramData { slot, upgrade_authority: Option<Pubkey> }`), so whoever can upgrade the program - and
//! nobody else - picks the crank. A program made immutable can no longer change it.

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};

use super::{check_owned, create_pda, take};
use crate::{error::LatrixError, state};

const BPF_UPGRADEABLE_LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [authority, config, program_data, _system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let mut off = 0;
    let crank = *take::<32>(data, &mut off)?;
    if off != data.len() {
        return Err(LatrixError::InvalidInstructionData.into());
    }
    if !authority.is_signer() || !authority.is_writable() || !config.is_writable() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // The signer must be this program's upgrade authority.
    if !program_data.owned_by(&BPF_UPGRADEABLE_LOADER)
        || *program_data.address() != Address::find_program_address(&[crate::ID.as_ref()], &BPF_UPGRADEABLE_LOADER).0
    {
        return Err(LatrixError::InvalidAccount.into());
    }
    {
        let d = program_data.try_borrow()?;
        if d.len() < 45 || d[0..4] != 3u32.to_le_bytes() || d[12] != 1 || d[13..45] != *authority.address().as_array() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }

    let (expected, bump) = Address::find_program_address(&[state::CONFIG_SEED], &crate::ID);
    if *config.address() != expected {
        return Err(LatrixError::InvalidBump.into());
    }
    if !config.owned_by(&crate::ID) {
        let b = [bump];
        let seeds = [Seed::from(state::CONFIG_SEED), Seed::from(&b[..])];
        create_pda(authority, config, state::CONFIG_LEN, &[Signer::from(&seeds)])?;
        let mut d = config.try_borrow_mut()?;
        d[state::config::DISC] = state::CONFIG_DISCRIMINATOR;
        d[state::config::BUMP] = bump;
    } else {
        check_owned(config, state::CONFIG_DISCRIMINATOR, state::CONFIG_LEN)?;
    }
    config.try_borrow_mut()?[state::config::CRANK].copy_from_slice(&crank);
    Ok(())
}
