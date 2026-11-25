pub mod attest_launch;
pub mod authorize_call;
pub mod buyback_burn;
pub mod buyback_burn_damm;
pub mod claim_fees;
pub mod claim_fees_damm;
pub mod external;
pub mod cancel_pending;
pub mod execute_call;
pub mod init_identity;
pub mod set_crank;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

use crate::{error::LatrixError, state};

/// `create_program_address(seeds ++ [bump])`, or `InvalidBump`.
pub fn derive(seeds: &[&[u8]], bump: u8) -> Result<Address, ProgramError> {
    let bump = [bump];
    let mut all: [&[u8]; 4] = [&[]; 4];
    let n = seeds.len();
    all[..n].copy_from_slice(seeds);
    all[n] = &bump;
    Address::create_program_address(&all[..n + 1], &crate::ID).map_err(|_| LatrixError::InvalidBump.into())
}

/// The canonical PDA of `seeds` (find_program_address). `bump` must be the canonical one: accepting any
/// valid bump would let a second account exist for the same seeds (e.g. a second launch record per mint).
pub fn derive_canonical(seeds: &[&[u8]], bump: u8) -> Result<Address, ProgramError> {
    let (address, canonical) = Address::find_program_address(seeds, &crate::ID);
    if bump != canonical {
        return Err(LatrixError::InvalidBump.into());
    }
    Ok(address)
}

/// Creates `account` (a PDA of this program, signed by `signer`) with `space` bytes, rent paid by `payer`. Works even
/// when someone already sent lamports to the address: a plain create_account fails forever then, so anyone could
/// block an identity's next approval (or a registration, or the config) by pre-funding a predictable address.
pub fn create_pda(payer: &AccountView, account: &AccountView, space: usize, signer: &[pinocchio::cpi::Signer]) -> ProgramResult {
    use pinocchio::sysvars::{rent::Rent, Sysvar};
    use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
    let rent = Rent::get()?.try_minimum_balance(space)?;
    if account.lamports() == 0 {
        return CreateAccount { from: payer, to: account, lamports: rent, space: space as u64, owner: &crate::ID }.invoke_signed(signer);
    }
    if !account.owned_by(&pinocchio_system::ID) || account.data_len() != 0 {
        return Err(LatrixError::InvalidAccount.into());
    }
    let short = rent.saturating_sub(account.lamports());
    if short > 0 {
        Transfer { from: payer, to: account, lamports: short }.invoke()?;
    }
    Allocate { account, space: space as u64 }.invoke_signed(signer)?;
    Assign { account, owner: &crate::ID }.invoke_signed(signer)
}

/// The identity's vault PDA: `["vault", identity, vault_bump]`.
pub fn vault_address(identity: &Address, vault_bump: u8) -> Result<Address, ProgramError> {
    derive(&[state::VAULT_SEED, identity.as_ref()], vault_bump)
}

/// The identity's agent PDA: `["agent", identity, agent_bump]`.
pub fn agent_address(identity: &Address, agent_bump: u8) -> Result<Address, ProgramError> {
    derive(&[state::AGENT_SEED, identity.as_ref()], agent_bump)
}

/// Checks the account is a Latrix account of `disc` with at least `len` bytes.
pub fn check_owned(account: &AccountView, disc: u8, len: usize) -> Result<(), ProgramError> {
    if !account.owned_by(&crate::ID) || account.data_len() < len {
        return Err(LatrixError::InvalidAccount.into());
    }
    let data = account.try_borrow()?;
    if data[0] != disc {
        return Err(LatrixError::InvalidAccount.into());
    }
    Ok(())
}

/// Moves all lamports to `to` and closes `account`.
pub fn close_to(account: &mut AccountView, to: &mut AccountView) -> Result<(), ProgramError> {
    let lamports = account.lamports();
    to.set_lamports(
        to.lamports()
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    account.set_lamports(0);
    account.close()
}

/// Reads `N` bytes from `data` at `*off`, advancing it.
pub fn take<'a, const N: usize>(data: &'a [u8], off: &mut usize) -> Result<&'a [u8; N], ProgramError> {
    let s = data
        .get(*off..*off + N)
        .ok_or(LatrixError::InvalidInstructionData)?;
    *off += N;
    Ok(s.try_into().map_err(|_| LatrixError::InvalidInstructionData)?)
}

pub fn take_u64(data: &[u8], off: &mut usize) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(*take::<8>(data, off)?))
}

pub fn take_u8(data: &[u8], off: &mut usize) -> Result<u8, ProgramError> {
    Ok(take::<1>(data, off)?[0])
}
