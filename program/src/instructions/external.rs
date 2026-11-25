//! The outside programs claim_fees / buyback_burn call: Meteora DBC (instructions encoded by hand from
//! its published IDL - no Meteora code is used) and the SPL Token program.

use pinocchio::{error::ProgramError, AccountView, Address};

use crate::{error::LatrixError, state};

pub const DBC: Address = Address::from_str_const("dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN");
pub const DBC_POOL_AUTHORITY: Address = Address::from_str_const("FhVo3mqL8PW5pH5U2CN4XE33DokiyZnUwuGpH2hmHLuM");
pub const TOKEN_PROGRAM: Address = Address::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const ATA_PROGRAM: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const WSOL: Address = Address::from_str_const("So11111111111111111111111111111111111111112");

/// Meteora DAMM v2 (cp-amm): where a coin goes when it graduates from its bonding curve.
pub const DAMM_V2: Address = Address::from_str_const("cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG");
pub const DAMM_POOL_AUTHORITY: Address = Address::from_str_const("HLnpSz9h2S4hiLQ43rnSD9XkcUThA7B8hQMKmDaiTLcC");
pub const DAMM_EVENT_AUTHORITY: Address = Address::from_str_const("3rmHSu74h1ZcmAisVcWerTCiRDQbUrBKmcwptYGjHfet");
/// DAMM v2 `swap(amount_in u64, minimum_amount_out u64)` (same discriminator as DBC's swap).
pub const DAMM_SWAP: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];
/// DAMM v2 Pool layout (cp_amm 0.2.0 IDL): token_a_mint @168, token_b_mint @200, token_a_vault @232,
/// token_b_vault @264, creator @648; account size 1112.
pub mod damm_pool {
    pub const TOKEN_A_MINT: core::ops::Range<usize> = 168..200;
    pub const TOKEN_B_MINT: core::ops::Range<usize> = 200..232;
    pub const TOKEN_A_VAULT: core::ops::Range<usize> = 232..264;
    pub const TOKEN_B_VAULT: core::ops::Range<usize> = 264..296;
    pub const CREATOR: core::ops::Range<usize> = 648..680;
    pub const LEN: usize = 1112;
}

/// DAMM v2 `claim_position_fee()` (no arguments).
pub const DAMM_CLAIM_POSITION_FEE: [u8; 8] = [180, 38, 154, 17, 133, 33, 162, 211];
/// DAMM v2 Position account: discriminator, then pool @8, nft_mint @40.
pub const DAMM_POSITION_DISCRIMINATOR: [u8; 8] = [170, 188, 143, 228, 122, 64, 247, 208];
pub mod damm_position {
    pub const POOL: core::ops::Range<usize> = 8..40;
    pub const MIN_LEN: usize = 72;
}

/// DBC `claim_creator_trading_fee(max_base_amount u64, max_quote_amount u64)`.
pub const DBC_CLAIM_CREATOR_FEE: [u8; 8] = [82, 220, 250, 189, 3, 85, 107, 45];
/// DBC `swap(amount_in u64, minimum_amount_out u64)`.
pub const DBC_SWAP: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

/// Helius Privacy Rings shielded pool, and its `transact` instruction tag.
pub const SHIELDED_POOL: Address = Address::from_str_const("ring1GaLCuJnkUMVkX2JeZLTTX17wKsV4fZmPVzXANW");
pub const RINGS_TRANSACT: u8 = 16;

/// True for a Rings `transact` whose public interface transfers are all WITHDRAWALS (out of the pool). Its
/// account 0 is the payer, who only pays the rent of the records the spend creates; a deposit would instead take
/// the payer's own funds into the pool. Layout: tag u8, expiry u64, tx viewing pk [33], salt [16], n u8, then per
/// transfer: kind u8 (0 sol deposit, 1 sol withdrawal, 2 spl deposit, 3 spl withdrawal), amount u64, spl bump u8.
pub fn rings_withdrawal_only(data: &[u8]) -> bool {
    if data.first() != Some(&RINGS_TRANSACT) {
        return false;
    }
    let mut off = 1 + 8 + 33 + 16;
    let Some(&n) = data.get(off) else { return false };
    if n == 0 {
        return false; // a spend with no public withdrawal never needs the relayer to pay
    }
    off += 1;
    for _ in 0..n {
        match data.get(off) {
            Some(1) => off += 9,
            Some(3) => off += 10,
            _ => return false,
        }
        if off > data.len() {
            return false;
        }
    }
    true
}

/// The most one buyback may spend; a larger fee vault is bought back over several calls.
pub const MAX_BUYBACK_LAMPORTS: u64 = 1_000_000_000;

/// Buybacks run only when the launchpad's crank (Latrix config, set by the upgrade authority) signs: the crank
/// sets a slippage floor from a fresh simulation, so nobody can bundle a buyback with `min_out = 0` and sandwich it.
pub fn check_crank(config: &AccountView, crank: &AccountView) -> Result<(), ProgramError> {
    super::check_owned(config, state::CONFIG_DISCRIMINATOR, state::CONFIG_LEN)?;
    if *config.address() != Address::find_program_address(&[state::CONFIG_SEED], &crate::ID).0 {
        return Err(LatrixError::InvalidAccount.into());
    }
    let d = config.try_borrow()?;
    if !crank.is_signer() || state::read_32(&d, state::config::CRANK) != *crank.address().as_array() {
        return Err(LatrixError::NotCrank.into());
    }
    Ok(())
}

/// One buyback per coin per BUYBACK_COOLDOWN_SLOTS, recorded in `["buyback", mint]` (created here on the first one, the
/// crank paying its rent). Even a stolen crank key can only buy back once per window per coin.
pub fn buyback_cooldown(state_acc: &mut AccountView, crank: &AccountView, mint: &Address) -> Result<(), ProgramError> {
    use pinocchio::sysvars::{clock::Clock, Sysvar};
    let (expected, bump) = Address::find_program_address(&[state::BUYBACK_SEED, mint.as_ref()], &crate::ID);
    expect(state_acc, &expected)?;
    let slot = Clock::get()?.slot;
    if !state_acc.owned_by(&crate::ID) {
        let b = [bump];
        let seeds = [pinocchio::cpi::Seed::from(state::BUYBACK_SEED), pinocchio::cpi::Seed::from(mint.as_ref()), pinocchio::cpi::Seed::from(&b[..])];
        super::create_pda(crank, state_acc, state::BUYBACK_LEN, &[pinocchio::cpi::Signer::from(&seeds)])?;
        let mut d = state_acc.try_borrow_mut()?;
        d[0] = state::BUYBACK_DISCRIMINATOR;
        d[1] = bump;
    } else {
        super::check_owned(state_acc, state::BUYBACK_DISCRIMINATOR, state::BUYBACK_LEN)?;
        let last = state::read_u64(&state_acc.try_borrow()?, 8..16);
        if slot < last.saturating_add(state::BUYBACK_COOLDOWN_SLOTS) {
            return Err(LatrixError::BuybackCooldown.into());
        }
    }
    state_acc.try_borrow_mut()?[8..16].copy_from_slice(&slot.to_le_bytes());
    Ok(())
}

/// SPL Token instruction tags.
pub const TOKEN_TRANSFER: u8 = 3;
pub const TOKEN_BURN: u8 = 8;

/// The associated token account of `owner` for `mint` (SPL Token).
pub fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), TOKEN_PROGRAM.as_ref(), mint.as_ref()], &ATA_PROGRAM).0
}

/// SPL token account amount (layout: mint 0..32, owner 32..64, amount 64..72).
pub fn token_amount(account: &AccountView) -> Result<u64, ProgramError> {
    if !account.owned_by(&TOKEN_PROGRAM) || account.data_len() < 72 {
        return Err(LatrixError::InvalidFeeAccount.into());
    }
    let d = account.try_borrow()?;
    Ok(u64::from_le_bytes(d[64..72].try_into().map_err(|_| LatrixError::InvalidFeeAccount)?))
}

pub fn expect(account: &AccountView, address: &Address) -> Result<(), ProgramError> {
    if account.address() != address {
        return Err(LatrixError::InvalidFeeAccount.into());
    }
    Ok(())
}

/// Loads a launch record and returns (mint, pool, dev_share_bps, fee_vault, fee_vault_bump). The record must sit
/// at the CANONICAL `["launch", mint]` address: a record anywhere else is refused.
pub fn launch_of(record: &AccountView) -> Result<(Address, Address, u16, Address, u8), ProgramError> {
    super::check_owned(record, state::LAUNCH_DISCRIMINATOR, state::LAUNCH_LEN)?;
    let d = record.try_borrow()?;
    let mint = Address::new_from_array(state::read_32(&d, state::launch::MINT));
    if *record.address() != Address::find_program_address(&[state::LAUNCH_SEED, mint.as_ref()], &crate::ID).0 {
        return Err(LatrixError::InvalidAccount.into());
    }
    let pool = Address::new_from_array(state::read_32(&d, state::launch::POOL));
    let bps = u16::from_le_bytes([d[2], d[3]]);
    let bump = d[state::launch::FEE_VAULT_BUMP];
    let fee_vault = super::derive(&[state::FEE_VAULT_SEED, mint.as_ref()], bump)?;
    Ok((mint, pool, bps, fee_vault, bump))
}

/// Adds `amount` to a u64 counter in the record.
pub fn bump_counter(record: &mut AccountView, range: core::ops::Range<usize>, amount: u64) -> Result<(), ProgramError> {
    let mut d = record.try_borrow_mut()?;
    let v = state::read_u64(&d, range.clone()).saturating_add(amount);
    d[range].copy_from_slice(&v.to_le_bytes());
    Ok(())
}
