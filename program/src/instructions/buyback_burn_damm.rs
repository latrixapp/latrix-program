//! `buyback_burn_damm` (permissionless): after a coin graduates, spend the fee vault's wSOL on the coin
//! in its Meteora DAMM v2 pool and burn everything bought.
//!
//! Accounts: 0 launch record [writable], 1 fee vault (`["fee_vault", mint]`),
//!           2 fee vault wSOL ATA [writable], 3 fee vault base ATA [writable],
//!           4 DAMM v2 pool authority, 5 DAMM v2 pool [writable], 6 token A vault [writable],
//!           7 token B vault [writable], 8 base mint [writable] (burned from), 9 quote mint (wSOL),
//!           10 token program, 11 DAMM v2 event authority, 12 DAMM v2 program, 13 Latrix config (`["config"]`),
//!           14 crank [signer, writable], then the coin's buyback state (`["buyback", mint]`) [writable], system program.
//! Data:     minimum_amount_out u64 (the crank's slippage floor, from a fresh simulation).
//!
//! Only the crank may run it (see external::check_crank), and one call spends at most MAX_BUYBACK_LAMPORTS.
//!
//! Only the coin's REAL graduated pool is accepted: a DAMM v2 pool owned by the DAMM v2 program whose
//! creator is Meteora DBC's pool authority (only DBC's migration can sign as it) and whose two mints
//! are this coin and wSOL. Anyone can open another DAMM v2 pool for the same pair at a bad price;
//! routing the buyback through one of those is refused.

use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

use super::{
    external::{self, ata, damm_pool, expect, launch_of, token_amount},
    take_u64,
};
use crate::{error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut off = 0;
    let min_out = take_u64(data, &mut off)?;
    if off != data.len() {
        return Err(LatrixError::InvalidInstructionData.into());
    }
    let [record, fee_vault, vault_wsol, vault_base, pool_authority, pool, a_vault, b_vault, base_mint, quote_mint, token_program, event_authority, damm, latrix_config, crank, cooldown, _system, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    external::check_crank(latrix_config, crank)?;
    let (mint, _dbc_pool, _bps, fee_vault_addr, fee_vault_bump) = launch_of(record)?;
    external::buyback_cooldown(cooldown, crank, &mint)?;
    expect(fee_vault, &fee_vault_addr)?;
    expect(vault_wsol, &ata(&fee_vault_addr, &external::WSOL))?;
    expect(vault_base, &ata(&fee_vault_addr, &mint))?;
    expect(pool_authority, &external::DAMM_POOL_AUTHORITY)?;
    expect(event_authority, &external::DAMM_EVENT_AUTHORITY)?;
    expect(damm, &external::DAMM_V2)?;
    expect(base_mint, &mint)?;
    expect(quote_mint, &external::WSOL)?;
    expect(token_program, &external::TOKEN_PROGRAM)?;

    // The genuine graduated pool, and its vaults.
    if !pool.owned_by(&external::DAMM_V2) || pool.data_len() < damm_pool::LEN {
        return Err(LatrixError::InvalidFeeAccount.into());
    }
    {
        let p = pool.try_borrow()?;
        let creator = state::read_32(&p, damm_pool::CREATOR);
        let a_mint = state::read_32(&p, damm_pool::TOKEN_A_MINT);
        let b_mint = state::read_32(&p, damm_pool::TOKEN_B_MINT);
        if creator != *external::DBC_POOL_AUTHORITY.as_array()
            || a_mint != *mint.as_array()
            || b_mint != *external::WSOL.as_array()
            || state::read_32(&p, damm_pool::TOKEN_A_VAULT) != *a_vault.address().as_array()
            || state::read_32(&p, damm_pool::TOKEN_B_VAULT) != *b_vault.address().as_array()
        {
            return Err(LatrixError::InvalidFeeAccount.into());
        }
    }

    let amount_in = token_amount(vault_wsol)?.min(external::MAX_BUYBACK_LAMPORTS);
    if amount_in == 0 {
        return Err(LatrixError::NothingToDo.into());
    }
    let vb = [fee_vault_bump];
    let seeds = [Seed::from(state::FEE_VAULT_SEED), Seed::from(mint.as_ref()), Seed::from(&vb[..])];
    let signer = [Signer::from(&seeds)];

    // 1. Buy on DAMM v2: wSOL (token B) -> coin (token A), the fee vault paying, no referral.
    let mut sd = [0u8; 24];
    sd[..8].copy_from_slice(&external::DAMM_SWAP);
    sd[8..16].copy_from_slice(&amount_in.to_le_bytes());
    sd[16..24].copy_from_slice(&min_out.to_le_bytes());
    let metas = [
        InstructionAccount::readonly(pool_authority.address()),
        InstructionAccount::writable(pool.address()),
        InstructionAccount::writable(vault_wsol.address()),
        InstructionAccount::writable(vault_base.address()),
        InstructionAccount::writable(a_vault.address()),
        InstructionAccount::writable(b_vault.address()),
        InstructionAccount::readonly(base_mint.address()),
        InstructionAccount::readonly(quote_mint.address()),
        InstructionAccount::readonly_signer(fee_vault.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(damm.address()), // referral: None
        InstructionAccount::readonly(event_authority.address()),
        InstructionAccount::readonly(damm.address()),
    ];
    invoke_signed(
        &InstructionView { program_id: damm.address(), accounts: &metas, data: &sd },
        &[
            &*pool_authority, &*pool, &*vault_wsol, &*vault_base, &*a_vault, &*b_vault, &*base_mint, &*quote_mint,
            &*fee_vault, &*token_program, &*token_program, &*damm, &*event_authority, &*damm,
        ],
        &signer,
    )?;

    // 2. Burn everything the fee vault holds of the coin.
    let to_burn = token_amount(vault_base)?;
    if to_burn > 0 {
        let mut b = [0u8; 9];
        b[0] = external::TOKEN_BURN;
        b[1..9].copy_from_slice(&to_burn.to_le_bytes());
        let bm = [
            InstructionAccount::writable(vault_base.address()),
            InstructionAccount::writable(base_mint.address()),
            InstructionAccount::readonly_signer(fee_vault.address()),
        ];
        invoke_signed(
            &InstructionView { program_id: token_program.address(), accounts: &bm, data: &b },
            &[&*vault_base, &*base_mint, &*fee_vault],
            &signer,
        )?;
    }
    external::bump_counter(record, state::launch::BURN_LAMPORTS, amount_in)?;
    external::bump_counter(record, state::launch::BURNED_TOKENS, to_burn)?;
    Ok(())
}
