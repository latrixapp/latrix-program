//! `buyback_burn` (permissionless): spend the fee vault's wSOL on the coin through its Meteora DBC pool
//! and burn everything bought. Runs on whatever claim_fees left behind (the non-dev share).
//!
//! Accounts: 0 launch record [writable], 1 fee vault (`["fee_vault", mint]`),
//!           2 fee vault wSOL ATA [writable], 3 fee vault base ATA [writable],
//!           4 DBC pool authority, 5 DBC config, 6 pool [writable], 7 base vault [writable],
//!           8 quote vault [writable], 9 base mint [writable] (burned from), 10 quote mint (wSOL),
//!           11 token program, 12 DBC event authority, 13 DBC, 14 Latrix config (`["config"]`), 15 crank [signer, writable], then the coin's buyback state (`["buyback", mint]`) [writable], system program.
//! Data:     minimum_amount_out u64 (the crank's slippage floor, from a fresh simulation).
//!
//! Only the crank may run it (see external::check_crank), and one call spends at most MAX_BUYBACK_LAMPORTS.
//!
//! Works while the coin is on its bonding curve (DBC). After graduation the pool is DAMM v2 and DBC
//! refuses the swap; the fees stay in the fee vault until a DAMM v2 route is added.

use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

use super::{
    external::{self, ata, expect, launch_of, token_amount},
    take_u64,
};
use crate::{error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut off = 0;
    let min_out = take_u64(data, &mut off)?;
    if off != data.len() {
        return Err(LatrixError::InvalidInstructionData.into());
    }
    let [record, fee_vault, vault_wsol, vault_base, pool_authority, config, pool, base_vault, quote_vault, base_mint, quote_mint, token_program, event_authority, dbc, latrix_config, crank, cooldown, _system, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    external::check_crank(latrix_config, crank)?;
    let (mint, pool_addr, _bps, fee_vault_addr, fee_vault_bump) = launch_of(record)?;
    external::buyback_cooldown(cooldown, crank, &mint)?;
    expect(fee_vault, &fee_vault_addr)?;
    expect(vault_wsol, &ata(&fee_vault_addr, &external::WSOL))?;
    expect(vault_base, &ata(&fee_vault_addr, &mint))?;
    expect(pool_authority, &external::DBC_POOL_AUTHORITY)?;
    expect(pool, &pool_addr)?;
    expect(base_mint, &mint)?;
    expect(quote_mint, &external::WSOL)?;
    expect(token_program, &external::TOKEN_PROGRAM)?;
    expect(dbc, &external::DBC)?;
    // The config must be the pool's own: DBC checks pool.config == config itself (has_one).

    let amount_in = token_amount(vault_wsol)?.min(external::MAX_BUYBACK_LAMPORTS);
    if amount_in == 0 {
        return Err(LatrixError::NothingToDo.into());
    }
    let vb = [fee_vault_bump];
    let seeds = [Seed::from(state::FEE_VAULT_SEED), Seed::from(mint.as_ref()), Seed::from(&vb[..])];
    let signer = [Signer::from(&seeds)];

    // 1. Buy: wSOL -> coin, the fee vault paying (no referral).
    let base_before = token_amount(vault_base)?;
    let mut sd = [0u8; 24];
    sd[..8].copy_from_slice(&external::DBC_SWAP);
    sd[8..16].copy_from_slice(&amount_in.to_le_bytes());
    sd[16..24].copy_from_slice(&min_out.to_le_bytes());
    let metas = [
        InstructionAccount::readonly(pool_authority.address()),
        InstructionAccount::readonly(config.address()),
        InstructionAccount::writable(pool.address()),
        InstructionAccount::writable(vault_wsol.address()),
        InstructionAccount::writable(vault_base.address()),
        InstructionAccount::writable(base_vault.address()),
        InstructionAccount::writable(quote_vault.address()),
        InstructionAccount::readonly(base_mint.address()),
        InstructionAccount::readonly(quote_mint.address()),
        InstructionAccount::readonly_signer(fee_vault.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(dbc.address()), // referral: None
        InstructionAccount::readonly(event_authority.address()),
        InstructionAccount::readonly(dbc.address()),
    ];
    invoke_signed(
        &InstructionView { program_id: dbc.address(), accounts: &metas, data: &sd },
        &[
            &*pool_authority, &*config, &*pool, &*vault_wsol, &*vault_base, &*base_vault, &*quote_vault, &*base_mint,
            &*quote_mint, &*fee_vault, &*token_program, &*token_program, &*dbc, &*event_authority, &*dbc,
        ],
        &signer,
    )?;
    let bought = token_amount(vault_base)?.saturating_sub(base_before);

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
    external::bump_counter(record, state::launch::BURNED_TOKENS, to_burn.max(bought))?;
    Ok(())
}
