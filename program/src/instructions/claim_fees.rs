//! `claim_fees` (permissionless): claim a launch's creator fees from Meteora DBC into its fee vault and
//! pay the dev their share. The rest stays in the fee vault for `buyback_burn`.
//!
//! Accounts: 0 launch record [writable], 1 identity, 2 fee vault (`["fee_vault", mint]`, the pool
//!           creator), 3 fee vault wSOL ATA [writable], 4 fee vault base ATA [writable],
//!           5 dev wSOL ATA [writable] (the ATA of the identity's AGENT),
//!           6 DBC pool authority, 7 pool [writable], 8 base vault [writable], 9 quote vault [writable],
//!           10 base mint, 11 quote mint (wSOL), 12 token program, 13 DBC event authority, 14 DBC.
//! Data:     none.
//!
//! The split is the one the dev's Falcon key signed at launch (record.dev_share_bps) - nobody can
//! change it, and the dev's share can only go to the identity's own agent.

use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

use super::{
    agent_address, check_owned,
    external::{self, ata, expect, launch_of, token_amount},
};
use crate::{error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(LatrixError::InvalidInstructionData.into());
    }
    let [record, identity, fee_vault, vault_wsol, vault_base, dev_wsol, pool_authority, pool, base_vault, quote_vault, base_mint, quote_mint, token_program, event_authority, dbc, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (mint, pool_addr, bps, fee_vault_addr, fee_vault_bump) = launch_of(record)?;

    // Every account must be the one this launch implies.
    check_owned(identity, state::IDENTITY_DISCRIMINATOR, state::IDENTITY_LEN)?;
    {
        let r = record.try_borrow()?;
        if state::read_32(&r, state::launch::IDENTITY) != *identity.address().as_array() {
            return Err(LatrixError::InvalidFeeAccount.into());
        }
    }
    let agent = agent_address(identity.address(), identity.try_borrow()?[state::identity::AGENT_BUMP])?;
    expect(fee_vault, &fee_vault_addr)?;
    expect(vault_wsol, &ata(&fee_vault_addr, &external::WSOL))?;
    expect(vault_base, &ata(&fee_vault_addr, &mint))?;
    expect(dev_wsol, &ata(&agent, &external::WSOL))?;
    expect(pool_authority, &external::DBC_POOL_AUTHORITY)?;
    expect(pool, &pool_addr)?;
    expect(base_mint, &mint)?;
    expect(quote_mint, &external::WSOL)?;
    expect(token_program, &external::TOKEN_PROGRAM)?;
    expect(dbc, &external::DBC)?;

    let vb = [fee_vault_bump];
    let seeds = [Seed::from(state::FEE_VAULT_SEED), Seed::from(mint.as_ref()), Seed::from(&vb[..])];
    let signer = [Signer::from(&seeds)];

    // 1. Claim every creator fee the pool holds (collect mode is quote-only: they arrive as wSOL).
    let before = token_amount(vault_wsol)?;
    let mut ix_data = [0u8; 24];
    ix_data[..8].copy_from_slice(&external::DBC_CLAIM_CREATOR_FEE);
    ix_data[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    ix_data[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    let metas = [
        InstructionAccount::readonly(pool_authority.address()),
        InstructionAccount::writable(pool.address()),
        InstructionAccount::writable(vault_base.address()),
        InstructionAccount::writable(vault_wsol.address()),
        InstructionAccount::writable(base_vault.address()),
        InstructionAccount::writable(quote_vault.address()),
        InstructionAccount::readonly(base_mint.address()),
        InstructionAccount::readonly(quote_mint.address()),
        InstructionAccount::readonly_signer(fee_vault.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(event_authority.address()),
        InstructionAccount::readonly(dbc.address()),
    ];
    invoke_signed(
        &InstructionView { program_id: dbc.address(), accounts: &metas, data: &ix_data },
        &[
            &*pool_authority, &*pool, &*vault_base, &*vault_wsol, &*base_vault, &*quote_vault, &*base_mint, &*quote_mint,
            &*fee_vault, &*token_program, &*token_program, &*event_authority, &*dbc,
        ],
        &signer,
    )?;
    let claimed = token_amount(vault_wsol)?.saturating_sub(before);
    if claimed == 0 {
        return Err(LatrixError::NothingToDo.into());
    }

    // 2. The dev's share goes to the agent's wSOL account; the rest waits for buyback_burn.
    let dev = (claimed as u128 * bps as u128 / 10_000) as u64;
    if dev > 0 {
        let mut t = [0u8; 9];
        t[0] = external::TOKEN_TRANSFER;
        t[1..9].copy_from_slice(&dev.to_le_bytes());
        let tm = [
            InstructionAccount::writable(vault_wsol.address()),
            InstructionAccount::writable(dev_wsol.address()),
            InstructionAccount::readonly_signer(fee_vault.address()),
        ];
        invoke_signed(
            &InstructionView { program_id: token_program.address(), accounts: &tm, data: &t },
            &[&*vault_wsol, &*dev_wsol, &*fee_vault],
            &signer,
        )?;
        external::bump_counter(record, state::launch::DEV_LAMPORTS, dev)?;
    }
    Ok(())
}
