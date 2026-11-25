//! `claim_fees_damm` (permissionless): after a coin graduates, claim the trading fees of the creator's share of
//! its locked liquidity in Meteora DAMM v2 into the fee vault, and pay the dev their share - the same split the
//! dev's Falcon key signed at launch, exactly as `claim_fees` does on the bonding curve. The rest stays in the
//! fee vault for `buyback_burn_damm`.
//!
//! DBC's migration gives the pool creator (the coin's fee vault, since attest_launch's companion transaction
//! moved the creator role there) a permanently locked DAMM v2 position; only the fee vault can claim its fees,
//! and only Latrix can sign for the fee vault.
//!
//! Accounts: 0 launch record [writable], 1 identity, 2 fee vault (`["fee_vault", mint]`, the position owner),
//!           3 fee vault wSOL ATA [writable], 4 fee vault base ATA [writable],
//!           5 dev wSOL ATA [writable] (the ATA of the identity's AGENT),
//!           6 DAMM v2 pool authority, 7 DAMM v2 pool, 8 position [writable], 9 token A vault [writable],
//!           10 token B vault [writable], 11 base mint, 12 quote mint (wSOL), 13 position NFT account,
//!           14 token program, 15 DAMM v2 event authority, 16 DAMM v2 program.
//! Data:     none.
//!
//! Only the coin's REAL graduated pool is accepted (owned by DAMM v2, created by Meteora DBC's pool authority,
//! mints = this coin and wSOL), and the position must belong to that pool. DAMM v2 itself checks that the
//! position NFT is held by the signing owner, i.e. the fee vault.

use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, ProgramResult,
};

use super::{
    agent_address, check_owned,
    external::{self, ata, damm_pool, damm_position, expect, launch_of, token_amount},
};
use crate::{error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(LatrixError::InvalidInstructionData.into());
    }
    let [record, identity, fee_vault, vault_wsol, vault_base, dev_wsol, pool_authority, pool, position, a_vault, b_vault, base_mint, quote_mint, nft_account, token_program, event_authority, damm, ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (mint, _dbc_pool, bps, fee_vault_addr, fee_vault_bump) = launch_of(record)?;

    // The launch's own identity, fee vault and fee accounts.
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
    expect(pool_authority, &external::DAMM_POOL_AUTHORITY)?;
    expect(event_authority, &external::DAMM_EVENT_AUTHORITY)?;
    expect(damm, &external::DAMM_V2)?;
    expect(base_mint, &mint)?;
    expect(quote_mint, &external::WSOL)?;
    expect(token_program, &external::TOKEN_PROGRAM)?;

    // The genuine graduated pool, its vaults, and a position of THAT pool.
    if !pool.owned_by(&external::DAMM_V2) || pool.data_len() < damm_pool::LEN {
        return Err(LatrixError::InvalidFeeAccount.into());
    }
    {
        let p = pool.try_borrow()?;
        if state::read_32(&p, damm_pool::CREATOR) != *external::DBC_POOL_AUTHORITY.as_array()
            || state::read_32(&p, damm_pool::TOKEN_A_MINT) != *mint.as_array()
            || state::read_32(&p, damm_pool::TOKEN_B_MINT) != *external::WSOL.as_array()
            || state::read_32(&p, damm_pool::TOKEN_A_VAULT) != *a_vault.address().as_array()
            || state::read_32(&p, damm_pool::TOKEN_B_VAULT) != *b_vault.address().as_array()
        {
            return Err(LatrixError::InvalidFeeAccount.into());
        }
    }
    if !position.owned_by(&external::DAMM_V2) || position.data_len() < damm_position::MIN_LEN {
        return Err(LatrixError::InvalidFeeAccount.into());
    }
    {
        let p = position.try_borrow()?;
        if p[..8] != external::DAMM_POSITION_DISCRIMINATOR || state::read_32(&p, damm_position::POOL) != *pool.address().as_array() {
            return Err(LatrixError::InvalidFeeAccount.into());
        }
    }

    let vb = [fee_vault_bump];
    let seeds = [Seed::from(state::FEE_VAULT_SEED), Seed::from(mint.as_ref()), Seed::from(&vb[..])];
    let signer = [Signer::from(&seeds)];

    // 1. Claim the position's fees into the fee vault (token A = the coin, token B = wSOL).
    let (sol_before, base_before) = (token_amount(vault_wsol)?, token_amount(vault_base)?);
    let metas = [
        InstructionAccount::readonly(pool_authority.address()),
        InstructionAccount::readonly(pool.address()),
        InstructionAccount::writable(position.address()),
        InstructionAccount::writable(vault_base.address()),
        InstructionAccount::writable(vault_wsol.address()),
        InstructionAccount::writable(a_vault.address()),
        InstructionAccount::writable(b_vault.address()),
        InstructionAccount::readonly(base_mint.address()),
        InstructionAccount::readonly(quote_mint.address()),
        InstructionAccount::readonly(nft_account.address()),
        InstructionAccount::readonly_signer(fee_vault.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(token_program.address()),
        InstructionAccount::readonly(event_authority.address()),
        InstructionAccount::readonly(damm.address()),
    ];
    invoke_signed(
        &InstructionView { program_id: damm.address(), accounts: &metas, data: &external::DAMM_CLAIM_POSITION_FEE },
        &[
            &*pool_authority, &*pool, &*position, &*vault_base, &*vault_wsol, &*a_vault, &*b_vault, &*base_mint, &*quote_mint,
            &*nft_account, &*fee_vault, &*token_program, &*token_program, &*event_authority, &*damm,
        ],
        &signer,
    )?;
    let claimed = token_amount(vault_wsol)?.saturating_sub(sol_before);
    if claimed == 0 && token_amount(vault_base)? <= base_before {
        return Err(LatrixError::NothingToDo.into());
    }

    // 2. The dev's share of the SOL goes to the agent's wSOL account; the rest waits for buyback_burn_damm (which
    //    also burns any coin-side fees sitting in the fee vault).
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
