//! `execute_call`: perform one approved instruction, signing as the identity's agent and vault.
//!
//! Accounts: 0 rent_payer [writable] (the account that funded the approval),
//!           1 identity, 2 pending [writable],
//!           3 target program,
//!           4.. the target instruction's accounts, in its own order (at most 48).
//! Data:     nonce u64, then the target instruction's data, forwarded unchanged.
//!
//! Anyone may submit it (a relayer): what runs was fixed by the Falcon signature. The program
//! recomputes the call digest over the target, the accounts (address + writable/signer flags) and
//! the data it was actually given, requires it to equal the approval's, closes the approval
//! (single use, right after the call) and invokes the target. In that CPI the agent and vault PDAs are the
//! only signers (plus the payer of a withdraw-only Privacy Rings spend).
//!
//! This one instruction covers every use: a Privacy Rings spend (target = shielded pool, with the
//! vault among its owners), a Meteora DBC launch or swap (the agent as creator / payer), a fee
//! claim, a token transfer.

use pinocchio::{
    address::address_eq,
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};

use super::{agent_address, check_owned, close_to, external, take_u64, vault_address};
use crate::{auth, error::LatrixError, state};

pub fn process(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [rent_payer, identity, pending, target, call_accounts @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if call_accounts.len() > auth::MAX_CALL_ACCOUNTS {
        return Err(LatrixError::TooManyAccounts.into());
    }
    // Never re-enter Latrix: an approved call could otherwise reach another identity's accounts
    // through this program's own instructions.
    if address_eq(target.address(), &crate::ID) || !target.executable() {
        return Err(LatrixError::ForbiddenTarget.into());
    }
    check_owned(identity, state::IDENTITY_DISCRIMINATOR, state::IDENTITY_LEN)?;
    check_owned(pending, state::PENDING_DISCRIMINATOR, state::PENDING_LEN)?;
    if !pending.is_writable() || !rent_payer.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut off = 0;
    let nonce = take_u64(data, &mut off)?;
    let call_data = &data[off..];

    let identity_addr = *identity.address();
    let (vault_bump, agent_bump) = {
        let d = identity.try_borrow()?;
        (d[state::identity::VAULT_BUMP], d[state::identity::AGENT_BUMP])
    };
    let vault = vault_address(&identity_addr, vault_bump)?;
    let agent = agent_address(&identity_addr, agent_bump)?;

    {
        let p = pending.try_borrow()?;
        if state::read_32(&p, state::pending::IDENTITY) != *identity_addr.as_array() {
            return Err(LatrixError::InvalidAccount.into());
        }
        if state::read_u64(&p, state::pending::NONCE) != nonce {
            return Err(LatrixError::InvalidNonce.into());
        }
        if Clock::get()?.slot > state::read_u64(&p, state::pending::VALID_UNTIL) {
            return Err(LatrixError::Expired.into());
        }
        if state::read_32(&p, state::pending::RENT_PAYER) != *rent_payer.address().as_array() {
            return Err(LatrixError::RentPayerMismatch.into());
        }
        let digest = auth::call_digest(target.address(), call_accounts, call_data, &[&agent, &vault]);
        if state::read_32(&p, state::pending::DIGEST) != digest {
            return Err(LatrixError::CallMismatch.into());
        }
    }

    // Signers in the CPI: the agent and vault (Latrix signs for them below) and NOTHING the transaction brought,
    // because the transaction's own signers include the relayer that pays the fees - an approval written by any
    // identity could otherwise spend the relayer's funds. One exception: the payer (account 0) of a Privacy Rings
    // spend that only WITHDRAWS keeps its signature, since it pays the rent of the records that spend creates.
    // ... and only if that key appears once in the call (the runtime would merge its signer flag into every duplicate).
    let rings_payer = address_eq(target.address(), &external::SHIELDED_POOL)
        && external::rings_withdrawal_only(call_data)
        && call_accounts.first().is_some_and(|p| call_accounts.iter().filter(|a| address_eq(a.address(), p.address())).count() == 1);
    let metas: Vec<InstructionAccount> = call_accounts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let ours = address_eq(a.address(), &agent) || address_eq(a.address(), &vault);
            InstructionAccount::new(a.address(), a.is_writable(), ours || (i == 0 && rings_payer && a.is_signer()))
        })
        .collect();
    let ix = InstructionView { program_id: target.address(), accounts: &metas, data: call_data };

    let vb = [vault_bump];
    let ab = [agent_bump];
    let vault_seeds = [Seed::from(state::VAULT_SEED), Seed::from(identity_addr.as_ref()), Seed::from(&vb[..])];
    let agent_seeds = [Seed::from(state::AGENT_SEED), Seed::from(identity_addr.as_ref()), Seed::from(&ab[..])];
    invoke_signed_with_bounds::<{ auth::MAX_CALL_ACCOUNTS }, _>(
        &ix,
        call_accounts,
        &[Signer::from(&agent_seeds), Signer::from(&vault_seeds)],
    )?;

    // Single use: the approval is closed in this same instruction. It is closed AFTER the call
    // because the runtime's balance check at the CPI boundary rejects a lamport move made before it
    // when the rent payer is also one of the call's accounts (it usually is: the relayer pays both).
    // The target can never be Latrix itself; a target re-entering Latrix through another program could only reach
    // this same, already-approved call (the approval is single use and closed here).
    close_to(pending, rent_payer)
}
