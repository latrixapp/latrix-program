//! Latrix: a Solana Privacy Rings balance that only a Falcon-512 key can move.
//!
//! A Falcon-512 smart account, and the private launchpad built on it.
//!
//! A user registers a Falcon-512 public key (`init_identity`). The identity has two PDAs only this
//! program signs for: the VAULT, owner of its private balance in the Solana Privacy Program (SPP,
//! the shielded pool), and the AGENT, the plain account it acts through in public (pays, holds
//! tokens, is the Meteora DBC pool creator). The program signs for them only after the Falcon key
//! approved the exact instruction:
//!
//! 1. `authorize_call` - the Falcon key signs the digest of one exact instruction (target program,
//!    every account with its writable/signer flags, the data), a nonce and an expiry slot. The
//!    program verifies the signature and records a one-time `Pending` approval.
//! 2. `execute_call` - anyone (a relayer) submits that instruction. The program recomputes the
//!    digest, checks it against the approval, closes the approval and invokes it, signing as the
//!    agent and the vault.
//!
//! A launch is a few approved calls: an SPP withdrawal into the agent, the DBC pool creation with
//! the agent as creator and payer, the dev buy; creator fees are claimed and re-shielded the same
//! way. Two transactions per call, because a 666-byte Falcon signature and the call rarely fit in
//! one. A compromised ed25519 wallet key - by a quantum computer or otherwise - moves nothing.

pub mod auth;
pub mod error;
pub mod instructions;
pub mod state;

use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};

// Mainnet uses the vanity id; the `devnet` feature builds the same code for a separate devnet
// deployment, so mainnet keys never touch devnet.
#[cfg(not(feature = "devnet"))]
pinocchio::address::declare_id!("LTRXiaWWy3KbwiwMPCPu6QomafKrj12BPkpnAAwhNHD");
#[cfg(feature = "devnet")]
pinocchio::address::declare_id!("C3XV9zaLaEQkUabR3AKyCv41VXjXqLpD9VpGJUjMVbir");

pub mod tag {
    pub const INIT_IDENTITY: u8 = 0;
    pub const AUTHORIZE_CALL: u8 = 1;
    pub const EXECUTE_CALL: u8 = 2;
    pub const CANCEL_PENDING: u8 = 3;
    pub const ATTEST_LAUNCH: u8 = 4;
    pub const CLAIM_FEES: u8 = 5;
    pub const BUYBACK_BURN: u8 = 6;
    pub const BUYBACK_BURN_DAMM: u8 = 7;
    pub const CLAIM_FEES_DAMM: u8 = 8;
    pub const SET_CRANK: u8 = 9;
}

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if !address_eq(program_id, &crate::ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (ix_tag, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *ix_tag {
        tag::INIT_IDENTITY => instructions::init_identity::process(accounts, data),
        tag::AUTHORIZE_CALL => instructions::authorize_call::process(accounts, data),
        tag::EXECUTE_CALL => instructions::execute_call::process(accounts, data),
        tag::CANCEL_PENDING => instructions::cancel_pending::process(accounts, data),
        tag::ATTEST_LAUNCH => instructions::attest_launch::process(accounts, data),
        tag::CLAIM_FEES => instructions::claim_fees::process(accounts, data),
        tag::BUYBACK_BURN => instructions::buyback_burn::process(accounts, data),
        tag::BUYBACK_BURN_DAMM => instructions::buyback_burn_damm::process(accounts, data),
        tag::CLAIM_FEES_DAMM => instructions::claim_fees_damm::process(accounts, data),
        tag::SET_CRANK => instructions::set_crank::process(accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
