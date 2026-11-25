//! What the Falcon key signs, and the digest that ties it to one exact instruction.

use pinocchio::{AccountView, Address};
use solana_sha256_hasher::hashv;

/// Domain tags, so a Latrix signature can never be replayed as some other protocol's message.
pub const DOMAIN_CALL: &[u8] = b"latrix/call/v1";
pub const DOMAIN_IDENTITY: &[u8] = b"latrix/identity/v1";
pub const DOMAIN_LAUNCH: &[u8] = b"latrix/launch/v1";

/// At most this many accounts can be passed to (and are bound by) one approved call.
pub const MAX_CALL_ACCOUNTS: usize = 48;

/// Account flags as they enter the digest.
pub const FLAG_WRITABLE: u8 = 1;
pub const FLAG_SIGNER: u8 = 2;

/// `sha256(DOMAIN_IDENTITY || falcon_pubkey)`: the identity seed. One key, one identity address.
pub fn pubkey_hash(falcon_pubkey: &[u8]) -> [u8; 32] {
    hashv(&[DOMAIN_IDENTITY, falcon_pubkey]).to_bytes()
}

/// One account of an approved call: its address and its writable / signer flags as passed in.
pub struct CallAccount<'a> {
    pub address: &'a [u8],
    pub flags: u8,
}

/// The call digest: the target program, every account with its flags, in order, and the
/// instruction data. Binding the flags too means a relayer cannot quietly make an account
/// writable or drop a signer after the key approved the call.
pub fn call_digest_of(target_program: &[u8], accounts: &[CallAccount], data: &[u8]) -> [u8; 32] {
    // [domain, program, n u8, (address, flags) * n, data_len u32 le, data]. The count and the length frame the
    // parts, so nobody can move bytes between the last account and the data and keep the digest.
    let mut flags = [0u8; MAX_CALL_ACCOUNTS];
    let n = accounts.len().min(MAX_CALL_ACCOUNTS);
    for (i, a) in accounts.iter().take(n).enumerate() {
        flags[i] = a.flags;
    }
    let count = [n as u8];
    let data_len = (data.len() as u32).to_le_bytes();
    let mut parts: [&[u8]; 5 + 2 * MAX_CALL_ACCOUNTS] = [&[]; 5 + 2 * MAX_CALL_ACCOUNTS];
    parts[0] = DOMAIN_CALL;
    parts[1] = target_program;
    parts[2] = &count;
    for i in 0..n {
        parts[3 + 2 * i] = accounts[i].address;
        parts[4 + 2 * i] = core::slice::from_ref(&flags[i]);
    }
    parts[3 + 2 * n] = &data_len;
    parts[4 + 2 * n] = data;
    hashv(&parts[..5 + 2 * n]).to_bytes()
}

/// [`call_digest_of`] over the instruction exactly as `execute_call` will INVOKE it: each account's
/// flags as passed in, except that `latrix_signers` (the identity's agent and vault) are signers,
/// because Latrix signs for them in the CPI. So the client signs the call as it will execute.
pub fn call_digest(
    target_program: &Address,
    accounts: &[AccountView],
    data: &[u8],
    latrix_signers: &[&Address],
) -> [u8; 32] {
    let mut list: [CallAccount; MAX_CALL_ACCOUNTS] =
        core::array::from_fn(|_| CallAccount { address: &[], flags: 0 });
    let n = accounts.len().min(MAX_CALL_ACCOUNTS);
    for (i, a) in accounts.iter().take(n).enumerate() {
        let ours = latrix_signers.iter().any(|s| *s == a.address());
        list[i] = CallAccount {
            address: a.address().as_ref(),
            flags: (a.is_writable() as u8) * FLAG_WRITABLE | ((a.is_signer() || ours) as u8) * FLAG_SIGNER,
        };
    }
    call_digest_of(target_program.as_ref(), &list[..n], data)
}

/// The message the Falcon key signs for one call:
/// `sha256(DOMAIN_CALL || program_id || identity || call_digest || nonce_le || valid_until_slot_le)`.
/// The nonce makes it single-use, the slot makes it expire, the program id and identity stop it
/// being replayed on another deployment or another identity.
pub fn call_message(
    program_id: &Address,
    identity: &Address,
    call_digest: &[u8; 32],
    nonce: u64,
    valid_until_slot: u64,
) -> [u8; 32] {
    hashv(&[
        DOMAIN_CALL,
        program_id.as_ref(),
        identity.as_ref(),
        call_digest,
        &nonce.to_le_bytes(),
        &valid_until_slot.to_le_bytes(),
    ])
    .to_bytes()
}

/// The digest a Falcon key approves (through `authorize_call`) to attest one launch: the coin's mint,
/// its Meteora DBC pool and the creator-fee split (dev share in basis points; the rest is bought back
/// and burned). Its own domain tag, so a launch approval can never be executed as a call and a call
/// approval can never attest a launch.
pub fn launch_digest(mint: &[u8], pool: &[u8], dev_share_bps: u16) -> [u8; 32] {
    hashv(&[DOMAIN_LAUNCH, mint, pool, &dev_share_bps.to_le_bytes()]).to_bytes()
}
