//! Runs the built program (target/deploy/latrix_program.so) under Mollusk, signing with real
//! Falcon-512 keys (PQClean via pqcrypto-falcon). Run with `bash scripts/build.sh`.

use latrix_program::{auth, state, tag};
use mollusk_svm::{program::keyed_account_for_system_program, result::ProgramResult as PR, Mollusk};
use pqcrypto_falcon::falconpadded512 as falcon;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const SOL: u64 = 1_000_000_000;

fn pid() -> Pubkey {
    Pubkey::new_from_array(latrix_program::ID.to_bytes())
}
fn sys() -> Pubkey {
    keyed_account_for_system_program().0
}
fn custom(code: u32) -> ProgramError {
    ProgramError::Custom(code)
}

struct Env {
    mollusk: Mollusk,
    payer: Pubkey,
    pk: falcon::PublicKey,
    sk: falcon::SecretKey,
    identity: Pubkey,
    identity_bump: u8,
    vault_bump: u8,
    agent: Pubkey,
    agent_bump: u8,
}

fn env() -> Env {
    let mollusk = Mollusk::new(&pid(), "latrix_program");
    let (pk, sk) = falcon::keypair();
    let pk_hash = auth::pubkey_hash(pk.as_bytes());
    let (identity, identity_bump) = Pubkey::find_program_address(&[state::IDENTITY_SEED, &pk_hash], &pid());
    let (_vault, vault_bump) = Pubkey::find_program_address(&[state::VAULT_SEED, identity.as_ref()], &pid());
    let (agent, agent_bump) = Pubkey::find_program_address(&[state::AGENT_SEED, identity.as_ref()], &pid());
    Env { mollusk, payer: Pubkey::new_unique(), pk, sk, identity, identity_bump, vault_bump, agent, agent_bump }
}

fn sol_account(lamports: u64) -> Account {
    Account::new(lamports, 0, &solana_sdk_ids::system_program::id())
}

fn init_ix(e: &Env, identity: Pubkey, pubkey: &[u8]) -> Instruction {
    let mut data = vec![tag::INIT_IDENTITY, e.identity_bump, e.vault_bump, e.agent_bump];
    data.extend_from_slice(pubkey);
    Instruction::new_with_bytes(
        pid(),
        &data,
        vec![AccountMeta::new(e.payer, true), AccountMeta::new(identity, false), AccountMeta::new_readonly(sys(), false)],
    )
}

/// Registers the identity and returns its resulting account.
fn init(e: &Env) -> Account {
    let r = e.mollusk.process_instruction(
        &init_ix(e, e.identity, e.pk.as_bytes()),
        &[(e.payer, sol_account(10 * SOL)), (e.identity, Account::default()), keyed_account_for_system_program()],
    );
    assert_eq!(r.program_result, PR::Success, "init_identity failed");
    println!("init_identity compute units: {}", r.compute_units_consumed);
    r.resulting_accounts[1].1.clone()
}

fn pending_pda(e: &Env, nonce: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[state::PENDING_SEED, e.identity.as_ref(), &nonce.to_le_bytes()], &pid())
}

fn sign(e: &Env, sk: &falcon::SecretKey, digest: &[u8; 32], nonce: u64, valid_until: u64) -> Vec<u8> {
    let msg = auth::call_message(
        &latrix_program::ID,
        &solana_address::Address::new_from_array(e.identity.to_bytes()),
        digest,
        nonce,
        valid_until,
    );
    let sig = falcon::detached_sign(&msg, sk).as_bytes().to_vec();
    assert_eq!(sig.len(), 666, "padded Falcon-512 signature");
    sig
}

/// The digest of `ix`, computed the way a client does before signing.
fn digest_of(ix: &Instruction) -> [u8; 32] {
    let addrs: Vec<[u8; 32]> = ix.accounts.iter().map(|m| m.pubkey.to_bytes()).collect();
    let list: Vec<auth::CallAccount> = ix
        .accounts
        .iter()
        .zip(&addrs)
        .map(|(m, a)| auth::CallAccount {
            address: &a[..],
            flags: (m.is_writable as u8) * auth::FLAG_WRITABLE | (m.is_signer as u8) * auth::FLAG_SIGNER,
        })
        .collect();
    auth::call_digest_of(ix.program_id.as_ref(), &list, &ix.data)
}

/// Runs authorize_call against an identity account; returns (result, pending address).
fn authorize(
    e: &Env,
    identity_acc: &Account,
    nonce: u64,
    valid_until: u64,
    digest: &[u8; 32],
    sig: &[u8],
) -> (mollusk_svm::result::InstructionResult, Pubkey) {
    let (pending, bump) = pending_pda(e, nonce);
    let mut data = vec![tag::AUTHORIZE_CALL];
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&valid_until.to_le_bytes());
    data.extend_from_slice(digest);
    data.push(bump);
    data.extend_from_slice(sig);
    let ix = Instruction::new_with_bytes(
        pid(),
        &data,
        vec![
            AccountMeta::new(e.payer, true),
            AccountMeta::new(e.identity, false),
            AccountMeta::new(pending, false),
            AccountMeta::new_readonly(sys(), false),
        ],
    );
    let r = e.mollusk.process_instruction(
        &ix,
        &[
            (e.payer, sol_account(10 * SOL)),
            (e.identity, identity_acc.clone()),
            (pending, Account::default()),
            keyed_account_for_system_program(),
        ],
    );
    (r, pending)
}

/// execute_call for `call`, with `state` giving each account's state before the call.
fn execute(
    e: &Env,
    id: &Account,
    pending: Pubkey,
    pending_acc: &Account,
    nonce: u64,
    call: &Instruction,
    state: &[(Pubkey, Account)],
) -> mollusk_svm::result::InstructionResult {
    let mut data = vec![tag::EXECUTE_CALL];
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&call.data);
    let mut metas = vec![
        AccountMeta::new(e.payer, true),
        AccountMeta::new_readonly(e.identity, false),
        AccountMeta::new(pending, false),
        AccountMeta::new_readonly(call.program_id, false),
    ];
    // The outer instruction must not make the agent a signer: only Latrix can sign for it.
    metas.extend(call.accounts.iter().map(|m| AccountMeta { is_signer: m.is_signer && m.pubkey != e.agent, ..m.clone() }));
    let mut accs = vec![(e.payer, sol_account(10 * SOL)), (e.identity, id.clone()), (pending, pending_acc.clone())];
    if call.program_id == sys() {
        accs.push(keyed_account_for_system_program());
    }
    for (k, a) in state {
        if !accs.iter().any(|(x, _)| x == k) {
            accs.push((*k, a.clone()));
        }
    }
    e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &data, metas), &accs)
}

/// A system transfer of `lamports` from the agent to `to`, as the CPI sees it (agent = signer).
fn agent_transfer(e: &Env, to: Pubkey, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec(); // SystemInstruction::Transfer
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction::new_with_bytes(sys(), &data, vec![AccountMeta::new(e.agent, true), AccountMeta::new(to, false)])
}

#[test]
fn init_identity_stores_prepared_key() {
    let e = env();
    let acc = init(&e);
    assert_eq!(acc.owner, pid());
    assert_eq!(acc.data.len(), state::IDENTITY_LEN);
    assert_eq!(acc.data[state::identity::DISC], state::IDENTITY_DISCRIMINATOR);
    assert_eq!(acc.data[state::identity::VAULT_BUMP], e.vault_bump);
    assert_eq!(acc.data[state::identity::AGENT_BUMP], e.agent_bump);
    assert_eq!(state::read_u64(&acc.data, state::identity::NONCE), 0);
    assert_eq!(state::read_32(&acc.data, state::identity::PK_HASH), auth::pubkey_hash(e.pk.as_bytes()));
}

#[test]
fn init_identity_rejects_wrong_address_and_bad_key() {
    let e = env();
    let other = Pubkey::new_unique();
    let r = e.mollusk.process_instruction(
        &init_ix(&e, other, e.pk.as_bytes()),
        &[(e.payer, sol_account(10 * SOL)), (other, Account::default()), keyed_account_for_system_program()],
    );
    assert_eq!(r.program_result, PR::Failure(custom(6002)), "identity not derived from the key");

    let mut bad = e.pk.as_bytes().to_vec();
    bad[0] ^= 0xff; // header byte
    let r = e.mollusk.process_instruction(
        &init_ix(&e, e.identity, &bad),
        &[(e.payer, sol_account(10 * SOL)), (e.identity, Account::default()), keyed_account_for_system_program()],
    );
    assert_eq!(r.program_result, PR::Failure(custom(6001)), "malformed Falcon key");
}

#[test]
fn authorize_call_verifies_falcon_and_consumes_nonce() {
    let e = env();
    let id = init(&e);
    let digest = [7u8; 32];
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Success, "authorize_call failed");
    println!("authorize_call compute units: {}", r.compute_units_consumed);

    let id_after = &r.resulting_accounts[1].1;
    assert_eq!(state::read_u64(&id_after.data, state::identity::NONCE), 1, "nonce consumed");
    let p = &r.resulting_accounts[2].1;
    assert_eq!(r.resulting_accounts[2].0, pending);
    assert_eq!(p.data[state::pending::DISC], state::PENDING_DISCRIMINATOR);
    assert_eq!(state::read_32(&p.data, state::pending::DIGEST), digest);
    assert_eq!(state::read_u64(&p.data, state::pending::VALID_UNTIL), 1_000);
    assert_eq!(state::read_32(&p.data, state::pending::RENT_PAYER), e.payer.to_bytes());

    let (r, _) = authorize(&e, id_after, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Failure(custom(6006)), "replayed signature: nonce moved on");
}

#[test]
fn authorize_call_rejects_forgery_wrong_key_and_expiry() {
    let mut e = env();
    let id = init(&e);
    let digest = [9u8; 32];

    let sig = sign(&e, &e.sk, &[1u8; 32], 0, 1_000);
    let (r, _) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Failure(custom(6004)), "signature over another call");

    let (_pk2, sk2) = falcon::keypair();
    let sig = sign(&e, &sk2, &digest, 0, 1_000);
    let (r, _) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Failure(custom(6004)), "another key's signature");

    let sig = sign(&e, &e.sk, &digest, 1, 1_000);
    let (r, _) = authorize(&e, &id, 1, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Failure(custom(6006)), "wrong nonce");

    e.mollusk.warp_to_slot(2_000);
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (r, _) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Failure(custom(6005)), "expired");
}

#[test]
fn execute_call_moves_funds_only_as_approved() {
    let e = env();
    let id = init(&e);
    let to = Pubkey::new_unique();
    let call = agent_transfer(&e, to, SOL / 10);
    let state = [(e.agent, sol_account(2 * SOL)), (to, sol_account(0))];

    let sig = sign(&e, &e.sk, &digest_of(&call), 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest_of(&call), &sig);
    assert_eq!(r.program_result, PR::Success);
    let id_after = r.resulting_accounts[1].1.clone();
    let pending_acc = r.resulting_accounts[2].1.clone();

    // Amount changed after approval.
    let r = execute(&e, &id_after, pending, &pending_acc, 0, &agent_transfer(&e, to, SOL), &state);
    assert_eq!(r.program_result, PR::Failure(custom(6007)), "different amount");

    // Recipient changed after approval.
    let thief = Pubkey::new_unique();
    let mut st2 = state.to_vec();
    st2.push((thief, sol_account(0)));
    let r = execute(&e, &id_after, pending, &pending_acc, 0, &agent_transfer(&e, thief, SOL / 10), &st2);
    assert_eq!(r.program_result, PR::Failure(custom(6007)), "different recipient");

    // A flag changed after approval (recipient made read-only).
    let mut flagged = call.clone();
    flagged.accounts[1].is_writable = false;
    let r = execute(&e, &id_after, pending, &pending_acc, 0, &flagged, &state);
    assert_eq!(r.program_result, PR::Failure(custom(6007)), "different account flags");

    // The exact approved call: the agent pays, signed by Latrix.
    let r = execute(&e, &id_after, pending, &pending_acc, 0, &call, &state);
    assert_eq!(r.program_result, PR::Success, "approved call");
    println!("execute_call (system transfer) compute units: {}", r.compute_units_consumed);
    let bal = |k: Pubkey| r.resulting_accounts.iter().find(|(x, _)| *x == k).unwrap().1.lamports;
    assert_eq!(bal(to), SOL / 10, "recipient paid");
    assert_eq!(bal(e.agent), 2 * SOL - SOL / 10, "agent debited");
    assert_eq!(bal(pending), 0, "approval closed");
    assert_eq!(bal(e.payer), 10 * SOL + pending_acc.lamports, "approval rent refunded");
}

#[test]
fn execute_call_cannot_target_latrix_itself() {
    let e = env();
    let id = init(&e);
    let call = Instruction::new_with_bytes(pid(), &[tag::CANCEL_PENDING], vec![AccountMeta::new(e.agent, false)]);
    let sig = sign(&e, &e.sk, &digest_of(&call), 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest_of(&call), &sig);
    assert_eq!(r.program_result, PR::Success);
    let state = [(e.agent, sol_account(SOL))];
    let r = execute(&e, &r.resulting_accounts[1].1, pending, &r.resulting_accounts[2].1, 0, &call, &state);
    assert_eq!(r.program_result, PR::Failure(custom(6012)), "re-entry into Latrix");
}

#[test]
fn cancel_pending_only_after_expiry() {
    let mut e = env();
    let id = init(&e);
    let digest = [3u8; 32];
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Success);
    let pending_acc = r.resulting_accounts[2].1.clone();

    let ix = Instruction::new_with_bytes(
        pid(),
        &[tag::CANCEL_PENDING],
        vec![AccountMeta::new(e.payer, false), AccountMeta::new(pending, false)],
    );
    let accs = [(e.payer, sol_account(10 * SOL)), (pending, pending_acc.clone())];
    let r = e.mollusk.process_instruction(&ix, &accs);
    assert_eq!(r.program_result, PR::Failure(custom(6009)), "not expired yet");

    e.mollusk.warp_to_slot(1_001);
    let r = e.mollusk.process_instruction(&ix, &accs);
    assert_eq!(r.program_result, PR::Success, "cancel after expiry");
    assert_eq!(r.resulting_accounts[0].1.lamports, 10 * SOL + pending_acc.lamports, "rent refunded");
    assert_eq!(r.resulting_accounts[1].1.lamports, 0);
}

fn attest(e: &Env, id: &Account, pending: Pubkey, pending_acc: &Account, nonce: u64, mint: Pubkey, pool: Pubkey, record_acc: Account) -> mollusk_svm::result::InstructionResult {
    attest_bps(e, id, pending, pending_acc, nonce, mint, pool, record_acc, 5_000)
}

#[allow(clippy::too_many_arguments)]
fn attest_bps(e: &Env, id: &Account, pending: Pubkey, pending_acc: &Account, nonce: u64, mint: Pubkey, pool: Pubkey, record_acc: Account, bps: u16) -> mollusk_svm::result::InstructionResult {
    let funder = Pubkey::new_unique();
    let (record, bump) = Pubkey::find_program_address(&[state::LAUNCH_SEED, mint.as_ref()], &pid());
    let mut data = vec![tag::ATTEST_LAUNCH];
    data.extend_from_slice(&nonce.to_le_bytes());
    data.push(bump);
    data.extend_from_slice(&bps.to_le_bytes());
    let ix = Instruction::new_with_bytes(
        pid(),
        &data,
        vec![
            AccountMeta::new(funder, true),
            AccountMeta::new(e.payer, false),
            AccountMeta::new_readonly(e.identity, false),
            AccountMeta::new(pending, false),
            AccountMeta::new_readonly(mint, true),
            AccountMeta::new_readonly(pool, false),
            AccountMeta::new(record, false),
            AccountMeta::new_readonly(sys(), false),
        ],
    );
    e.mollusk.process_instruction(
        &ix,
        &[
            (funder, sol_account(SOL)),
            (e.payer, sol_account(10 * SOL)),
            (e.identity, id.clone()),
            (pending, pending_acc.clone()),
            (mint, Account::default()),
            (pool, Account::default()),
            (record, record_acc),
            keyed_account_for_system_program(),
        ],
    )
}

#[test]
fn attest_launch_records_only_the_signed_mint_and_pool() {
    let e = env();
    let id = init(&e);
    let (mint, pool) = (Pubkey::new_unique(), Pubkey::new_unique());
    let digest = auth::launch_digest(mint.as_ref(), pool.as_ref(), 5_000);
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Success);
    let id_after = r.resulting_accounts[1].1.clone();
    let pending_acc = r.resulting_accounts[2].1.clone();

    // Another pool than the one the key signed.
    let r = attest(&e, &id_after, pending, &pending_acc, 0, mint, Pubkey::new_unique(), Account::default());
    assert_eq!(r.program_result, PR::Failure(custom(6013)), "different pool");

    // A call approval can never be used as a launch approval (different domain).
    let call_digest = [5u8; 32];
    let sig2 = sign(&e, &e.sk, &call_digest, 1, 1_000);
    let (r2, pending2) = authorize(&e, &id_after, 1, 1_000, &call_digest, &sig2);
    assert_eq!(r2.program_result, PR::Success);
    let r = attest(&e, &r2.resulting_accounts[1].1, pending2, &r2.resulting_accounts[2].1, 1, mint, pool, Account::default());
    assert_eq!(r.program_result, PR::Failure(custom(6013)), "call approval used as a launch");

    // The same mint and pool but another fee split than the key signed (100% to the dev).
    let r = attest_bps(&e, &id_after, pending, &pending_acc, 0, mint, pool, Account::default(), 10_000);
    assert_eq!(r.program_result, PR::Failure(custom(6013)), "different fee split");

    // The signed launch: record written, approval closed.
    let r = attest(&e, &id_after, pending, &pending_acc, 0, mint, pool, Account::default());
    assert_eq!(r.program_result, PR::Success, "attest_launch");
    println!("attest_launch compute units: {}", r.compute_units_consumed);
    let rec = &r.resulting_accounts[6].1;
    assert_eq!(rec.owner, pid());
    assert_eq!(rec.data[state::launch::DISC], state::LAUNCH_DISCRIMINATOR);
    assert_eq!(state::read_32(&rec.data, state::launch::IDENTITY), e.identity.to_bytes());
    assert_eq!(state::read_32(&rec.data, state::launch::MINT), mint.to_bytes());
    assert_eq!(state::read_32(&rec.data, state::launch::POOL), pool.to_bytes());
    assert_eq!(u16::from_le_bytes([rec.data[2], rec.data[3]]), 5_000, "fee split stored");
    let (fv, fv_bump) = Pubkey::find_program_address(&[state::FEE_VAULT_SEED, mint.as_ref()], &pid());
    assert_eq!(rec.data[state::launch::FEE_VAULT_BUMP], fv_bump, "fee vault {fv}");
    assert_eq!(r.resulting_accounts[3].1.lamports, 0, "approval closed");

    // The same coin cannot be attested twice (the record already exists).
    let sig3 = sign(&e, &e.sk, &digest, 2, 1_000);
    let mut id3 = id_after.clone();
    id3.data[state::identity::NONCE].copy_from_slice(&2u64.to_le_bytes());
    let (r3, pending3) = authorize(&e, &id3, 2, 1_000, &digest, &sig3);
    assert_eq!(r3.program_result, PR::Success);
    let r = attest(&e, &r3.resulting_accounts[1].1, pending3, &r3.resulting_accounts[2].1, 2, mint, pool, rec.clone());
    assert!(r.program_result.is_err(), "second attestation of the same mint must fail");
}

/// A DAMM v2 pool that is not the coin's graduated pool (created by someone other than Meteora DBC's
/// migration) must be refused, even with the right mints - otherwise a fake pool could absorb the buyback.
#[test]
fn buyback_burn_damm_refuses_a_fake_pool() {
    let e = env();
    let mint = Pubkey::new_unique();
    let wsol = Pubkey::new_from_array(latrix_program::instructions::external::WSOL.to_bytes());
    let damm = Pubkey::new_from_array(latrix_program::instructions::external::DAMM_V2.to_bytes());
    let token = Pubkey::new_from_array(latrix_program::instructions::external::TOKEN_PROGRAM.to_bytes());
    let ata_prog = Pubkey::new_from_array(latrix_program::instructions::external::ATA_PROGRAM.to_bytes());
    let (record, _) = Pubkey::find_program_address(&[state::LAUNCH_SEED, mint.as_ref()], &pid());
    let (fee_vault, fv_bump) = Pubkey::find_program_address(&[state::FEE_VAULT_SEED, mint.as_ref()], &pid());
    let ata = |o: &Pubkey, m: &Pubkey| Pubkey::find_program_address(&[o.as_ref(), token.as_ref(), m.as_ref()], &ata_prog).0;

    let mut rec = vec![0u8; state::LAUNCH_LEN];
    rec[state::launch::DISC] = state::LAUNCH_DISCRIMINATOR;
    rec[state::launch::FEE_VAULT_BUMP] = fv_bump;
    rec[state::launch::IDENTITY].copy_from_slice(e.identity.as_ref());
    rec[state::launch::MINT].copy_from_slice(mint.as_ref());
    rec[state::launch::POOL].copy_from_slice(Pubkey::new_unique().as_ref());
    let record_acc = Account { lamports: SOL, data: rec, owner: pid(), executable: false, rent_epoch: 0 };

    // Counterfeit pool: owned by DAMM v2, right mints and vaults, but its creator is NOT DBC's pool authority.
    let (pool, a_vault, b_vault) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
    let mut pd = vec![0u8; 1112];
    pd[168..200].copy_from_slice(mint.as_ref());
    pd[200..232].copy_from_slice(wsol.as_ref());
    pd[232..264].copy_from_slice(a_vault.as_ref());
    pd[264..296].copy_from_slice(b_vault.as_ref());
    pd[648..680].copy_from_slice(Pubkey::new_unique().as_ref()); // someone else
    let pool_acc = Account { lamports: SOL, data: pd, owner: damm, executable: false, rent_epoch: 0 };

    let pa = Pubkey::new_from_array(latrix_program::instructions::external::DAMM_POOL_AUTHORITY.to_bytes());
    let ea = Pubkey::new_from_array(latrix_program::instructions::external::DAMM_EVENT_AUTHORITY.to_bytes());
    let mut data = vec![tag::BUYBACK_BURN_DAMM];
    data.extend_from_slice(&0u64.to_le_bytes());
    let crank = Pubkey::new_unique();
    let (config, config_acc) = config_account(crank);
    let (cooldown, _) = Pubkey::find_program_address(&[state::BUYBACK_SEED, mint.as_ref()], &pid());
    let keys = [record, fee_vault, ata(&fee_vault, &wsol), ata(&fee_vault, &mint), pa, pool, a_vault, b_vault, mint, wsol, token, ea, damm, config, crank, cooldown, sys()];
    let metas: Vec<AccountMeta> = keys.iter().enumerate().map(|(i, k)| match i {
        0 | 2 | 3 | 5 | 6 | 7 | 8 | 15 => AccountMeta::new(*k, false),
        14 => AccountMeta::new(*k, true),
        _ => AccountMeta::new_readonly(*k, false),
    }).collect();
    let accs: Vec<(Pubkey, Account)> = keys.iter().map(|k| {
        let a = if *k == record { record_acc.clone() } else if *k == pool { pool_acc.clone() } else if *k == config { config_acc.clone() }
            else if *k == cooldown { Account::default() } else if *k == sys() { keyed_account_for_system_program().1 } else { sol_account(SOL) };
        (*k, a)
    }).collect();
    let r = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &data, metas), &accs);
    assert_eq!(r.program_result, PR::Failure(custom(6015)), "counterfeit DAMM v2 pool refused");
}

/// claim_fees_damm: the fee vault's position fees after graduation. Refuses a pool that is not the coin's
/// graduated pool, and a position that belongs to another pool (the rest - that the fee vault owns the position -
/// DAMM v2 itself checks against the signing owner).
#[test]
fn claim_fees_damm_refuses_fake_pool_and_foreign_position() {
    use latrix_program::instructions::external as x;
    let e = env();
    let id = init(&e);
    let mint = Pubkey::new_unique();
    let pk = |a: pinocchio::Address| Pubkey::new_from_array(a.to_bytes());
    let (wsol, damm, token, ata_prog) = (pk(x::WSOL), pk(x::DAMM_V2), pk(x::TOKEN_PROGRAM), pk(x::ATA_PROGRAM));
    let (record, _) = Pubkey::find_program_address(&[state::LAUNCH_SEED, mint.as_ref()], &pid());
    let (fee_vault, fv_bump) = Pubkey::find_program_address(&[state::FEE_VAULT_SEED, mint.as_ref()], &pid());
    let ata = |o: &Pubkey, m: &Pubkey| Pubkey::find_program_address(&[o.as_ref(), token.as_ref(), m.as_ref()], &ata_prog).0;
    let agent = Pubkey::create_program_address(&[b"agent", e.identity.as_ref(), &[id.data[state::identity::AGENT_BUMP]]], &pid()).unwrap();

    let mut rec = vec![0u8; state::LAUNCH_LEN];
    rec[state::launch::DISC] = state::LAUNCH_DISCRIMINATOR;
    rec[state::launch::FEE_VAULT_BUMP] = fv_bump;
    rec[2..4].copy_from_slice(&5_000u16.to_le_bytes());
    rec[state::launch::IDENTITY].copy_from_slice(e.identity.as_ref());
    rec[state::launch::MINT].copy_from_slice(mint.as_ref());
    rec[state::launch::POOL].copy_from_slice(Pubkey::new_unique().as_ref());
    let record_acc = Account { lamports: SOL, data: rec, owner: pid(), executable: false, rent_epoch: 0 };

    let (pool, a_vault, b_vault, position) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
    let pool_data = |creator: Pubkey| {
        let mut pd = vec![0u8; 1112];
        pd[168..200].copy_from_slice(mint.as_ref());
        pd[200..232].copy_from_slice(wsol.as_ref());
        pd[232..264].copy_from_slice(a_vault.as_ref());
        pd[264..296].copy_from_slice(b_vault.as_ref());
        pd[648..680].copy_from_slice(creator.as_ref());
        Account { lamports: SOL, data: pd, owner: damm, executable: false, rent_epoch: 0 }
    };
    let position_of = |p: Pubkey| {
        let mut d = vec![0u8; 400];
        d[..8].copy_from_slice(&x::DAMM_POSITION_DISCRIMINATOR);
        d[8..40].copy_from_slice(p.as_ref());
        d[40..72].copy_from_slice(Pubkey::new_unique().as_ref());
        Account { lamports: SOL, data: d, owner: damm, executable: false, rent_epoch: 0 }
    };
    let keys = [record, e.identity, fee_vault, ata(&fee_vault, &wsol), ata(&fee_vault, &mint), ata(&agent, &wsol),
        pk(x::DAMM_POOL_AUTHORITY), pool, position, a_vault, b_vault, mint, wsol, Pubkey::new_unique(), token, pk(x::DAMM_EVENT_AUTHORITY), damm];
    let run = |pool_acc: Account, pos_acc: Account| {
        let metas: Vec<AccountMeta> = keys.iter().enumerate().map(|(i, k)| match i {
            0 | 3 | 4 | 5 | 8 | 9 | 10 => AccountMeta::new(*k, false),
            _ => AccountMeta::new_readonly(*k, false),
        }).collect();
        let accs: Vec<(Pubkey, Account)> = keys.iter().map(|k| {
            let a = if *k == record { record_acc.clone() } else if *k == e.identity { id.clone() } else if *k == pool { pool_acc.clone() }
                else if *k == position { pos_acc.clone() } else { sol_account(SOL) };
            (*k, a)
        }).collect();
        e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &[tag::CLAIM_FEES_DAMM], metas), &accs)
    };

    let r = run(pool_data(Pubkey::new_unique()), position_of(pool));
    assert_eq!(r.program_result, PR::Failure(custom(6015)), "counterfeit DAMM v2 pool refused");
    let r = run(pool_data(pk(x::DBC_POOL_AUTHORITY)), position_of(Pubkey::new_unique()));
    assert_eq!(r.program_result, PR::Failure(custom(6015)), "position of another pool refused");
}

/// The Latrix config PDA with `crank` set, as set_crank leaves it.
fn config_account(crank: Pubkey) -> (Pubkey, Account) {
    let (config, bump) = Pubkey::find_program_address(&[state::CONFIG_SEED], &pid());
    let mut d = vec![0u8; state::CONFIG_LEN];
    d[state::config::DISC] = state::CONFIG_DISCRIMINATOR;
    d[state::config::BUMP] = bump;
    d[state::config::CRANK].copy_from_slice(crank.as_ref());
    (config, Account { lamports: SOL, data: d, owner: pid(), executable: false, rent_epoch: 0 })
}

/// The relayer (any signer of the transaction) never lends its signature to an approved call: an identity that
/// approves "transfer from the relayer to me" gets a failed CPI, not the relayer's SOL.
#[test]
fn execute_call_never_passes_on_outside_signers() {
    let e = env();
    let id = init(&e);
    let thief = Pubkey::new_unique();
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&(SOL / 2).to_le_bytes());
    let steal = Instruction::new_with_bytes(sys(), &data, vec![AccountMeta::new(e.payer, true), AccountMeta::new(thief, false)]);
    let digest = digest_of(&steal);
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Success);
    let r = execute(&e, &r.resulting_accounts[1].1, pending, &r.resulting_accounts[2].1, 0, &steal, &[(thief, sol_account(0))]);
    assert_eq!(r.program_result, PR::Failure(ProgramError::MissingRequiredSignature), "the relayer's signature must not reach the call");
}

#[test]
fn rings_payer_exception_is_withdraw_only() {
    use latrix_program::instructions::external::rings_withdrawal_only as w;
    let base = |transfers: &[u8]| {
        let mut d = vec![16u8];
        d.extend_from_slice(&[0u8; 8 + 33 + 16]);
        d.extend_from_slice(transfers);
        d.extend_from_slice(&[0u8; 64]);
        d
    };
    assert!(w(&base(&[1, 1, 0, 0, 0, 0, 0, 0, 0, 0])), "one sol withdrawal");
    assert!(!w(&base(&[0])), "no public withdrawal: the payer exception is not needed");
    let mut cut = base(&[2, 1, 0, 0, 0, 0, 0, 0, 0, 0]);
    cut.truncate(1 + 8 + 33 + 16 + 1 + 9 + 3);
    assert!(!w(&cut), "declared two transfers, data holds one and a half");
    assert!(!w(&[16u8; 10]), "shorter than the header");
    assert!(!w(&base(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0])), "sol deposit refused");
    assert!(!w(&base(&[2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1])), "spl deposit refused");
    let mut other = base(&[0]);
    other[0] = 15;
    assert!(!w(&other), "not a transact");
}

/// Only the canonical launch record counts: attest refuses another bump and needs the mint's signature, and the
/// fee paths refuse a record that is not at the canonical address.
#[test]
fn launch_records_are_canonical_only() {
    let e = env();
    let id = init(&e);
    let (mint, pool) = (Pubkey::new_unique(), Pubkey::new_unique());
    let (canonical_record, canonical) = Pubkey::find_program_address(&[state::LAUNCH_SEED, mint.as_ref()], &pid());
    let other = (0..canonical)
        .rev()
        .find_map(|b| Pubkey::create_program_address(&[state::LAUNCH_SEED, mint.as_ref(), &[b]], &pid()).ok().map(|a| (a, b)))
        .expect("a non-canonical bump");

    let digest = auth::launch_digest(mint.as_ref(), pool.as_ref(), 5_000);
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (r, pending) = authorize(&e, &id, 0, 1_000, &digest, &sig);
    assert_eq!(r.program_result, PR::Success);
    let funder = Pubkey::new_unique();
    let mut data = vec![tag::ATTEST_LAUNCH];
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(other.1);
    data.extend_from_slice(&5_000u16.to_le_bytes());
    let metas = vec![
        AccountMeta::new(funder, true), AccountMeta::new(e.payer, false), AccountMeta::new_readonly(e.identity, false), AccountMeta::new(pending, false),
        AccountMeta::new_readonly(mint, true), AccountMeta::new_readonly(pool, false), AccountMeta::new(other.0, false), AccountMeta::new_readonly(sys(), false),
    ];
    let accs = vec![
        (funder, sol_account(SOL)), (e.payer, sol_account(10 * SOL)), (e.identity, r.resulting_accounts[1].1.clone()),
        (pending, r.resulting_accounts[2].1.clone()), (mint, Account::default()), (pool, Account::default()), (other.0, Account::default()),
        keyed_account_for_system_program(),
    ];
    let res = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &data, metas.clone()), &accs);
    assert_eq!(res.program_result, PR::Failure(custom(6008)), "non-canonical launch bump refused");

    let mut unsigned = metas.clone();
    unsigned[4].is_signer = false;
    unsigned[6].pubkey = canonical_record;
    let mut data2 = data.clone();
    data2[9] = canonical;
    let mut accs2 = accs.clone();
    accs2[6] = (canonical_record, Account::default());
    let res = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &data2, unsigned), &accs2);
    assert_eq!(res.program_result, PR::Failure(ProgramError::MissingRequiredSignature), "attest without the mint's signature refused");

    let mut rec = vec![0u8; state::LAUNCH_LEN];
    rec[state::launch::DISC] = state::LAUNCH_DISCRIMINATOR;
    rec[2..4].copy_from_slice(&10_000u16.to_le_bytes());
    rec[state::launch::IDENTITY].copy_from_slice(e.identity.as_ref());
    rec[state::launch::MINT].copy_from_slice(mint.as_ref());
    let fake = Account { lamports: SOL, data: rec, owner: pid(), executable: false, rent_epoch: 0 };
    let keys: Vec<Pubkey> = std::iter::once(other.0).chain((0..14).map(|_| Pubkey::new_unique())).collect();
    let metas: Vec<AccountMeta> = keys.iter().map(|k| AccountMeta::new(*k, false)).collect();
    let accs: Vec<(Pubkey, Account)> = keys.iter().map(|k| (*k, if *k == other.0 { fake.clone() } else { sol_account(SOL) })).collect();
    let res = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &[tag::CLAIM_FEES], metas), &accs);
    assert_eq!(res.program_result, PR::Failure(custom(6003)), "claim with a non-canonical record refused");
}

#[test]
fn init_identity_requires_canonical_bumps() {
    let e = env();
    let other = (0..e.vault_bump)
        .rev()
        .find(|b| Pubkey::create_program_address(&[state::VAULT_SEED, e.identity.as_ref(), &[*b]], &pid()).is_ok())
        .expect("a non-canonical vault bump");
    let mut ix = init_ix(&e, e.identity, e.pk.as_bytes());
    ix.data[2] = other;
    let r = e.mollusk.process_instruction(&ix, &[(e.payer, sol_account(10 * SOL)), (e.identity, Account::default()), keyed_account_for_system_program()]);
    assert_eq!(r.program_result, PR::Failure(custom(6008)), "non-canonical vault bump refused");
}

/// Buybacks need the crank's signature; set_crank needs the program's upgrade authority.
#[test]
fn buybacks_need_the_crank_and_only_the_upgrade_authority_sets_it() {
    let e = env();
    let crank = Pubkey::new_unique();
    let (config, config_acc) = config_account(crank);
    let mut data = vec![tag::BUYBACK_BURN];
    data.extend_from_slice(&0u64.to_le_bytes());
    let stranger = Pubkey::new_unique();
    let keys: Vec<Pubkey> = (0..14).map(|_| Pubkey::new_unique()).chain([config, stranger, Pubkey::new_unique(), sys()]).collect();
    let metas: Vec<AccountMeta> = keys.iter().enumerate().map(|(i, k)| if i == 15 { AccountMeta::new_readonly(*k, true) } else { AccountMeta::new(*k, false) }).collect();
    let accs: Vec<(Pubkey, Account)> = keys.iter().map(|k| (*k, if *k == config { config_acc.clone() } else { sol_account(SOL) })).collect();
    let r = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &data, metas), &accs);
    assert_eq!(r.program_result, PR::Failure(custom(6017)), "buyback by someone other than the crank refused");

    let loader = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    let (program_data, _) = Pubkey::find_program_address(&[pid().as_ref()], &loader);
    let authority = Pubkey::new_unique();
    let mut pd = vec![0u8; 45];
    pd[0..4].copy_from_slice(&3u32.to_le_bytes());
    pd[12] = 1;
    pd[13..45].copy_from_slice(authority.as_ref());
    let pd_acc = Account { lamports: SOL, data: pd, owner: loader, executable: false, rent_epoch: 0 };
    let run = |signer: Pubkey| {
        let mut d = vec![tag::SET_CRANK];
        d.extend_from_slice(crank.as_ref());
        e.mollusk.process_instruction(
            &Instruction::new_with_bytes(
                pid(),
                &d,
                vec![AccountMeta::new(signer, true), AccountMeta::new(config, false), AccountMeta::new_readonly(program_data, false), AccountMeta::new_readonly(sys(), false)],
            ),
            &[(signer, sol_account(SOL)), (config, Account::default()), (program_data, pd_acc.clone()), keyed_account_for_system_program()],
        )
    };
    assert!(run(Pubkey::new_unique()).program_result.is_err(), "not the upgrade authority");
    let r = run(authority);
    assert_eq!(r.program_result, PR::Success, "upgrade authority sets the crank");
    let cfg = &r.resulting_accounts[1].1;
    assert_eq!(cfg.owner, pid());
    assert_eq!(&cfg.data[state::config::CRANK], crank.as_ref());
}


/// Pre-funding the next approval's address (a predictable PDA) must not block the identity: authorize_call still
/// creates it (the old create_account would fail forever, freezing the vault).
#[test]
fn prefunded_pending_address_does_not_block_the_identity() {
    let e = env();
    let id = init(&e);
    let digest = [9u8; 32];
    let sig = sign(&e, &e.sk, &digest, 0, 1_000);
    let (pending, bump) = pending_pda(&e, 0);
    let mut data = vec![tag::AUTHORIZE_CALL];
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&1_000u64.to_le_bytes());
    data.extend_from_slice(&digest);
    data.push(bump);
    data.extend_from_slice(&sig);
    let ix = Instruction::new_with_bytes(pid(), &data, vec![AccountMeta::new(e.payer, true), AccountMeta::new(e.identity, false), AccountMeta::new(pending, false), AccountMeta::new_readonly(sys(), false)]);
    let r = e.mollusk.process_instruction(&ix, &[(e.payer, sol_account(10 * SOL)), (e.identity, id), (pending, sol_account(1_000_000)), keyed_account_for_system_program()]);
    assert_eq!(r.program_result, PR::Success, "approval created on a pre-funded address");
    assert_eq!(r.resulting_accounts[2].1.owner, pid());
}

/// A coin's buyback state blocks a second buyback inside the cooldown (checked before any swap).
#[test]
fn buyback_cooldown_is_enforced() {
    let e = env();
    let mint = Pubkey::new_unique();
    let crank = Pubkey::new_unique();
    let (config, config_acc) = config_account(crank);
    let (record, _) = Pubkey::find_program_address(&[state::LAUNCH_SEED, mint.as_ref()], &pid());
    let (_, fv_bump) = Pubkey::find_program_address(&[state::FEE_VAULT_SEED, mint.as_ref()], &pid());
    let mut rec = vec![0u8; state::LAUNCH_LEN];
    rec[state::launch::DISC] = state::LAUNCH_DISCRIMINATOR;
    rec[state::launch::FEE_VAULT_BUMP] = fv_bump;
    rec[state::launch::IDENTITY].copy_from_slice(e.identity.as_ref());
    rec[state::launch::MINT].copy_from_slice(mint.as_ref());
    let record_acc = Account { lamports: SOL, data: rec, owner: pid(), executable: false, rent_epoch: 0 };
    let (cooldown, cb) = Pubkey::find_program_address(&[state::BUYBACK_SEED, mint.as_ref()], &pid());
    let mut cd = vec![0u8; state::BUYBACK_LEN];
    cd[0] = state::BUYBACK_DISCRIMINATOR;
    cd[1] = cb;
    let cooldown_acc = Account { lamports: SOL, data: cd, owner: pid(), executable: false, rent_epoch: 0 }; // last buyback at slot 0
    let mut data = vec![tag::BUYBACK_BURN];
    data.extend_from_slice(&0u64.to_le_bytes());
    let keys: Vec<Pubkey> = std::iter::once(record).chain((0..13).map(|_| Pubkey::new_unique())).chain([config, crank, cooldown, sys()]).collect();
    let metas: Vec<AccountMeta> = keys.iter().enumerate().map(|(i, k)| match i { 15 => AccountMeta::new(*k, true), _ => AccountMeta::new(*k, false) }).collect();
    let accs: Vec<(Pubkey, Account)> = keys.iter().map(|k| (*k, if *k == record { record_acc.clone() } else if *k == config { config_acc.clone() }
        else if *k == cooldown { cooldown_acc.clone() } else if *k == sys() { keyed_account_for_system_program().1 } else { sol_account(SOL) })).collect();
    let r = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &data, metas), &accs);
    assert_eq!(r.program_result, PR::Failure(custom(6018)), "second buyback inside the cooldown refused");

    // trailing bytes after min_out are refused
    let mut long = data.clone();
    long.push(0);
    let metas2: Vec<AccountMeta> = keys.iter().enumerate().map(|(i, k)| match i { 15 => AccountMeta::new(*k, true), _ => AccountMeta::new(*k, false) }).collect();
    let r = e.mollusk.process_instruction(&Instruction::new_with_bytes(pid(), &long, metas2), &accs);
    assert_eq!(r.program_result, PR::Failure(custom(6000)), "trailing data refused");
}

/// set_crank: rotation works for the authority; an immutable program, a ProgramData not owned by the loader, or one
/// at the wrong address cannot set it.
#[test]
fn set_crank_rotation_and_refusals() {
    let e = env();
    let loader = Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    let (program_data, _) = Pubkey::find_program_address(&[pid().as_ref()], &loader);
    let authority = Pubkey::new_unique();
    let pd = |opt: u8, owner: Pubkey| {
        let mut d = vec![0u8; 45];
        d[0..4].copy_from_slice(&3u32.to_le_bytes());
        d[12] = opt;
        d[13..45].copy_from_slice(authority.as_ref());
        Account { lamports: SOL, data: d, owner, executable: false, rent_epoch: 0 }
    };
    let old_crank = Pubkey::new_unique();
    let (config, config_acc) = config_account(old_crank);
    let new_crank = Pubkey::new_unique();
    let run = |pd_key: Pubkey, pd_acc: Account| {
        let mut d = vec![tag::SET_CRANK];
        d.extend_from_slice(new_crank.as_ref());
        e.mollusk.process_instruction(
            &Instruction::new_with_bytes(pid(), &d, vec![AccountMeta::new(authority, true), AccountMeta::new(config, false), AccountMeta::new_readonly(pd_key, false), AccountMeta::new_readonly(sys(), false)]),
            &[(authority, sol_account(SOL)), (config, config_acc.clone()), (pd_key, pd_acc), keyed_account_for_system_program()],
        )
    };
    let r = run(program_data, pd(1, loader));
    assert_eq!(r.program_result, PR::Success, "authority rotates the crank");
    assert_eq!(&r.resulting_accounts[1].1.data[state::config::CRANK], new_crank.as_ref());
    assert_eq!(run(program_data, pd(0, loader)).program_result, PR::Failure(ProgramError::MissingRequiredSignature), "immutable program: no authority");
    assert_eq!(run(program_data, pd(1, Pubkey::new_unique())).program_result, PR::Failure(custom(6003)), "ProgramData not owned by the loader");
    assert_eq!(run(Pubkey::new_unique(), pd(1, loader)).program_result, PR::Failure(custom(6003)), "ProgramData at the wrong address");
}
