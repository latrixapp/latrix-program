//! Account layouts. Fixed little-endian byte layouts, read and written in place (no serializer).
//!
//! Identity  (seeds `["identity", sha256(falcon_pubkey)]`, owned by this program)
//!   0        discriminator = 1
//!   1        identity bump
//!   2        vault bump
//!   3        agent bump
//!   4..8     padding
//!   8..16    nonce (u64)            next authorization nonce; every authorize_spend consumes one
//!   16..48   falcon_pubkey_hash     sha256 of the 897-byte Falcon-512 public key
//!   48..1072 prepared pubkey        the key in NTT form (1024 bytes), so each verify skips decoding
//!
//! Vault     (seeds `["vault", identity]`) - holds no data and is never created. It is the
//!           shielded-pool OWNER of the identity's private balance; only this program signs for it.
//!
//! Agent     (seeds `["agent", identity]`) - a plain system account (no data) the identity acts
//!           through in public: it holds SOL and tokens, pays, and is the Meteora DBC pool creator.
//!           Only this program signs for it, and only for a call the Falcon key approved.
//!
//! Pending   (seeds `["pending", identity, nonce_le]`, owned by this program)
//!   0        discriminator = 2
//!   1        bump
//!   2..8     padding
//!   8..16    valid_until_slot (u64)
//!   16..24   nonce (u64)
//!   24..56   identity
//!   56..88   call_digest            sha256 of the exact instruction the key approved (auth.rs)
//!   88..120  rent_payer             gets the account's rent back when it is used or cancelled
//!
//! Launch    (seeds `["launch", mint]`, owned by this program) - written by attest_launch: proof that
//!           an identity's Falcon key launched this coin. One per mint, never changed.
//!   0        discriminator = 3
//!   1        bump
//!   2..4     dev_share_bps (u16)    share of creator fees to the dev (0..=10000); the rest is
//!                                   bought back and burned. Signed by the Falcon key, never changes
//!   4        fee_vault bump
//!   5..8     padding
//!   8..16    slot (u64)             when the launch was attested
//!   16..48   identity
//!   48..80   mint
//!   80..112  pool                   the Meteora DBC pool created in the same transaction
//!   112..120 dev_lamports (u64)     creator fees paid to the dev so far
//!   120..128 burn_lamports (u64)    creator fees spent on buybacks so far
//!   128..136 burned_tokens (u64)    tokens bought back and burned so far
//!
//! Fee vault (seeds `["fee_vault", mint]`) - no data, never created: the Meteora DBC pool CREATOR.
//!           Creator fees can only leave it through claim_fees (dev share) and buyback_burn.

use solana_falcon512::FALCON_512_PREPARED_PUBKEY_LEN;

pub const IDENTITY_SEED: &[u8] = b"identity";
pub const VAULT_SEED: &[u8] = b"vault";
pub const AGENT_SEED: &[u8] = b"agent";
pub const PENDING_SEED: &[u8] = b"pending";
pub const LAUNCH_SEED: &[u8] = b"launch";
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";
/// Config (seeds `["config"]`, owned by this program): set by the program's upgrade authority (set_crank).
///   0 discriminator = 4, 1 bump, 2..8 padding, 8..40 crank (the only key that may run buybacks)
pub const CONFIG_SEED: &[u8] = b"config";
/// Buyback state (seeds `["buyback", mint]`, owned by this program): 0 discriminator = 5, 1 bump, 8..16 last buyback slot.
/// Created by the crank on a coin's first buyback; enforces BUYBACK_COOLDOWN_SLOTS between buybacks.
pub const BUYBACK_SEED: &[u8] = b"buyback";

pub const IDENTITY_DISCRIMINATOR: u8 = 1;
pub const PENDING_DISCRIMINATOR: u8 = 2;
pub const LAUNCH_DISCRIMINATOR: u8 = 3;
pub const CONFIG_DISCRIMINATOR: u8 = 4;
pub const BUYBACK_DISCRIMINATOR: u8 = 5;

pub const IDENTITY_LEN: usize = 48 + FALCON_512_PREPARED_PUBKEY_LEN;
pub const PENDING_LEN: usize = 120;
pub const LAUNCH_LEN: usize = 136;
pub const CONFIG_LEN: usize = 40;
pub const BUYBACK_LEN: usize = 16;
/// ~30 minutes at 400 ms slots: one buyback per coin per window, so no one can time repeated buybacks against it.
pub const BUYBACK_COOLDOWN_SLOTS: u64 = 4_500;

pub mod config {
    pub const DISC: usize = 0;
    pub const BUMP: usize = 1;
    pub const CRANK: core::ops::Range<usize> = 8..40;
}

pub mod identity {
    pub const DISC: usize = 0;
    pub const BUMP: usize = 1;
    pub const VAULT_BUMP: usize = 2;
    pub const AGENT_BUMP: usize = 3;
    pub const NONCE: core::ops::Range<usize> = 8..16;
    pub const PK_HASH: core::ops::Range<usize> = 16..48;
    pub const PREPARED: core::ops::Range<usize> = 48..super::IDENTITY_LEN;
}

pub mod pending {
    pub const DISC: usize = 0;
    pub const BUMP: usize = 1;
    pub const VALID_UNTIL: core::ops::Range<usize> = 8..16;
    pub const NONCE: core::ops::Range<usize> = 16..24;
    pub const IDENTITY: core::ops::Range<usize> = 24..56;
    pub const DIGEST: core::ops::Range<usize> = 56..88;
    pub const RENT_PAYER: core::ops::Range<usize> = 88..120;
}

pub mod launch {
    pub const DISC: usize = 0;
    pub const BUMP: usize = 1;
    pub const DEV_SHARE_BPS: core::ops::Range<usize> = 2..4;
    pub const FEE_VAULT_BUMP: usize = 4;
    pub const SLOT: core::ops::Range<usize> = 8..16;
    pub const IDENTITY: core::ops::Range<usize> = 16..48;
    pub const MINT: core::ops::Range<usize> = 48..80;
    pub const POOL: core::ops::Range<usize> = 80..112;
    pub const DEV_LAMPORTS: core::ops::Range<usize> = 112..120;
    pub const BURN_LAMPORTS: core::ops::Range<usize> = 120..128;
    pub const BURNED_TOKENS: core::ops::Range<usize> = 128..136;
}

#[inline(always)]
pub fn read_u64(data: &[u8], r: core::ops::Range<usize>) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[r]);
    u64::from_le_bytes(b)
}

#[inline(always)]
pub fn read_32(data: &[u8], r: core::ops::Range<usize>) -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(&data[r]);
    b
}
