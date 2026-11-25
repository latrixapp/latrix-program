# Latrix program

The on-chain program behind [latrix.app](https://latrix.app): a Solana launchpad where coins are launched by a
**Falcon-512 identity** (a NIST-selected post-quantum signature scheme) instead of a wallet, funded privately through
**Helius Privacy Rings**, with pools on **Meteora DBC** and, after graduation, **Meteora DAMM v2**.

| | |
|---|---|
| Program (mainnet) | `LTRXiaWWy3KbwiwMPCPu6QomafKrj12BPkpnAAwhNHD` |
| Framework | [pinocchio](https://github.com/anza-xyz/pinocchio) (no Anchor) |
| Falcon-512 verifier | [`solana-falcon512`](https://crates.io/crates/solana-falcon512) by Blueshift (MIT) |
| Status | **not audited** |

## How it works

An **identity** is an account at `["identity", sha256(falcon_pubkey)]` holding a Falcon-512 public key (stored
pre-transformed, so every verification is cheaper). Each identity owns two PDAs that only this program can sign for:

- **vault** `["vault", identity]`: the owner of the identity's private Privacy Rings balance;
- **agent** `["agent", identity]`: the account the identity acts through in public (it receives the dev's fee share).

Nothing moves without the Falcon key. Every action is two steps:

1. `authorize_call` verifies a Falcon-512 signature over *(program, identity, digest of one exact instruction, nonce,
   expiry slot)* and stores a single-use approval;
2. `execute_call` recomputes the digest of the instruction it is given (target program, every account with its
   writable/signer flags, the data; length-framed), checks it equals the approval, and invokes it with the vault and
   agent as signers. No other account in the call receives a signature it did not bring.

### Launches and fees

- `attest_launch` consumes a **launch-domain** approval (it cannot be confused with a call approval) and writes a
  permanent record at `["launch", mint]`: the identity, the coin, its Meteora DBC pool and the creator-fee split the key
  signed. The coin's mint must sign the same transaction, so nobody can copy a pending launch's attestation.
- The pool's creator role goes to a per-coin **fee vault** `["fee_vault", mint]` with no key.
- `claim_fees` (bonding curve) and `claim_fees_damm` (after graduation: the fee vault's share of the permanently locked
  DAMM v2 liquidity) are permissionless. They pay the dev exactly the share their key signed, to their agent; the rest
  stays in the fee vault.
- `buyback_burn` / `buyback_burn_damm` spend the fee vault on the coin and burn everything bought. Only the
  launchpad's **crank** may run them (named in `["config"]` by the program's upgrade authority through `set_crank`),
  at most 1 SOL per call and one buyback per coin per ~30 minutes (`["buyback", mint]`), with a price floor.

| Tag | Instruction | Who |
|---|---|---|
| 0 | `init_identity` | anyone (registers a key) |
| 1 | `authorize_call` | Falcon signature |
| 2 | `execute_call` | the approved call only |
| 3 | `cancel_pending` | anyone, after expiry (rent back to its payer) |
| 4 | `attest_launch` | Falcon launch approval + the mint's signature |
| 5 | `claim_fees` | anyone |
| 6 | `buyback_burn` | crank |
| 7 | `buyback_burn_damm` | crank |
| 8 | `claim_fees_damm` | anyone |
| 9 | `set_crank` | upgrade authority |

Meteora DBC and DAMM v2 instructions are encoded by hand from their published on-chain IDLs; no Meteora code is used.

## Security notes

- Every PDA must be at its canonical bump; accounts are created correctly even if someone pre-funded their address.
- `execute_call` never lends a signature: in its CPI only the identity's agent and vault are signers. The single
  exception is the payer of a Privacy Rings `transact` that only **withdraws** (it pays the rent of the records the
  spend creates), and only when that key appears once in the call.
- The program has been through two internal security review rounds; it has **not** been audited by a third party.

## Build and test

Solana platform tools v1.54, SBPF v0 (as the Privacy Rings SDK builds). On Linux / WSL with the Solana CLI installed:

```bash
bash scripts/build.sh            # mainnet build + the Mollusk test suite
CLUSTER=devnet bash scripts/build.sh   # the same code with the devnet program id
```

The tests (`program/tests/latrix.rs`) run every instruction against real Falcon-512 keys, including the refusals:
forged and expired signatures, changed calls, non-canonical PDAs, borrowed signers, pre-funded addresses, buybacks
by anyone but the crank and inside the cooldown.

## Verify the deployed program

```bash
solana-verify get-program-hash LTRXiaWWy3KbwiwMPCPu6QomafKrj12BPkpnAAwhNHD
```

and compare it with a verifiable build of this repository (see the OtterSec verification on the program's explorer
page).

## License

MIT
