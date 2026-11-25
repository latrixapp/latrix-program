use solana_program_error::ProgramError;

/// Custom error codes (`ProgramError::Custom`). Codes are stable: clients map them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[repr(u32)]
pub enum LatrixError {
    #[error("instruction data is malformed")]
    InvalidInstructionData = 6000,
    #[error("the Falcon-512 public key is malformed")]
    InvalidFalconPubkey = 6001,
    #[error("the identity account does not match the Falcon public key")]
    IdentityMismatch = 6002,
    #[error("the account is not a Latrix account of the expected kind")]
    InvalidAccount = 6003,
    #[error("the Falcon-512 signature is invalid")]
    InvalidSignature = 6004,
    #[error("the authorization has expired")]
    Expired = 6005,
    #[error("the nonce does not match the identity's next nonce")]
    InvalidNonce = 6006,
    #[error("the call does not match what the Falcon key authorized")]
    CallMismatch = 6007,
    #[error("a PDA bump does not derive the expected address")]
    InvalidBump = 6008,
    #[error("the authorization has not expired yet")]
    NotExpired = 6009,
    #[error("the rent payer does not match the one that funded the authorization")]
    RentPayerMismatch = 6010,
    #[error("too many accounts for one approved call")]
    TooManyAccounts = 6011,
    #[error("an approved call cannot target this program")]
    ForbiddenTarget = 6012,
    #[error("the launch does not match what the Falcon key attested")]
    LaunchMismatch = 6013,
    #[error("the dev share must be at most 10000 basis points")]
    InvalidFeeSplit = 6014,
    #[error("a fee account is not the one this launch requires")]
    InvalidFeeAccount = 6015,
    #[error("nothing to claim or buy back")]
    NothingToDo = 6016,
    #[error("only the launchpad's crank may run a buyback")]
    NotCrank = 6017,
    #[error("this coin had a buyback too recently")]
    BuybackCooldown = 6018,
}

impl From<LatrixError> for ProgramError {
    fn from(e: LatrixError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
