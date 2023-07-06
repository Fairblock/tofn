use super::{
    r1::{self},
    r3,
};
#[cfg(feature = "malicious")]
use crate::gg20::keygen::malicious;
use crate::{
    collections::{TypedUsize, VecMap},
    crypto_tools::{enc::Key, rng},
    gg20::constants::{KEYPAIR_TAG, ZKSETUP_TAG},
    sdk::{
        api::{PartyShareCounts, Protocol, TofnFatal, TofnResult},
        implementer_api::{new_protocol, ProtocolBuilder},
    },
};
use group::ff::PrimeField;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use tracing::{debug, error};
use zeroize::Zeroize;

/// Maximum byte length of messages exchanged during keygen.
/// The sender of a message larger than this maximum will be accused as a faulter.
/// View all message sizes in the logs of the integration test `single_thred::basic_correctness`.
/// The largest keygen message is r1::Bcast with size ~4833 bytes on the wire.
/// There is also a variable-sized message in r2::Bcast that depends on the
/// threshold: 34t + 73. For t = 100, this is still smaller than the limit.
/// See https://github.com/axelarnetwork/tofn/issues/171
pub const MAX_MSG_LEN: usize = 5500;

pub use super::secret_key_share::*;
pub use rng::SecretRecoveryKey;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenShareId;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyId;

pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenShareId, KeygenPartyId, MAX_MSG_LEN>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenShareId>;
pub type KeygenPartyShareCounts = PartyShareCounts<KeygenPartyId>;
pub type Disputes = r3::P2pSad;
#[derive(Debug, Clone)]

pub struct PartyKeyPair {
    pub(super) enc_key: bls12_381::G1Projective,
    pub(super) dec_key: bls12_381::Scalar,
}

#[derive(Debug, Clone)]
pub struct PartyKeygenData {
    pub encryption_keypair: PartyKeyPair,
}

// // BEWARE: This is only made visible for faster integration testing
pub fn create_party_keypair_and_zksetup_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeygenData> {
    let encryption_keypair =
        recover_party_keypair_unsafe(my_party_id, secret_recovery_key, session_nonce)?;

    Ok(PartyKeygenData { encryption_keypair })
}

// // BEWARE: This is only made visible for faster integration testing
pub fn recover_party_keypair_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = keygen_unsafe(&mut rng);

    Ok(PartyKeyPair {
        enc_key: ek,
        dec_key: dk,
    })
}
pub fn keygen_unsafe(
    rng: &mut (impl CryptoRng + RngCore),
) -> (bls12_381::G1Projective, bls12_381::Scalar) {
    let u = rng.next_u64();

    let dk = bls12_381::Scalar::from_u128(u as u128);
    let ek = dk * bls12_381::G1Projective::generator();
    return (ek, dk);
}

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

// TODO use const generics for these bounds
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

// BEWARE: This is only made visible for faster integration testing
// TODO: Use a better way to hide this from the API, while allowing it for integration tests
// since #[cfg(tests)] only works for unit tests

/// Initialize a new keygen protocol
#[allow(clippy::too_many_arguments)]
pub fn new_keygen(
    party_share_count: usize,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    // my_subshare_id: usize, // in 0..party_share_counts[my_party_id]
    party_keygen_data: &PartyKeyPair,
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<KeygenProtocol> {
    // validate args
    let v = vec![1; party_share_count];
    let party_share_counts = KeygenPartyShareCounts {
        party_share_counts: VecMap::from_vec(v),
        total_share_count: party_share_count,
    };

    let my_keygen_id = party_share_counts.party_to_share_id(my_party_id, my_party_id.as_usize())?;

    #[cfg(feature = "malicious")]
    debug!("{:?}", behaviour);

    let round2 = r1::start(
        threshold,
        party_share_counts.clone(),
        party_keygen_data,
        #[cfg(feature = "malicious")]
        behaviour,
    )?;

    new_protocol(party_share_counts, my_keygen_id, round2)
}
