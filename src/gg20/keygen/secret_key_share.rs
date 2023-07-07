use std::{convert::TryInto};

use super::{KeygenPartyShareCounts, KeygenShareId};
use crate::{
    collections::{TypedUsize},
    crypto_tools::{enc::Key},
    sdk::{
        api::{BytesVec, TofnResult},
        implementer_api::{encode},
    },
};

use bls12_381::{G1Affine, Scalar};
use group::{Curve, GroupEncoding};

use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
use tracing::{debug};


/// final output of keygen: store this struct in tofnd kvstore
#[derive(Debug, Clone, PartialEq)]
pub struct SecretKeyShare {
    pubKey: bls12_381::G1Projective,
    group: GroupPublicInfo,
    share: ShareSecretInfo,
}

/// `GroupPublicInfo` is the same for all shares
#[derive(Debug, Clone, PartialEq)]
pub struct GroupPublicInfo {
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    y: bls12_381::G1Projective,
}

impl Serialize for GroupPublicInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GroupPublicInfo", 3)?;
        state.serialize_field("party_share_counts", &self.party_share_counts)?;
        state.serialize_field("threshold", &self.threshold)?;
        let y_bytes = self.y.to_affine().to_compressed().as_ref().to_vec();
        state.serialize_field("y", &y_bytes)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for GroupPublicInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GroupPublicInfoVisitor;

        impl<'de> serde::de::Visitor<'de> for GroupPublicInfoVisitor {
            type Value = GroupPublicInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct GroupPublicInfo")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let party_share_counts = seq.next_element().unwrap().unwrap();
                let threshold = seq.next_element().unwrap().unwrap();
                let y_bytes: Vec<u8> = seq.next_element()?.unwrap();
                let y = G1Affine::from_compressed(&y_bytes[..].try_into().unwrap())
                    .unwrap()
                    .into();

                Ok(GroupPublicInfo {
                    party_share_counts,
                    threshold,
                    y,
                })
            }
        }

        deserializer.deserialize_struct(
            "GroupPublicInfo",
            &["party_share_counts", "threshold", "y"],
            GroupPublicInfoVisitor,
        )
    }
}
/// `SharePublicInfo` public info unique to each share
/// all parties store a list of `SharePublicInfo`
#[derive(Debug, Clone, PartialEq)]
#[allow(non_snake_case)]
pub struct SharePublicInfo {
    X_i: bls12_381::G1Projective,
    ek: Key,
}

/// `ShareSecretInfo` secret info unique to each share
/// `index` is not secret but it's stored here anyway
/// because it's an essential part of secret data
/// and parties need a way to know their own index
#[derive(Debug, Clone, PartialEq)]

pub struct ShareSecretInfo {
    index: TypedUsize<KeygenShareId>,
    ek: bls12_381::G1Projective,
    x_i: bls12_381::Scalar,
}

impl Serialize for ShareSecretInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ShareSecretInfo", 3)?;
        state.serialize_field("index", &self.index)?;
        let x_i_bytes = self.x_i.to_bytes();
        state.serialize_field("ek", &self.ek.to_bytes().as_ref())?;
        state.serialize_field("x_i", &x_i_bytes)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ShareSecretInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ShareSecretInfoVisitor;

        impl<'de> serde::de::Visitor<'de> for ShareSecretInfoVisitor {
            type Value = ShareSecretInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ShareSecretInfo")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: serde::de::SeqAccess<'de>,
            {
                let index = seq.next_element().unwrap().unwrap();
                let ek_bytes: Vec<u8> = seq.next_element().unwrap().unwrap();

                let ek = G1Affine::from_compressed(ek_bytes.as_slice().try_into().unwrap())
                    .unwrap()
                    .into();
                let x_i_bytes: Vec<u8> = seq.next_element().unwrap().unwrap();
                let x_i = Scalar::from_bytes(&x_i_bytes.try_into().unwrap()).unwrap();

                Ok(ShareSecretInfo { index, ek, x_i })
            }
        }

        deserializer.deserialize_struct(
            "ShareSecretInfo",
            &["index", "x_i"],
            ShareSecretInfoVisitor,
        )
    }
}

/// Subset of `SecretKeyShare` that goes on-chain.
/// (Secret data is encrypted so it's ok to post publicly.)
/// When combined with similar data from all parties,
/// this data + mnemonic can be used to recover a full `SecretKeyShare` struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyShareRecoveryInfo {
    x_i_ciphertext: [u8; 32],
    index: usize,
}

impl GroupPublicInfo {
    pub fn party_share_counts(&self) -> &KeygenPartyShareCounts {
        &self.party_share_counts
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// SEC1-encoded curve point
    /// tofnd can send this data through grpc
    /// TODO change return type to `[u8; 33]`?
    pub fn encoded_pubkey(&self) -> BytesVec {
        self.y.to_bytes().as_ref().to_vec()
    }

    pub fn y(&self) -> &bls12_381::G1Projective {
        &self.y
    }

    pub(super) fn new(
        party_share_counts: KeygenPartyShareCounts,
        threshold: usize,
        y: bls12_381::G1Projective,
    ) -> Self {
        Self {
            party_share_counts,
            threshold,
            y,
        }
    }
}

#[allow(non_snake_case)]
impl SharePublicInfo {
    pub fn X_i(&self) -> &bls12_381::G1Projective {
        &self.X_i
    }

    pub fn ek(&self) -> &Key {
        &self.ek
    }

    pub(super) fn new(X_i: bls12_381::G1Projective, ek: Key) -> Self {
        Self { X_i, ek }
    }
}

impl ShareSecretInfo {
    pub fn index(&self) -> TypedUsize<KeygenShareId> {
        self.index
    }

    pub(super) fn new(
        index: TypedUsize<KeygenShareId>,
        ek: bls12_381::G1Projective,
        x_i: bls12_381::Scalar,
    ) -> Self {
        Self { index, ek, x_i }
    }

    pub(crate) fn x_i(&self) -> &bls12_381::Scalar {
        &self.x_i
    }
}

impl SecretKeyShare {
    pub fn group(&self) -> &GroupPublicInfo {
        &self.group
    }

    pub fn share(&self) -> &ShareSecretInfo {
        &self.share
    }

    pub fn recovery_info(&self) -> TofnResult<BytesVec> {
        let _index = self.share.index;
        let _share = self.share.clone();
        let x_i_ciphertext = &self.share.x_i.to_bytes();

        debug!("share tofnd: {:?}", self.share.x_i);
        let _x: [u8; 16] = x_i_ciphertext[..16]
            .try_into()
            .expect("Array size mismatch");

        encode(&KeyShareRecoveryInfo {
            x_i_ciphertext: *x_i_ciphertext,
            index: self.share.index.as_usize(),
        })
    }

    // super::super so it's visible in sign
    // TODO change file hierarchy so that you need only pub(super)
    pub(in super::super) fn new(
        pubKey: bls12_381::G1Projective,
        share: ShareSecretInfo,
        group: GroupPublicInfo,
    ) -> Self {
        Self {
            pubKey,
            group,
            share,
        }
    }
}
