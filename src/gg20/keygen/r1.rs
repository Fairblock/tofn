use crate::{
    collections::TypedUsize,
    crypto_tools::{constants, enc::Key, vss},
    sdk::{
        api::TofnResult,
        implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
    },
};

use super::{
    r2, KeygenPartyShareCounts, KeygenProtocolBuilder, KeygenShareId, PartyKeyPair, PartyKeygenData,
};
use group::GroupEncoding;
use serde::Deserializer;
use serde::{Deserialize, Serialize, Serializer};
use tracing::debug;

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

use bls12_381::{G1Affine, G1Projective};
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub(super) struct Bcast {
    pub(super) ek: G1Projective,
}

impl<'de> Deserialize<'de> for Bcast {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BcastVisitor;

        impl<'de> serde::de::Visitor<'de> for BcastVisitor {
            type Value = Bcast;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array of length 96")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let ek_bytes: [u8; 48] = v
                    .try_into()
                    .map_err(|_| E::invalid_length(v.len(), &self))?;

                let ek = G1Affine::from_compressed(&ek_bytes).unwrap().into();

                Ok(Bcast { ek })
            }
        }

        deserializer.deserialize_bytes(BcastVisitor)
    }
}

impl Serialize for Bcast {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Ok(serializer
            .serialize_bytes(self.ek.to_bytes().as_ref())
            .unwrap())
    }
}

pub(super) fn start(
    // my_keygen_id: TypedUsize<KeygenShareId>,
    threshold: usize,
    party_share_counts: KeygenPartyShareCounts,
    party_keygen_data: &PartyKeyPair,
    #[cfg(feature = "malicious")] behaviour: Behaviour,
) -> TofnResult<KeygenProtocolBuilder> {
    let u_i_vss = vss::Vss::new(threshold);

    let bcast_out = Some(serialize(&Bcast {
        ek: party_keygen_data.enc_key.clone(),
    })?);
    debug!("r1 done");
    Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
        Box::new(r2::R2 {
            threshold,
            party_share_counts,
            dk: party_keygen_data.dec_key.clone(),
            ek: party_keygen_data.enc_key.clone(),
            u_i_vss,
            // y_i_reveal,
            #[cfg(feature = "malicious")]
            behaviour,
        }),
        bcast_out,
        None,
    )))
}

