use crate::{
    collections::TypedUsize,
    crypto_tools::{constants, hash, vss, enc::Key},
    sdk::{
        api::TofnResult,
        implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
    },
};

use group::GroupEncoding;
use serde::{Deserialize, Serialize, Serializer};
use serde::Deserializer;
use tracing::debug;
use super::{r2, KeygenPartyShareCounts, KeygenProtocolBuilder, KeygenShareId, PartyKeygenData, PartyKeyPair};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;


use std::convert::TryInto;
use bls12_381::{G1Projective, G1Affine};

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
// impl<'de> Deserialize<'de> for Bcast {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let ek_bytes = Self::deserialize(deserializer)?;
//         let ek = bls12_381::G1Projective::from_bytes(&ek_bytes.ek.to_bytes()).unwrap();
//         Ok(Bcast { ek })
//     }

// }



impl Serialize for Bcast {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Ok(
            serializer.serialize_bytes(self.ek.to_bytes().as_ref()).unwrap()
        )
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
    // let s = group::GroupEncoding::to_bytes(&(u_i_vss.get_secret() * bls12_381::G1Projective::generator()));
    // let (y_i_commit, y_i_reveal) = hash::commit(
    //     constants::Y_I_COMMIT_TAG,
    //     my_keygen_id,
    //     s,
    // );
   
    // corrupt!(
    //     y_i_commit,
    //     malicious::corrupt_commit(my_keygen_id, &behaviour, y_i_commit)
    // );

    // let ek_proof = party_keygen_data.encryption_keypair_proof.clone();
    // corrupt!(
    //     ek_proof,
    //     malicious::corrupt_ek_proof(my_keygen_id, &behaviour, ek_proof)
    // );

    // let zkp_proof = party_keygen_data.zk_setup_proof.clone();
    // corrupt!(
    //     zkp_proof,
    //     malicious::corrupt_zkp_proof(my_keygen_id, &behaviour, zkp_proof)
    // );

    let bcast_out = Some(serialize(&Bcast {
        // y_i_commit,
        ek: party_keygen_data.enc_key.clone(),
        // ek_proof,
        // zkp: party_keygen_data.zk_setup.clone(),
        // zkp_proof,
    })?);
debug!("r1 done");
    Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
        Box::new(r2::R2 {
            threshold,
            party_share_counts,
            dk: party_keygen_data.dec_key.clone(),
            u_i_vss,
            // y_i_reveal,
            #[cfg(feature = "malicious")]
            behaviour,
        }),
        bcast_out,
        None,
    )))
}

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::TypedUsize,
        crypto_tools::{
            hash::Output,
            paillier,
            paillier::zk::{EncryptionKeyProof, ZkSetupProof},
        },
        gg20::keygen::{malicious::Behaviour, KeygenShareId},
    };
    use tracing::info;

    pub fn corrupt_commit(
        my_keygen_id: TypedUsize<KeygenShareId>,
        behaviour: &Behaviour,
        commit: Output,
    ) -> Output {
        if let Behaviour::R1BadCommit = behaviour {
            info!("malicious peer {} does {:?}", my_keygen_id, behaviour);
            commit.corrupt()
        } else {
            commit
        }
    }

    pub fn corrupt_ek_proof(
        my_keygen_id: TypedUsize<KeygenShareId>,
        behaviour: &Behaviour,
        ek_proof: EncryptionKeyProof,
    ) -> EncryptionKeyProof {
        if let Behaviour::R1BadEncryptionKeyProof = behaviour {
            info!("malicious peer {} does {:?}", my_keygen_id, behaviour);
            paillier::zk::malicious::corrupt_ek_proof(ek_proof)
        } else {
            ek_proof
        }
    }

    pub fn corrupt_zkp_proof(
        my_keygen_id: TypedUsize<KeygenShareId>,
        behaviour: &Behaviour,
        zkp_proof: ZkSetupProof,
    ) -> ZkSetupProof {
        if let Behaviour::R1BadZkSetupProof = behaviour {
            info!("malicious peer {} does {:?}", my_keygen_id, behaviour);
            paillier::zk::malicious::corrupt_zksetup_proof(zkp_proof)
        } else {
            zkp_proof
        }
    }
}
