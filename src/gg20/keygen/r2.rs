use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
//use tracing_subscriber::field::debug;

use super::{r1, KeygenPartyShareCounts, KeygenShareId};
use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    crypto_tools::{
        enc::{EncDec, Key},
        vss,
    },
    gg20::keygen::{r3, SecretKeyShare},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnResult,
        },
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::{typenum};
use aes::Aes256;
use group::GroupEncoding;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use typenum::U16;
use vec_map::VecMap as DVecMap;

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

/// TODO: The byte length of this struct is proportional to the threshold: 34t + 73
/// Instead it should be constant.
/// https://github.com/axelarnetwork/tofn/issues/171
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
   
    pub(super) u_i_vss_commit: vss::Commit,
    
    pub(super) id: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) u_i_share_ciphertext: [u8; 32],
    pub(super) id: usize,
    pub(super) from: usize,
}

pub(super) struct R2 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) dk: bls12_381::Scalar,
    pub(super) ek: bls12_381::G1Projective,
    pub(super) u_i_vss: vss::Vss,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}
impl EncDec for Key {
    fn encrypt(_key: Self, plaintext: [u8; 32]) -> GenericArray<u8, U16> {
        let key = GenericArray::from(_key);
        let hashvalue = Sha256::digest(&key.as_ref());
        let (first_half, _second_half) = hashvalue.split_at(hashvalue.len() / 2);
        let nonce = first_half;

        // Initialize cipher
        let cipher = Aes256::new(&key);

        // initialize the outputOne for taking the result of the first XOR
        let mut output = GenericArray::from([0u8; 16]);

        //XOR the nonce and plaintext
        for i in 0..16 {
            output[i] = plaintext[i] ^ nonce[i]
        }

        // Encrypt the first block in-place
        cipher.encrypt_block(&mut output);
     
        return output;
    }
    fn decrypt(_key: Self, ciphertext: [u8; 16]) -> GenericArray<u8, U16> {
        let key = GenericArray::from(_key);
        let hashvalue = Sha256::digest(&key.as_ref());
        let (first_half, _second_half) = hashvalue.split_at(hashvalue.len() / 2);
        let nonce = first_half;

        let cipher = Aes256::new(&key);
        let mut decrypted_plaintext = GenericArray::from([0u8; 16]);
        // Decrypt the first ciphertext
        let mut ciphertext_array = GenericArray::from(ciphertext);
        cipher.decrypt_block(&mut ciphertext_array);

        //XOR the nonce and decrypted value
        for i in 0..16 {
            decrypted_plaintext[i] = ciphertext_array[i] ^ nonce[i]
        }
      
        return decrypted_plaintext;
    }
}
impl Executer for R2 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r1::Bcast;
    type P2p = ();

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_keygen_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());
        debug!("r2 start");
        // anyone who did not send a bcast is a faulter
        // TODO strictly speaking peer_keygen_id might be me so we should not use peer_?
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 2",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        // anyone who sent p2ps is a faulter
        for (peer_keygen_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps from peer {} in round 2",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }

        // everyone sent a bcast---unwrap all bcasts
        let bcasts_in = bcasts_in.to_vecmap()?;

        let (peer_u_i_shares, u_i_share) =
            VecMap::from_vec(self.u_i_vss.shares(info.total_share_count()))
                .puncture_hole(my_keygen_id)?;

        corrupt!(
            peer_u_i_shares,
            self.corrupt_share(my_keygen_id, peer_u_i_shares)?
        );
        let mut kij_list = DVecMap::new();
        let p2ps_out = Some(peer_u_i_shares.map2_result(|(peer_keygen_id, share)| {
            // encrypt the share for party i

            let key = bcasts_in.get(peer_keygen_id)?.ek;
            let kij = self.dk * key;

            let k = kij.to_bytes();
         
            let binding = k.as_ref();
            let mut dest_array: [u8; 32] = [0u8; 32];
            dest_array.copy_from_slice(&binding[..32]);
            let mut u_i_share_ciphertext =
                Key::encrypt(dest_array, (*share.get_scalar()).to_bytes());
            kij_list.insert(peer_keygen_id.as_usize(), kij);

            let encShare = GenericArray::as_mut_slice(&mut u_i_share_ciphertext);
            let mut shareB = share.get_scalar().to_bytes();
            let plainSecondHalf = &shareB.as_mut()[16..];
           
            let c: &[&[u8]] = &[encShare, plainSecondHalf];
            let concatC = c.concat();
            corrupt!(
                concatC,
                self.corrupt_ciphertext(
                    my_keygen_id,
                    peer_keygen_id,
                    concatC.clone().try_into().unwrap()
                )
            );

            serialize(&P2p {
                u_i_share_ciphertext: concatC.try_into().unwrap(),
                id: peer_keygen_id.as_usize(),
                from: my_keygen_id.as_usize(),
            })
        })?);
        let cc =self.u_i_vss.commit();
        let cb = cc.secret_commit().to_bytes();
      //  debug!("commit: {:?}", cb);
        let bcast_out = Some(serialize(&Bcast {
            // y_i_reveal: self.y_i_reveal.clone(),
            //faulters: faulters.clone(),
            u_i_vss_commit: self.u_i_vss.commit(),
            id: my_keygen_id.as_usize(),
        })?);
        debug!("r2 done");
        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r3::R3 {
                threshold: self.threshold,
                party_share_counts: self.party_share_counts,
                dk: self.dk,
                ek: self.ek,
                kij: kij_list,
                u_i_share,
                r1bcasts: bcasts_in,
                faulters: faulters.clone(),
                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            p2ps_out,
        )))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::{HoleVecMap, TypedUsize},
        crypto_tools::vss::Share,
        gg20::keygen::{malicious::Behaviour, KeygenShareId},
        sdk::api::TofnResult,
    };

    use super::R2;

    use tracing::{debug, info};

    impl R2 {
        pub fn corrupt_share(
            &self,
            my_keygen_id: TypedUsize<KeygenShareId>,
            mut peer_shares: HoleVecMap<KeygenShareId, Share>,
        ) -> TofnResult<HoleVecMap<KeygenShareId, Share>> {
            if let Behaviour::R2BadShare { victim, faulty } = self.behaviour {
                if my_keygen_id.as_usize() == faulty.as_usize() {

                    info!("malicious peer {} does {:?}", my_keygen_id, self.behaviour);

                    peer_shares.get_mut(victim)?.corrupt();
                    debug!("this one is malicious!");
                }
            }

            Ok(peer_shares)
        }

        pub fn corrupt_ciphertext(
            &self,
            my_keygen_id: TypedUsize<KeygenShareId>,
            victim_keygen_id: TypedUsize<KeygenShareId>,
            mut ciphertext: [u8; 32],
        ) -> [u8; 32] {
            if let Behaviour::R2BadEncryption { victim } = self.behaviour {
                if victim == victim_keygen_id {
                    if victim.as_usize() != my_keygen_id.as_usize() {
                        info!("malicious peer {} does {:?}", my_keygen_id, self.behaviour);
                        ciphertext = [0u8; 32];
                    }
                }
            }

            ciphertext
        }
    }
}
