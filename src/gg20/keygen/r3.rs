use rand::seq::index;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use tracing::warn;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    crypto_tools::{constants, hash, vss::{self, Proof}, enc::Key},
    gg20::keygen::{r4, SecretKeyShare},
    sdk::{
        api::{Fault::{ProtocolFault, self}, TofnFatal, TofnResult},
        implementer_api::{
            log_accuse_warn, serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder,
        },
    },
};
use vec_map::VecMap as DVecMap;
use std::convert::TryInto;
use crate::crypto_tools::enc::EncDec;
use super::{r1, r2, KeygenPartyShareCounts, KeygenShareId};
use group::GroupEncoding;
#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct BcastHappy {
    pub(super) x_i_proof: Proof,
}



#[derive(Debug, Clone, Serialize)]
pub(super) struct P2pSad {
    pub(super) vss_complaint: Option<ShareInfoDispute>,
}

#[derive(Debug, Clone,Serialize)]
pub(super) struct ShareInfo {
    pub(super) share: vss::Share,
   
   
}
#[derive(Debug, Clone)]
pub(super) struct ShareInfoDispute {
    pub(super) share: vss::Share,
    pub(super) kij: bls12_381::G1Projective,
    pub(super) proof: ([u8; 32], [u8;32])
}

impl Serialize for ShareInfoDispute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut shareDispute = serializer.serialize_struct("ShareInfoDispute",3).unwrap();
        shareDispute.serialize_field("share", &self.share)?;
        shareDispute.serialize_field("kij", &self.kij.to_bytes().as_ref())?;
        shareDispute.serialize_field("proof", &self.proof)?;
        shareDispute.end()
        
    }
}

pub(super) struct R3 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) dk: bls12_381::Scalar,
    pub(super) kij: DVecMap<bls12_381::G1Projective>,
    pub(super) u_i_share: vss::Share,
    pub(super) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(super) faulters: FillVecMap<KeygenShareId, Fault>,
    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl Executer for R3 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_keygen_id = info.my_id();
        let mut faulters = self.faulters.clone();

        // anyone who did not send a bcast is a faulter
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {} in round 3",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
                // bcasts_in_w.unset(peer_keygen_id);
             
                // p2ps_in.remove(peer_keygen_id);
            }
        }
        // anyone who did not send p2ps is a faulter
        for (peer_keygen_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {} in round 3",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
                // bcasts_in_w.unset(peer_keygen_id);
                // p2ps_in.remove(peer_keygen_id);
            }
        }
        // if !faulters.is_empty() {
        //     return Ok(ProtocolBuilder::Done(Err(faulters)));
        // }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // check vss commit lengths
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if !faulters.is_none(peer_keygen_id).unwrap(){}
            else{
            if self.threshold + 1 != bcast.u_i_vss_commit.len() {
                warn!(
                    "peer {} says: u_i vss commit of invalid length {} (expected {}) from peer {}",
                    my_keygen_id,
                    bcast.u_i_vss_commit.len(),
                    self.threshold + 1,
                    peer_keygen_id,
                );

                faulters.set(peer_keygen_id, ProtocolFault)?;
                // bcasts_in_w.unset(peer_keygen_id);
                // bcasts_in = bcasts_in_w.to_vecmap()?;
                // p2ps_in.remove(peer_keygen_id);
            }}
        }

        // if !faulters.is_empty() {
        //     return Ok(ProtocolBuilder::Done(Err(faulters)));
        // }

        // check y_i commits
        // for (peer_keygen_id, bcast) in bcasts_in.iter() {
          
        //     let peer_y_i = bcast.u_i_vss_commit.secret_commit();
        //     let peer_y_i_commit = hash::commit_with_randomness(
        //         constants::Y_I_COMMIT_TAG,
        //         peer_keygen_id,
        //         group::GroupEncoding::to_bytes( peer_y_i),
        //         &bcast.y_i_reveal,
        //     );

        //     if peer_y_i_commit != self.r1bcasts.get(peer_keygen_id)?.y_i_commit {
        //         warn!(
        //             "peer {} says: invalid y_i reveal by peer {}",
        //             my_keygen_id, peer_keygen_id
        //         );

        //         faulters.set(peer_keygen_id, ProtocolFault)?;
        //         // bcasts_in_w.unset(peer_keygen_id);
        //         // bcasts_in = bcasts_in_w.to_vecmap()?;
        //         // p2ps_in.remove(peer_keygen_id);
        //     }
        // }

        // if !faulters.is_empty() {
        //     return Ok(ProtocolBuilder::Done(Err(faulters)));
        // }

        // validate u_i_share_ciphertexts
        // let ek = &self.r1bcasts.get(my_keygen_id)?.ek;
        // p2ps_in.map_to_me2(my_keygen_id, |(peer_keygen_id, p2p)| {
         
          
        //     if !ek.validate_ciphertext(&p2p.u_i_share_ciphertext) {
        //         warn!(
        //             "peer {} says: invalid u_i_share_ciphertext from peer {}",
        //             my_keygen_id, peer_keygen_id
        //         );

        //         faulters.set(peer_keygen_id, ProtocolFault)?;
        //         // bcasts_in_w.unset(peer_keygen_id);
        //         // bcasts_in = bcasts_in_w.to_vecmap()?;
        //         // p2ps_in.remove(peer_keygen_id);
        //     }

        //     Ok::<(), TofnFatal>(())
        // })?;

        // if !faulters.is_empty() {
        //     return Ok(ProtocolBuilder::Done(Err(faulters)));
        // }
     
        let kijs = self.kij.clone();
       
        // decrypt shares
        let share_infos = p2ps_in.map_to_me(my_keygen_id, |p2p| {
           
          
            let k = kijs.get(p2p.id).unwrap().to_bytes();
            let kRef = k.as_ref();
            let mut dest_array: [u8; 32] = [0u8;32];
            dest_array.copy_from_slice(&kRef[..32]);
            let u_i_share_plaintext = Key::decrypt(dest_array,p2p.u_i_share_ciphertext);
            let u_i_share =
                vss::Share::from_scalar(bls12_381::Scalar::from_bytes(u_i_share_plaintext.as_slice().try_into().unwrap()).unwrap() , my_keygen_id.as_usize());

            ShareInfo {
                share: u_i_share,
                
            }
        })?;

        // validate shares
        
        let vss_complaints = share_infos.ref_map2_result(|(peer_keygen_id, share_info)| {
            Ok(
                if !bcasts_in
                    .get(peer_keygen_id)?
                    .u_i_vss_commit
                    .validate_share(&share_info.share)
                {
                    let key =  self.r1bcasts
            .get(peer_keygen_id)?
            .ek;
                    log_accuse_warn(my_keygen_id, peer_keygen_id, "invalid vss share");
                    Some(ShareInfoDispute{ share: share_info.share.clone(), kij: *self.kij.get(peer_keygen_id.as_usize()).unwrap(), proof: vss::Proof::generate_proof(&bls12_381::G1Projective::generator(),&key,&(self.dk*bls12_381::G1Projective::generator()),self.kij.get(peer_keygen_id.as_usize()).unwrap(),&self.dk).unwrap() })
                } else {
                    None
                },
            )
        })?;

        corrupt!(
            vss_complaints,
            self.corrupt_complaint(my_keygen_id, &share_infos, vss_complaints)?
        );

     let bcast_out = Some(
                vss_complaints
                    .map2_result(|(_, vss_complaint)| serialize(&P2pSad { vss_complaint }))?,
            );
            Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r4::R4Happy {
                    threshold: self.threshold,
                    party_share_counts: self.party_share_counts,
                    dk: self.dk,
                    kij:self.kij.clone(),
                    u_i_share: self.u_i_share,
                    r1bcasts: self.r1bcasts,
                    r2bcasts: bcasts_in,
                    r2p2ps: p2ps_in,
                    faulters:faulters,
                 
                }),
                None,
                bcast_out,
            )))
           
        


     
     

        
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::{ShareInfo, R3};
    use crate::{
        collections::{HoleVecMap, TypedUsize},
        gg20::keygen::KeygenShareId,
        sdk::api::TofnResult,
    };

    use super::super::malicious::{log_confess_info, Behaviour};

    impl R3 {
        pub fn corrupt_scalar(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            mut x_i: k256::Scalar,
        ) -> k256::Scalar {
            if let Behaviour::R3BadXIWitness = self.behaviour {
                log_confess_info(keygen_id, &self.behaviour, "");
                x_i += k256::Scalar::one();
            }
            x_i
        }

        pub fn corrupt_complaint(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            share_infos: &HoleVecMap<KeygenShareId, ShareInfo>,
            mut vss_complaints: HoleVecMap<KeygenShareId, Option<ShareInfo>>,
        ) -> TofnResult<HoleVecMap<KeygenShareId, Option<ShareInfo>>> {
            if let Behaviour::R3FalseAccusation { victim } = self.behaviour {
                let complaint = vss_complaints.get_mut(victim)?;
                if complaint.is_some() {
                    log_confess_info(keygen_id, &self.behaviour, "but the accusation is true");
                } else {
                    log_confess_info(keygen_id, &self.behaviour, "");
                    *complaint = Some(share_infos.get(victim)?.clone());
                }
            }

            Ok(vss_complaints)
        }
    }
}
