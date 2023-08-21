use bls12_381::{G1Affine, G1Projective};

use rand::Fill;
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};
//use tracing::warn;
//se tracing_subscriber::field::debug;
#[cfg(feature = "malicious")]
use super::malicious::Behaviour;
use super::{r1, r2, KeygenPartyShareCounts, KeygenShareId};
use crate::crypto_tools::enc::EncDec;
use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, P2ps, VecMap},
    crypto_tools::{
        enc::Key,
        vss::{self, Commit, Proof},
    },
    gg20::keygen::{r4, SecretKeyShare},
    sdk::{
        api::{
            Fault::{self, ProtocolFault},
            TofnResult,
        },
        implementer_api::{
            log_accuse_warn, serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder,
        },
    },
};
use group::GroupEncoding;
use std::convert::TryInto;
use tracing::{debug, warn};
use vec_map::VecMap as DVecMap;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct BcastHappy {
    pub(super) x_i_proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pSad {
    pub(super) vss_complaint: Vec<ShareInfoDispute>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ShareInfo {
    pub(super) share: vss::Share,
}
#[derive(Debug, Clone)]
pub(super) struct ShareInfoDispute {
    pub(super) share: vss::Share,
    pub(super) kij: bls12_381::G1Projective,
    pub(super) proof: ([u8; 32], [u8; 32], [u8; 32]),
    pub(super) commit: Commit,
    pub(super) faulter: bls12_381::G1Projective,
    pub(super) accuser: bls12_381::G1Projective,
    pub(super) accuserId: usize,
    pub(super) faulterId: usize,
}
impl<'de> Deserialize<'de> for ShareInfoDispute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (share, mut r, p, c, mut f, mut a, aid, fid) = <(
            vss::Share,
            [u8; 32],
            ([u8; 32], [u8; 32], [u8; 32]),
            Commit,
            [u8; 32],
            [u8; 32],
            usize,
            usize,
        )>::deserialize(deserializer)?;
        let r_vec: &[u8] = r.as_mut();
        let kij = G1Affine::from_compressed(r_vec.try_into().unwrap())
            .unwrap()
            .into();
        let key_vec: &[u8] = f.as_mut();
        let key = G1Affine::from_compressed(key_vec.try_into().unwrap())
            .unwrap()
            .into();
        let mykey_vec: &[u8] = a.as_mut();
        let mykey = G1Affine::from_compressed(mykey_vec.try_into().unwrap())
            .unwrap()
            .into();
        Ok(ShareInfoDispute {
            share: share,
            kij: kij,
            proof: p,
            commit: c,
            faulter: key,
            accuser: mykey,
            accuserId: aid,
            faulterId: fid,
        })
    }
}

impl Serialize for ShareInfoDispute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut shareDispute = serializer.serialize_struct("ShareInfoDispute", 8).unwrap();
        shareDispute.serialize_field("share", &self.share)?;
        shareDispute.serialize_field("kij", &self.kij.to_bytes().as_ref())?;
        shareDispute.serialize_field("proof", &self.proof)?;
        shareDispute.serialize_field("commit", &self.commit)?;
        shareDispute.serialize_field("faulter", &self.faulter.to_bytes().as_ref())?;
        shareDispute.serialize_field("accuser", &self.accuser.to_bytes().as_ref())?;
        shareDispute.serialize_field("accuserId", &self.accuserId)?;
        shareDispute.serialize_field("faulterId", &self.faulterId)?;
        shareDispute.end()
    }
}

pub(super) struct R3 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) dk: bls12_381::Scalar,
    pub(super) ek: bls12_381::G1Projective,
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
        debug!("r3 start");
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
            }
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // check vss commit lengths
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if !faulters.is_none(peer_keygen_id).unwrap() {
            } else {
                if self.threshold + 1 != bcast.u_i_vss_commit.len() {
                    warn!(
                    "peer {} says: u_i vss commit of invalid length {} (expected {}) from peer {}",
                    my_keygen_id,
                    bcast.u_i_vss_commit.len(),
                    self.threshold + 1,
                    peer_keygen_id,
                );

                    faulters.set(peer_keygen_id, ProtocolFault)?;
                }
            }
        }

        let kijs = self.kij.clone();

        // decrypt shares
        let share_infos = p2ps_in.map_to_me(my_keygen_id, |p2p| {
            if p2p.id == my_keygen_id.as_usize() {
                let k = kijs.get(p2p.from).unwrap().to_bytes();

                let kRef = k.as_ref();
                let mut dest_array: [u8; 32] = [0u8; 32];
                dest_array.copy_from_slice(&kRef[..32]);
                let u_i_share_plaintext = Key::decrypt(
                    dest_array,
                    p2p.u_i_share_ciphertext[0..16].try_into().unwrap(),
                );
                let s = u_i_share_plaintext.as_slice();

                let mut destination_array: [u8; 32] = [0; 32];

                destination_array[..s.len()].copy_from_slice(&s);
                destination_array[s.len()..].copy_from_slice(&p2p.u_i_share_ciphertext[16..]);

                let u_i_share = vss::Share::from_scalar(
                    bls12_381::Scalar::from_bytes(&destination_array).unwrap(),
                    my_keygen_id.as_usize(),
                );

                ShareInfo { share: u_i_share }
            } else {
                ShareInfo {
                    share: self.u_i_share.clone(),
                }
            }
        })?;

        // validate shares

        let mut vss_complaints_vec: Vec<ShareInfoDispute> = Vec::new();
        let _vss_complaints = share_infos.ref_map2_result(|(peer_keygen_id, share_info)| {
            Ok(
                if !bcasts_in
                    .get(peer_keygen_id)?
                    .u_i_vss_commit
                    .validate_share(&share_info.share)
                {
                    let commit = bcasts_in.get(peer_keygen_id)?.u_i_vss_commit.clone();
                    let key = self.r1bcasts.get(peer_keygen_id)?.ek;
                    let my_key = self.r1bcasts.get(my_keygen_id)?.ek;
                    log_accuse_warn(my_keygen_id, peer_keygen_id, "invalid vss share");
                    let p = vss::Proof::generate_proof(
                        &bls12_381::G1Projective::generator(),
                        &key,
                        &(self.dk * bls12_381::G1Projective::generator()),
                        self.kij.get(peer_keygen_id.as_usize()).unwrap(),
                        &self.dk,
                    )
                    .unwrap();
                    // let cc = serialize(&commit);
                    //debug!("share: {:?} - commits: {:?}",share_info.share.clone(),cc );
                    vss_complaints_vec.push(ShareInfoDispute {
                        share: share_info.share.clone(),
                        kij: *self.kij.get(peer_keygen_id.as_usize()).unwrap(),
                        proof: p,
                        commit: commit,
                        faulter: key,
                        accuser: my_key,
                        accuserId: my_keygen_id.as_usize(),
                        faulterId: peer_keygen_id.as_usize(),
                    });
                } else {
                    #[cfg(feature = "malicious")]
                    if let Behaviour::R3FalseAccusation { victim, faulty } = &self.behaviour {
                        for &faulty_element in faulty {
                            if my_keygen_id.as_usize() == faulty_element.as_usize() {
                                for &victim_element in victim {
                                    if peer_keygen_id.as_usize() == victim_element.as_usize() {
                                        let commit =
                                            bcasts_in.get(peer_keygen_id)?.u_i_vss_commit.clone();
                                        let key = self.r1bcasts.get(peer_keygen_id)?.ek;
                                        let my_key = self.r1bcasts.get(my_keygen_id)?.ek;
                                        log_accuse_warn(
                                            my_keygen_id,
                                            peer_keygen_id,
                                            "invalid vss share",
                                        );
                                        let p = vss::Proof::generate_proof(
                                            &bls12_381::G1Projective::generator(),
                                            &key,
                                            &(self.dk * bls12_381::G1Projective::generator()),
                                            self.kij.get(peer_keygen_id.as_usize()).unwrap(),
                                            &self.dk,
                                        )
                                        .unwrap();
                                        // let cc = serialize(&commit);
                                        // debug!("share: {:?} - commits: {:?}", share_info.share.clone(), cc);
                                        vss_complaints_vec.push(ShareInfoDispute {
                                            share: share_info.share.clone(),
                                            kij: *self.kij.get(peer_keygen_id.as_usize()).unwrap(),
                                            proof: p,
                                            commit: commit,
                                            faulter: key,
                                            accuser: my_key,
                                            accuserId: my_keygen_id.as_usize(),
                                            faulterId: peer_keygen_id.as_usize(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                },
            )
        })?;

        debug!("r3 done");
        if vss_complaints_vec.len() == 0 {
            Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r4::R4Happy {
                    threshold: self.threshold,
                    party_share_counts: self.party_share_counts,
                    dk: self.dk,
                    ek: self.ek,
                    kij: self.kij.clone(),
                    u_i_share: self.u_i_share,
                    // r1bcasts: self.r1bcasts,
                    r2bcasts: bcasts_in,
                    r2p2ps: p2ps_in,
                    faulters: faulters,
                }),
                None,
                None,
            )))
        } else {
            let bcast = serde_json::to_string(&P2pSad {
                vss_complaint: vss_complaints_vec.clone(),
            })
            .unwrap();
            let bcast_out = Some(bcast.as_bytes().to_vec());

            let mut r2bc: FillVecMap<KeygenShareId, r2::Bcast> =
                FillVecMap::with_size((bcasts_in.len()));
            for (key, value) in bcasts_in.iter() {
                let mut temp: Vec<G1Projective> = Vec::new();
                temp.insert(0, *bcasts_in.get(key)?.u_i_vss_commit.secret_commit());
                let _ = r2bc.set(
                    key,
                    r2::Bcast {
                        u_i_vss_commit: Commit {
                            coeff_commits: temp,
                        },
                        id: value.id,
                    },
                );
            }

            let new_elements = p2ps_in
                .map_to_me(my_keygen_id, |value| {
                    // Here you can transform the value if necessary
                    value.clone() // Cloning or transforming the value
                })
                .expect("Failed to map to me");
            // Create a VecMap with the extracted elements
            let mut x = Vec::new();
            x.insert(0, new_elements);
            let vec_map: VecMap<KeygenShareId, HoleVecMap<KeygenShareId, r2::P2p>> =
                VecMap::from_vec(x);

            // Create a new FullP2ps with the VecMap
            let r2p2p_filtered: FullP2ps<KeygenShareId, r2::P2p> = FullP2ps::new(vec_map);
            let o = ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r4::R4Happy {
                    threshold: self.threshold,
                    party_share_counts: self.party_share_counts,
                    dk: self.dk,
                    ek: self.ek,
                    kij: self.kij.clone(),
                    u_i_share: self.u_i_share,
                    // r1bcasts: self.r1bcasts,
                    r2bcasts: r2bc.to_vecmap().unwrap(),
                    r2p2ps: p2ps_in,
                    faulters: faulters,
                }),
                bcast_out,
                None,
            ));
            debug!("this is fine!!!!");
            //debug!("bcastout1:{:?}, me: {:?}, len:{:?}, len p2p before:{:?} , len p2p after:{:?}", bcast_out.clone(), my_keygen_id.as_usize(), bcast_out.clone().unwrap().len(), p2ps_in.size(),r2p2p_filtered.size());
            Ok(o)
        }
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::{ShareInfo, ShareInfoDispute, R3};
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

        // pub fn corrupt_complaint(
        //     &self,
        //     keygen_id: TypedUsize<KeygenShareId>,
        //     share_infos: &HoleVecMap<KeygenShareId, ShareInfo>,
        //     mut vss_complaints: Vec<ShareInfoDispute>,
        // ) -> Vec<ShareInfoDispute> {
        //     if let Behaviour::R3FalseAccusation { victim , faulty} = self.behaviour {
        //         for dispute in vss_complaints.iter_mut() {
        //             if dispute.faulterId == victim.as_usize(){
        //                 dispute.proof = ([0u8;32],[0u8;32],[0u8;32]);
        //           }
        //            // *number *= 2; // Modify the element
        //             //println!("{}", number);
        //         }

        //     }

        //     vss_complaints
        // }
    }
}
