use aes::cipher::generic_array::GenericArray;
use group::ff::PrimeField;
use tracing::warn;

use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::{ vss, enc::Key},
    gg20::keygen::{
        r1, r2, r3::{self, ShareInfo},  GroupPublicInfo, KeygenPartyShareCounts, KeygenShareId,
        SecretKeyShare, SharePublicInfo, ShareSecretInfo,
    },
    sdk::{
        api::{Fault::{ProtocolFault, self}, TofnResult},
        implementer_api::{log_fault_warn, Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use group::GroupEncoding;
use vec_map::VecMap as DVecMap;
use std::convert::TryInto;
use crate::crypto_tools::enc::EncDec;
#[allow(non_snake_case)]
pub(in super::super) struct R4Happy {
    pub(in super::super) threshold: usize,
    pub(in super::super) party_share_counts: KeygenPartyShareCounts,
    pub(in super::super) dk: bls12_381::Scalar,
    pub(in super::super) u_i_share: vss::Share,
    pub(crate) kij: DVecMap<bls12_381::G1Projective>,
    pub(in super::super) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,
    pub(in super::super) r2bcasts: VecMap<KeygenShareId, r2::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<KeygenShareId, r2::P2p>,
    pub(crate) faulters: FillVecMap<KeygenShareId, Fault>,

}
fn ip_to_u128(input: &[u8]) -> u128 {
    // If the input is always exactly the right length you can remove the next line.
    let input = &input[..16];
    let ip_bytes: &[u8; 16] = input.try_into().unwrap();

    u128::from_le_bytes(*ip_bytes)
}
impl Executer for R4Happy {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r3::BcastHappy;
    type P2p = r2::P2p;

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        // let my_keygen_id = info.my_id();
        // let mut faulters = FillVecMap::with_size(info.total_share_count());

        // // TODO boilerplate
        // // anyone who sent both bcast and p2p is a faulter
        // for (peer_keygen_id, bcast_option, p2ps_option) in zip2(&bcasts_in, &p2ps_in) {
        //     if bcast_option.is_some() && p2ps_option.is_some() {
        //         warn!(
        //             "peer {} says: unexpected p2ps and bcast from peer {} in round 4 happy path",
        //             my_keygen_id, peer_keygen_id
        //         );
        //         faulters.set(peer_keygen_id, ProtocolFault)?;
        //     }
        // }
        // if !faulters.is_empty() {
        //     return Ok(ProtocolBuilder::Done(Err(faulters)));
        // }

        // // if anyone complained then move to sad path
        // if p2ps_in.iter().any(|(_, p2ps_option)| p2ps_option.is_some()) {
        //     warn!(
        //         "peer {} says: received R4 complaints from others--move to sad path",
        //         my_keygen_id,
        //     );
        //     return Box::new(R4Sad {
        //         r1bcasts: self.r1bcasts,
        //         r2bcasts: self.r2bcasts,
        //         r2p2ps: self.r2p2ps,
        //     })
        //     .execute(info, bcasts_in, p2ps_in);
        // }

        // // happy path: everyone sent bcast---unwrap all bcasts
        // let bcasts_in = bcasts_in.to_vecmap()?;

        // // verify proofs
        // for (peer_keygen_id, bcast) in bcasts_in.iter() {
        //     if !schnorr::verify(
        //         &schnorr::Statement {
        //             prover_id: peer_keygen_id,
        //             base: &k256::ProjectivePoint::generator(),
        //             target: self.all_X_i.get(peer_keygen_id)?,
        //         },
        //         &bcast.x_i_proof,
        //     ) {
        //         log_fault_warn(my_keygen_id, peer_keygen_id, "bad DL proof");
        //         faulters.set(peer_keygen_id, ProtocolFault)?;
        //     }
        // }
        // if !faulters.is_empty() {
        //     return Ok(ProtocolBuilder::Done(Err(faulters)));
        // }

        // // prepare data for final output
        // let all_shares = self
        //     .r1bcasts
        //     .iter()
        //     .map(|(peer_keygen_id, r1bcast)| {
        //         Ok(SharePublicInfo::new(
        //             self.all_X_i.get(peer_keygen_id)?.into(),
        //             r1bcast.ek.clone(),
        //             r1bcast.zkp.clone(),
        //         ))
        //     })
        //     .collect::<TofnResult<VecMap<_, _>>>()?;
        let kijs = self.kij;
        let my_keygen_id = info.my_id();
        let p2ps_in = p2ps_in.to_fullp2ps()?;
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
     
    
        // compute x_i
        let x_i = share_infos
            .into_iter()
            .fold(*self.u_i_share.get_scalar(), |acc, (_, share_info)| {
                acc + share_info.share.get_scalar()
            });

        // compute y
        let y = self.r2bcasts
            .iter()
            .fold(bls12_381::G1Projective::identity(), |acc, (_, r2bcast)| {
                acc + r2bcast.u_i_vss_commit.secret_commit()
            });

        // compute all_X_i
        // let all_X_i: VecMap<KeygenShareId, bls12_381::G1Projective> = (0..info.total_share_count())
        //     .map(|i| {
        //         self.r2bcasts
        //             .iter()
        //             .fold(bls12_381::G1Projective::identity(), |acc, (_, x)| {
        //                 acc + x.u_i_vss_commit.share_commit(i)
        //             })
        //     })
        //     .collect();

        corrupt!(x_i, self.corrupt_scalar(my_keygen_id, x_i));
        Ok(ProtocolBuilder::Done(Ok(SecretKeyShare::new(
            ShareSecretInfo::new(my_keygen_id, x_i.into()),
            GroupPublicInfo::new(
                self.party_share_counts,
                self.threshold,
                y.into(),
                //  all_shares,
            ),
            
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
