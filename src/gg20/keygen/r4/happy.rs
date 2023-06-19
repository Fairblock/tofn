use aes::cipher::generic_array::GenericArray;
use group::ff::PrimeField;
use tracing::{warn, debug};

use crate::{
    collections::{zip2, FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::{ vss::{self, Share}, enc::Key},
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
use std::{convert::TryInto, string};
use crate::crypto_tools::enc::EncDec;
#[allow(non_snake_case)]
pub(in super::super) struct R4Happy {
    pub(in super::super) threshold: usize,
    pub(in super::super) party_share_counts: KeygenPartyShareCounts,
    pub(in super::super) dk: bls12_381::Scalar,
    pub(in super::super) ek: bls12_381::G1Projective,
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
    type Bcast = usize;
    type P2p = r2::P2p;

    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        // let my_keygen_id = info.my_id();
        // let mut faulters = FillVecMap::with_size(info.total_share_count());
//  for (peer_keygen_id, bcast) in bcasts_in.iter() {
    debug!("r4 start");
            
//         }
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

        // verify proofs
      
     

        // // prepare data for final output
        // let all_shares = self
        //     .r1bcasts
        //     .iter()
        //     .map(|(peer_keygen_id, r1bcast)| {
        //         Ok(SharePublicInfo::new(
        //             self.all_X_i.get(peer_keygen_id)?.into(),
        //             ek
        //         ))
        //     })
        //     .collect::<TofnResult<VecMap<_, _>>>()?;
        let mut faulty_list: Vec<usize>= vec![];
        let kijs: DVecMap<bls12_381::G1Projective> = self.kij;
        let my_keygen_id = info.my_id();
        let p2ps_in: FullP2ps<KeygenShareId, r2::P2p> = self.r2p2ps;
        let share_infos: crate::collections::HoleVecMap<KeygenShareId, ShareInfo> = p2ps_in.map_to_me(my_keygen_id, |p2p| {
           let mut skip: bool = false;
           
            for (peer_keygen_id, bcast) in bcasts_in.iter() {
               
                if !bcast.is_none(){
                    debug!("peer: {:?} - me:{}, from :{:?}, bcast:{:?}", peer_keygen_id.as_usize(), my_keygen_id.as_usize(), p2p.from,bcast.unwrap());
                    if p2p.from == bcast.unwrap(){
                        
                        faulty_list.push(bcast.unwrap());
                        skip = true;
                    } 
                }
                
            }
if !skip{
            let k = kijs.get(p2p.from).unwrap().to_bytes();
            let k_ref = k.as_ref();
            let mut dest_array: [u8; 32] = [0u8;32];
            dest_array.copy_from_slice(&k_ref[..32]);
            let u_i_share_plaintext = Key::decrypt(dest_array,p2p.u_i_share_ciphertext[0..16].try_into().unwrap());
           let s = u_i_share_plaintext.as_slice();

           let mut destination_array: [u8; 32] = [0; 32];

           destination_array[..s.len()].copy_from_slice(&s);
           destination_array[s.len()..].copy_from_slice(&p2p.u_i_share_ciphertext[16..]);
           //debug!("decrypted : {:?}", destination_array);
            let u_i_share =
                vss::Share::from_scalar(bls12_381::Scalar::from_bytes(&destination_array).unwrap() , my_keygen_id.as_usize());

            ShareInfo {
                share: u_i_share,
                
            }}else{
                debug!("discarded - me:{}", my_keygen_id.as_usize());
                let destination_array: [u8; 32] = [0; 32];
                let u_i_share =
                vss::Share::from_scalar(bls12_381::Scalar::from_bytes(&destination_array).unwrap() , 123456789);

                ShareInfo {
                    share: u_i_share,
                    
                }
            }
        })?;
     
   debug!("faulty: {:?}", faulty_list); 
        // compute x_i
        let x_i = share_infos
            .into_iter()
            .fold(*self.u_i_share.get_scalar(), |acc, (_, share_info)| {
              
                if share_info.share.get_index() != 123456789{
                 
                    acc + share_info.share.get_scalar()
                }else{
                    debug!("share index excluded: {}, me: {}",share_info.share.get_index(), my_keygen_id.as_usize());
               acc}
            });
          //  debug!("share r4 : {:?}", x_i);
          debug!("index: {:?} - share :{:?}",my_keygen_id.as_usize(),x_i.to_bytes());
        // compute y
        let y = self.r2bcasts
            .iter()
            .fold(bls12_381::G1Projective::identity(), |acc, (_, r2bcast)| {
                let mut skip: bool = false;
                
                   // debug!("peer id: {:?}", peer_keygen_id);
                  for id in &faulty_list{
                    if *id == r2bcast.id{
                        
                        skip = true;
                    }
                  }
                    
                
                if !skip{
                acc + r2bcast.u_i_vss_commit.secret_commit()}
                else{
                    debug!("skipped :{:?}",r2bcast.id);
                    acc
                }
            });
              
//debug!("pk: {:?}", y.to_string());
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
    //  let s1 =   bls12_381::Scalar::from_bytes(&[249, 227, 197, 161, 108, 61, 118, 222, 202, 91, 141, 110, 154, 164, 62, 134, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    //    let s2 =  bls12_381::Scalar::from_bytes(&[99, 136, 148, 102, 93, 202, 227, 57, 250, 37, 108, 166, 1, 30, 253, 15, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
      //  corrupt!(x_i, self.corrupt_scalar(my_keygen_id, x_i));
    //     debug!("xi : {:?}", x_i.to_bytes());
    //     let shares = &[Share{ scalar: s1, index: 0}, Share{scalar:s2,index:1}];
    //     let secret = vss::recover_secret(shares);
    //     let pk = bls12_381::G1Projective::generator() * secret;
    //     debug!("secret: {:?}", secret.to_bytes());
    // debug!("base {:?}", bls12_381::G1Projective::generator().to_bytes());
    //     debug!("pk bytes {:?}", pk.to_bytes());
    //     debug!("y bytes {:?}", [152, 201, 203, 178, 240, 239, 211, 28, 217, 91, 9, 248, 225, 171, 25, 103, 26, 138, 8, 155, 162, 169, 206, 95, 130, 191, 140, 201, 79, 112, 164, 83, 243, 156, 226, 31, 203, 63, 124, 33, 133, 165, 155, 69, 133, 127, 101, 49]);
        Ok(ProtocolBuilder::Done(Ok(SecretKeyShare::new(
            y.into(),
            ShareSecretInfo::new(my_keygen_id, self.ek, x_i.into()),
            GroupPublicInfo::new(
                self.party_share_counts,
                self.threshold,
                y.into(),
                 
            ),
            
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
