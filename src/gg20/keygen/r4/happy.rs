

use tracing::{debug};

use crate::crypto_tools::enc::EncDec;
use crate::{
    collections::{FillVecMap, FullP2ps, P2ps, VecMap},
    crypto_tools::{
        enc::Key,
        vss::{self},
    },
    gg20::keygen::{
        r1, r2,
        r3::{ShareInfo},
        GroupPublicInfo, KeygenPartyShareCounts, KeygenShareId, SecretKeyShare,
        ShareSecretInfo,
    },
    sdk::{
        api::{
            Fault::{self},
            TofnResult,
        },
        implementer_api::{Executer, ProtocolBuilder, ProtocolInfo},
    },
};
use group::GroupEncoding;
use std::{convert::TryInto};
use vec_map::VecMap as DVecMap;
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
        _p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        debug!("r4 start");

        let mut faulty_list: Vec<usize> = vec![];
        let kijs: DVecMap<bls12_381::G1Projective> = self.kij;
        let my_keygen_id = info.my_id();
        let p2ps_in: FullP2ps<KeygenShareId, r2::P2p> = self.r2p2ps;
        let share_infos: crate::collections::HoleVecMap<KeygenShareId, ShareInfo> = p2ps_in
            .map_to_me(my_keygen_id, |p2p| {
                let mut skip: bool = false;

                for (peer_keygen_id, bcast) in bcasts_in.iter() {
                    if !bcast.is_none() {
                        debug!(
                            "peer: {:?} - me:{}, from :{:?}, bcast:{:?}",
                            peer_keygen_id.as_usize(),
                            my_keygen_id.as_usize(),
                            p2p.from,
                            bcast.unwrap()
                        );
                        if p2p.from == bcast.unwrap() {
                            faulty_list.push(bcast.unwrap());
                            skip = true;
                        }
                    }
                }
                if !skip {
                    let k = kijs.get(p2p.from).unwrap().to_bytes();
                    let k_ref = k.as_ref();
                    let mut dest_array: [u8; 32] = [0u8; 32];
                    dest_array.copy_from_slice(&k_ref[..32]);
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
                    debug!("discarded - me:{}", my_keygen_id.as_usize());
                    let destination_array: [u8; 32] = [0; 32];
                    let u_i_share = vss::Share::from_scalar(
                        bls12_381::Scalar::from_bytes(&destination_array).unwrap(),
                        123456789,
                    );

                    ShareInfo { share: u_i_share }
                }
            })?;

        debug!("faulty: {:?}", faulty_list);
        // compute x_i
        let x_i =
            share_infos
                .into_iter()
                .fold(*self.u_i_share.get_scalar(), |acc, (_, share_info)| {
                    if share_info.share.get_index() != 123456789 {
                        acc + share_info.share.get_scalar()
                    } else {
                        debug!(
                            "share index excluded: {}, me: {}",
                            share_info.share.get_index(),
                            my_keygen_id.as_usize()
                        );
                        acc
                    }
                });

        debug!(
            "index: {:?} - share :{:?}",
            my_keygen_id.as_usize(),
            x_i.to_bytes()
        );
        // compute y
        let y =
            self.r2bcasts
                .iter()
                .fold(bls12_381::G1Projective::identity(), |acc, (_, r2bcast)| {
                    let mut skip: bool = false;

                   
                    for id in &faulty_list {
                        if *id == r2bcast.id {
                            skip = true;
                        }
                    }

                    if !skip {
                      //  debug!("y process :{:?}",acc.to_bytes());
                        acc + r2bcast.u_i_vss_commit.secret_commit()
                    } else {
                        debug!("skipped :{:?}", r2bcast.id);
                        acc
                    }
                   
                });

        Ok(ProtocolBuilder::Done(Ok(SecretKeyShare::new(
            y.into(),
            ShareSecretInfo::new(my_keygen_id, self.ek, x_i.into()),
            GroupPublicInfo::new(self.party_share_counts, self.threshold, y.into()),
        ))))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
