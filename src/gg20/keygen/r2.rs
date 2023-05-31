use serde::{Deserialize, Serialize};
use tracing::{warn, debug};
//use tracing_subscriber::field::debug;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    crypto_tools::{hash,  vss, enc::{Key, EncDec}},
    gg20::keygen::{r3, SecretKeyShare},
    sdk::{
        api::{Fault::{ProtocolFault, self}, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use vec_map::VecMap as DVecMap;
use group::GroupEncoding;
use std::convert::TryInto;
use aes::Aes256;
use aes::cipher::{ArrayLength, typenum, Block, BlockSizeUser};
use aes::cipher::typenum::bit::{B0, B1};
use typenum::{ U16};
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use sha2::{Sha256, Digest};
use super::{r1, KeygenPartyShareCounts, KeygenShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

/// TODO: The byte length of this struct is proportional to the threshold: 34t + 73
/// Instead it should be constant.
/// https://github.com/axelarnetwork/tofn/issues/171
#[derive(Clone, Debug, Serialize,Deserialize)]
pub(super) struct Bcast {
    // pub(super) y_i_reveal: hash::Randomness,
    pub(super) u_i_vss_commit: vss::Commit,
    pub(super) faulters: FillVecMap<KeygenShareId, Fault>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) u_i_share_ciphertext: [u8;32],
    pub(super) id: usize,
    pub(super) from: usize
}

pub(super) struct R2 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) dk: bls12_381::Scalar,
    pub(super) u_i_vss: vss::Vss,
    // pub(super) y_i_reveal: hash::Randomness,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}
impl EncDec for Key {
	fn encrypt(_key:Self, plaintext:  [u8; 32]) -> GenericArray<u8, U16> {
        debug!("plain: {:?}",plaintext);
		let key = GenericArray::from(_key);
		let hashvalue = Sha256::digest(&key);
		let (first_half, _second_half) = hashvalue.split_at(hashvalue.len()/2);
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
        // debug!("nonce : {:?}", output);
		return  output;
	}
	fn decrypt(_key:Self, ciphertext:  [u8; 16])-> GenericArray<u8, U16> {
		let key = GenericArray::from(_key);
		let hashvalue = Sha256::digest(&key);
		let (first_half, _second_half) = hashvalue.split_at(hashvalue.len()/2);
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
   // debug!("decrypted : {:?}", decrypted_plaintext);
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
            

            
            let key =  bcasts_in
            .get(peer_keygen_id)?
            .ek;
            let kij = (self.dk * key);
            
            let k = kij.to_bytes();
           // debug!("enc key: {:?}", k);
            let binding = k.as_ref();
            let mut dest_array: [u8; 32] = [0u8;32];
            dest_array.copy_from_slice(&binding[..32]);
            let mut u_i_share_ciphertext = Key::encrypt(dest_array,(*share.get_scalar()).to_bytes());
            kij_list.insert(peer_keygen_id.as_usize(),kij);
            corrupt!(
                u_i_share_ciphertext,
                self.corrupt_ciphertext(my_keygen_id, peer_keygen_id, u_i_share_ciphertext)
            );
            let encShare = GenericArray::as_mut_slice(&mut u_i_share_ciphertext);
            let mut shareB = share.get_scalar().to_bytes();
            let mut plainSecondHalf =  &shareB.as_mut()[16..];
           // debug!("plainSecondHalf : {:?}",plainSecondHalf);
            let c: &[&[u8]] = &[encShare, plainSecondHalf];
            let concatC = c.concat();
            //debug!("combined_slice : {:?}",concatC);
        //     let kRef = k.as_ref();
        //     let mut dest_array: [u8; 32] = [0u8;32];
        //     dest_array.copy_from_slice(&kRef[..32]);
        //     let u_i_share_plaintext = Key::decrypt(dest_array,encShare.try_into().unwrap());
        //    let s = u_i_share_plaintext.as_slice();

        //    let mut destination_array: [u8; 32] = [0; 32];

        //    destination_array[..s.len()].copy_from_slice(&s);
           
        //     let u_i_share =
        //         vss::Share::from_scalar(bls12_381::Scalar::from_bytes(&destination_array).unwrap() , my_keygen_id.as_usize());
              
            debug!("share :{:?}", share);
            serialize(&P2p {
                
                u_i_share_ciphertext: concatC.try_into().unwrap(),
                id:peer_keygen_id.as_usize(),
                from: my_keygen_id.as_usize()
            })
        })?);
    
        let bcast_out = Some(serialize(&Bcast {
            // y_i_reveal: self.y_i_reveal.clone(),
            faulters:faulters.clone(),
            u_i_vss_commit: self.u_i_vss.commit(),
        })?);
        debug!("r2 done");
        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r3::R3 {
                threshold: self.threshold,
                party_share_counts: self.party_share_counts,
                dk: self.dk,
                kij:kij_list,
                u_i_share,
                r1bcasts: bcasts_in,
                faulters:faulters.clone(),
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
        crypto_tools::{paillier::Ciphertext, vss::Share},
        gg20::keygen::{malicious::Behaviour, KeygenShareId},
        sdk::api::TofnResult,
    };

    use super::R2;

    use tracing::info;

    impl R2 {
        pub fn corrupt_share(
            &self,
            my_keygen_id: TypedUsize<KeygenShareId>,
            mut peer_shares: HoleVecMap<KeygenShareId, Share>,
        ) -> TofnResult<HoleVecMap<KeygenShareId, Share>> {
            if let Behaviour::R2BadShare { victim } = self.behaviour {
                info!("malicious peer {} does {:?}", my_keygen_id, self.behaviour);
                peer_shares.get_mut(victim)?.corrupt();
            }

            Ok(peer_shares)
        }

        pub fn corrupt_ciphertext(
            &self,
            my_keygen_id: TypedUsize<KeygenShareId>,
            victim_keygen_id: TypedUsize<KeygenShareId>,
            mut ciphertext: Ciphertext,
        ) -> Ciphertext {
            if let Behaviour::R2BadEncryption { victim } = self.behaviour {
                if victim == victim_keygen_id {
                    info!("malicious peer {} does {:?}", my_keygen_id, self.behaviour);
                    ciphertext.corrupt();
                }
            }

            ciphertext
        }
    }
}
