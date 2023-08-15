//! Helpers for verifiable secret sharing
use crate::sdk::api::{TofnFatal, TofnResult};


use group::{ff::PrimeField, GroupEncoding};
use num_bigint::BigUint;
use num_traits::{FromPrimitive};
use rand::Rng;
use serde::{ser::SerializeSeq, ser::SerializeStruct, Deserializer, Serialize, Serializer};
use std::{convert::TryInto};
//use k256::elliptic_curve::Field;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{error};

// use num_bigint::{BigUint, ToBigUint};
// use kyber::{Scalar, GroupElement};
use bls12_381::{G1Affine, Scalar as BlsScalar};
use std::error::Error;


#[derive(Debug)]

pub struct Vss {
    secret_coeffs: Vec<bls12_381::Scalar>,
}

impl Vss {
    pub fn new(threshold: usize) -> Self {
        let secret_coeffs: Vec<bls12_381::Scalar> = (0..=threshold)
            .map(|_| bls12_381::Scalar::from_u128(rand::thread_rng().gen::<u128>()))
            .collect();
        Self { secret_coeffs }
    }

    pub fn get_threshold(&self) -> usize {
        self.secret_coeffs.len() - 1
    }

    pub fn get_secret(&self) -> &bls12_381::Scalar {
        &self.secret_coeffs[0]
    }

    pub fn commit(&self) -> Commit {
        let G = bls12_381::G1Projective::generator();
        Commit {
            coeff_commits: self
                .secret_coeffs
                .iter()
                .map(|coeff| (G * coeff).into())
                .collect(),
        }
    }

    pub fn shares(&self, n: usize) -> Vec<Share> {
        debug_assert!(self.get_threshold() < n); // also ensures that n > 0

        (0..n)
            .map(|index| {
                let index_scalar = bls12_381::Scalar::from(index as u64 + 1); // vss indices start at 1
                Share {
                    // evaluate the polynomial at i using Horner's method
                    scalar: self
                        .secret_coeffs
                        .iter()
                        .rev()
                        .fold(bls12_381::Scalar::zero(), |acc, coeff| {
                            acc * index_scalar + coeff
                        })
                        .into(),
                    index,
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug)]

pub struct Commit {
    pub(crate) coeff_commits: Vec<bls12_381::G1Projective>,
}

impl Serialize for Commit {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.coeff_commits.len()))?;
        for commit in &self.coeff_commits {
            let mut commit_b = commit.to_bytes();
            let bytes = commit_b.as_mut();
            seq.serialize_element(&bytes)?;
        }
        seq.end()
    }
}

struct MyStruct<'a> {
    bytes: Vec<&'a [u8]>,
}

impl<'de> Deserialize<'de> for MyStruct<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<&'de [u8]>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();

                while let Some(byte_seq) = seq.next_element()? {
                    bytes.push(byte_seq);
                }

                Ok(bytes)
            }
        }

        let my_struct = MyStruct {
            bytes: deserializer.deserialize_seq(BytesVisitor)?,
        };

        Ok(my_struct)
    }

    fn deserialize_in_place<D>(deserializer: D, place: &mut Self) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        // Default implementation just delegates to `deserialize` impl.
        *place = (Deserialize::deserialize(deserializer)).unwrap();
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Commit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = MyStruct::deserialize(deserializer)?;
        let coeff_commits = fields
            .bytes
            .into_iter()
            .map(|bytes| {
                G1Affine::from_compressed(bytes.try_into().unwrap())
                    .unwrap()
                    .into()
            })
            .collect();

        Ok(Commit { coeff_commits })
    }
}

impl Commit {
    pub fn len(&self) -> usize {
        self.coeff_commits.len()
    }

    pub fn share_commit(&self, index: usize) -> bls12_381::G1Projective {
        let index_scalar = bls12_381::Scalar::from(index as u64 + 1); // vss indices start at 1
        self.coeff_commits
            .iter()
            .rev()
            .fold(bls12_381::G1Projective::identity(), |acc, p| {
                acc * index_scalar + p
            })
    }

    pub fn secret_commit(&self) -> &bls12_381::G1Projective {
        &self.coeff_commits[0]
    }

    pub fn validate_share_commit(
        &self,
        share_commit: &bls12_381::G1Projective,
        index: usize,
    ) -> bool {
        self.share_commit(index) == *share_commit
    }

    pub fn validate_share(&self, share: &Share) -> bool {
        self.validate_share_commit(
            &(bls12_381::G1Projective::generator() * share.get_scalar()),
            share.get_index(),
        )
    }
}

#[derive(Clone, Debug, PartialEq)]

pub struct Share {
    pub(crate) scalar: bls12_381::Scalar,
    pub(crate) index: usize,
}

impl From<Share> for (bls12_381::Scalar, usize) {
    fn from(share: Share) -> (bls12_381::Scalar, usize) {
        let scalar = share.scalar;
        (scalar, share.index)
    }
}
impl<'de> Deserialize<'de> for Share {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (c, r) = <([u8; 32], usize)>::deserialize(deserializer)?;
        let shareScalar = bls12_381::Scalar::from_bytes(&c).unwrap();

        Ok(Share {
            scalar: shareScalar,
            index: r,
        })
    }
}
impl Serialize for Share {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (scalar, index) = self.clone().into();
        let mut state = serializer.serialize_struct("Share", 2)?;
        state.serialize_field("scalar", &scalar.to_bytes())?;
        state.serialize_field("index", &index)?;
        state.end()
    }
}

pub struct EncKey {
    kij: bls12_381::Scalar,
}
#[derive(Debug, Clone)]
pub struct Proof {
    c: bls12_381::Scalar,
    r: bls12_381::Scalar,
}

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (c, r) = <([u8; 32], [u8; 32])>::deserialize(deserializer)?;
        let cScalar = bls12_381::Scalar::from_bytes(&c).unwrap();
        let rScalar = bls12_381::Scalar::from_bytes(&r).unwrap();
        Ok(Proof {
            c: cScalar,
            r: rScalar,
        })
    }
}

impl Proof {
    pub fn generate_proof(
        point_g: &bls12_381::G1Projective,
        public_key_i: &bls12_381::G1Projective,
        public_key_j: &bls12_381::G1Projective,
        encryption_key_ij: &bls12_381::G1Projective,
        secret_key_j: &BlsScalar,
    ) -> Result<([u8; 32], [u8; 32], [u8; 32]), Box<dyn Error>> {
        let one = BigUint::from_i32(1).unwrap();
        let order = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

        let group_order = BigUint::parse_bytes(order.as_bytes(), 16).unwrap();

        let _max = group_order - &one;

        let mut rng = rand::thread_rng();
        let mut w: u64 = rng.gen();

        w = w + 1;

        let omega = bls12_381::Scalar::from(w);

        let mut t1 = bls12_381::G1Projective::generator();
        let mut t2 = bls12_381::G1Projective::generator();

        t1 = t1 * omega;

        t2 = public_key_i * omega;

        let concat = format!(
            "{:?}{:?}{:?}{:?}{:?}{:?}",
            (*point_g).to_bytes(),
            public_key_j.to_bytes(),
            public_key_i.to_bytes(),
            encryption_key_ij.to_bytes(),
            t1.to_bytes(),
            t2.to_bytes()
        );
        
        let mut hasher = Sha256::new();
        hasher.update(concat.as_bytes());
        let c = hasher.finalize();
        
        let mut hash_bytes: [u8; 32] = [0u8; 32];
        let mut result: [u8; 32] = [0u8; 32];
        hash_bytes.copy_from_slice(&c.as_ref());
        let mut hash2_kyber_scalar = bls12_381::Scalar::from_bytes(&hash_bytes);
        while hash2_kyber_scalar.is_some().unwrap_u8() == 0 {
           
            let gorder = order.as_bytes();
            for i in 0..32 {
                result[i] = hash_bytes[i].wrapping_sub(gorder[i]);
            }
            hash_bytes = result;
            hash2_kyber_scalar = bls12_381::Scalar::from_bytes(&result);
        }
        let u = &hash2_kyber_scalar.unwrap();

        let s = secret_key_j;

        let binding = s * u;

        let b = binding.neg();
        let r = b + omega;

        Ok(((*u).to_bytes(), r.to_bytes(), c.into()))
    }
}
impl Share {
    pub fn from_scalar(scalar: bls12_381::Scalar, index: usize) -> Self {
        Self {
            scalar: scalar.into(),
            index,
        }
    }

    pub fn get_scalar(&self) -> &bls12_381::Scalar {
        &self.scalar
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ShareCommit {
    index: usize,
    point: bls12_381::G1Projective,
}

impl ShareCommit {
    pub fn from_point(index: usize, point: bls12_381::G1Projective) -> Self {
        Self { point, index }
    }
}

pub fn recover_secret_commit(
    share_commits: &[ShareCommit],
    threshold: usize,
) -> TofnResult<bls12_381::G1Projective> {
    debug_assert!(share_commits.len() > threshold);

    let indices: Vec<usize> = share_commits.iter().map(|s| s.index).collect();
    share_commits.iter().enumerate().try_fold(
        bls12_381::G1Projective::identity(),
        |sum, (i, share_commit)| Ok(sum + share_commit.point * &lagrange_coefficient(i, &indices)?),
    )
}

pub fn lagrange_coefficient(i: usize, indices: &[usize]) -> TofnResult<bls12_381::Scalar> {
    let scalars: Vec<bls12_381::Scalar> = indices
        .iter()
        .map(|&index| bls12_381::Scalar::from(index as u64 + 1))
        .collect();

    let (numerator, denominator) = scalars.iter().enumerate().fold(
        (bls12_381::Scalar::one(), bls12_381::Scalar::one()),
        |(num, den), (j, scalar_j)| {
            if j == i {
                (num, den)
            } else {
                (num * scalar_j, den * (scalar_j - &scalars[i]))
            }
        },
    );

    let den_inv = denominator.invert();

    if bool::from(den_inv.is_none()) {
        error!("Denominator in lagrange coefficient computation is 0");
        return Err(TofnFatal);
    }

    Ok(numerator * den_inv.unwrap())
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use super::*;
    impl Share {
        pub fn corrupt(&mut self) {
            self.scalar = bls12_381::Scalar::one();
        }
    }
}

pub fn recover_secret(shares: &[Share]) -> bls12_381::Scalar {
    let indices: Vec<usize> = shares.iter().map(|s| s.index).collect();
    shares
        .iter()
        .enumerate()
        .fold(bls12_381::Scalar::zero(), |sum, (i, share)| {
            
            sum + share.scalar * &lagrange_coefficient(i, &indices).unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::SliceRandom;

    #[test]
    fn polynomial_evaluation() {
        // secret polynomial p(x) = 2 + 2x + 2x^2
        let vss = Vss {
            secret_coeffs: vec![
                bls12_381::Scalar::from(2u64),
                bls12_381::Scalar::from(2u64),
                bls12_381::Scalar::from(2u64),
            ],
        };
        let shares = vss.shares(3);
        // expected shares:
        // index: 0, share: p(1) = 6
        // index: 1, share: p(2) = 14
        // index: 2, share: p(3) = 26
        let expected_shares = vec![
            Share {
                scalar: bls12_381::Scalar::from(6u64).into(),
                index: 0,
            },
            Share {
                scalar: bls12_381::Scalar::from(14u64).into(),
                index: 1,
            },
            Share {
                scalar: bls12_381::Scalar::from(26u64).into(),
                index: 2,
            },
        ];
        assert_eq!(shares, expected_shares);
    }

    #[test]
    fn share_validation() {
        let (t, n) = (2, 5);
        let vss = Vss::new(t);
        let shares = vss.shares(n);
        let commit = vss.commit();
        for s in shares.iter() {
            assert!(commit.validate_share(s));
        }
    }

    impl Vss {
        fn shuffled_shares(&self, n: usize) -> Vec<Share> {
            let mut shares = self.shares(n);
            shares.shuffle(&mut rand::thread_rng());
            shares
        }
    }

    #[test]
    fn secret_recovery() {
        let (t, n) = (2, 5);
        let vss = Vss::new(t);
        let secret = vss.get_secret();
        let shuffled_shares = vss.shuffled_shares(n);
        let recovered_secret = recover_secret(&shuffled_shares);
        assert_eq!(recovered_secret, *secret);

        let secret_commit = *vss.commit().secret_commit();
        let shuffled_share_commits: Vec<ShareCommit> = shuffled_shares
            .iter()
            .map(|share| ShareCommit {
                point: (bls12_381::G1Projective::generator() * share.get_scalar()).into(),
                index: share.get_index(),
            })
            .collect();
        let recovered_secret_commit = recover_secret_commit(&shuffled_share_commits, t).unwrap();
        assert_eq!(recovered_secret_commit, secret_commit);
    }

    #[test]
    fn additive_shares() {
        let (t, s, n) = (2, 4, 6);
        let vss = Vss::new(t);

        // take a random subset of s shares
        let shares: Vec<Share> = vss.shuffled_shares(n).into_iter().take(s).collect();
        let indices: Vec<usize> = shares.iter().map(|share| share.index).collect();

        // convert polynomial shares to additive shares
        let additive_shares: Vec<Share> = shares
            .iter()
            .enumerate()
            .map(|(i, share)| Share {
                scalar: (share.get_scalar() * &lagrange_coefficient(i, &indices).unwrap()).into(),
                ..*share
            })
            .collect();

        let recovered_secret = additive_shares
            .iter()
            .fold(bls12_381::Scalar::zero(), |acc, share| {
                acc + share.get_scalar()
            });
        assert_eq!(recovered_secret, *vss.get_secret());
    }
}
