
use aes::cipher::{typenum};

use typenum::{ U16};
use aes::cipher::{
    generic_array::GenericArray,
};

pub type Key = [u8;32];
pub trait EncDec {
	 fn encrypt(_key:[u8; 32], plaintext:  [u8; 32]) -> GenericArray<u8, U16> ;
	 fn decrypt(_key:[u8; 32], ciphertext:  [u8; 16])-> GenericArray<u8, U16>;
	 fn convert(slice: &[u8]) -> Result<[u8; 32], &'static str> ;
}

