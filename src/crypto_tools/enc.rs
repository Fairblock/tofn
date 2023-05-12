use aes::Aes256;
use aes::cipher::{ArrayLength, typenum, Block, BlockSizeUser};
use aes::cipher::typenum::bit::{B0, B1};
use typenum::{ U16};
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use sha2::{Sha256, Digest};
pub type Key = [u8;32];
pub trait EncDec {
	 fn encrypt(_key:[u8; 32], plaintext:  [u8; 32]) -> GenericArray<u8, U16> ;
	 fn decrypt(_key:[u8; 32], ciphertext:  [u8; 16])-> GenericArray<u8, U16>;
}

