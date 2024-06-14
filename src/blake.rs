// notice that we are getting signatures in feild G2 instead of G1
// this is because G1 is intended to be for public keys

/*
elements of G1 take less space than G2 elements
G2 is an extension field of G1 and G2 has more elements

there are two variants of bls signatures one 1. min-pubkey-size and min-singature-type

When you generate a public key with G1, it’s called min-pubkey-size type, and when you generate a signature with G1,
 it’s called min-signature-size type.
 Depending on whether you need to minimize the size of the signature or the public key,
 you can simply place the element to be minimized as G1 and the other as G2.
 */
use ark_bls12_381::{Fr as ScalerField, G2Projective as G2};
use ark_ec::Group;
use ark_ff::PrimeField;
use blake2::{Blake2s256 as Blake, Digest};

fn hash_to_field(message: &str) -> ScalerField {
    let mut hasher = Blake::new();
    hasher.update(message.as_bytes());
    // getting the hash(message) but in bytse
    let hash = hasher.finalize();
    // convert into a field element
    let hash = ScalerField::from_le_bytes_mod_order(&hash);
    // return the feild element
    hash
}
pub fn hash_to_curve(message: &str) -> G2 {
    // get the messege in the scaler field
    let message_scaler = hash_to_field(message);
    G2::generator() * message_scaler
}
