use ark_bls12_381::{Bls12_381, Fr as ScalerField, G1Projective as G1, G2Projective as G2};
use ark_ec::{pairing::Pairing, Group};
use ark_std::{UniformRand, Zero};
mod blake;
mod bls_id;

fn main() {
    // lets make some private Keys
    let mut rng = ark_std::rand::thread_rng();
    let sk1 = ScalerField::rand(&mut rng);
    let sk2 = ScalerField::rand(&mut rng);
    // lets make bls_id pair of keys (private key , public key)
    let pair1 = bls_id::KeyPair::new(sk1);
    let pair2 = bls_id::KeyPair::new(sk2);
    // lets verify that the public keys do actually correspond to private keys
    if bls_id::KeyPair::verify_sk_pk(pair1.get_secret_key(), pair1.get_public_key()) {
        iko_sawa();
    }
    if bls_id::KeyPair::verify_sk_pk(pair2.get_secret_key(), pair2.get_public_key()) {
        iko_sawa();
    }
    // now lets get some messages to for both parties
    let message1 = "aggregated bls signatures have a big flaw";
    let message2 = "do you know of the splitting zero attack";
    // now lets get both parties to sign this messages
    let sig1 = bls_id::KeyPair::sign(sk1, message1);
    let sig2 = bls_id::KeyPair::sign(sk2, message2);
    // now lets verify the signatures
    if bls_id::KeyPair::verify_signature(sig1, pair1.get_public_key(), message1) {
        iko_sawa();
    }
    if bls_id::KeyPair::verify_signature(sig2, pair2.get_public_key(), message2) {
        iko_sawa();
    }
    // now lets aggregate the signatures
    let sig_aggregate = bls_id::Aggregate::aggregate_signatures(&[sig1, sig2]);
    // now lets verify the signatures
    // getting the messeges a points
    let point1 = blake::hash_to_curve(message1);
    let point2 = blake::hash_to_curve(message2);

    let verified = bls_id::Aggregate::verify_aggregate_signatures(
        sig_aggregate,
        &[pair1.get_public_key(), pair2.get_public_key()],
        &[point1, point2],
    );
    assert!(verified);
}
// for testing reasons

fn iko_sawa() {
    println!("iko sawa");
}
