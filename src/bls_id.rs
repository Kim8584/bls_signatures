use ark_bls12_381::{Bls12_381, Fr as ScalerField, G1Projective as G1, G2Projective as G2};
use ark_ec::{pairing::Pairing, Group};
use ark_std::{UniformRand, Zero};

use super::blake;

pub struct KeyPair {
    secret_key: ScalerField,
    public_key: G1,
}
impl KeyPair {
    pub fn new(secret_key: ScalerField) -> Self {
        let public_key = G1::generator() * secret_key;
        KeyPair {
            secret_key,
            public_key,
        }
    }
    pub fn get_secret_key(&self) -> ScalerField {
        self.secret_key
    }
    pub fn get_public_key(&self) -> G1 {
        self.public_key
    }
    // verify that a sk corresponds to a public key
    pub fn verify_sk_pk(secret_key: ScalerField, public_key: G1) -> bool {
        // get the corresponding pk of the sk
        let pk = G1::generator() * secret_key;
        pk == public_key
    }
    pub fn sign(secret_key: ScalerField, message: &str) -> G2 {
        // get the message as a point on the curve
        let message_point = blake::hash_to_curve(message);
        message_point * secret_key
    }
    pub fn verify_signature(signature: G2, public_key: G1, message: &str) -> bool {
        // e(G1 , signature) == e(Pk, hash (message))

        // first we will get the messege as a point on the curve
        let message_point = blake::hash_to_curve(message);
        let g1 = G1::generator();
        let left_side = Bls12_381::pairing(g1, signature);
        let right_side = Bls12_381::pairing(public_key, message_point);
        left_side == right_side
    }
}
pub struct Aggregate;
impl Aggregate {
    // notice this function does not keep track of the public keys used in the signatures verification
    pub fn aggregate_signatures(sigz: &[G2]) -> G2 {
        // this is just a sum of all signatures
        sigz.iter().fold(G2::zero(), |acc, &x| acc + x)
    }
    // this aggregates the public keys to get a final public Key
    pub fn aggregate_pks(public_keys: &[G1]) -> G1 {
        public_keys.iter().fold(G1::zero(), |acc, &x| acc + x)
    }
    pub fn aggregate_message_points(messages: &[G2]) -> G2 {
        messages.iter().fold(G2::zero(), |acc, &x| acc + x)
    }
    pub fn verify_aggregate_signatures(
        aggregate_signature: G2,
        public_keys: &[G1],
        messages: &[G2],
    ) -> bool {
        let aggregate_public_key = Self::aggregate_pks(public_keys);
        let aggregate_message_point = Self::aggregate_message_points(messages);
        // e(G1 , signature) == e(Pk, hash (message))
        let g1 = G1::generator();
        let right_side = Bls12_381::pairing(g1, aggregate_signature);
        let left_side = Bls12_381::pairing(aggregate_public_key, aggregate_message_point);
        right_side == left_side
    }
}
