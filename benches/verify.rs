#![feature(test)]

extern crate test;
extern crate ecdsa_verify;

use test::Bencher;
use ecdsa_verify::{verify, Point3D, EcdsaSignature, secp256r1};
use num_bigint::BigInt;
use num_traits::Zero;

#[bench]
fn bench_verify(b: &mut Bencher) {
    let message_hash = hex::decode("48c08394455a5007945a9025c58be18f1795db8a6f8c12e70a00c1cdd6d3df78").unwrap();
    let sig = EcdsaSignature {
        r: BigInt::parse_bytes(b"7679932563960414347091205306595575529033945270189659289643076129390605281494", 10).unwrap(),
        s: BigInt::parse_bytes(b"47844299635965077418200610260443789525430653377570372618360888620298576429143", 10).unwrap(),
    };
    let public_key = Point3D {
        x: BigInt::parse_bytes(b"57742645121064378973436687487225580113493928349340781038880342836084265852815", 10).unwrap(),
        y: BigInt::parse_bytes(b"99327750397910171089097863507426920114029443958399733106031194020330646322282", 10).unwrap(),
        z: BigInt::zero(),
    };
    let curve = secp256r1();

    b.iter(|| {
        assert!(verify(&message_hash, &sig, &public_key, &curve));
    });
}
