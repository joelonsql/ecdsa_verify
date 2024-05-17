# ECDSA Verify

![CI](https://github.com/joelonsql/ecdsa_verify/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/ecdsa_verify.svg)](https://crates.io/crates/ecdsa_verify)

`ecdsa_verify` is a pure Rust crate for verifying ECDSA (Elliptic Curve Digital
Signature Algorithm) signatures. This crate provides functions to handle
elliptic curve operations and verify signatures against given message hashes
and public keys.

## Features

- Supports the `secp256k1` and `secp256r1` elliptic curves.
- Implements elliptic curve operations in Jacobian coordinates.
- Provides a function to verify ECDSA signatures.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
ecdsa_verify = "1.1"
```

## Usage

```rust
use ecdsa_verify::{verify, Point3D, EcdsaSignature, secp256r1};
use num_bigint::BigInt;
use num_traits::Zero;

fn main() {
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
    let is_valid = verify(&message_hash, &sig, &public_key, &curve);
    println!("Signature valid: {}", is_valid);
}
```


## Benchmarks

To benchmark the extension, ensure you are using the Rust Nightly toolchain,
then use the following command:

To run the benchmarks, execute:

```sh
cargo bench
```

#### Benchmark Results

The benchmarks were run on an Intel Core i9-14900K. The results are as follows:

```
$ cargo bench

     Running benches/ecdsa_verify.rs (target/release/deps/ecdsa_verify-f2c7ac91fb3e2e9c)

test bench_verify ... bench:     864,913 ns/iter (+/- 13,821)
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Based on v2.2.0 of the [starkbank-ecdsa](https://github.com/starkbank/ecdsa-python/commit/9acdc661b7acde453b9bd6b20c57b88d5a3bf7e3) Python library by Star Bank.

## Contributing

Bugfixes, optimizations and simplifications are welcome, but no more features.
Please open an issue or submit a pull request.
