//! ECDSA Signature verification algorithm implemented in Rust  
//!
//! This code is based on v2.2.0 of the [starkbank-ecdsa] Python library
//! developed by Star Bank [Star Bank].
//!
//! [starkbank-ecdsa]: https://github.com/starkbank/ecdsa-python/commit/9acdc661b7acde453b9bd6b20c57b88d5a3bf7e3
//! [Star Bank]: https://starkbank.com/
use num_bigint::BigInt;
use num_traits::{One, Zero};

/// A struct representing a point in 3D space for elliptic curve operations.
#[derive(Debug, Clone, PartialEq)]
pub struct Point3D {
    /// The x-coordinate of the point.
    pub x: BigInt,
    /// The y-coordinate of the point.
    pub y: BigInt,
    /// The z-coordinate of the point.
    pub z: BigInt,
}

/// A struct representing an ECDSA signature with r and s components.
#[derive(Debug, Clone, PartialEq)]
pub struct EcdsaSignature {
    /// The r component of the signature.
    pub r: BigInt,
    /// The s component of the signature.
    pub s: BigInt,
}

/// A struct representing the parameters of an elliptic curve used in ECDSA.
#[derive(Debug, Clone)]
pub struct EcdsaCurve {
    /// The prime number defining the finite field of the curve.
    pub prime: BigInt,
    /// The a coefficient in the elliptic curve equation.
    pub a: BigInt,
    /// The b coefficient in the elliptic curve equation.
    pub b: BigInt,
    /// The x-coordinate of the generator point.
    pub g_x: BigInt,
    /// The y-coordinate of the generator point.
    pub g_y: BigInt,
    /// The order of the curve.
    pub n: BigInt,
}

fn to_jacobian(p: &Point3D) -> Point3D {
    Point3D {
        x: p.x.clone(),
        y: p.y.clone(),
        z: BigInt::one(),
    }
}

fn from_jacobian(p: &Point3D, prime: &BigInt) -> Option<Point3D> {
    if p.z.is_zero() {
        return Some(Point3D {
            x: BigInt::zero(),
            y: BigInt::zero(),
            z: BigInt::zero(),
        });
    }
    let z_inv = p.z.modinv(prime)?;
    let z_inv2 = &z_inv * &z_inv;
    let z_inv3 = &z_inv * &z_inv2;
    Some(Point3D {
        x: (&p.x * &z_inv2) % prime,
        y: (&p.y * &z_inv3) % prime,
        z: BigInt::zero(),
    })
}

fn jacobian_double(p: &Point3D, a: &BigInt, prime: &BigInt) -> Point3D {
    if p.y.is_zero() {
        return Point3D {
            x: BigInt::zero(),
            y: BigInt::zero(),
            z: BigInt::zero(),
        };
    }
    let ysq = (&p.y * &p.y) % prime;
    let s = (BigInt::from(4) * &p.x * &ysq) % prime;
    let m = (BigInt::from(3) * &p.x * &p.x + a * &p.z * &p.z * &p.z * &p.z) % prime;
    let nx = (&m * &m - BigInt::from(2) * &s) % prime;
    let ny = (&m * (&s - &nx) - BigInt::from(8) * &ysq * &ysq) % prime;
    let nz = (BigInt::from(2) * &p.y * &p.z) % prime;
    Point3D {
        x: nx,
        y: ny,
        z: nz,
    }
}

fn jacobian_add(p: &Point3D, q: &Point3D, a: &BigInt, prime: &BigInt) -> Point3D {
    if p.y.is_zero() {
        return q.clone();
    }
    if q.y.is_zero() {
        return p.clone();
    }

    let u1 = (&p.x * &q.z * &q.z) % prime;
    let u2 = (&q.x * &p.z * &p.z) % prime;
    let s1 = (&p.y * &q.z * &q.z * &q.z) % prime;
    let s2 = (&q.y * &p.z * &p.z * &p.z) % prime;

    if u1 == u2 {
        if s1 != s2 {
            return Point3D {
                x: BigInt::zero(),
                y: BigInt::zero(),
                z: BigInt::one(),
            };
        }
        return jacobian_double(p, a, prime);
    }

    let h = &u2 - &u1;
    let r = &s2 - &s1;
    let h2 = (&h * &h) % prime;
    let h3 = (&h * &h2) % prime;
    let u1h2 = (&u1 * &h2) % prime;
    let nx = (&r * &r - &h3 - BigInt::from(2) * &u1h2) % prime;
    let ny = (&r * (&u1h2 - &nx) - &s1 * &h3) % prime;
    let nz = (&h * &p.z * &q.z) % prime;
    Point3D {
        x: nx,
        y: ny,
        z: nz,
    }
}

fn jacobian_multiply(p: &Point3D, i: &BigInt, n: &BigInt, a: &BigInt, prime: &BigInt) -> Point3D {
    if p.y.is_zero() || i.is_zero() {
        return Point3D {
            x: BigInt::zero(),
            y: BigInt::zero(),
            z: BigInt::one(),
        };
    }
    if i.is_one() {
        return p.clone();
    }
    if i < &BigInt::zero() || i >= n {
        return jacobian_multiply(p, &(i % n), n, a, prime);
    }
    if i % BigInt::from(2) == BigInt::zero() {
        return jacobian_double(&jacobian_multiply(p, &(i / BigInt::from(2)), n, a, prime), a, prime);
    }
    jacobian_add(
        &jacobian_double(&jacobian_multiply(p, &(i / BigInt::from(2)), n, a, prime), a, prime),
        p,
        a,
        prime,
    )
}

fn multiply(p: &Point3D, i: &BigInt, n: &BigInt, a: &BigInt, prime: &BigInt) -> Option<Point3D> {
    from_jacobian(&jacobian_multiply(&to_jacobian(p), i, n, a, prime), prime)
}

fn add(p: &Point3D, q: &Point3D, a: &BigInt, prime: &BigInt) -> Option<Point3D> {
    from_jacobian(&jacobian_add(&to_jacobian(p), &to_jacobian(q), a, prime), prime)
}

fn contains(p: &Point3D, a: &BigInt, b: &BigInt, prime: &BigInt) -> bool {
    if p.x < BigInt::zero() || p.x >= *prime {
        return false;
    }
    if p.y < BigInt::zero() || p.y >= *prime {
        return false;
    }
    (&p.y * &p.y - (&p.x * &p.x * &p.x + a * &p.x + b)) % prime == BigInt::zero()
}

/// Verifies an ECDSA signature against a given message hash and public key.
///
/// # Arguments
///
/// * `message_hash` - A byte slice representing the hash of the message to verify.
/// * `sig` - A reference to an `EcdsaSignature` containing the r and s values of the signature.
/// * `public_key` - A reference to a `Point3D` representing the public key.
/// * `curve` - A reference to an `EcdsaCurve` containing the elliptic curve parameters.
///
/// # Returns
///
/// * `bool` - `true` if the signature is valid, `false` otherwise.
///
/// # Examples
///
/// ```
/// use ecdsa_verify::{verify, Point3D, EcdsaSignature, secp256r1};
/// use num_bigint::BigInt;
/// use num_traits::Zero;
///
/// let message_hash = hex::decode("48c08394455a5007945a9025c58be18f1795db8a6f8c12e70a00c1cdd6d3df78").unwrap();
/// let sig = EcdsaSignature {
///     r: BigInt::parse_bytes(b"7679932563960414347091205306595575529033945270189659289643076129390605281494", 10).unwrap(),
///     s: BigInt::parse_bytes(b"47844299635965077418200610260443789525430653377570372618360888620298576429143", 10).unwrap(),
/// };
/// let public_key = Point3D {
///     x: BigInt::parse_bytes(b"57742645121064378973436687487225580113493928349340781038880342836084265852815", 10).unwrap(),
///     y: BigInt::parse_bytes(b"99327750397910171089097863507426920114029443958399733106031194020330646322282", 10).unwrap(),
///     z: BigInt::zero(),
/// };
/// let curve = secp256r1();
/// assert!(verify(&message_hash, &sig, &public_key, &curve));
/// ```
pub fn verify(
    message_hash: &[u8],
    sig: &EcdsaSignature,
    public_key: &Point3D,
    curve: &EcdsaCurve,
) -> bool {
    let number_message = BigInt::from_bytes_be(num_bigint::Sign::Plus, message_hash);
    if !contains(&public_key, &curve.a, &curve.b, &curve.prime) {
        return false;
    }
    if sig.r < BigInt::one() || sig.r >= curve.n {
        return false;
    }
    if sig.s < BigInt::one() || sig.s >= curve.n {
        return false;
    }
    let inv = match sig.s.modinv(&curve.n) {
        Some(inv) => inv,
        None => return false,
    };

    let u1 = match multiply(
        &Point3D {
            x: curve.g_x.clone(),
            y: curve.g_y.clone(),
            z: BigInt::zero(),
        },
        &((number_message * &inv) % &curve.n),
        &curve.n,
        &curve.a,
        &curve.prime,
    ) {
        Some(point) => point,
        None => return false,
    };

    let u2 = match multiply(&public_key, &((&sig.r * &inv) % &curve.n), &curve.n, &curve.a, &curve.prime) {
        Some(point) => point,
        None => return false,
    };

    let v = match add(&u1, &u2, &curve.a, &curve.prime) {
        Some(point) => point,
        None => return false,
    };

    if v.y.is_zero() {
        return false;
    }

    v.x % &curve.n == sig.r
}

/// Returns the parameters for the secp256k1 elliptic curve.
///
/// # Returns
///
/// * `EcdsaCurve` - The secp256k1 curve parameters.
pub fn secp256k1() -> EcdsaCurve {
    // The following parameters can be reproduced using the OpenSSL command:
    // openssl ecparam -genkey -name secp256k1 -param_enc explicit | \
    // openssl ec -noout -text
    EcdsaCurve {
        // Prime:
        // 00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        // ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:fe:ff:
        // ff:fc:2f
        prime: BigInt::parse_bytes(
            b"00ffffffffffffffffffffffffffff\
              fffffffffffffffffffffffffffeff\
              fffc2f", 16).unwrap(),

        // A:    0
        a: BigInt::zero(),

        // B:    7 (0x7)
        b: BigInt::from(7),

        // Generator (uncompressed):
        // 04:79:be:66:7e:f9:dc:bb:ac:55:a0:62:95:ce:87:
        // 0b:07:02:9b:fc:db:2d:ce:28:d9:59:f2:81:5b:16:
        // f8:17:98:48:3a:da:77:26:a3:c4:65:5d:a4:fb:fc:
        // 0e:11:08:a8:fd:17:b4:48:a6:85:54:19:9c:47:d0:
        // 8f:fb:10:d4:b8
        g_x: BigInt::parse_bytes(
            b"79be667ef9dcbbac55a06295ce87\
              0b07029bfcdb2dce28d959f2815b16\
              f81798", 16).unwrap(),
        g_y: BigInt::parse_bytes(
            b"483ada7726a3c4655da4fbfc\
              0e1108a8fd17b448a68554199c47d0\
              8ffb10d4b8", 16).unwrap(),

        // Order:
        // 00:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        // ff:fe:ba:ae:dc:e6:af:48:a0:3b:bf:d2:5e:8c:d0:
        // 36:41:41
        n: BigInt::parse_bytes(
            b"00ffffffffffffffffffffffffffff\
              fffebaaedce6af48a03bbfd25e8cd0\
              364141", 16).unwrap(),
    }
}

/// Returns the parameters for the secp256r1 elliptic curve.
///
/// # Returns
///
/// * `EcdsaCurve` - The secp256r1 curve parameters.
pub fn secp256r1() -> EcdsaCurve {
    // The following parameters can be reproduced using the OpenSSL command:
    // openssl ecparam -genkey -name secp256r1 -param_enc explicit | \
    // openssl ec -noout -text
    EcdsaCurve {
        // Prime:
        // 00:ff:ff:ff:ff:00:00:00:01:00:00:00:00:00:00:
        // 00:00:00:00:00:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        // ff:ff:ff
        prime: BigInt::parse_bytes(
            b"00ffffffff00000001000000000000\
              000000000000ffffffffffffffffff\
              ffffff", 16).unwrap(),

        // A:
        // 00:ff:ff:ff:ff:00:00:00:01:00:00:00:00:00:00:
        // 00:00:00:00:00:00:ff:ff:ff:ff:ff:ff:ff:ff:ff:
        // ff:ff:fc
        a: BigInt::parse_bytes(
            b"00ffffffff00000001000000000000\
              000000000000ffffffffffffffffff\
              fffffc", 16).unwrap(),

        // B:
        // 5a:c6:35:d8:aa:3a:93:e7:b3:eb:bd:55:76:98:86:
        // bc:65:1d:06:b0:cc:53:b0:f6:3b:ce:3c:3e:27:d2:
        // 60:4b
        b: BigInt::parse_bytes(
            b"5ac635d8aa3a93e7b3ebbd55769886\
              bc651d06b0cc53b0f63bce3c3e27d2\
              604b", 16).unwrap(),

        // Generator (uncompressed):
        // 04:6b:17:d1:f2:e1:2c:42:47:f8:bc:e6:e5:63:a4:
        // 40:f2:77:03:7d:81:2d:eb:33:a0:f4:a1:39:45:d8:
        // 98:c2:96:4f:e3:42:e2:fe:1a:7f:9b:8e:e7:eb:4a:
        // 7c:0f:9e:16:2b:ce:33:57:6b:31:5e:ce:cb:b6:40:
        // 68:37:bf:51:f5
        g_x: BigInt::parse_bytes(
            b"6b17d1f2e12c4247f8bce6e563a4\
            40f277037d812deb33a0f4a13945d8\
            98c296", 16).unwrap(),
        g_y: BigInt::parse_bytes(
            b"4fe342e2fe1a7f9b8ee7eb4a\
              7c0f9e162bce33576b315ececbb640\
              6837bf51f5", 16).unwrap(),

        // Order:
        // 00:ff:ff:ff:ff:00:00:00:00:ff:ff:ff:ff:ff:ff:
        // ff:ff:bc:e6:fa:ad:a7:17:9e:84:f3:b9:ca:c2:fc:
        // 63:25:51
        n: BigInt::parse_bytes(
            b"00ffffffff00000000ffffffffffff\
              ffffbce6faada7179e84f3b9cac2fc\
              632551", 16).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    #[test]
    fn test_to_jacobian() {
        let p = Point3D {
            x: BigInt::from(2),
            y: BigInt::from(3),
            z: BigInt::zero(),
        };
        let expected = Point3D {
            x: BigInt::from(2),
            y: BigInt::from(3),
            z: BigInt::one(),
        };
        assert_eq!(to_jacobian(&p), expected);
    }

    #[test]
    fn test_from_jacobian() {
        let p = Point3D {
            x: BigInt::from(2),
            y: BigInt::from(3),
            z: BigInt::one(),
        };
        let prime = BigInt::from(5);
        let expected = Some(Point3D {
            x: BigInt::from(2),
            y: BigInt::from(3),
            z: BigInt::zero(),
        });
        assert_eq!(from_jacobian(&p, &prime), expected);
    }
    
    #[test]
    fn test_jacobian_double() {
        let p = Point3D {
            x: BigInt::from(2),
            y: BigInt::from(3),
            z: BigInt::one(),
        };
        let a = BigInt::zero();
        let prime = BigInt::from(5);
        let expected = Point3D {
            x: BigInt::zero(),
            y: BigInt::from(-4),
            z: BigInt::one(),
        };
        assert_eq!(jacobian_double(&p, &a, &prime), expected);
    }

    #[test]
    fn test_jacobian_add() {
        let p = Point3D {
            x: BigInt::from(2),
            y: BigInt::from(3),
            z: BigInt::one(),
        };
        let q = Point3D {
            x: BigInt::from(1),
            y: BigInt::from(4),
            z: BigInt::one(),
        };
        let a = BigInt::zero();
        let prime = BigInt::from(5);
        let expected = Point3D {
            x: BigInt::from(-2),
            y: BigInt::from(2),
            z: BigInt::from(-1),
        };
        assert_eq!(jacobian_add(&p, &q, &a, &prime), expected);
    }

    #[test]
    fn test_multiply() {
        let p = Point3D {
            x: BigInt::parse_bytes(b"55066263022277343669578718895168534326250603453777594175500187360389116729240", 10).unwrap(),
            y: BigInt::parse_bytes(b"32670510020758816978083085130507043184471273380659243275938904335757337482424", 10).unwrap(),
            z: BigInt::zero(),
        };
        let i = BigInt::parse_bytes(b"76650304483176495741675648870262264680257041494540363405951857559263604352053", 10).unwrap();
        let n = BigInt::parse_bytes(b"115792089237316195423570985008687907852837564279074904382605163141518161494337", 10).unwrap();
        let a = BigInt::zero();
        let prime = BigInt::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
        let expected = Some(Point3D {
            x: BigInt::parse_bytes(b"85217781944227650815758470769803916518073404692604958778490580619436728646316", 10).unwrap(),
            y: BigInt::parse_bytes(b"-52225341456763567064525879521783886427788861703590286785555970483835115400271", 10).unwrap(),
            z: BigInt::zero(),
        });
        assert_eq!(multiply(&p, &i, &n, &a, &prime), expected);
    }

    #[test]
    fn test_add() {
        let p = Point3D {
            x: BigInt::parse_bytes(b"31403115364582379550907050631875140702418979177549974706941498652441512470458", 10).unwrap(),
            y: BigInt::parse_bytes(b"101818303961377311447148617614805458780290001799451860481930108618473055802284", 10).unwrap(),
            z: BigInt::zero(),
        };
        let q = Point3D {
            x: BigInt::parse_bytes(b"101690386697888660822536733613325166154267525726772224824634387558104511424840", 10).unwrap(),
            y: BigInt::parse_bytes(b"-47036664861243869909569076480358479904318913594830847776653065859528326656316", 10).unwrap(),
            z: BigInt::zero(),
        };
        let a = BigInt::parse_bytes(b"115792089210356248762697446949407573530086143415290314195533631308867097853948", 10).unwrap();
        let prime = BigInt::parse_bytes(b"115792089210356248762697446949407573530086143415290314195533631308867097853951", 10).unwrap();
        let expected = Some(Point3D {
            x: BigInt::parse_bytes(b"7679932563960414347091205306595575529033945270189659289643076129390605281494", 10).unwrap(),
            y: BigInt::parse_bytes(b"-107375252532095138741597567516714532302943937430093290901277802845815571422141", 10).unwrap(),
            z: BigInt::zero(),
        });
        assert_eq!(add(&p, &q, &a, &prime), expected);
    }

    #[test]
    fn test_contains() {
        let p = Point3D {
            x: BigInt::parse_bytes(b"115106164243905984849100475305234630054675646194978645692811434710714363667279", 10).unwrap(),
            y: BigInt::parse_bytes(b"19706235080398884982913350654710526234719564240780022609690651720634760609570", 10).unwrap(),
            z: BigInt::zero(),
        };
        let a = BigInt::zero();
        let b = BigInt::from(7);
        let prime = BigInt::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
        assert!(contains(&p, &a, &b, &prime));
    }

    #[test]
    fn test_verify_secp256k1() {
        let message_hash = hex::decode("d94b9ba3e7dd18a7a265b4d619286c0615ccb24817bb6898578c160a0fec4baa").unwrap();
        let sig = EcdsaSignature {
            r: BigInt::parse_bytes(b"25620709521037740117758667172134018589525233359318772110869897469209888916545", 10).unwrap(),
            s: BigInt::parse_bytes(b"113898187235606387790617275461401926013993175009609646753506476585129921911557", 10).unwrap(),
        };
        let public_key = Point3D {
            x: BigInt::parse_bytes(b"115106164243905984849100475305234630054675646194978645692811434710714363667279", 10).unwrap(),
            y: BigInt::parse_bytes(b"19706235080398884982913350654710526234719564240780022609690651720634760609570", 10).unwrap(),
            z: BigInt::zero(),
        };
        let curve = secp256k1();
        assert!(verify(&message_hash, &sig, &public_key, &curve));
    }

    #[test]
    fn test_verify_secp256r1() {
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
        assert!(verify(&message_hash, &sig, &public_key, &curve));
    }

    #[test]
    fn test_invalid_signature() {
        let message_hash = hex::decode("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let sig = EcdsaSignature {
            r: BigInt::parse_bytes(b"1234567890123456789012345678901234567890123456789012345678901234567890123456", 10).unwrap(),
            s: BigInt::parse_bytes(b"9876543210987654321098765432109876543210987654321098765432109876543210987654", 10).unwrap(),
        };
        let public_key = Point3D {
            x: BigInt::parse_bytes(b"1234567890123456789012345678901234567890123456789012345678901234567890123456", 10).unwrap(),
            y: BigInt::parse_bytes(b"9876543210987654321098765432109876543210987654321098765432109876543210987654", 10).unwrap(),
            z: BigInt::zero(),
        };
        let curve = secp256r1();
        assert!(!verify(&message_hash, &sig, &public_key, &curve));
    }
   
}
