///|
/// RSA Public Key according to RFC 8017 PICS #1 v2.2
/// 
/// Fields:
/// * `modulus` : The RSA modulus n.
/// * `publicExponent` : the RSA public exponent e.
pub struct RsaPublicKey {
  modulus : BigInt
  publicExponent : BigInt
}

///|
/// RSA Version according to RFC 8017 PICS #1 v2.2 
pub enum RsaVersion {
  TWO_PRIME
  MULTI
}

///|
/// Other Prime Info according to RFC 8017 PICS #1 v2.2
/// 
/// Fields:
/// * `prime` : A prime factor r_i of n, where i >= 3.
/// * `exponent` : d_i = d mod (r_i - 1).
/// * `coefficient` : The CRT coefficient t_i = (r_1 * r_2 * ... * r_(i-1))^(-1) mod r_i.
pub struct OtherPrimeInfo {
  prime : BigInt
  exponent : BigInt
  coefficient : BigInt
}

///|
/// RSA Private Key according to RFC 8017 PICS #1 v2.2
/// 
/// TODO:
/// * Note: It is important to protect the RSA private key against both
///   disclosure and modification.  Techniques for such protection are
///   outside the scope of RFC 8017 PICS #1 v2.2. Methods for storing and
///   distributing private keys and other cryptographic data are described
///   in PKCS #12 and #15.
/// 
/// Fields:
/// * `modulus` : The RSA modulus n.
/// * `publicExponent` : The RSA public exponent e.
/// * `privateExponent` : The RSA private exponent d.
/// * `prime1` : The prime factor p of n.
/// * `prime2` : The prime factor q of n.
/// * `exponent1` : d mod (p - 1).
/// * `exponent2` : d mod (q - 1).
/// * `coefficient` : The CRT coefficient q^(-1) mod p.
/// * `otherPrimeInfos` : It contains the information for the additional primes
///   r_3, ..., r_u, in order. It SHALL be omitted if version is 0 and
///   SHALL contain at least one instance of OtherPrimeInfo if version
///   is 1.
pub struct RsaPrivateKey {
  version : RsaVersion
  modulus : BigInt
  publicExponent : BigInt
  privateExponent : BigInt
  prime1 : BigInt
  prime2 : BigInt
  exponent1 : BigInt
  exponent2 : BigInt
  coefficient : BigInt
  otherPrimeInfos : FixedArray[OtherPrimeInfo]
}
