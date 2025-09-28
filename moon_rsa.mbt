///|
priv suberror ArgumentError String

///|
priv suberror FailedFindPrimeError String

///|
fn gcd(a : BigInt, b : BigInt) -> BigInt {
  if b == 0 {
    return a
  }
  gcd(b, a % b)
}

///|
fn getRandom32BytesSeed() -> Bytes {
  let time = @env.now()
  time.to_be_bytes() +
  time.to_le_bytes() +
  time.to_be_bytes() +
  time.to_le_bytes()
}

///|
fn abs(a : BigInt) -> BigInt {
  if a < 0 {
    -a
  } else {
    a
  }
}

///|
/// Generate two probably primes(`p` and `q`) used for RSA algorithm according to FIPS 186-5 A.1.3
/// 
/// Parameters:
/// 
/// * `nlen` : The intended bit length of the modulus n.
/// * `e` : The public verification exponent.
/// 
/// Returns `(p, q)`
fn generateProbablyPrimes(
  nlen : Int,
  e : BigInt,
) -> (BigInt, BigInt) raise Error {
  if nlen < 2048 {
    raise ArgumentError("nlen must not less than 2048")
  }
  let twoPow256 = BigInt::from_hex(
    "10000000000000000000000000000000000000000000000000000000000000000",
  )
  if e <= BigInt::from_int(65536) || e >= twoPow256 || e % 2 == 0 {
    raise ArgumentError("e must satisfy: 2^16 < e < 2^256 and e is odd.")
  }
  // Set securityStrength according to NIST SP 800-57 PART 1 REV.5 5.6.1.1
  // let mut securityStrength = 0
  // if nlen >= 15360 {
  //   securityStrength = 256
  // } else if nlen >= 7680 {
  //   securityStrength = 192
  // } else if nlen >= 3072 {
  //   securityStrength = 128
  // } else {
  //   securityStrength = 112
  // }
  // TODO: make sure the DRBG supports securityStrength. (NIST SP 800-90A Rev.1)
  let r = @random.Rand::chacha8(seed=getRandom32BytesSeed())
  let mut p = BigInt::from_int(0)
  // Generate p:
  for i = 0; ; i = i + 1 {
    p = r.bigint(nlen / 2)
    if p % 2 == 0 {
      p = p + 1
    }
    if p * p < BigInt::pow(2, BigInt::from_int(nlen - 1)) {
      continue
    }
    if gcd(p - 1, e) == 1 {
      // Make sure iterations satisfy FIPS 186-5 Table B.1, which is:
      // For more than or equal to 2048 bits with a error probability = 2^-144,
      // otherwise error probability = 2^-128
      let mut iterations = 64
      if p.bit_length() >= 2048 {
        iterations = 72
      }
      if @math.is_probable_prime(p, r, iters=iterations) {
        break
      }
    }
    if i + 1 >= 5 * nlen {
      raise FailedFindPrimeError(
        "After 5 * nlen attemps, failed to find a prime number.",
      )
    }
  }
  // Generate q:
  let mut q = BigInt::from_int(0)
  for i = 0; ; i = i + 1 {
    q = r.bigint(nlen / 2)
    if q % 2 == 0 {
      q = q + 1
    }
    if q * q < BigInt::pow(2, BigInt::from_int(nlen - 1)) {
      continue
    }
    if abs(p - q) <= BigInt::pow(2, BigInt::from_int(nlen / 2 - 100)) {
      continue
    }
    if gcd(q - 1, e) == 1 {
      // Make sure iterations satisfy FIPS 186-5 Table B.1, which is:
      // For more than or equal to 2048 bits with a error probability = 2^-144,
      // otherwise error probability = 2^-128
      let mut iterations = 64
      if q.bit_length() >= 2048 {
        iterations = 72
      }
      if @math.is_probable_prime(q, r, iters=iterations) {
        break
      }
    }
    if i + 1 >= 5 * nlen {
      raise FailedFindPrimeError(
        "After 5 * nlen attemps, failed to find a prime number.",
      )
    }
  }
  (p, q)
}

///|
/// Test if (p, q) satisfy with FIPS 186-5 A.1.1
test "generateProbablyPrimes" {
  let pairs = [
    (2048, BigInt::from_int(65537)),
    (3072, BigInt::from_int(65537)),
    (4096, BigInt::from_int(65537)),
  ]
  for pair in pairs {
    let (nlen, e) = pair
    let (p, q) = generateProbablyPrimes(nlen, e)
    inspect(gcd(p, e), content="1")
    inspect(gcd(q, e), content="1")
    inspect(p * p >= BigInt::pow(2, BigInt::from_int(nlen - 1)), content="true")
    inspect(p <= BigInt::pow(2, BigInt::from_int(nlen / 2)) - 1, content="true")
    inspect(q * q >= BigInt::pow(2, BigInt::from_int(nlen - 1)), content="true")
    inspect(q <= BigInt::pow(2, BigInt::from_int(nlen / 2)) - 1, content="true")
    inspect(
      abs(p - q) > BigInt::pow(2, BigInt::from_int(nlen / 2 - 100)),
      content="true",
    )
  }
}

///|
fn lcm(a : BigInt, b : BigInt) -> BigInt {
  a * b / gcd(a, b)
}

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
pub fn RsaVersion::getValue(self : RsaVersion) -> Int {
  match self {
    RsaVersion::TWO_PRIME => 0
    RsaVersion::MULTI => 1
  }
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

///|
/// Generate RSA Key Pairs.
/// 
/// Parameters:
/// * `nlen` : The intended bit length of the modulus n.
/// * `e` : The public verification exponent.
/// 
/// Returns `(publicKey, privateKey)`
pub fn generateKeyPairs(
  nlen : Int,
  e : BigInt,
) -> (RsaPublicKey, RsaPrivateKey) raise Error {
  /// Extended Euclidean algorithm.
  fn exGcd(a : BigInt, b : BigInt) -> (BigInt, BigInt) {
    if b == 0 {
      (1, 0)
    } else {
      let (x1, y1) = exGcd(b, a % b)
      let x = y1
      let y = x1 - a / b * y1
      (x, y)
    }
  }

  /// Returns a^-1 mod m, which is the modular inverse of a modulo m.
  /// Assumes that gcd(a, m) = 1, so the inverse exists.
  fn inverse(a : BigInt, m : BigInt) {
    let (x, _) = exGcd(a, m)
    (x % m + m) % m
  }

  for {
    let (p, q) = generateProbablyPrimes(nlen, e)
    let d = inverse(e, lcm(p - 1, q - 1))
    if d > BigInt::pow(2, BigInt::from_int(nlen / 2)) {
      let n = p * q
      let publicKey = RsaPublicKey::{ modulus: n, publicExponent: e }
      let privateKey = RsaPrivateKey::{
        version: RsaVersion::TWO_PRIME,
        modulus: n,
        publicExponent: e,
        privateExponent: d,
        prime1: p,
        prime2: q,
        exponent1: d % (p - 1),
        exponent2: d % (q - 1),
        coefficient: inverse(q, p),
        otherPrimeInfos: [],
      }
      return (publicKey, privateKey)
    }
  }
}

///|
/// Hash algorithm for PSS encoding
pub(all) enum HashAlgorithm {
  SHA1
  SHA224
  SHA256
}

///|
/// PSS encoding parameters according to RFC 8017
pub struct PssParams {
  hashAlg : HashAlgorithm
  mgf : HashAlgorithm
  saltLen : Int
}

///|
/// Default PSS parameters for different hash algorithms
pub fn PssParams::default(hashAlg : HashAlgorithm) -> PssParams {
  match hashAlg {
    HashAlgorithm::SHA1 =>
      PssParams::{
        hashAlg: HashAlgorithm::SHA1,
        mgf: HashAlgorithm::SHA1,
        saltLen: 20,
      }
    HashAlgorithm::SHA224 =>
      PssParams::{
        hashAlg: HashAlgorithm::SHA224,
        mgf: HashAlgorithm::SHA224,
        saltLen: 28,
      }
    HashAlgorithm::SHA256 =>
      PssParams::{
        hashAlg: HashAlgorithm::SHA256,
        mgf: HashAlgorithm::SHA256,
        saltLen: 32,
      }
  }
}

///|
/// Get hash output length in bytes
pub fn HashAlgorithm::outputLen(self : HashAlgorithm) -> Int {
  match self {
    HashAlgorithm::SHA1 => 20
    HashAlgorithm::SHA224 => 28
    HashAlgorithm::SHA256 => 32
  }
}

///|
/// Hash a message using the specified algorithm
fn hashMessage(msg : Bytes, alg : HashAlgorithm) -> Bytes {
  match alg {
    HashAlgorithm::SHA1 => @bytes.of(@crypto.sha1(msg))
    HashAlgorithm::SHA224 => @bytes.of(@crypto.sha224(msg))
    HashAlgorithm::SHA256 => @bytes.of(@crypto.sha256(msg))
  }
}

///|
/// MGF1 (Mask Generation Function 1) according to RFC 8017 B.2.1
fn mgf1(mgfSeed : Bytes, maskLen : Int, hashAlg : HashAlgorithm) -> Bytes raise Error {
  let hLen = hashAlg.outputLen()
  if maskLen > ((2^32) - 1) * hLen {
    raise ArgumentError("maskLen too large for MGF1")
  }
  
  let mut t = Bytes::new(0)
  let mut counter = 0
  
  while t.length() < maskLen {
    let c = counter.to_be_bytes()
    let t_i = hashMessage(mgfSeed + c, hashAlg)
    t = t + t_i
    counter = counter + 1
  }
  
  Bytes::from_iter(t[0:maskLen].iter())
}

///|
/// EMSA-PSS-ENCODE according to RFC 8017 9.1.1
fn emsaPssEncode(
  mHash : Bytes,
  emBits : Int,
  params : PssParams,
) -> Bytes raise Error {
  let hLen = params.hashAlg.outputLen()
  let sLen = params.saltLen
  if mHash.length() != hLen {
    raise ArgumentError("mHash length must equal hash output length")
  }
  if emBits < hLen + sLen + 2 {
    raise ArgumentError("emBits too small")
  }
  let emLen = (emBits + 7) / 8

  // Generate random salt
  let r = @random.Rand::chacha8(seed=getRandom32BytesSeed())
  let saltBigInt = r.bigint(sLen * 8)
  let salt = saltBigInt.to_octets()

  // M' = 0x0000000000000000 || mHash || salt
  let m_prime = Bytes::new(8) + mHash + salt

  // H = Hash(M')
  let h = hashMessage(m_prime, params.hashAlg)

  // Generate DB
  let psLen = emLen - sLen - hLen - 1
  let db = Bytes::new(psLen) + @bytes.from_array([b'\x01']) + salt

  // Generate dbMask
  let dbMask = mgf1(h, emLen - hLen - 1, params.mgf)

  // maskedDB = DB XOR dbMask
  let mut maskedDB = Bytes::new(0)
  for i = 0; i < db.length(); i = i + 1 {
    maskedDB = maskedDB + @bytes.from_array([b'\x00' + (db[i] ^ dbMask[i])])
  }

  // Set the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB to zero
  let leftmostBits = (8 * emLen - emBits) % 8
  if leftmostBits > 0 {
    let mask = b'\xff' >> leftmostBits
    let firstByte = b'\x00' + (maskedDB[0] & mask)
    maskedDB = @bytes.from_array([firstByte]) + @bytes.from_iter(maskedDB[1:maskedDB.length()].iter())
  }

  // EM = maskedDB || H || 0xbc
  maskedDB + h + @bytes.from_array([b'\xbc'])
}

///|
/// EMSA-PSS-VERIFY according to RFC 8017 9.1.2
fn emsaPssVerify(
  mHash : Bytes,
  em : Bytes,
  emBits : Int,
  params : PssParams,
) -> Bool raise Error {
  let hLen = params.hashAlg.outputLen()
  let sLen = params.saltLen

  if mHash.length() != hLen {
    raise ArgumentError("mHash length must equal hash output length")
  }

  if emBits < hLen + sLen + 2 {
    return false
  }

  let emLen = (emBits + 7) / 8

  if em.length() != emLen {
    return false
  }

  // Check rightmost octet
  if em[em.length() - 1] != 0xbc {
    return false
  }

  // Extract maskedDB and H
  let maskedDB = Bytes::from_iter(em[0:emLen - hLen - 1].iter())
  let h = Bytes::from_iter(em[emLen - hLen - 1:emLen - 1].iter())

  // Check that the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are zero
  let leftmostBits = (8 * emLen - emBits) % 8
  if leftmostBits > 0 {
    let mask = b'\xff' << (8 - leftmostBits)
    if (maskedDB[0] & mask) != 0 {
      return false
    }
  }

  // Generate dbMask
  let dbMask = mgf1(h, emLen - hLen - 1, params.mgf)

  // DB = maskedDB XOR dbMask
  let mut db = Bytes::new(0)
  for i = 0; i < maskedDB.length(); i = i + 1 {
    db = db + @bytes.from_array([b'\x00' + (maskedDB[i] ^ dbMask[i])])
  }

  // Check that the leftmost 8emLen - emBits bits of DB are zero
  let psLen = emLen - sLen - hLen - 1
  for i = 0; i < psLen; i = i + 1 {
    if db[i] != 0 {
      return false
    }
  }

  if db[psLen] != 0x01 {
    return false
  }

  // Extract salt
  let salt = Bytes::from_iter(db[psLen + 1:db.length()].iter())

  // M' = 0x0000000000000000 || mHash || salt
  let m_prime = Bytes::new(8) + mHash + salt

  // H' = Hash(M')
  let h_prime = hashMessage(m_prime, params.hashAlg)

  // Compare H and H'
  h == h_prime
}

///|
/// RSASSA-PSS-SIGN according to RFC 8017 8.1.1
pub fn rsassaPssSign(
  m : Bytes,
  privateKey : RsaPrivateKey,
  params : PssParams,
) -> BigInt raise Error {
  let k = (privateKey.modulus.bit_length() + 7) / 8
  let emBits = privateKey.modulus.bit_length() - 1

  // Hash the message
  let mHash = hashMessage(m, params.hashAlg)

  // Encode the message
  let em = emsaPssEncode(mHash, emBits, params)

  // Convert EM to integer
  let m_int = BigInt::from_octets(em)

  // Apply RSASP1
  let s = rsasp1(m_int, privateKey)
  s
}

///|
/// RSASSA-PSS-VERIFY according to RFC 8017 8.2.2
pub fn rsassaPssVerify(
  m : Bytes,
  s : BigInt,
  publicKey : RsaPublicKey,
  params : PssParams,
) -> Bool raise Error {
  let k = (publicKey.modulus.bit_length() + 7) / 8
  let emBits = publicKey.modulus.bit_length() - 1

  // Apply RSAVP1
  let m_int = rsavp1(s, publicKey)

  // Convert to bytes
  let em = m_int.to_octets()

  // Hash the message
  let mHash = hashMessage(m, params.hashAlg)

  // Verify the encoding
  emsaPssVerify(mHash, em, emBits, params)
}

///|
/// RSASP1 according to RFC 8017 5.2.1
fn rsasp1(m : BigInt, privateKey : RsaPrivateKey) -> BigInt raise Error {
  if m < 0 || m >= privateKey.modulus {
    raise ArgumentError("message representative out of range")
  }

  // Use Chinese Remainder Theorem for efficiency
  let s1 = m.pow(privateKey.exponent1, modulus=privateKey.prime1)
  let s2 = m.pow(privateKey.exponent2, modulus=privateKey.prime2)

  // s = s2 + q * ((s1 - s2) * coefficient mod p)
  let h = (s1 - s2) * privateKey.coefficient % privateKey.prime1
  let s = s2 + privateKey.prime2 * h
  s
}

///|
/// RSAVP1 according to RFC 8017 5.2.2
fn rsavp1(s : BigInt, publicKey : RsaPublicKey) -> BigInt raise Error {
  if s < 0 || s >= publicKey.modulus {
    raise ArgumentError("signature representative out of range")
  }
  s.pow(publicKey.publicExponent, modulus=publicKey.modulus)
}

