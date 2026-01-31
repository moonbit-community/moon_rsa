///|
pub suberror ArgumentError {
  ArgumentError(String)
}

///|
pub suberror FailedFindPrimeError {
  FailedFindPrimeError(String)
}

///|
pub fn RsaVersion::get_value(self : RsaVersion) -> Int {
  match self {
    RsaVersion::TWO_PRIME => 0
    RsaVersion::MULTI => 1
  }
}

///|
fn gcd(a : BigInt, b : BigInt) -> BigInt {
  if b == 0 {
    return a
  }
  gcd(b, a % b)
}

///|
fn get_random_32_bytes_seed() -> Bytes {
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
fn generate_probably_primes(
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
  // TODO: make sure the DRBG supports securityStrength. (NIST SP 800-90A Rev.1)
  let r = @random.Rand::chacha8(seed=get_random_32_bytes_seed())
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
test "generate_probably_primes" {
  let pairs = [
    (2048, BigInt::from_int(65537)),
    (3072, BigInt::from_int(65537)),
    (4096, BigInt::from_int(65537)),
  ]
  for pair in pairs {
    let (nlen, e) = pair
    let (p, q) = generate_probably_primes(nlen, e)
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
/// Generate RSA Key Pairs.
/// 
/// Parameters:
/// * `nlen` : The intended bit length of the modulus n.
/// * `e` : The public verification exponent.
/// 
/// Returns `(publicKey, privateKey)`
pub fn generate_key_pairs(
  nlen : Int,
  e : BigInt,
) -> (RsaPublicKey, RsaPrivateKey) raise Error {
  /// Extended Euclidean algorithm.
  fn ex_gcd(a : BigInt, b : BigInt) -> (BigInt, BigInt) {
    if b == 0 {
      (1, 0)
    } else {
      let (x1, y1) = ex_gcd(b, a % b)
      let x = y1
      let y = x1 - a / b * y1
      (x, y)
    }
  }

  /// Returns a^-1 mod m, which is the modular inverse of a modulo m.
  /// Assumes that gcd(a, m) = 1, so the inverse exists.
  fn inverse(a : BigInt, m : BigInt) {
    let (x, _) = ex_gcd(a, m)
    (x % m + m) % m
  }

  for {
    let (p, q) = generate_probably_primes(nlen, e)
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
/// RSA signature primitive (RSASP1) according to RFC 8017
fn rsasp1(n : BigInt, d : BigInt, m : BigInt) -> BigInt raise Error {
  if m < 0 || m >= n {
    raise ArgumentError("Message representative out of range")
  }
  // s = m^d mod n
  BigInt::pow(m, d, modulus=n)
}

///|
/// XOR two byte sequences of the same length
fn xor_bytes(a : Bytes, b : Bytes) -> Bytes raise Error {
  if a.length() != b.length() {
    raise ArgumentError("Byte sequences must have the same length")
  }
  let arr = FixedArray::make(a.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    arr[i] = a.at(i) ^ b.at(i)
  }
  Bytes::from_array(arr)
}

///|
/// MGF1 mask generation function according to RFC 8017
fn mgf1(
  seed : Bytes,
  mask_len : Int64,
  hash : (Bytes) -> FixedArray[Byte],
) -> Bytes raise Error {
  // Step 1: Check if mask length is valid
  let h_len = Int64::from_int(hash(Bytes::new(0)).length())
  if mask_len > (1L << 32) * h_len {
    raise ArgumentError("Mask too long")
  }

  // Step 2: Initialize output buffer as empty octet string
  let mut t = Bytes::new(0)

  // Step 3: Calculate required number of iterations
  let count = mask_len / h_len + 1
  let mut cur_len = 0L
  // Step 3: Process each counter value from 0 to count-1
  for counter = 0L; counter < count && cur_len < mask_len; counter = counter + 1 {
    // Convert counter to 4-byte octet string (I2OSP)
    let c = BigInt::from_int64(counter).to_octets(length=4)

    // Compute hash of (seed || c) and append to output buffer
    let hash_input = seed + c
    let h = hash(hash_input)
    let mut right = h_len.to_int()
    if cur_len + h_len > mask_len {
      right = (mask_len - cur_len).to_int()
    }
    t = t + Bytes::from_array(h[:right])
    cur_len = cur_len + h_len
  }
  // Step 4: Output leading mask_len octets of buffer
  t
}

///|
/// RSASSA-PSS-SIGN according to RFC 8017
/// 
/// Parameters:
/// * `k` : The RSA private key
/// * `message` : The message to be signed
/// 
/// Returns the signature
pub fn rsassa_pss_sign(k : RsaPrivateKey, message : Bytes) -> Bytes raise Error {
  // Use SHA-256 as the default hash function
  let hash = @crypto.sha256

  // Get the length of the modulus in bytes
  let modulus_len = (k.modulus.bit_length() + 7) / 8

  // Generate a random salt of length equal to the hash output length (32 bytes for SHA-256)
  let s_len = 32
  let salt = if s_len == 0 {
    Bytes::new(0)
  } else {
    let r = @random.Rand::new()
    r.bigint(s_len * 8).to_octets()
  }
  // Compute the hash of the message
  let h = hash(message)
  let h_len = h.length()

  // Check if the encoded message length is sufficient
  let em_len = modulus_len
  if em_len < h_len + s_len + 2 {
    raise ArgumentError("EM length too short for RSASSA-PSS-SIGN")
  }

  // Generate padding string PS consisting of emLen - sLen - hLen - 2 zeros
  let ps = Bytes::new(em_len - s_len - h_len - 2)

  // Concatenate PS, the octet 0x01, and the salt to form DB
  let db = ps + Bytes::from_array([b'\x01']) + salt

  // Compute the hash of M' = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 || H || salt
  let m_prime = Bytes::new(8) + Bytes::from_array(h) + salt
  let h_prime = hash(m_prime)

  // Apply MGF1 to H' to get a mask of length equal to DB length
  let mask_len = db.length().to_int64()
  let mask = mgf1(Bytes::from_array(h_prime), mask_len, hash)

  // XOR the mask with DB
  let masked_db = xor_bytes(db, mask)

  // Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB to zero
  let em_bits = 8 * em_len - k.modulus.bit_length() % 8
  let first_octet = masked_db.at(0)
  let adjusted_first_octet = first_octet & ((1 << (em_bits % 8)) - 1)
  let adjusted_db = Bytes::from_array([adjusted_first_octet]) +
    masked_db[1:].to_bytes()

  // Form the encoded message EM = DB || 0xBC || H'
  let em = adjusted_db +
    Bytes::from_array([b'\xBC']) +
    Bytes::from_array(h_prime)

  // Convert em to integer m
  let m = BigInt::from_octets(em)

  // Apply RSASP1 to get signature representative s
  let s = rsasp1(k.modulus, k.privateExponent, m)

  // Convert s to octet string signature
  s.to_octets(length=modulus_len)
}

///|
/// RSAEP public-key encryption primitive according to RFC 8017
fn rsaep_pub(n : BigInt, e : BigInt, m : BigInt) -> BigInt raise Error {
  if m < 0 || m >= n {
    raise ArgumentError("Message representative out of range")
  }
  // c = m^e mod n
  BigInt::pow(m, e, modulus=n)
}

///|
/// RSASSA-PSS-VERIFY according to RFC 8017
/// 
/// Parameters:
/// * `key` : The RSA public key
/// * `message` : The message to be verified
/// * `signature` : The signature to be verified
/// 
/// Returns true if the signature is valid, false otherwise
pub fn rsassa_pss_verify(
  key : RsaPublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool {
  try {
    // Use SHA-256 as the default hash function
    let hash = @crypto.sha256

    // Get the length of the modulus in bytes
    let modulus_len = (key.modulus.bit_length() + 7) / 8

    // Step 1: Check that the length of the signature is modulus_len
    if signature.length() != modulus_len {
      return false
    }

    // Step 2: Convert the signature to an integer m
    let s = BigInt::from_octets(signature)

    // Step 3: Apply RSAEP to recover the encoded message EM
    let m = rsaep_pub(key.modulus, key.publicExponent, s)

    // Step 4: Convert m to an octet string EM of length modulus_len
    let em = m.to_octets(length=modulus_len)

    // Step 5: Compute the hash of the message
    let h = hash(message)
    let h_len = h.length()

    // Step 6: Verify the encoded message EM
    let em_len = modulus_len

    // Check if the encoded message length is sufficient
    if em_len < h_len + 2 {
      return false
    }

    // Get the salt length (for SHA-256, it's 32 bytes)
    let s_len = h_len

    // Check if EM has the expected format
    if em_len < h_len + s_len + 2 {
      return false
    }

    // Split EM into DB and H'
    // EM = DB || 0xBC || H'
    let db_end = em_len - h_len - 1

    // Check if db_end is valid
    if db_end <= 0 {
      return false
    }
    let db = em[:db_end].to_bytes()

    // Check if DB length is correct
    if db.length() != db_end {
      return false
    }

    // Safely check the separator byte
    if db_end >= em.length() {
      return false
    }
    let separator = em.at(db_end)
    if separator != b'\xBC' {
      return false
    }

    // Extract H' part
    let h_prime_start = db_end + 1
    if h_prime_start >= em.length() {
      return false
    }
    let h_prime_part = em[h_prime_start:].to_bytes()

    // Check if H' length is correct
    if h_prime_part.length() != h_len {
      return false
    }

    // Compute the hash of M' = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 || H || salt
    // Step 7: Apply the MGF1 mask generation function to H'
    // Make sure h_prime_part is not empty before passing to MGF1
    if h_prime_part.length() == 0 {
      return false
    }
    let mask = mgf1(h_prime_part, (em_len - h_len - 1).to_int64(), hash)

    // Step 8: XOR the mask with DB
    let masked_db = xor_bytes(db, mask)

    // Step 9: Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB to zero
    let em_bits = 8 * em_len - key.modulus.bit_length() % 8
    let first_octet = masked_db.at(0)
    let adjusted_first_octet = first_octet & ((1 << (em_bits % 8)) - 1)
    let adjusted_db = Bytes::from_array([adjusted_first_octet]) +
      masked_db[1:].to_bytes()

    // Step 10: Verify padding and extract salt
    // Reset all bits in the leftmost octet that are outside of emBits
    let masked_db_prime = adjusted_db

    // Step 11: Verify that the leftmost emLen - hLen - sLen - 2 octets of DB' are zero
    let ps_len = em_len - h_len - s_len - 2

    // Verify PS (padding string) consists of zeros
    for i = 0; i < ps_len; i = i + 1 {
      if masked_db_prime.at(i) != 0 {
        return false
      }
    }

    // Verify the next octet is 0x01
    if masked_db_prime.at(ps_len) != b'\x01' {
      return false
    }

    // Extract salt with bounds checking
    let salt_start = ps_len + 1
    let salt_end = salt_start + s_len
    if salt_start < 0 || salt_end > masked_db_prime.length() {
      return false
    }
    let extracted_salt = masked_db_prime[salt_start:salt_end].to_bytes()

    // Verify extracted salt length is correct
    if extracted_salt.length() != s_len {
      return false
    }

    // Step 12: Compute M' = 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 || H || salt
    let m_prime = Bytes::new(8) + Bytes::from_array(h) + extracted_salt
    let computed_h_prime = hash(m_prime)

    // Step 13: Compare H' from the signature with the computed H'
    Bytes::from_array(computed_h_prime) == h_prime_part
  } catch {
    // If any error occurs during verification, return false
    _ => false
  }
}

///|
/// RSAES-OAEP-ENCRYPT according to RFC 8017
/// 
/// Parameters:
/// * `key` : The RSA public key
/// * `message` : The message to be encrypted
/// * `label` : Optional label (default is empty string)
/// 
/// Returns the encrypted message (ciphertext)
pub fn rsaes_oaep_encrypt(
  key : RsaPublicKey,
  message : Bytes,
  label : Bytes,
) -> Bytes raise Error {
  // Use SHA-256 as the default hash function
  let hash = @crypto.sha256

  // Get the length of the modulus in bytes
  let modulus_len = (key.modulus.bit_length() + 7) / 8

  // Get hash length (32 bytes for SHA-256)
  let h_len = hash(Bytes::new(0)).length()

  // Step 1a: Check message length
  let m_len = message.length()
  if m_len > modulus_len - 2 * h_len - 2 {
    raise ArgumentError("Message too long for RSAES-OAEP-ENCRYPT")
  }

  // Step 1b: Generate hash of label (empty label by default)
  let l_hash = hash(label)

  // Step 1c: Generate padding string PS consisting of modulus_len - m_len - 2*h_len - 2 zeros
  let ps_len = modulus_len - m_len - 2 * h_len - 2
  let ps = Bytes::new(ps_len)

  // Step 1d: Concatenate l_hash, PS, 0x01, and message to form data block DB
  let db = Bytes::from_array(l_hash) +
    ps +
    Bytes::from_array([b'\x01']) +
    message

  // Step 1e: Generate random seed of length h_len
  let r = @random.Rand::new()
  let seed = r.bigint(h_len * 8).to_octets()

  // Step 1f: Apply MGF1 to seed to get db_mask of length modulus_len - h_len - 1
  let db_mask = mgf1(seed, (modulus_len - h_len - 1).to_int64(), hash)

  // Step 1g: XOR db_mask with DB to get masked_db
  let masked_db = xor_bytes(db, db_mask)

  // Step 1h: Apply MGF1 to masked_db to get seed_mask of length h_len
  let seed_mask = mgf1(masked_db, h_len.to_int64(), hash)

  // Step 1i: XOR seed_mask with seed to get masked_seed
  let masked_seed = xor_bytes(seed, seed_mask)

  // Step 1j: Concatenate 0x00, masked_seed, and masked_db to form encoded message EM
  let em = Bytes::from_array([b'\x00']) + masked_seed + masked_db

  // Step 2: Convert EM to integer m
  let m = BigInt::from_octets(em)

  // Step 3: Apply RSAEP to get ciphertext representative c
  let c = rsaep_pub(key.modulus, key.publicExponent, m)

  // Step 4: Convert c to octet string C
  c.to_octets(length=modulus_len)
}

///|
/// Generate random non-zero bytes for PKCS#1 v1.5 padding
fn generate_non_zero_random_bytes(len : Int) -> Bytes {
  let r = @random.Rand::new()
  let arr = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    // Generate random byte in range 1-255 (non-zero)
    arr[i] = (r.uint() % 255 + 1).to_byte()
  }
  Bytes::from_array(arr)
}

///|
/// RSAES-PKCS1-v1_5-ENCRYPT according to RFC 8017 Section 7.2.1
///
/// Parameters:
/// * `key` : The RSA public key
/// * `message` : The message to be encrypted
///
/// Returns the encrypted message (ciphertext)
pub fn rsaes_pkcs1_v1_5_encrypt(
  key : RsaPublicKey,
  message : Bytes,
) -> Bytes raise Error {
  // Step 1: Get the length of the modulus in bytes
  let k = (key.modulus.bit_length() + 7) / 8

  // Step 2: Check message length
  let m_len = message.length()
  if m_len > k - 11 {
    raise ArgumentError("Message too long for RSAES-PKCS1-v1_5")
  }

  // Step 3: Generate padding string PS of length k - mLen - 3
  // PS consists of random non-zero bytes
  let ps_len = k - m_len - 3
  let ps = generate_non_zero_random_bytes(ps_len)

  // Step 4: Form encoded message EM = 0x00 || 0x02 || PS || 0x00 || M
  let em = Bytes::from_array([b'\x00', b'\x02']) +
    ps +
    Bytes::from_array([b'\x00']) +
    message

  // Step 5: Convert EM to integer m
  let m = BigInt::from_octets(em)

  // Step 6: Apply RSAEP to get ciphertext representative c
  let c = rsaep_pub(key.modulus, key.publicExponent, m)

  // Step 7: Convert c to ciphertext C of length k
  c.to_octets(length=k)
}

///|
/// RSAES-PKCS1-v1_5-DECRYPT according to RFC 8017 Section 7.2.2
///
/// Parameters:
/// * `key` : The RSA private key
/// * `ciphertext` : The ciphertext to be decrypted
///
/// Returns the decrypted message
pub fn rsaes_pkcs1_v1_5_decrypt(
  key : RsaPrivateKey,
  ciphertext : Bytes,
) -> Bytes raise Error {
  // Step 1: Get the length of the modulus in bytes
  let k = (key.modulus.bit_length() + 7) / 8

  // Step 2: Check ciphertext length
  if ciphertext.length() != k {
    raise ArgumentError("Decryption error: ciphertext length incorrect")
  }

  // Step 3: Convert ciphertext to integer c
  let c = BigInt::from_octets(ciphertext)

  // Step 4: Apply RSADP to recover the encoded message
  let m = rsasp1(key.modulus, key.privateExponent, c)

  // Step 5: Convert m to encoded message EM of length k
  let em = m.to_octets(length=k)

  // Step 6: Verify EM format: EM = 0x00 || 0x02 || PS || 0x00 || M
  if em.length() < 11 {
    raise ArgumentError("Decryption error: invalid EM format")
  }
  if em.at(0) != b'\x00' || em.at(1) != b'\x02' {
    raise ArgumentError("Decryption error: invalid EM format")
  }

  // Step 7: Find the separator 0x00 byte (must be at index >= 10 for PS >= 8)
  let mut separator_index = -1
  for i = 2; i < em.length(); i = i + 1 {
    if em.at(i) == b'\x00' {
      separator_index = i
      break
    }
  }

  // Step 8: Verify separator was found and PS length >= 8
  if separator_index < 10 {
    raise ArgumentError("Decryption error: invalid padding")
  }

  // Step 9: Verify all PS bytes are non-zero
  for i = 2; i < separator_index; i = i + 1 {
    if em.at(i) == b'\x00' {
      raise ArgumentError("Decryption error: invalid padding")
    }
  }

  // Step 10: Extract and return the message M
  let message_start = separator_index + 1
  if message_start >= em.length() {
    // Empty message case
    return Bytes::new(0)
  }
  em[message_start:].to_bytes()
}

///|
/// DER-encoded DigestInfo prefix for SHA-256 according to RFC 8017 Section 9.2 Note 1
/// DigestInfo ::= SEQUENCE { digestAlgorithm AlgorithmIdentifier, digest OCTET STRING }
/// For SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
fn sha256_digest_info_prefix() -> Bytes {
  Bytes::from_array([
    b'\x30', b'\x31', b'\x30', b'\x0d', b'\x06', b'\x09', b'\x60', b'\x86', b'\x48',
    b'\x01', b'\x65', b'\x03', b'\x04', b'\x02', b'\x01', b'\x05', b'\x00', b'\x04',
    b'\x20',
  ])
}

///|
/// EMSA-PKCS1-v1_5-ENCODE according to RFC 8017 Section 9.2
///
/// Parameters:
/// * `message` : The message to be encoded
/// * `em_len` : The intended length of the encoded message
///
/// Returns the encoded message EM
fn emsa_pkcs1_v1_5_encode(message : Bytes, em_len : Int) -> Bytes raise Error {
  // Step 1: Hash the message using SHA-256
  let hash = @crypto.sha256
  let h = hash(message)

  // Step 2: Encode the DigestInfo value T
  let t = sha256_digest_info_prefix() + Bytes::from_array(h)
  let t_len = t.length()

  // Step 3: Check that emLen >= tLen + 11
  if em_len < t_len + 11 {
    raise ArgumentError("Intended encoded message length too short")
  }

  // Step 4: Generate padding string PS of 0xFF bytes
  let ps_len = em_len - t_len - 3
  let ps_arr = FixedArray::make(ps_len, b'\xFF')
  let ps = Bytes::from_array(ps_arr)

  // Step 5: Form EM = 0x00 || 0x01 || PS || 0x00 || T
  Bytes::from_array([b'\x00', b'\x01']) + ps + Bytes::from_array([b'\x00']) + t
}

///|
/// RSASSA-PKCS1-v1_5-SIGN according to RFC 8017 Section 8.2.1
///
/// Parameters:
/// * `key` : The RSA private key
/// * `message` : The message to be signed
///
/// Returns the signature
pub fn rsassa_pkcs1_v1_5_sign(
  key : RsaPrivateKey,
  message : Bytes,
) -> Bytes raise Error {
  // Step 1: Get the length of the modulus in bytes
  let k = (key.modulus.bit_length() + 7) / 8

  // Step 2: EMSA-PKCS1-v1_5 encoding
  let em = emsa_pkcs1_v1_5_encode(message, k)

  // Step 3: Convert EM to integer m
  let m = BigInt::from_octets(em)

  // Step 4: Apply RSASP1 to get signature representative s
  let s = rsasp1(key.modulus, key.privateExponent, m)

  // Step 5: Convert s to signature S of length k
  s.to_octets(length=k)
}

///|
/// RSASSA-PKCS1-v1_5-VERIFY according to RFC 8017 Section 8.2.2
///
/// Parameters:
/// * `key` : The RSA public key
/// * `message` : The message to be verified
/// * `signature` : The signature to be verified
///
/// Returns true if the signature is valid, false otherwise
pub fn rsassa_pkcs1_v1_5_verify(
  key : RsaPublicKey,
  message : Bytes,
  signature : Bytes,
) -> Bool {
  try {
    // Step 1: Get the length of the modulus in bytes
    let k = (key.modulus.bit_length() + 7) / 8

    // Step 2: Check that the length of the signature is k
    if signature.length() != k {
      return false
    }

    // Step 3: Convert the signature to an integer s
    let s = BigInt::from_octets(signature)

    // Step 4: Apply RSAVP1 to recover the encoded message
    let m = rsaep_pub(key.modulus, key.publicExponent, s)

    // Step 5: Convert m to encoded message EM of length k
    let em = m.to_octets(length=k)

    // Step 6: EMSA-PKCS1-v1_5 encode the message to get EM'
    let em_prime = emsa_pkcs1_v1_5_encode(message, k)

    // Step 7: Compare EM and EM'
    em == em_prime
  } catch {
    _ => false
  }
}

///|
/// RSAES-OAEP-DECRYPT according to RFC 8017
/// 
/// Parameters:
/// * `key` : The RSA private key
/// * `ciphertext` : The ciphertext to be decrypted
/// * `label` : Optional label (default is empty string)
/// 
/// Returns the decrypted message
pub fn rsaes_oaep_decrypt(
  key : RsaPrivateKey,
  ciphertext : Bytes,
  label : Bytes,
) -> Bytes raise Error {
  // Use SHA-256 as the default hash function
  let hash = @crypto.sha256

  // Get the length of the modulus in bytes
  let modulus_len = (key.modulus.bit_length() + 7) / 8

  // Get hash length (32 bytes for SHA-256)
  let h_len = hash(Bytes::new(0)).length()

  // Step 1: Check ciphertext length
  if ciphertext.length() != modulus_len {
    raise ArgumentError("Decryption error: ciphertext length incorrect")
  }

  // Step 2: Convert ciphertext to integer c
  let c = BigInt::from_octets(ciphertext)

  // Step 3: Apply RSADP to recover the encoded message EM
  let m = rsasp1(key.modulus, key.privateExponent, c)

  // Step 4: Convert m to octet string EM of length modulus_len
  let em = m.to_octets(length=modulus_len)

  // Step 5: Check that EM starts with 0x00
  if em.length() < 1 || em.at(0) != b'\x00' {
    raise ArgumentError("Decryption error: EM does not start with 0x00")
  }

  // Step 5a: Split EM into masked_seed and masked_db
  // EM = 0x00 || masked_seed || masked_db
  let masked_seed = em[1:h_len + 1].to_bytes()
  let masked_db = em[h_len + 1:].to_bytes()

  // Step 5b: Apply MGF1 to masked_db to get seed_mask of length h_len
  let seed_mask = mgf1(masked_db, h_len.to_int64(), hash)

  // Step 5c: XOR seed_mask with masked_seed to recover seed
  let seed = xor_bytes(masked_seed, seed_mask)

  // Step 5d: Apply MGF1 to seed to get db_mask of length modulus_len - h_len - 1
  let db_mask = mgf1(seed, (modulus_len - h_len - 1).to_int64(), hash)

  // Step 5e: XOR db_mask with masked_db to recover DB
  let db = xor_bytes(masked_db, db_mask)

  // Step 5f: Generate hash of label (empty label by default)
  let l_hash = hash(label)

  // Step 5g: Check that the leftmost h_len octets of DB equal l_hash
  let db_l_hash = db[0:h_len].to_bytes()
  if db_l_hash != Bytes::from_array(l_hash) {
    raise ArgumentError("Decryption error: label hash mismatch")
  }

  // Step 5h: Find the index of the first 0x01 byte after the padding string
  let mut i = h_len
  let mut found = false
  while i < db.length() && !found {
    if db.at(i) == b'\x01' {
      found = true
    } else if db.at(i) != b'\x00' {
      raise ArgumentError("Decryption error: invalid padding")
    }
    i = i + 1
  }
  if !found {
    raise ArgumentError("Decryption error: no 0x01 separator found")
  }

  // Step 5i: Extract the message M
  let message_start = i
  if message_start >= db.length() {
    raise ArgumentError("Decryption error: message start out of bounds")
  }
  let message = db[message_start:].to_bytes()

  // Step 6: Return the message
  message
}
