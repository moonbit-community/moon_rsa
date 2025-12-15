///|
test "generate_key_pairs" {
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)
  inspect(publicKey.modulus.bit_length(), content="2048")
  inspect(privateKey.modulus.bit_length(), content="2048")
}

///|
test "rsassa_pss_sign" {
  // Generate RSA key pair
  let (_, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])

  // Generate signature
  let signature = @rsa.rsassa_pss_sign(privateKey, message)

  // Verify signature length matches modulus length
  let modulus_len = (privateKey.modulus.bit_length() + 7) / 8
  inspect(signature.length(), content=modulus_len.to_string())

  // Verify signature is not empty
  inspect(signature.length() > 0, content="true")
}

///|
test "rsassa_pss_verify_valid_signature" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])

  // Generate signature
  let signature = @rsa.rsassa_pss_sign(privateKey, message)

  // Verify signature
  let is_valid = @rsa.rsassa_pss_verify(publicKey, message, signature)

  // Confirm verification passes
  inspect(is_valid, content="true")
}

///|
test "rsassa_pss_verify_invalid_signatures" {
  // Generate two different RSA key pairs
  let (publicKey1, privateKey1) = @rsa.generate_key_pairs(2048, 65537)
  let (publicKey2, _) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test messages
  let original_message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])
  let modified_message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o', b'!'])

  // Generate signature
  let original_signature = @rsa.rsassa_pss_sign(privateKey1, original_message)

  // Test 1: Verify tampered message - should fail
  let invalid1 = @rsa.rsassa_pss_verify(
    publicKey1, modified_message, original_signature,
  )
  inspect(invalid1, content="false")

  // Test 2: Verify tampered signature - should fail
  // Tamper signature by modifying first byte
  if original_signature.length() > 0 {
    let mut corrupted_signature = Bytes::from_array(
      original_signature.to_array(),
    )
    let first_byte = corrupted_signature.at(0)
    corrupted_signature = Bytes::from_array([first_byte ^ 0xFF]) +
      corrupted_signature[1:].to_bytes()
    let invalid2 = @rsa.rsassa_pss_verify(
      publicKey1, original_message, corrupted_signature,
    )
    inspect(invalid2, content="false")
  }

  // Test 3: Use wrong public key - should fail
  let invalid3 = @rsa.rsassa_pss_verify(
    publicKey2, original_message, original_signature,
  )
  inspect(invalid3, content="false")
}
