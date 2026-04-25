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

///|
test "rsaes_oaep_encrypt_decrypt" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([
    b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r', b'l', b'd',
  ])

  // Encrypt message with empty label
  let label = Bytes::new(0)
  let ciphertext = @rsa.rsaes_oaep_encrypt(publicKey, message, label)

  // Verify ciphertext length matches modulus length
  let modulus_len = (publicKey.modulus.bit_length() + 7) / 8
  inspect(ciphertext.length(), content=modulus_len.to_string())

  // Decrypt ciphertext
  let decrypted_message = @rsa.rsaes_oaep_decrypt(privateKey, ciphertext, label)

  // Verify decrypted message matches original message
  inspect(decrypted_message == message, content="true")
}

///|
test "rsaes_oaep_encrypt_decrypt_with_label" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([
    b'T', b'e', b's', b't', b' ', b'M', b'e', b's', b's', b'a', b'g', b'e',
  ])

  // Prepare label
  let label = Bytes::from_array([b'M', b'y', b'L', b'a', b'b', b'e', b'l'])

  // Encrypt message with label
  let ciphertext = @rsa.rsaes_oaep_encrypt(publicKey, message, label)

  // Decrypt ciphertext with same label
  let decrypted_message = @rsa.rsaes_oaep_decrypt(privateKey, ciphertext, label)

  // Verify decrypted message matches original message
  inspect(decrypted_message == message, content="true")
}

///|
test "rsaes_oaep_decrypt_with_wrong_label" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'S', b'e', b'c', b'r', b'e', b't'])

  // Encrypt with one label
  let label1 = Bytes::from_array([b'L', b'a', b'b', b'e', b'l', b'1'])
  let ciphertext = @rsa.rsaes_oaep_encrypt(publicKey, message, label1)

  // Try to decrypt with different label - should fail
  let label2 = Bytes::from_array([b'L', b'a', b'b', b'e', b'l', b'2'])
  let result = try {
    let _ = @rsa.rsaes_oaep_decrypt(privateKey, ciphertext, label2)
    false
  } catch {
    _ => true
  }
  inspect(result, content="true")
}

///|
test "rsaes_oaep_encrypt_decrypt_large_message" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare larger test message (100 bytes)
  let message_bytes = FixedArray::make(100, b'\x00')
  for i = 0; i < 100; i = i + 1 {
    message_bytes[i] = (i % 256).to_byte()
  }
  let message = Bytes::from_array(message_bytes)

  // Encrypt message
  let label = Bytes::new(0)
  let ciphertext = @rsa.rsaes_oaep_encrypt(publicKey, message, label)

  // Decrypt ciphertext
  let decrypted_message = @rsa.rsaes_oaep_decrypt(privateKey, ciphertext, label)

  // Verify decrypted message matches original message
  inspect(decrypted_message == message, content="true")
}

///|
test "rsaes_oaep_decrypt_with_wrong_key" {
  // Generate two different RSA key pairs
  let (publicKey1, _) = @rsa.generate_key_pairs(2048, 65537)
  let (_, privateKey2) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'P', b'r', b'i', b'v', b'a', b't', b'e'])

  // Encrypt with first public key
  let label = Bytes::new(0)
  let ciphertext = @rsa.rsaes_oaep_encrypt(publicKey1, message, label)

  // Try to decrypt with different private key - should fail
  let result = try {
    let _ = @rsa.rsaes_oaep_decrypt(privateKey2, ciphertext, label)
    false
  } catch {
    _ => true
  }
  inspect(result, content="true")
}

///|
test "rsaes_pkcs1_v1_5_encrypt_decrypt" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([
    b'H', b'e', b'l', b'l', b'o', b' ', b'W', b'o', b'r', b'l', b'd',
  ])

  // Encrypt message
  let ciphertext = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey, message)

  // Verify ciphertext length matches modulus length
  let modulus_len = (publicKey.modulus.bit_length() + 7) / 8
  inspect(ciphertext.length(), content=modulus_len.to_string())

  // Decrypt ciphertext
  let decrypted_message = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey, ciphertext)

  // Verify decrypted message matches original message
  inspect(decrypted_message == message, content="true")
}

///|
test "rsaes_pkcs1_v1_5_encrypt_decrypt_empty_message" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare empty message
  let message = Bytes::new(0)

  // Encrypt message
  let ciphertext = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey, message)

  // Decrypt ciphertext
  let decrypted_message = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey, ciphertext)

  // Verify decrypted message matches original (empty) message
  inspect(decrypted_message.length(), content="0")
}

///|
test "rsaes_pkcs1_v1_5_encrypt_decrypt_max_length" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Calculate maximum message length for 2048-bit key
  // k = 256 bytes, max message = k - 11 = 245 bytes
  let modulus_len = (publicKey.modulus.bit_length() + 7) / 8
  let max_len = modulus_len - 11

  // Create maximum length message
  let message_bytes = FixedArray::make(max_len, b'\x00')
  for i = 0; i < max_len; i = i + 1 {
    message_bytes[i] = (i % 256).to_byte()
  }
  let message = Bytes::from_array(message_bytes)

  // Encrypt message
  let ciphertext = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey, message)

  // Decrypt ciphertext
  let decrypted_message = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey, ciphertext)

  // Verify decrypted message matches original message
  inspect(decrypted_message == message, content="true")
  inspect(decrypted_message.length(), content=max_len.to_string())
}

///|
test "rsaes_pkcs1_v1_5_encrypt_message_too_long" {
  // Generate RSA key pair
  let (publicKey, _) = @rsa.generate_key_pairs(2048, 65537)

  // Calculate modulus length and create message that is too long
  let modulus_len = (publicKey.modulus.bit_length() + 7) / 8
  let too_long_len = modulus_len - 10 // One byte more than max (k - 11)
  let message_bytes = FixedArray::make(too_long_len, b'A')
  let message = Bytes::from_array(message_bytes)

  // Attempt to encrypt - should fail
  let result = try {
    let _ = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey, message)
    false
  } catch {
    _ => true
  }
  inspect(result, content="true")
}

///|
test "rsaes_pkcs1_v1_5_decrypt_with_wrong_key" {
  // Generate two different RSA key pairs
  let (publicKey1, _) = @rsa.generate_key_pairs(2048, 65537)
  let (_, privateKey2) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'S', b'e', b'c', b'r', b'e', b't'])

  // Encrypt with first public key
  let ciphertext = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey1, message)

  // Try to decrypt with different private key - should fail
  let result = try {
    let _ = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey2, ciphertext)
    false
  } catch {
    _ => true
  }
  inspect(result, content="true")
}

///|
test "rsaes_pkcs1_v1_5_decrypt_corrupted_ciphertext" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'T', b'e', b's', b't'])

  // Encrypt message
  let ciphertext = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey, message)

  // Corrupt ciphertext by flipping a byte
  let corrupted_ciphertext = if ciphertext.length() > 0 {
    let first_byte = ciphertext.at(0)
    Bytes::from_array([first_byte ^ 0xFF]) + ciphertext[1:].to_bytes()
  } else {
    ciphertext
  }

  // Try to decrypt corrupted ciphertext - should fail
  let result = try {
    let _ = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey, corrupted_ciphertext)
    false
  } catch {
    _ => true
  }
  inspect(result, content="true")
}

///|
test "rsaes_pkcs1_v1_5_encrypt_decrypt_various_sizes" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Test various message sizes
  let sizes = [1, 10, 50, 100, 200]
  for size in sizes {
    let message_bytes = FixedArray::make(size, b'\x00')
    for i = 0; i < size; i = i + 1 {
      message_bytes[i] = ((i * 7 + 13) % 256).to_byte()
    }
    let message = Bytes::from_array(message_bytes)

    // Encrypt and decrypt
    let ciphertext = @rsa.rsaes_pkcs1_v1_5_encrypt(publicKey, message)
    let decrypted = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey, ciphertext)

    // Verify roundtrip
    inspect(decrypted == message, content="true")
  }
}

///|
test "rsassa_pkcs1_v1_5_sign_verify" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Prepare test message
  let message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])

  // Generate signature
  let signature = @rsa.rsassa_pkcs1_v1_5_sign(privateKey, message)

  // Verify signature length matches modulus length
  let modulus_len = (publicKey.modulus.bit_length() + 7) / 8
  inspect(signature.length(), content=modulus_len.to_string())

  // Verify signature
  let is_valid = @rsa.rsassa_pkcs1_v1_5_verify(publicKey, message, signature)
  inspect(is_valid, content="true")
}

///|
test "rsassa_pkcs1_v1_5_deterministic" {
  // RSASSA-PKCS1-v1_5 is deterministic (unlike PSS), so signing the same
  // message twice with the same key should produce the same signature
  let (_, privateKey) = @rsa.generate_key_pairs(2048, 65537)
  let message = Bytes::from_array([b'T', b'e', b's', b't'])
  let sig1 = @rsa.rsassa_pkcs1_v1_5_sign(privateKey, message)
  let sig2 = @rsa.rsassa_pkcs1_v1_5_sign(privateKey, message)
  inspect(sig1 == sig2, content="true")
}

///|
test "rsassa_pkcs1_v1_5_verify_tampered_message" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Sign original message
  let original_message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o'])
  let signature = @rsa.rsassa_pkcs1_v1_5_sign(privateKey, original_message)

  // Verify with tampered message - should fail
  let modified_message = Bytes::from_array([b'h', b'e', b'l', b'l', b'o', b'!'])
  let invalid = @rsa.rsassa_pkcs1_v1_5_verify(
    publicKey, modified_message, signature,
  )
  inspect(invalid, content="false")
}

///|
test "rsassa_pkcs1_v1_5_verify_tampered_signature" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)
  let message = Bytes::from_array([b'D', b'a', b't', b'a'])
  let signature = @rsa.rsassa_pkcs1_v1_5_sign(privateKey, message)

  // Corrupt signature by flipping first byte
  let corrupted = Bytes::from_array([signature.at(0) ^ 0xFF]) +
    signature[1:].to_bytes()
  let invalid = @rsa.rsassa_pkcs1_v1_5_verify(publicKey, message, corrupted)
  inspect(invalid, content="false")
}

///|
test "rsassa_pkcs1_v1_5_verify_wrong_key" {
  // Generate two different RSA key pairs
  let (_, privateKey1) = @rsa.generate_key_pairs(2048, 65537)
  let (publicKey2, _) = @rsa.generate_key_pairs(2048, 65537)
  let message = Bytes::from_array([b'M', b's', b'g'])
  let signature = @rsa.rsassa_pkcs1_v1_5_sign(privateKey1, message)

  // Verify with wrong public key - should fail
  let invalid = @rsa.rsassa_pkcs1_v1_5_verify(publicKey2, message, signature)
  inspect(invalid, content="false")
}

///|
test "rsassa_pkcs1_v1_5_sign_verify_large_message" {
  // Generate RSA key pair
  let (publicKey, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Create a larger message (500 bytes)
  let message_bytes = FixedArray::make(500, b'\x00')
  for i = 0; i < 500; i = i + 1 {
    message_bytes[i] = ((i * 13 + 7) % 256).to_byte()
  }
  let message = Bytes::from_array(message_bytes)

  // Sign and verify
  let signature = @rsa.rsassa_pkcs1_v1_5_sign(privateKey, message)
  let is_valid = @rsa.rsassa_pkcs1_v1_5_verify(publicKey, message, signature)
  inspect(is_valid, content="true")
}

///|
test "rsaes_pkcs1_v1_5_decrypt_wrong_ciphertext_length" {
  // Generate RSA key pair
  let (_, privateKey) = @rsa.generate_key_pairs(2048, 65537)

  // Create ciphertext with wrong length
  let wrong_length_ciphertext = Bytes::from_array([b'\x00', b'\x01', b'\x02'])

  // Try to decrypt - should fail due to length check
  let result = try {
    let _ = @rsa.rsaes_pkcs1_v1_5_decrypt(privateKey, wrong_length_ciphertext)
    false
  } catch {
    _ => true
  }
  inspect(result, content="true")
}
