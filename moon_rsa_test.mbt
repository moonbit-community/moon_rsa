///|
test "generateKeyPairs" {
  let (publicKey, privateKey) = generateKeyPairs(2048, 65537)
  inspect(publicKey.modulus.bit_length(), content="2048")
  inspect(privateKey.modulus.bit_length(), content="2048")
}

///|
test "rsassaPssSignAndVerify" {
  let (publicKey, privateKey) = generateKeyPairs(2048, 65537)
  let message = "Hello, RSA-PSS!".to_bytes()
  let params = PssParams::default(HashAlgorithm::SHA256)

  // Sign the message
  let signature = rsassaPssSign(message, privateKey, params)
  inspect(signature > BigInt::from_int(0), content="true")

  // Verify the signature
  let isValid = rsassaPssVerify(message, signature, publicKey, params)
  inspect(isValid, content="true")
}
